/*
 * vDSO ELF image
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Builds a minimal vDSO ELF image in guest memory exposing versioned
 * __kernel_{rt_sigreturn,clock_getres,clock_gettime,gettimeofday,getcpu}.
 * clock_gettime and gettimeofday are CNTVCT-based fast-path trampolines that
 * serve CLOCK_MONOTONIC (clockid 1) and CLOCK_REALTIME (clockid 0) inline
 * without trapping; clock_getres serves the common nsec-resolution clockids
 * inline; getcpu always returns cpu=0/node=0 (elfuse models one CPU);
 * rt_sigreturn remains a 12-byte SVC trampoline.
 *
 * The fast path reads CNTVCT_EL0 at EL0 (enabled via CNTKCTL_EL1.EL0VCTEN in
 * the bootstrap), looks up the host-published anchor in the vvar (seq,
 * anchor_cntvct, anchor_mono_sec/nsec, anchor_real_sec/nsec), and interpolates
 * the requested clock from the CNTVCT delta. The vvar is seeded on the first
 * clock_gettime SVC fallback, gated on ELR_EL1 == svc_fallback_pc + 4 so an
 * unrelated raw syscall(SYS_clock_gettime, ...) cannot poison the anchor from
 * an arbitrary X9 value. A Linux-style seqlock (see the vvar layout block
 * below) keeps concurrent publishers and readers race-free.
 *
 * Anchor-age cap: the time trampolines refuse to interpolate once (cntvct -
 * anchor_cntvct) exceeds 2**22 cycles (~0.175 s at 24 MHz). That forces an SVC
 * fallback the host can use to re-anchor against fresh macOS clocks, bounding
 * any drift relative to a fresh REALTIME SVC after an NTP step or long sleep.
 * The host SVC path also computes a predicted REALTIME from the anchor and
 * invalidates whenever the delta against a fresh REALTIME sample exceeds
 * VDSO_ANCHOR_MAX_DRIFT_NS, so workloads that do take an SVC for any reason
 * re-anchor immediately.
 */

#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

#include "core/vdso.h"
#include "core/elf.h"
#include "debug/log.h"

/* ELF section header (not in core/elf.h). */

typedef struct {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
} elf64_shdr_t;

typedef struct {
    int64_t d_tag;
    uint64_t d_val;
} elf64_dyn_t;

typedef struct {
    uint32_t st_name;
    uint8_t st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
} elf64_sym_t;

typedef struct {
    uint16_t vd_version;
    uint16_t vd_flags;
    uint16_t vd_ndx;
    uint16_t vd_cnt;
    uint32_t vd_hash;
    uint32_t vd_aux;
    uint32_t vd_next;
} elf64_verdef_t;

typedef struct {
    uint32_t vda_name;
    uint32_t vda_next;
} elf64_verdaux_t;

/* ELF constants */
#define SHT_STRTAB 3
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_DYNSYM 11
#define SHT_GNU_VERDEF 0x6ffffffd
#define SHT_GNU_VERSYM 0x6fffffff
#define SHF_ALLOC (1ULL << 1)
#define SHF_EXECINSTR (1ULL << 2)
#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_VERSYM 0x6ffffff0
#define DT_VERDEF 0x6ffffffc
#define DT_VERDEFNUM 0x6ffffffd
#define STB_GLOBAL 1
#define STT_FUNC 2
#define VER_DEF_CURRENT 1
#define VDSO_LINUX_VERSION_INDEX 2
#define ELF_ST_INFO(bind, type) (((bind) << 4) | ((type) & 0xf))

/* Host-owned vDSO page accessor. The vDSO is mapped RX to EL0, so guest
 * permission walkers cannot write here; route every host build/seed/attention
 * mutation through this bounds-checked direct host_base+VDSO_BASE pointer.
 */
static uint8_t *vdso_host_page(guest_t *g)
{
    if (VDSO_BASE + VDSO_SIZE > g->guest_size)
        return NULL;
    return (uint8_t *) g->host_base + VDSO_BASE;
}

/* Layout.
 *
 * Symbol layout (sizes vary; the time trampolines are CNTVCT-fast paths, getcpu
 * / clock_getres are pure-arithmetic fast paths, rt_sigreturn is a 12-byte SVC
 * trampoline):
 *   [0] __kernel_rt_sigreturn
 *   [1] __kernel_clock_getres
 *   [2] __kernel_clock_gettime
 *   [3] __kernel_gettimeofday
 *   [4] __kernel_getcpu
 *
 * Page layout (4 KiB):
 *   0x000  EHDR
 *   0x040  NT_GNU_ABI_TAG note (32 B)
 *   0x0B0  vvar (seqlock counter, attention, anchor pairs)
 *   0x0E0  rt_sigreturn trampoline
 *   0x0EC  clock_getres / clock_gettime / gettimeofday / getcpu trampolines
 *   ...    dynstr / dynsym / hash / versym / verdef / dynamic / shdr
 *   0x4B0  section header table (8 entries)
 *   0x6B0  program header table (3 entries: PT_LOAD, PT_DYNAMIC, PT_NOTE)
 *
 * The PHDR table sits at the bottom of the structural area so that the
 * 4-byte-aligned NT_GNU_ABI_TAG note can occupy the old PHDR window and glibc
 * 2.41's dynamic-linker vDSO probe finds the expected note without any of the
 * trampoline / section offsets shifting.
 */

/* Offsets within the 4KiB page.
 *
 * The PHDR table now sits past the SHDR area at 0x6B0 (the EHDR's e_phoff field
 * follows it there). This leaves the old PHDR slot at 0x040 free for the
 * NT_GNU_ABI_TAG note data that glibc 2.41 expects to find via the PT_NOTE
 * entry, without disturbing VVAR (0xB0), SIGRET (0xE0), or any of the
 * trampoline / section offsets. PT_LOAD still maps the whole page so the note
 * is loaded with the rest.
 */
#define VDSO_OFF_EHDR 0x000

/* NT_GNU_ABI_TAG note data lives at the old PHDR slot; 32 bytes fits
 * comfortably inside the 112-byte gap up to VVAR.
 */
#define VDSO_OFF_NOTE 0x040
#define VDSO_NOTE_SIZE 0x20

/* vvar at fixed offset; host writes the wall-clock anchor on first
 * clock_gettime SVC, after the guest trampoline has stored its own CNTVCT_EL0
 * read into X9. Layout:
 *   +0   uint32 seq (Linux-style seqlock counter; see state machine below)
 *   +4   uint32 attention (host mirrors shim attention bits; nonzero -> SVC)
 *   +8   uint64 anchor_cntvct (guest frame, written by host from X9)
 *   +16  uint64 anchor_mono_sec  (CLOCK_MONOTONIC anchor)
 *   +24  uint64 anchor_mono_nsec
 *   +32  uint64 anchor_real_sec  (CLOCK_REALTIME anchor)
 *   +40  uint64 anchor_real_nsec
 *
 * seq state machine (a Linux-style seqlock):
 *   0           : unseeded -- never written, no anchor data yet
 *   odd N >= 1  : writer reserved generation (N+1)/2; anchor fields in flux
 *   even N >= 2 : stable generation N/2; anchor fields readable
 *
 * Writers (vdso_seed_anchor) CAS seq from an even value (0 or 2K) to the next
 * odd, store new anchor fields, and release-store the next even. This handles
 * both initial seeding (0 -> 1 -> 2) and refresh (2K -> 2K+1 -> 2K+2)
 * atomically; no separate invalidate path is needed.
 *
 * Trampoline readers LDAR seq into a snapshot register, bail on 0 (unseeded) or
 * odd (writer in progress), read anchor fields with plain loads, then LDAR seq
 * again -- any change between the two reads means a writer raced, so fall back
 * to SVC.
 *
 * Both MONO and REAL anchor pairs are written together so a fast-path caller
 * for either clockid sees a consistent pair after observing an even seq. The
 * trampoline interpolates either pair from the shared CNTVCT delta; the picking
 * of MONO vs REAL is done by adding VVAR_OFF_ANCHOR_MONO_SEC or
 * VVAR_OFF_ANCHOR_REAL_SEC to the vvar base and LDPing the two-doubleword
 * anchor.
 *
 * The trampoline's anchor-age cap (LSR + CBNZ on the CNTVCT delta) and the
 * host's drift detector in sys_clock_gettime together bound drift after a macOS
 * NTP step or a long sleep.
 */
#define VDSO_OFF_VVAR 0x0B0
/* Linux-style seqlock counter; see the state machine above. */
#define VVAR_OFF_SEQ 0x00
#define VVAR_OFF_ATTENTION 0x04
#define VVAR_OFF_ANCHOR_CNTVCT 0x08
#define VVAR_OFF_ANCHOR_MONO_SEC 0x10
#define VVAR_OFF_ANCHOR_MONO_NSEC 0x18
#define VVAR_OFF_ANCHOR_REAL_SEC 0x20
#define VVAR_OFF_ANCHOR_REAL_NSEC 0x28
#define VVAR_SIZE 0x30

/* .text trampoline offsets and sizes. rt_sigreturn is a 12-byte SVC trampoline.
 * clock_getres / getcpu are arithmetic fast paths. clock_gettime / gettimeofday
 * are CNTVCT fast paths that implement a seqlock-style read against the vvar
 * above (see the per-emitter comments for instruction-level layout). Sizes are
 * exact; the static_asserts on each emitter catch drift.
 */
#define TEXT_OFF_SIGRET 0x0E0
#define TEXT_OFF_GETRES 0x0EC
#define TEXT_GETRES_SIZE 0x5C
#define TEXT_OFF_GETTIME (TEXT_OFF_GETRES + TEXT_GETRES_SIZE)
#define TEXT_GETTIME_SIZE 0xA8
#define TEXT_OFF_GETTOD (TEXT_OFF_GETTIME + TEXT_GETTIME_SIZE)
#define TEXT_GETTOD_SIZE 0xA0
#define TEXT_OFF_GETCPU (TEXT_OFF_GETTOD + TEXT_GETTOD_SIZE)
#define TEXT_GETCPU_SIZE 0x34
#define TEXT_END (TEXT_OFF_GETCPU + TEXT_GETCPU_SIZE)

/* Offset of the SVC instruction inside __kernel_clock_gettime's svc_fallback
 * (svc_fallback opens at instruction 39 of 42, i.e. byte 0x9C; the SVC is the
 * second instruction of the fallback, at byte 0xA0). The host's
 * sys_clock_gettime uses this value to gate vvar seeding: only a trap whose
 * ELR_EL1 equals SVC_PC + 4 came from the trampoline and may carry a
 * trustworthy CNTVCT in X9.
 */
#define VDSO_CLOCK_GETTIME_SVC_PC (TEXT_OFF_GETTIME + 0xA0)

/* gettimeofday svc_fallback opens at instruction 37 of 40 (byte 0x94); SVC at
 * byte 0x98.
 */
#define VDSO_GETTIMEOFDAY_SVC_PC (TEXT_OFF_GETTOD + 0x98)

/* Anchor-age cap. The trampolines refuse to interpolate once (cntvct -
 * anchor_cntvct) exceeds (1ULL << ANCHOR_AGE_SHIFT) cycles, checked via LSR +
 * CBNZ on the delta. With CNTFRQ = 24 MHz, shift 22 caps the delta at ~0.175 s
 * (~175e6 ns).
 *
 * Shift 22 is load-bearing: it keeps delta_ns + anchor_nsec below 2e9, so the
 * sub-1e9 carry collapses to one SUBS + CSEL + CINC instead of a UDIV-by-1e9.
 * Loosening the cap or raising CNTFRQ past that bound requires restoring a real
 * division. The host drift check in sys_clock_gettime must use the same shift
 * to stay coherent.
 */
#define VDSO_ANCHOR_AGE_SHIFT 22

/* dynstr, dynsym, hash, GNU version metadata, dynamic, shdr follow. TEXT_END is
 * 0x2C4 after the dmb-ishld insertion in gettime/gettod.
 */
#define VDSO_OFF_DYNSTR TEXT_END

/* dynstr_data is 119 bytes (six \0-prefixed names + LINUX_2.6.39 + trailing
 * NUL). Pad to 8-byte align for DYNSYM: 0x2C4 + 119 = 0x33B -> 0x340.
 */
#define VDSO_OFF_DYNSYM 0x340

/* 6 * 24 = 144, 0x340 + 144 = 0x3D0 (already 8-byte aligned for HASH) */
#define VDSO_OFF_HASH 0x3D0

/* (2 + 1 + 6) * 4 = 36, 0x3D0 + 36 = 0x3F4, 4-byte aligned for VERSYM */
#define VDSO_OFF_VERSYM 0x3F4

/* 6 * 2 = 12, 0x3F4 + 12 = 0x400, already 8-byte aligned for VERDEF */
#define VDSO_OFF_VERDEF 0x400

/* Verdef + verdaux = 28, 0x400 + 28 = 0x41C, pad to 0x420 for DYNAMIC */
#define VDSO_OFF_DYNAMIC 0x420

/* 9 * 16 = 144, 0x420 + 144 = 0x4B0 */
#define VDSO_OFF_SHDR 0x4B0

/* 8 * 64 = 512, 0x4B0 + 512 = 0x6B0 (fits in 4 KiB) */

/* Program header table sits after the section headers so the old PHDR window at
 * 0x040 can host the NT_GNU_ABI_TAG note data. Three entries (PT_LOAD,
 * PT_DYNAMIC, PT_NOTE) at 56 bytes each end at 0x758, leaving the rest of the
 * page reserved for future growth.
 */
#define VDSO_OFF_PHDR 0x6B0
#define VDSO_OFF_PHDR1 (VDSO_OFF_PHDR + 0x38)
#define VDSO_OFF_PHDR2 (VDSO_OFF_PHDR1 + 0x38)
#define VDSO_PHDR_TABLE_END (VDSO_OFF_PHDR2 + 0x38)

#define VDSO_NUM_SYMS 5
#define HASH_NCHAIN (VDSO_NUM_SYMS + 1)
#define HASH_NBUCKET 1
#define HASH_SIZE ((2 + HASH_NBUCKET + HASH_NCHAIN) * sizeof(uint32_t))
#define VERSYM_SIZE ((VDSO_NUM_SYMS + 1) * sizeof(uint16_t))
#define VERDEF_SIZE (sizeof(elf64_verdef_t) + sizeof(elf64_verdaux_t))
#define VDSO_NUM_DYN 9

/* NT_GNU_ABI_TAG note. glibc 2.41's vDSO setup expects this entry to be present
 * alongside the dynamic symbol table; without it the dynamic linker still maps
 * the page but skips the per-symbol fast-path lookup, forcing the
 * dynamically-linked guest into the SVC tail of every trampoline. The note
 * layout matches what the upstream Linux kernel emits from
 * arch/arm64/kernel/vdso/note.S:
 *
 *   namesz : 4   (uint32, "GNU\0")
 *   descsz : 16  (uint32, four-word descriptor)
 *   type   : 1   (NT_GNU_ABI_TAG)
 *   name   : "GNU\0"
 *   desc   : { 0 (Linux), major, minor, sublevel } as uint32 each
 *
 * The desc declares the minimum supported kernel ABI. 2.6.39 matches the
 * LINUX_2.6.39 symbol version already exposed through DT_VERDEF -- both say
 * "this vDSO speaks the 2.6.39 ABI" -- so a glibc that accepts the symbol
 * version also accepts the note.
 */
#define NT_GNU_ABI_TAG 1
#define ELF_NOTE_OS_LINUX 0
#define VDSO_NOTE_KERNEL_MAJOR 2
#define VDSO_NOTE_KERNEL_MINOR 6
#define VDSO_NOTE_KERNEL_SUBLEVEL 39

typedef struct {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    char name[4]; /* "GNU\0" */
    uint32_t desc[4];
} elf64_note_gnu_abi_tag_t;

_Static_assert(sizeof(elf64_note_gnu_abi_tag_t) == VDSO_NOTE_SIZE,
               "GNU ABI tag note must match VDSO_NOTE_SIZE");

/* .dynstr data */
static const char dynstr_data[] =
    "\0__kernel_rt_sigreturn"
    "\0__kernel_clock_getres"
    "\0__kernel_clock_gettime"
    "\0__kernel_gettimeofday"
    "\0__kernel_getcpu"
    "\0LINUX_2.6.39";
#define DYNSTR_SIZE sizeof(dynstr_data)

/* Symbol name offsets, derived from preceding string-literal lengths so a
 * future edit to dynstr_data shifts them in lockstep instead of silently
 * breaking the version lookup (sizeof("\0X") - 1 == bytes contributed when X is
 * concatenated into dynstr_data; only the very last literal's trailing NUL
 * survives concatenation).
 */
#define DYNSTR_BYTES_RT_SIGRETURN (sizeof("\0__kernel_rt_sigreturn") - 1)
#define DYNSTR_BYTES_CLOCK_GETRES (sizeof("\0__kernel_clock_getres") - 1)
#define DYNSTR_BYTES_CLOCK_GETTIME (sizeof("\0__kernel_clock_gettime") - 1)
#define DYNSTR_BYTES_GETTIMEOFDAY (sizeof("\0__kernel_gettimeofday") - 1)
#define DYNSTR_BYTES_GETCPU (sizeof("\0__kernel_getcpu") - 1)

static const uint32_t sym_name_offsets[VDSO_NUM_SYMS] = {
    1,
    DYNSTR_BYTES_RT_SIGRETURN + 1,
    DYNSTR_BYTES_RT_SIGRETURN + DYNSTR_BYTES_CLOCK_GETRES + 1,
    DYNSTR_BYTES_RT_SIGRETURN + DYNSTR_BYTES_CLOCK_GETRES +
        DYNSTR_BYTES_CLOCK_GETTIME + 1,
    DYNSTR_BYTES_RT_SIGRETURN + DYNSTR_BYTES_CLOCK_GETRES +
        DYNSTR_BYTES_CLOCK_GETTIME + DYNSTR_BYTES_GETTIMEOFDAY + 1,
};
/* Skip the leading \0 of "\0LINUX_2.6.39" to land on 'L'. */
#define VDSO_LINUX_VERSION_NAME_OFF                           \
    (DYNSTR_BYTES_RT_SIGRETURN + DYNSTR_BYTES_CLOCK_GETRES +  \
     DYNSTR_BYTES_CLOCK_GETTIME + DYNSTR_BYTES_GETTIMEOFDAY + \
     DYNSTR_BYTES_GETCPU + 1)

_Static_assert(sizeof(dynstr_data) <= (VDSO_OFF_DYNSYM - VDSO_OFF_DYNSTR),
               "dynstr_data outgrew the DYNSYM padding window");

/* Symbol text offsets and sizes */
static const uint32_t sym_text_off[VDSO_NUM_SYMS] = {
    TEXT_OFF_SIGRET, TEXT_OFF_GETRES, TEXT_OFF_GETTIME,
    TEXT_OFF_GETTOD, TEXT_OFF_GETCPU,
};
static const uint32_t sym_text_size[VDSO_NUM_SYMS] = {
    12, TEXT_GETRES_SIZE, TEXT_GETTIME_SIZE, TEXT_GETTOD_SIZE, TEXT_GETCPU_SIZE,
};

/* Emit a 12-byte SVC trampoline: mov x8, #syscall_nr; svc #0; ret. */
static void emit_svc_trampoline(uint32_t *code, unsigned syscall_nr)
{
    /* MOVZ Xd, #imm16, LSL #0: encoding 0xD2800000 | (imm16<<5) | rd. */
    code[0] = 0xD2800000U | (((uint32_t) syscall_nr & 0xFFFF) << 5) | 8;
    code[1] = 0xD4000001U; /* svc #0 */
    code[2] = 0xD65F03C0U; /* ret    */
}

/* AArch64 instruction encoders (only the ones used here). */
static uint32_t enc_movz_x(unsigned rd, uint16_t imm)
{
    return 0xD2800000U | ((uint32_t) imm << 5) | (rd & 0x1F);
}

static uint32_t enc_movk_x_lsl16(unsigned rd, uint16_t imm)
{
    return 0xF2A00000U | ((uint32_t) imm << 5) | (rd & 0x1F);
}

static uint32_t enc_adr(unsigned rd, int32_t pc_rel)
{
    uint32_t immlo = (uint32_t) (pc_rel & 0x3);
    uint32_t immhi = (uint32_t) ((pc_rel >> 2) & 0x7FFFF);
    return 0x10000000U | (immlo << 29) | (immhi << 5) | (rd & 0x1F);
}

/* B.cond imm19. cond is the 4-bit AArch64 condition (NE=0x1, LO=0x3, etc.). */
#define COND_EQ 0x0
#define COND_NE 0x1
#define COND_HS 0x2 /* unsigned >=, alias CS */
#define COND_LO 0x3
#define COND_HI 0x8
static uint32_t enc_bcond_imm19(unsigned cond, int32_t pc_rel)
{
    uint32_t imm19 = (uint32_t) ((pc_rel >> 2) & 0x7FFFF);
    return 0x54000000U | (imm19 << 5) | (cond & 0xF);
}

static uint32_t enc_ldr_x_imm12(unsigned rt, unsigned rn, uint32_t off_bytes)
{
    return 0xF9400000U | ((off_bytes / 8) << 10) | ((rn & 0x1F) << 5) |
           (rt & 0x1F);
}

static uint32_t enc_add_x(unsigned rd, unsigned rn, unsigned rm)
{
    return 0x8B000000U | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F);
}

static uint32_t enc_add_x_imm12(unsigned rd, unsigned rn, uint16_t imm)
{
    return 0x91000000U | (((uint32_t) imm & 0xFFF) << 10) | ((rn & 0x1F) << 5) |
           (rd & 0x1F);
}

static uint32_t enc_mul_x(unsigned rd, unsigned rn, unsigned rm)
{
    return 0x9B007C00U | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F);
}

static uint32_t enc_udiv_x(unsigned rd, unsigned rn, unsigned rm)
{
    return 0x9AC00800U | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F);
}

/* CSEL Xd, Xn, Xm, cond: if cond Xd=Xn else Xd=Xm. */
static uint32_t enc_csel_x(unsigned rd, unsigned rn, unsigned rm, unsigned cond)
{
    return 0x9A800000U | ((rm & 0x1F) << 16) | ((cond & 0xF) << 12) |
           ((rn & 0x1F) << 5) | (rd & 0x1F);
}

/* CSINC Xd, Xn, Xm, cond: if cond Xd=Xn else Xd=Xm+1. Encodes CINC Xd, Xn, cond
 * as CSINC Xd, Xn, Xn, invert(cond).
 */
static uint32_t enc_csinc_x(unsigned rd,
                            unsigned rn,
                            unsigned rm,
                            unsigned cond)
{
    return 0x9A800400U | ((rm & 0x1F) << 16) | ((cond & 0xF) << 12) |
           ((rn & 0x1F) << 5) | (rd & 0x1F);
}

static uint32_t enc_msub_x(unsigned rd, unsigned rn, unsigned rm, unsigned ra)
{
    return 0x9B008000U | ((rm & 0x1F) << 16) | ((ra & 0x1F) << 10) |
           ((rn & 0x1F) << 5) | (rd & 0x1F);
}

static uint32_t enc_stp_x_imm7(unsigned rt1,
                               unsigned rt2,
                               unsigned rn,
                               int32_t off_bytes)
{
    int32_t imm7 = (off_bytes / 8) & 0x7F;
    return 0xA9000000U | ((uint32_t) imm7 << 15) | ((rt2 & 0x1F) << 10) |
           ((rn & 0x1F) << 5) | (rt1 & 0x1F);
}

static uint32_t enc_cmp_w_imm12(unsigned rn, uint32_t imm12)
{
    /* SUBS WZR, Wn, #imm12 */
    return 0x7100001FU | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5);
}

/* LDAR Wt, [Xn] -- acquire load of a 32-bit word. Pairs with the host's
 * atomic_store_explicit(initialized, ..., memory_order_release) so that
 * observing initialized != 0 also makes the prior anchor stores visible.
 */
static uint32_t enc_ldar_w(unsigned rt, unsigned rn)
{
    return 0x88DFFC00U | ((rn & 0x1F) << 5) | (rt & 0x1F);
}

/* SUBS Xd, Xn, Xm (set flags). */
static uint32_t enc_subs_x(unsigned rd, unsigned rn, unsigned rm)
{
    return 0xEB000000U | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F);
}

/* CBZ Wt, imm19 (byte-relative; encoder shifts >>2 internally). */
static uint32_t enc_cbz_w(unsigned rt, int32_t pc_rel)
{
    uint32_t imm19 = (uint32_t) ((pc_rel >> 2) & 0x7FFFF);
    return 0x34000000U | (imm19 << 5) | (rt & 0x1F);
}

static uint32_t enc_cbnz_w(unsigned rt, int32_t pc_rel)
{
    uint32_t imm19 = (uint32_t) ((pc_rel >> 2) & 0x7FFFF);
    return 0x35000000U | (imm19 << 5) | (rt & 0x1F);
}

/* B imm26 unconditional branch (byte-relative). */
static uint32_t enc_b(int32_t pc_rel)
{
    uint32_t imm26 = (uint32_t) ((pc_rel >> 2) & 0x3FFFFFF);
    return 0x14000000U | imm26;
}

/* LDP Xt1, Xt2, [Xn, #off_bytes] (signed 7-bit imm, multiple of 8). */
static uint32_t enc_ldp_x_imm7(unsigned rt1,
                               unsigned rt2,
                               unsigned rn,
                               int32_t off_bytes)
{
    int32_t imm7 = (off_bytes / 8) & 0x7F;
    return 0xA9400000U | ((uint32_t) imm7 << 15) | ((rt2 & 0x1F) << 10) |
           ((rn & 0x1F) << 5) | (rt1 & 0x1F);
}

/* LSR Xd, Xn, #shift -- UBFM Xd, Xn, #shift, #63. shift in 1..63. */
static uint32_t enc_lsr_x_imm(unsigned rd, unsigned rn, unsigned shift)
{
    return 0xD340FC00U | ((shift & 0x3F) << 16) | ((rn & 0x1F) << 5) |
           (rd & 0x1F);
}

/* STR Xt, [Xn, #off_bytes] (off multiple of 8). */
static uint32_t enc_str_x_imm12(unsigned rt, unsigned rn, uint32_t off_bytes)
{
    return 0xF9000000U | ((off_bytes / 8) << 10) | ((rn & 0x1F) << 5) |
           (rt & 0x1F);
}

/* STR Wt, [Xn, #off_bytes] (off multiple of 4). */
static uint32_t enc_str_w_imm12(unsigned rt, unsigned rn, uint32_t off_bytes)
{
    return 0xB9000000U | ((off_bytes / 4) << 10) | ((rn & 0x1F) << 5) |
           (rt & 0x1F);
}

/* CBZ Xt, imm19 (byte-relative; encoder shifts >>2 internally). */
static uint32_t enc_cbz_x(unsigned rt, int32_t pc_rel)
{
    uint32_t imm19 = (uint32_t) ((pc_rel >> 2) & 0x7FFFF);
    return 0xB4000000U | (imm19 << 5) | (rt & 0x1F);
}

/* CBNZ Xt, imm19. */
static uint32_t enc_cbnz_x(unsigned rt, int32_t pc_rel)
{
    uint32_t imm19 = (uint32_t) ((pc_rel >> 2) & 0x7FFFF);
    return 0xB5000000U | (imm19 << 5) | (rt & 0x1F);
}

/* TBNZ Rt, #bit, imm14 (byte-relative). When bit < 32 the encoder uses the
 * W-form (sf-bit of bit-number = 0); the seqlock checks only test bit 0 so the
 * W/X distinction is moot for callers here.
 */
static uint32_t enc_tbnz(unsigned rt, unsigned bit, int32_t pc_rel)
{
    uint32_t b5 = (bit >> 5) & 1;
    uint32_t b40 = bit & 0x1F;
    uint32_t imm14 = (uint32_t) ((pc_rel >> 2) & 0x3FFF);
    return 0x37000000U | (b5 << 31) | (b40 << 19) | (imm14 << 5) | (rt & 0x1F);
}

/* MOV Wd, Wm (alias for ORR Wd, WZR, Wm). */
static uint32_t enc_mov_w_reg(unsigned rd, unsigned rm)
{
    return 0x2A0003E0U | ((rm & 0x1F) << 16) | (rd & 0x1F);
}

/* CMP Wn, Wm (alias for SUBS WZR, Wn, Wm). */
static uint32_t enc_cmp_w_reg(unsigned rn, unsigned rm)
{
    return 0x6B00001FU | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5);
}

/* DMB ISHLD: inner-shareable load-load barrier. Pairs the seqlock reader's
 * snapshot LDAR (forward acquire) with the plain anchor loads so a subsequent
 * recheck LDAR cannot be reordered before them. ARM ARM B2.3: LDAR orders later
 * memory ops after itself but does NOT order prior ops before itself, so the
 * recheck needs an explicit load barrier.
 */
#define VDSO_INSN_DMB_ISHLD 0xD50339BFU

/* Emit the CNTVCT fast-path clock_gettime trampoline at page+pc_off; the vvar
 * lives at page+vvar_off. The trampoline is exactly TEXT_GETTIME_SIZE bytes;
 * the static_assert below catches drift.
 *
 * Layout (42 instructions, 0xA8 bytes):
 *
 *   0x00  mrs  x9, cntvct_el0           ; always read first; x9 stays live
 *                                       ; to feed host CNTVCT to fallback SVC
 *   0x04  cbz  w0, .Lreal               ; clockid==0 -> CLOCK_REALTIME
 *   0x08  cmp  w0, #1                   ; clockid==1 -> CLOCK_MONOTONIC
 *   0x0C  b.ne svc_fallback              ; other clockid -> SVC
 *   0x10  mov  w7, #ANCHOR_MONO_SEC      ; offset within vvar of MONO sec
 *   0x14  b    .Linit
 *   0x18  .Lreal: mov w7, #ANCHOR_REAL_SEC
 *   0x1C  .Linit: adr x2, vvar
 *   0x20  add  x10, x2, #ATTENTION
 *   0x24  ldar w3, [x10]                 ; load attention flag (acquire)
 *   0x28  cbnz w3, svc_fallback          ; timers/signals need epilogue
 *   0x2C  ldar w3, [x2]                  ; seqlock snapshot (acquire)
 *   0x30  cbz  w3, svc_fallback          ; seq == 0 -> unseeded
 *   0x34  tbnz w3, #0, svc_fallback      ; seq odd -> writer in progress
 *   0x38  mov  w11, w3                   ; save seqlock snapshot
 *   0x3C  ldr  x3, [x2, #ANCHOR_CNTVCT]
 *   0x40  add  x8, x2, x7                ; x8 = vvar base + sec_offset
 *   0x44  ldp  x4, x5, [x8]              ; x4=anchor_sec, x5=anchor_nsec
 *   0x48  subs x6, x9, x3                ; cntvct delta
 *   0x4C  b.lo svc_fallback              ; underflow -> SVC
 *   0x50  lsr  x7, x6, #ANCHOR_AGE_SHIFT ; anchor-age cap (~0.175 s @ 24 MHz)
 *   0x54  cbnz x7, svc_fallback          ; stale anchor -> SVC, host reseeds
 *   ... (math: delta_ns = (delta * 699050666) >> 24; nsec += delta_ns;
 *        SUBS + CSEL + CINC carries the sub-1e9 fraction into sec.
 *        See the inline code[22-31] comments for the multiplier and
 *        carry-collapse rationale.)
 *   0x80  dmb  ishld                     ; load barrier before recheck
 *   0x84  ldar w12, [x2]                 ; seqlock recheck (acquire)
 *   0x88  cmp  w11, w12
 *   0x8C  b.ne svc_fallback              ; race -> SVC; x9 still = CNTVCT
 *   0x90  stp  x4, x5, [x1]              ; store {sec, nsec}
 *   0x94  mov  x0, #0
 *   0x98  ret
 *   0x9C  svc_fallback: mov x8, #113
 *   0xA0  svc  #0                        ; ELR_EL1 + 4 == SVC_PC
 *   0xA4  ret
 *
 * Both clockids share the same CNTVCT delta math; only the anchor pair loaded
 * via LDP changes. Picking via a runtime offset register avoids duplicating the
 * entire math block per clockid. The age check clobbers x7 (which has already
 * been consumed by ADD X8, X2, X7) before the math reloads x7 with the
 * mult+shift constant.
 *
 * The seqlock recheck runs after all anchor field reads and the math but before
 * the user-visible store. The preceding DMB ISHLD is critical: LDAR-acquire
 * orders later memory ops after itself but NOT prior ops before itself (ARM ARM
 * B2.3.4), so without the barrier the recheck LDAR could be observed by other
 * CPUs before the plain anchor LDR/LDP have committed -- allowing seq == snap
 * to pass while the field loads raced with a host CAS-bump-publish. A mismatch
 * with w11 means a host refresher ran between the two LDARs, so the trampoline
 * falls through to SVC for a fresh sample.
 */
static void emit_clock_gettime_trampoline(uint32_t *code,
                                          uint32_t pc_off,
                                          uint32_t vvar_off)
{
    /* Branch targets within the trampoline. */
    int32_t real_off = 0x18;         /* .Lreal */
    int32_t init_off = 0x1C;         /* .Linit (common path entry) */
    int32_t svc_fallback_off = 0x9C; /* svc_fallback */
    int32_t adr_pc_off = 0x1C;       /* offset of 'adr x2, vvar' */
    int32_t vvar_rel = (int32_t) vvar_off - (int32_t) (pc_off + adr_pc_off);

    code[0] = 0xD53BE049U;                   /* mrs  x9, cntvct_el0          */
    code[1] = enc_cbz_w(0, real_off - 0x04); /* cbz w0, .Lreal               */
    code[2] = enc_cmp_w_imm12(0, 1);         /* cmp  w0, #1                  */
    code[3] = enc_bcond_imm19(COND_NE, svc_fallback_off - 0x0C);
    /* b.ne svc_fallback  */
    code[4] = enc_movz_x(7, VVAR_OFF_ANCHOR_MONO_SEC);
    code[5] = enc_b(init_off - 0x14);                  /* b .Linit           */
    code[6] = enc_movz_x(7, VVAR_OFF_ANCHOR_REAL_SEC); /* .Lreal             */
    code[7] = enc_adr(2, vvar_rel);                    /* .Linit: adr x2,vv  */
    code[8] = enc_add_x_imm12(10, 2, VVAR_OFF_ATTENTION);
    code[9] = enc_ldar_w(3, 10);
    code[10] = enc_cbnz_w(3, svc_fallback_off - 0x28);
    code[11] = enc_ldar_w(3, 2);                      /* ldar w3, [x2]      */
    code[12] = enc_cbz_w(3, svc_fallback_off - 0x30); /* cbz w3, fallback   */
    code[13] = enc_tbnz(3, 0, svc_fallback_off - 0x34);
    /* tbnz w3, #0, fallback */
    code[14] = enc_mov_w_reg(11, 3); /* mov w11, w3        */
    code[15] = enc_ldr_x_imm12(3, 2, VVAR_OFF_ANCHOR_CNTVCT);
    code[16] = enc_add_x(8, 2, 7);         /* add x8, x2, x7     */
    code[17] = enc_ldp_x_imm7(4, 5, 8, 0); /* ldp x4, x5, [x8]   */
    code[18] = enc_subs_x(6, 9, 3);        /* subs x6, x9, x3    */
    code[19] = enc_bcond_imm19(COND_LO, svc_fallback_off - 0x4C);
    /* b.lo svc_fallback  */
    code[20] = enc_lsr_x_imm(7, 6, VDSO_ANCHOR_AGE_SHIFT);
    /* lsr x7, x6, #ANCHOR_AGE_SHIFT */
    code[21] = enc_cbnz_x(7, svc_fallback_off - 0x54);

    /* cbnz x7, svc_fallback (age cap) delta_ns = (delta * 699050666) >> 24.
     * 699050666 is floor((1e9 << 24) / 24e6), the mult+shift form Linux's arm64
     * vDSO uses for CNTFRQ = 24 MHz; an LSR (~1 cycle) in place of any 64-bit
     * UDIV (~10-22 cycles on Apple Silicon). Rounding down keeps the trampoline
     * tick slightly slower than the host so the next reseed never steps time
     * backwards. The age cap bounds delta < 2^22, so delta * 699050666 < 2^52
     * -- no overflow.
     */
    code[22] = enc_movz_x(7, 0xAAAA);
    code[23] = enc_movk_x_lsl16(7, 0x29AA); /* w7 = 699050666     */
    code[24] = enc_mul_x(6, 6, 7);          /* delta * mult       */
    code[25] = enc_lsr_x_imm(6, 6, 24);     /* delta_ns           */
    code[26] = enc_add_x(5, 5, 6);          /* nsec += delta_ns   */
    code[27] = enc_movz_x(7, 0xCA00);
    code[28] = enc_movk_x_lsl16(7, 0x3B9A); /* x7 = 1e9           */
    /* sub-1e9 carry: the age cap guarantees nsec < 2e9, so the /1e9 quotient is
     * always 0 or 1 and SUBS + CSEL + CINC suffices in place of a UDIV.
     * Sequence:
     *   subs x8, x5, x7       ; x8 = nsec - 1e9, C set iff nsec >= 1e9
     *   csel x5, x8, x5, HS   ; if HS, nsec -= 1e9
     *   cinc x4, x4, HS       ; if HS, sec++
     * CINC has no direct encoder; emit it as CSINC Xd, Xn, Xn with the inverted
     * condition (HS -> LO).
     */
    code[29] = enc_subs_x(8, 5, 7);
    code[30] = enc_csel_x(5, 8, 5, COND_HS);
    code[31] = enc_csinc_x(4, 4, 4, COND_LO);
    code[32] = VDSO_INSN_DMB_ISHLD;   /* dmb ishld          */
    code[33] = enc_ldar_w(12, 2);     /* seqlock recheck    */
    code[34] = enc_cmp_w_reg(11, 12); /* cmp w11, w12     */
    code[35] = enc_bcond_imm19(COND_NE, svc_fallback_off - 0x8C);
    /* b.ne svc_fallback (race) */
    code[36] = enc_stp_x_imm7(4, 5, 1, 0); /* stp x4, x5, [x1]   */
    code[37] = enc_movz_x(0, 0);           /* mov x0, #0         */
    code[38] = 0xD65F03C0U;                /* ret                */
    /* svc_fallback at offset 0x9C (instruction 39) */
    code[39] = enc_movz_x(8, 113); /* mov x8, #113       */
    code[40] = 0xD4000001U;        /* svc #0             */
    code[41] = 0xD65F03C0U;        /* ret                */
}

_Static_assert(TEXT_GETTIME_SIZE == 42 * sizeof(uint32_t),
               "clock_gettime trampoline size must match emitter");

/* Emit the CNTVCT fast-path gettimeofday trampoline. Mirrors clock_gettime but
 * always uses the REALTIME anchor and converts the nanosecond residue to
 * microseconds for tv->tv_usec. tz, if non-NULL, gets a single 64-bit store of
 * zero (covers both timezone fields). NULL tv / tz are honored. Uses the same
 * seqlock protocol as clock_gettime, including a DMB ISHLD before the recheck
 * LDAR (see the clock_gettime emitter for the memory- model justification).
 *
 * Layout (40 instructions, 0xA0 bytes):
 *
 *   0x00  mrs  x9, cntvct_el0
 *   0x04  adr  x2, vvar
 *   0x08  add  x10, x2, #ATTENTION
 *   0x0C  ldar w3, [x10]
 *   0x10  cbnz w3, svc_fallback
 *   0x14  ldar w3, [x2]                 ; seqlock snapshot
 *   0x18  cbz  w3, svc_fallback         ; seq == 0 -> unseeded
 *   0x1C  tbnz w3, #0, svc_fallback     ; seq odd -> writer in progress
 *   0x20  mov  w11, w3                  ; save snapshot
 *   0x24  ldr  x3, [x2, #ANCHOR_CNTVCT]
 *   0x28  ldp  x4, x5, [x2, #ANCHOR_REAL_SEC]
 *   0x2C  subs x6, x9, x3
 *   0x30  b.lo svc_fallback
 *   0x34  lsr  x7, x6, #ANCHOR_AGE_SHIFT
 *   0x38  cbnz x7, svc_fallback
 *   0x3C  movz w7, #0xAAAA
 *   0x40  movk w7, #0x29AA, lsl #16    ; w7 = 699050666 (mult)
 *   0x44  mul  x6, x6, x7
 *   0x48  lsr  x6, x6, #24             ; delta_ns
 *   0x4C  add  x5, x5, x6              ; nsec += delta_ns
 *   0x50  mov  w7, #0xCA00
 *   0x54  movk x7, #0x3B9A, lsl #16    ; x7 = 1e9
 *   0x58  udiv x8, x5, x7              ; sec carry
 *   0x5C  msub x5, x8, x7, x5          ; nsec %= 1e9
 *   0x60  add  x4, x4, x8              ; sec += carry
 *   0x64  mov  w7, #1000
 *   0x68  udiv x5, x5, x7              ; usec = nsec / 1000
 *   0x6C  dmb  ishld                   ; load barrier before recheck
 *   0x70  ldar w12, [x2]               ; seqlock recheck
 *   0x74  cmp  w11, w12
 *   0x78  b.ne svc_fallback            ; race detected -> SVC
 *   0x7C  cbz  x0, .Ltz                ; skip tv if null
 *   0x80  stp  x4, x5, [x0]
 *   0x84  .Ltz: cbz x1, .Lok           ; skip tz if null
 *   0x88  str  xzr, [x1]               ; tz = {0, 0} (8 bytes)
 *   0x8C  .Lok: mov x0, #0
 *   0x90  ret
 *   0x94  svc_fallback: mov x8, #169
 *   0x98  svc #0
 *   0x9C  ret
 */
static void emit_gettimeofday_trampoline(uint32_t *code,
                                         uint32_t pc_off,
                                         uint32_t vvar_off)
{
    int32_t svc_fallback_off = 0x94;
    int32_t ltz_off = 0x84;
    int32_t lok_off = 0x8C;
    int32_t adr_pc_off = 0x04; /* offset of 'adr x2, vvar' */
    int32_t vvar_rel = (int32_t) vvar_off - (int32_t) (pc_off + adr_pc_off);

    code[0] = 0xD53BE049U; /* mrs x9, cntvct_el0 */
    code[1] = enc_adr(2, vvar_rel);
    code[2] = enc_add_x_imm12(10, 2, VVAR_OFF_ATTENTION);
    code[3] = enc_ldar_w(3, 10);
    code[4] = enc_cbnz_w(3, svc_fallback_off - 0x10);
    code[5] = enc_ldar_w(3, 2);                      /* seqlock snapshot   */
    code[6] = enc_cbz_w(3, svc_fallback_off - 0x18); /* cbz w3, fallback   */
    code[7] = enc_tbnz(3, 0, svc_fallback_off - 0x1C);
    /* tbnz w3, #0, fallback */
    code[8] = enc_mov_w_reg(11, 3); /* mov w11, w3        */
    code[9] = enc_ldr_x_imm12(3, 2, VVAR_OFF_ANCHOR_CNTVCT);
    code[10] = enc_ldp_x_imm7(4, 5, 2, VVAR_OFF_ANCHOR_REAL_SEC);
    code[11] = enc_subs_x(6, 9, 3);
    code[12] = enc_bcond_imm19(COND_LO, svc_fallback_off - 0x30);
    code[13] = enc_lsr_x_imm(7, 6, VDSO_ANCHOR_AGE_SHIFT);
    code[14] = enc_cbnz_x(7, svc_fallback_off - 0x38);

    /* Same mult+shift CNTVCT-to-ns conversion as clock_gettime; see
     * emit_clock_gettime_trampoline for the multiplier rationale.
     */
    code[15] = enc_movz_x(7, 0xAAAA);
    code[16] = enc_movk_x_lsl16(7, 0x29AA); /* w7 = 699050666 */
    code[17] = enc_mul_x(6, 6, 7);          /* delta * mult */
    code[18] = enc_lsr_x_imm(6, 6, 24);     /* delta_ns */
    code[19] = enc_add_x(5, 5, 6);
    code[20] = enc_movz_x(7, 0xCA00);
    code[21] = enc_movk_x_lsl16(7, 0x3B9A);
    code[22] = enc_udiv_x(8, 5, 7);
    code[23] = enc_msub_x(5, 8, 7, 5);
    code[24] = enc_add_x(4, 4, 8);
    code[25] = enc_movz_x(7, 1000);
    code[26] = enc_udiv_x(5, 5, 7); /* usec = nsec / 1000 */
    code[27] = VDSO_INSN_DMB_ISHLD; /* dmb ishld */
    code[28] = enc_ldar_w(12, 2);   /* seqlock recheck */
    code[29] = enc_cmp_w_reg(11, 12);
    code[30] = enc_bcond_imm19(COND_NE, svc_fallback_off - 0x78);
    /* b.ne svc_fallback (race) */
    code[31] = enc_cbz_x(0, ltz_off - 0x7C);
    code[32] = enc_stp_x_imm7(4, 5, 0, 0); /* stp x4, x5, [x0] */
    code[33] = enc_cbz_x(1, lok_off - 0x84);
    code[34] = enc_str_x_imm12(31, 1, 0); /* str xzr, [x1] */
    code[35] = enc_movz_x(0, 0);          /* mov x0, #0 */
    code[36] = 0xD65F03C0U;               /* ret */
    code[37] = enc_movz_x(8, 169);        /* svc_fallback: mov x8, #169 */
    code[38] = 0xD4000001U;               /* svc #0 */
    code[39] = 0xD65F03C0U;               /* ret */
}

_Static_assert(TEXT_GETTOD_SIZE == 40 * sizeof(uint32_t),
               "gettimeofday trampoline size must match emitter");

/* Emit the arithmetic fast-path clock_getres trampoline.
 *
 * Returns {tv_sec=0, tv_nsec=1} for the common high-resolution clockids and
 * SVCs the rest. Supported inline: REALTIME (0), MONOTONIC (1), MONOTONIC_RAW
 * (4), BOOTTIME (7). Coarse clocks (5, 6), CPUTIME clocks (2, 3), and dynamic
 * negative clockids fall through to SVC because their resolution differs from
 * the high-resolution constant or depends on host scheduler state.
 *
 * Layout (23 instructions, 0x5C bytes):
 *
 *   0x00  adr  x2, vvar
 *   0x04  add  x10, x2, #ATTENTION
 *   0x08  ldar w3, [x10]
 *   0x0C  cbnz w3, svc_fallback
 *   0x10  cmp  w0, #7
 *   0x14  b.hi svc_fallback        ; clockid > 7 or negative -> SVC
 *   0x18  cmp  w0, #2
 *   0x1C  b.eq svc_fallback        ; PROCESS_CPUTIME -> SVC
 *   0x20  cmp  w0, #3
 *   0x24  b.eq svc_fallback        ; THREAD_CPUTIME -> SVC
 *   0x28  cmp  w0, #5
 *   0x2C  b.eq svc_fallback        ; REALTIME_COARSE -> SVC
 *   0x30  cmp  w0, #6
 *   0x34  b.eq svc_fallback        ; MONOTONIC_COARSE -> SVC
 *   0x38  cbz  x1, .Lok            ; NULL res -> just return 0
 *   0x3C  mov  x2, #0              ; tv_sec
 *   0x40  mov  x3, #1              ; tv_nsec
 *   0x44  stp  x2, x3, [x1]
 *   0x48  .Lok: mov x0, #0
 *   0x4C  ret
 *   0x50  svc_fallback: mov x8, #114
 *   0x54  svc #0
 *   0x58  ret
 */
static void emit_clock_getres_trampoline(uint32_t *code,
                                         uint32_t pc_off,
                                         uint32_t vvar_off)
{
    int32_t svc_fallback_off = 0x50;
    int32_t lok_off = 0x48;
    int32_t adr_pc_off = 0x00;
    int32_t vvar_rel = (int32_t) vvar_off - (int32_t) (pc_off + adr_pc_off);

    code[0] = enc_adr(2, vvar_rel);
    code[1] = enc_add_x_imm12(10, 2, VVAR_OFF_ATTENTION);
    code[2] = enc_ldar_w(3, 10);
    code[3] = enc_cbnz_w(3, svc_fallback_off - 0x0C);
    code[4] = enc_cmp_w_imm12(0, 7);
    code[5] = enc_bcond_imm19(COND_HI, svc_fallback_off - 0x14);
    code[6] = enc_cmp_w_imm12(0, 2);
    code[7] = enc_bcond_imm19(COND_EQ, svc_fallback_off - 0x1C);
    code[8] = enc_cmp_w_imm12(0, 3);
    code[9] = enc_bcond_imm19(COND_EQ, svc_fallback_off - 0x24);
    code[10] = enc_cmp_w_imm12(0, 5);
    code[11] = enc_bcond_imm19(COND_EQ, svc_fallback_off - 0x2C);
    code[12] = enc_cmp_w_imm12(0, 6);
    code[13] = enc_bcond_imm19(COND_EQ, svc_fallback_off - 0x34);
    code[14] = enc_cbz_x(1, lok_off - 0x38);
    code[15] = enc_movz_x(2, 0);
    code[16] = enc_movz_x(3, 1);
    code[17] = enc_stp_x_imm7(2, 3, 1, 0);
    code[18] = enc_movz_x(0, 0);   /* .Lok: mov x0, #0 */
    code[19] = 0xD65F03C0U;        /* ret */
    code[20] = enc_movz_x(8, 114); /* svc_fallback: mov x8, #114 */
    code[21] = 0xD4000001U;        /* svc #0 */
    code[22] = 0xD65F03C0U;        /* ret */
}

_Static_assert(TEXT_GETRES_SIZE == 23 * sizeof(uint32_t),
               "clock_getres trampoline size must match emitter");

/* Emit the arithmetic fast-path getcpu trampoline. elfuse models one online CPU
 * and one NUMA node, so cpu = node = 0 unconditionally; the cache argument is
 * ignored (binfmt/glibc both treat it as obsolete).
 *
 * Layout (13 instructions, 0x34 bytes):
 *
 *   0x00  adr  x2, vvar
 *   0x04  add  x10, x2, #ATTENTION
 *   0x08  ldar w3, [x10]
 *   0x0C  cbnz w3, svc_fallback
 *   0x10  cbz  x0, .Lnode          ; skip if cpu pointer is null
 *   0x14  str  wzr, [x0]
 *   0x18  .Lnode: cbz x1, .Lret
 *   0x1C  str  wzr, [x1]
 *   0x20  .Lret: mov x0, #0
 *   0x24  ret
 *   0x28  svc_fallback: mov x8, #168
 *   0x2C  svc #0
 *   0x30  ret
 */
static void emit_getcpu_trampoline(uint32_t *code,
                                   uint32_t pc_off,
                                   uint32_t vvar_off)
{
    int32_t svc_fallback_off = 0x28;
    int32_t adr_pc_off = 0x00;
    int32_t vvar_rel = (int32_t) vvar_off - (int32_t) (pc_off + adr_pc_off);

    code[0] = enc_adr(2, vvar_rel);
    code[1] = enc_add_x_imm12(10, 2, VVAR_OFF_ATTENTION);
    code[2] = enc_ldar_w(3, 10);
    code[3] = enc_cbnz_w(3, svc_fallback_off - 0x0C);
    code[4] = enc_cbz_x(0, 0x18 - 0x10); /* cbz x0, .Lnode (+0x08) */
    code[5] = enc_str_w_imm12(31, 0, 0); /* str wzr, [x0] */
    code[6] = enc_cbz_x(1, 0x20 - 0x18); /* cbz x1, .Lret (+0x08) */
    code[7] = enc_str_w_imm12(31, 1, 0); /* str wzr, [x1] */
    code[8] = enc_movz_x(0, 0);
    code[9] = 0xD65F03C0U;         /* ret */
    code[10] = enc_movz_x(8, 168); /* svc_fallback: mov x8, #168 */
    code[11] = 0xD4000001U;        /* svc #0 */
    code[12] = 0xD65F03C0U;        /* ret */
}

_Static_assert(TEXT_GETCPU_SIZE == 13 * sizeof(uint32_t),
               "getcpu trampoline size must match emitter");

/* The public sigret offset declared in core/vdso.h must match the internal
 * layout above; signal.c sets X30 to VDSO_BASE + VDSO_OFF_SIGRET as the
 * return-from-handler target.
 */
_Static_assert(VDSO_OFF_SIGRET == TEXT_OFF_SIGRET,
               "VDSO_OFF_SIGRET in core/vdso.h must equal TEXT_OFF_SIGRET");

static uint32_t elf_hash(const char *name)
{
    uint32_t h = 0, g;

    while (*name) {
        h = (h << 4) + (unsigned char) *name++;
        g = h & 0xf0000000U;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

uint64_t vdso_build(guest_t *g)
{
    /* The vDSO page is host-built into the guest backing buffer before any
     * page-table entry covers it, so route through vdso_host_page which just
     * bounds-checks against guest_size. The earlier guest_ptr walk worked by
     * coincidence (the slot happened to be reachable) but tied host
     * construction to whatever EL0 permission walker state existed at the time
     * -- a fragile coupling for host-owned memory.
     */
    uint8_t *page = vdso_host_page(g);
    if (!page) {
        log_error("vdso: VDSO_BASE 0x%llx out of guest memory",
                  (unsigned long long) VDSO_BASE);
        return 0;
    }

    memset(page, 0, VDSO_SIZE);

    /* ELF header. */
    elf64_ehdr_t *ehdr = (elf64_ehdr_t *) (page + VDSO_OFF_EHDR);
    ehdr->e_ident[0] = ELFMAG0;
    ehdr->e_ident[1] = ELFMAG1;
    ehdr->e_ident[2] = ELFMAG2;
    ehdr->e_ident[3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[6] = 1;
    ehdr->e_type = ET_DYN;
    ehdr->e_machine = EM_AARCH64;
    ehdr->e_version = 1;
    ehdr->e_entry = TEXT_OFF_SIGRET;
    ehdr->e_phoff = VDSO_OFF_PHDR;
    ehdr->e_shoff = VDSO_OFF_SHDR;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(elf64_ehdr_t);
    ehdr->e_phentsize = sizeof(elf64_phdr_t);
    ehdr->e_phnum = 3;
    ehdr->e_shentsize = sizeof(elf64_shdr_t);
    ehdr->e_shnum = 8;
    ehdr->e_shstrndx = 2;
    _Static_assert(VDSO_OFF_SHDR + 8 * sizeof(elf64_shdr_t) <= VDSO_SIZE,
                   "vDSO sections overflow the 4 KiB page");
    _Static_assert(VDSO_PHDR_TABLE_END <= VDSO_SIZE,
                   "vDSO program headers overflow the 4 KiB page");
    _Static_assert(VDSO_OFF_NOTE + VDSO_NOTE_SIZE <= VDSO_OFF_VVAR,
                   "GNU ABI tag note must not encroach on vvar");

    /* NT_GNU_ABI_TAG note. PT_LOAD covers the whole page so the note is already
     * mapped; PT_NOTE simply tags this offset for the dynamic linker's vDSO
     * probe.
     */
    elf64_note_gnu_abi_tag_t *note =
        (elf64_note_gnu_abi_tag_t *) (page + VDSO_OFF_NOTE);
    note->namesz = sizeof(note->name);
    note->descsz = sizeof(note->desc);
    note->type = NT_GNU_ABI_TAG;
    memcpy(note->name, "GNU", sizeof(note->name));
    note->desc[0] = ELF_NOTE_OS_LINUX;
    note->desc[1] = VDSO_NOTE_KERNEL_MAJOR;
    note->desc[2] = VDSO_NOTE_KERNEL_MINOR;
    note->desc[3] = VDSO_NOTE_KERNEL_SUBLEVEL;

    /* Program header 0: PT_LOAD. */
    elf64_phdr_t *phdr0 = (elf64_phdr_t *) (page + VDSO_OFF_PHDR);
    phdr0->p_type = PT_LOAD;
    phdr0->p_flags = PF_R | PF_X;
    phdr0->p_offset = 0;
    phdr0->p_vaddr = 0;
    phdr0->p_paddr = 0;
    phdr0->p_filesz = VDSO_SIZE;
    phdr0->p_memsz = VDSO_SIZE;
    phdr0->p_align = 0x1000;

    /* Program header 1: PT_DYNAMIC. */
    elf64_phdr_t *phdr1 = (elf64_phdr_t *) (page + VDSO_OFF_PHDR1);
    phdr1->p_type = PT_DYNAMIC;
    phdr1->p_flags = PF_R;
    phdr1->p_offset = VDSO_OFF_DYNAMIC;
    phdr1->p_vaddr = VDSO_OFF_DYNAMIC;
    phdr1->p_paddr = VDSO_OFF_DYNAMIC;
    phdr1->p_filesz = VDSO_NUM_DYN * sizeof(elf64_dyn_t);
    phdr1->p_memsz = VDSO_NUM_DYN * sizeof(elf64_dyn_t);
    phdr1->p_align = 8;

    /* Program header 2: PT_NOTE pointing at the NT_GNU_ABI_TAG above. */
    elf64_phdr_t *phdr2 = (elf64_phdr_t *) (page + VDSO_OFF_PHDR2);
    phdr2->p_type = PT_NOTE;
    phdr2->p_flags = PF_R;
    phdr2->p_offset = VDSO_OFF_NOTE;
    phdr2->p_vaddr = VDSO_OFF_NOTE;
    phdr2->p_paddr = VDSO_OFF_NOTE;
    phdr2->p_filesz = VDSO_NOTE_SIZE;
    phdr2->p_memsz = VDSO_NOTE_SIZE;
    phdr2->p_align = 4;

    /* Text trampolines. rt_sigreturn keeps the 12-byte SVC pattern; the other
     * four entries are fast paths (CNTVCT for clock_gettime / gettimeofday;
     * arithmetic for clock_getres / getcpu) with their own svc_fallback tails.
     */
    emit_svc_trampoline((uint32_t *) (page + TEXT_OFF_SIGRET), 139);
    emit_clock_getres_trampoline((uint32_t *) (page + TEXT_OFF_GETRES),
                                 TEXT_OFF_GETRES, VDSO_OFF_VVAR);
    emit_clock_gettime_trampoline((uint32_t *) (page + TEXT_OFF_GETTIME),
                                  TEXT_OFF_GETTIME, VDSO_OFF_VVAR);
    emit_gettimeofday_trampoline((uint32_t *) (page + TEXT_OFF_GETTOD),
                                 TEXT_OFF_GETTOD, VDSO_OFF_VVAR);
    emit_getcpu_trampoline((uint32_t *) (page + TEXT_OFF_GETCPU),
                           TEXT_OFF_GETCPU, VDSO_OFF_VVAR);

    /* vvar starts zero (initialized==0). The first __kernel_clock_gettime SVC
     * fallback will let the host populate the anchor.
     */

    /* Dynamic string table. */
    memcpy(page + VDSO_OFF_DYNSTR, dynstr_data, DYNSTR_SIZE);

    /* Dynamic symbol table. */
    elf64_sym_t *sym = (elf64_sym_t *) (page + VDSO_OFF_DYNSYM);
    memset(&sym[0], 0, sizeof(elf64_sym_t));
    for (int i = 0; i < VDSO_NUM_SYMS; i++) {
        sym[i + 1].st_name = sym_name_offsets[i];
        sym[i + 1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
        sym[i + 1].st_other = 0;
        sym[i + 1].st_shndx = 1;
        sym[i + 1].st_value = sym_text_off[i];
        sym[i + 1].st_size = sym_text_size[i];
    }

    /* ELF hash table. */
    uint32_t *hash = (uint32_t *) (page + VDSO_OFF_HASH);
    hash[0] = HASH_NBUCKET, hash[1] = HASH_NCHAIN;
    hash[2] = 0;
    uint32_t *chain = &hash[2 + HASH_NBUCKET];
    memset(chain, 0, HASH_NCHAIN * sizeof(uint32_t));
    uint32_t first_sym = 0;
    for (int i = VDSO_NUM_SYMS; i >= 1; i--) {
        chain[i] = first_sym;
        first_sym = (uint32_t) i;
    }
    hash[2] = first_sym;

    /* GNU symbol versioning. glibc's aarch64 vDSO resolver asks for
     * LINUX_2.6.39 and ignores unversioned helpers.
     */
    uint16_t *versym = (uint16_t *) (page + VDSO_OFF_VERSYM);
    versym[0] = 0;
    for (int i = 1; i <= VDSO_NUM_SYMS; i++)
        versym[i] = VDSO_LINUX_VERSION_INDEX;

    elf64_verdef_t *verdef = (elf64_verdef_t *) (page + VDSO_OFF_VERDEF);
    elf64_verdaux_t *verdaux =
        (elf64_verdaux_t *) (page + VDSO_OFF_VERDEF + sizeof(*verdef));
    verdef->vd_version = VER_DEF_CURRENT;
    verdef->vd_flags = 0;
    verdef->vd_ndx = VDSO_LINUX_VERSION_INDEX;
    verdef->vd_cnt = 1;
    verdef->vd_hash = elf_hash("LINUX_2.6.39");
    verdef->vd_aux = sizeof(*verdef);
    verdef->vd_next = 0;
    verdaux->vda_name = VDSO_LINUX_VERSION_NAME_OFF;
    verdaux->vda_next = 0;

    /* Dynamic table. */
    elf64_dyn_t *dyn = (elf64_dyn_t *) (page + VDSO_OFF_DYNAMIC);
    dyn[0] = (elf64_dyn_t) {DT_HASH, VDSO_OFF_HASH};
    dyn[1] = (elf64_dyn_t) {DT_SYMTAB, VDSO_OFF_DYNSYM};
    dyn[2] = (elf64_dyn_t) {DT_STRTAB, VDSO_OFF_DYNSTR};
    dyn[3] = (elf64_dyn_t) {DT_STRSZ, DYNSTR_SIZE};
    dyn[4] = (elf64_dyn_t) {DT_SYMENT, sizeof(elf64_sym_t)};
    dyn[5] = (elf64_dyn_t) {DT_VERSYM, VDSO_OFF_VERSYM};
    dyn[6] = (elf64_dyn_t) {DT_VERDEF, VDSO_OFF_VERDEF};
    dyn[7] = (elf64_dyn_t) {DT_VERDEFNUM, 1};
    dyn[8] = (elf64_dyn_t) {DT_NULL, 0};

    /* Section headers. */
    elf64_shdr_t *shdr = (elf64_shdr_t *) (page + VDSO_OFF_SHDR);
    memset(&shdr[0], 0, sizeof(elf64_shdr_t));

    shdr[1].sh_name = 0;
    shdr[1].sh_type = 1; /* SHT_PROGBITS */
    shdr[1].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr[1].sh_addr = TEXT_OFF_SIGRET;
    shdr[1].sh_offset = TEXT_OFF_SIGRET;
    shdr[1].sh_size = TEXT_END - TEXT_OFF_SIGRET;
    shdr[1].sh_addralign = 4;

    shdr[2].sh_name = 0;
    shdr[2].sh_type = SHT_STRTAB;
    shdr[2].sh_flags = SHF_ALLOC;
    shdr[2].sh_addr = VDSO_OFF_DYNSTR;
    shdr[2].sh_offset = VDSO_OFF_DYNSTR;
    shdr[2].sh_size = DYNSTR_SIZE;
    shdr[2].sh_addralign = 1;

    shdr[3].sh_name = 0;
    shdr[3].sh_type = SHT_DYNSYM;
    shdr[3].sh_flags = SHF_ALLOC;
    shdr[3].sh_addr = VDSO_OFF_DYNSYM;
    shdr[3].sh_offset = VDSO_OFF_DYNSYM;
    shdr[3].sh_size = (VDSO_NUM_SYMS + 1) * sizeof(elf64_sym_t);
    shdr[3].sh_link = 2;
    shdr[3].sh_info = 1;
    shdr[3].sh_addralign = 8;
    shdr[3].sh_entsize = sizeof(elf64_sym_t);

    shdr[4].sh_name = 0;
    shdr[4].sh_type = SHT_HASH;
    shdr[4].sh_flags = SHF_ALLOC;
    shdr[4].sh_addr = VDSO_OFF_HASH;
    shdr[4].sh_offset = VDSO_OFF_HASH;
    shdr[4].sh_size = HASH_SIZE;
    shdr[4].sh_link = 3;
    shdr[4].sh_addralign = 4;
    shdr[4].sh_entsize = 4;

    shdr[5].sh_name = 0;
    shdr[5].sh_type = SHT_DYNAMIC;
    shdr[5].sh_flags = SHF_ALLOC;
    shdr[5].sh_addr = VDSO_OFF_DYNAMIC;
    shdr[5].sh_offset = VDSO_OFF_DYNAMIC;
    shdr[5].sh_size = VDSO_NUM_DYN * sizeof(elf64_dyn_t);
    shdr[5].sh_link = 2;
    shdr[5].sh_addralign = 8;
    shdr[5].sh_entsize = sizeof(elf64_dyn_t);

    shdr[6].sh_name = 0;
    shdr[6].sh_type = SHT_GNU_VERSYM;
    shdr[6].sh_flags = SHF_ALLOC;
    shdr[6].sh_addr = VDSO_OFF_VERSYM;
    shdr[6].sh_offset = VDSO_OFF_VERSYM;
    shdr[6].sh_size = VERSYM_SIZE;
    shdr[6].sh_link = 3;
    shdr[6].sh_addralign = 2;
    shdr[6].sh_entsize = sizeof(uint16_t);

    shdr[7].sh_name = 0;
    shdr[7].sh_type = SHT_GNU_VERDEF;
    shdr[7].sh_flags = SHF_ALLOC;
    shdr[7].sh_addr = VDSO_OFF_VERDEF;
    shdr[7].sh_offset = VDSO_OFF_VERDEF;
    shdr[7].sh_size = VERDEF_SIZE;
    shdr[7].sh_link = 2;
    shdr[7].sh_info = 1;
    shdr[7].sh_addralign = 4;

    return VDSO_BASE;
}

void vdso_seed_anchor(guest_t *g,
                      uint64_t guest_cntvct,
                      int64_t mono_sec,
                      int64_t mono_nsec,
                      int64_t real_sec,
                      int64_t real_nsec)
{
    /* Match vdso_attention_or: host-owned vvar writes go through the direct
     * host_base + VDSO_BASE accessor, not the guest permission walker. The vDSO
     * is RX to EL0 so guest_ptr_w would silently bail here; guest_ptr happens
     * to work because it only requires read perm, but that inconsistency is
     * brittle.
     */
    uint8_t *page = vdso_host_page(g);
    if (!page)
        return;
    _Atomic uint32_t *initialized = (_Atomic uint32_t *) (page + VDSO_OFF_VVAR);
    uint8_t *vvar = page + VDSO_OFF_VVAR;

    /* Seqlock publish. Handles both initial seeding (seq 0 -> 1 -> 2) and
     * refresh (seq 2K -> 2K+1 -> 2K+2) atomically through one code path:
     *
     *   1. Acquire-load the current seq. Odd means another writer is in
     *      the field-store window; bail rather than spin so the caller
     *      (sys_clock_gettime) does not block its trapping vCPU.
     *   2. CAS seq from the even snapshot to snapshot+1. On failure, a
     *      racing writer claimed this generation; bail.
     *   3. Store the new anchor fields. The trailing release-store on
     *      seq orders them ahead of the trampoline's recheck LDAR.
     *   4. Release-store seq = snapshot + 2 (next stable generation).
     *      Pairs with the trampoline's recheck LDAR and vdso_anchor_*'s
     *      acquire loads.
     *
     * MONO and REAL anchor pairs are written together under the same generation
     * so a fast-path caller for either clockid sees a consistent pair.
     */
    uint32_t cur = atomic_load_explicit(initialized, memory_order_acquire);
    if (cur & 1u)
        return; /* concurrent writer holds the generation */

    uint32_t reserve = cur + 1u;
    if (!atomic_compare_exchange_strong_explicit(initialized, &cur, reserve,
                                                 memory_order_acquire,
                                                 memory_order_relaxed))
        return; /* lost the race against another publisher */

    /* Store-store barrier between the CAS-bump (odd publish) and the RELAXED
     * field stores. ARMv8 is not multi-copy atomic without barriers: another
     * CPU could otherwise observe a field store before the odd seq becomes
     * visible, allowing a reader whose snapshot LDAR still sees the old even to
     * read mid-write fields and then recheck with the same old even (snapshot
     * == recheck, race undetected). atomic_thread_fence(memory_order_release)
     * lowers to DMB ISH on AArch64 and orders the CAS odd-publish ahead of
     * every subsequent field store from every observer's perspective.
     */
    atomic_thread_fence(memory_order_release);

    /* RELAXED atomic stores: the trailing release-store on seq orders all these
     * field stores before any reader's acquire-load of the next even seq. Using
     * atomic_store_explicit (rather than plain assignment) keeps the accesses
     * well-defined under the C abstract machine even though the compiler will
     * lower them to ordinary aligned 64-bit stores.
     */
    _Atomic uint64_t *vvar64 = (_Atomic uint64_t *) vvar;
    atomic_store_explicit(&vvar64[VVAR_OFF_ANCHOR_CNTVCT / 8], guest_cntvct,
                          memory_order_relaxed);
    atomic_store_explicit(&vvar64[VVAR_OFF_ANCHOR_MONO_SEC / 8],
                          (uint64_t) mono_sec, memory_order_relaxed);
    atomic_store_explicit(&vvar64[VVAR_OFF_ANCHOR_MONO_NSEC / 8],
                          (uint64_t) mono_nsec, memory_order_relaxed);
    atomic_store_explicit(&vvar64[VVAR_OFF_ANCHOR_REAL_SEC / 8],
                          (uint64_t) real_sec, memory_order_relaxed);
    atomic_store_explicit(&vvar64[VVAR_OFF_ANCHOR_REAL_NSEC / 8],
                          (uint64_t) real_nsec, memory_order_relaxed);

    /* Release-store the next even generation. Pairs with the trampoline's
     * snapshot LDAR (initial check) and recheck LDAR (race detection).
     */
    atomic_store_explicit(initialized, reserve + 1u, memory_order_release);
}

uint64_t vdso_clock_gettime_svc_pc(void)
{
    return VDSO_BASE + VDSO_CLOCK_GETTIME_SVC_PC;
}

uint64_t vdso_gettimeofday_svc_pc(void)
{
    return VDSO_BASE + VDSO_GETTIMEOFDAY_SVC_PC;
}

/* Acquire-load the seqlock counter. Pairs with the release store at the tail of
 * vdso_seed_anchor.
 */
static uint32_t vvar_seq_acquire(const uint8_t *page)
{
    return atomic_load_explicit(
        (const _Atomic uint32_t *) (page + VDSO_OFF_VVAR),
        memory_order_acquire);
}

bool vdso_anchor_is_seeded(guest_t *g)
{
    uint8_t *page = vdso_host_page(g);
    if (!page)
        return false;

    /* A seeded-and-stable anchor has seq != 0 && (seq & 1) == 0 (see the vvar
     * layout block for the state machine). Acquire pairs with the release store
     * at the tail of vdso_seed_anchor.
     */
    uint32_t seq = vvar_seq_acquire(page);
    return seq != 0 && (seq & 1u) == 0;
}

void vdso_attention_or(guest_t *g, uint32_t bits)
{
    uint8_t *page = vdso_host_page(g);
    if (!page)
        return;
    _Atomic uint32_t *attention =
        (_Atomic uint32_t *) (page + VDSO_OFF_VVAR + VVAR_OFF_ATTENTION);

    /* SEQ_CST mirrors shim_globals_attn_or: the EL0 fast paths read this word
     * without going through HVC, so a reader that LDARs attn=0 must not observe
     * later publish_creds stores. Release-acquire alone only orders the forward
     * direction.
     */
    atomic_fetch_or_explicit(attention, bits, memory_order_seq_cst);
}

void vdso_attention_and(guest_t *g, uint32_t mask)
{
    uint8_t *page = vdso_host_page(g);
    if (!page)
        return;
    _Atomic uint32_t *attention =
        (_Atomic uint32_t *) (page + VDSO_OFF_VVAR + VVAR_OFF_ATTENTION);
    atomic_fetch_and_explicit(attention, mask, memory_order_release);
}

/* Anchor fields read together under one seqlock generation. */
typedef struct {
    uint64_t cntvct;
    int64_t mono_sec, mono_nsec;
    int64_t real_sec, real_nsec;
} vvar_anchor_t;

/* Snapshot the anchor fields under the seqlock.
 *
 * Returns false when the read window straddles a host refresh (seq mismatch,
 * odd, or zero), leaving *out untouched; callers must treat false as "no useful
 * data, skip the staleness check".
 *
 * Returns true with the fields filled when the read landed entirely within one
 * stable generation.
 *
 * Ordering mirrors the trampoline: acquire-load of seq snapshots the
 * generation, RELAXED atomic loads of fields, then a thread-fence(ACQUIRE)
 * before the recheck so the field loads cannot be reordered past the recheck
 * LDAR. Without the fence an acquire load only orders subsequent ops after
 * itself, not prior ops before itself (the same memory-model corner the
 * trampoline's DMB ISHLD addresses).
 */
static bool vvar_snapshot_anchor(const uint8_t *page, vvar_anchor_t *out)
{
    uint32_t snap = vvar_seq_acquire(page);
    if (snap == 0 || (snap & 1u))
        return false;

    const _Atomic uint64_t *vvar64 =
        (const _Atomic uint64_t *) (page + VDSO_OFF_VVAR);
    vvar_anchor_t a;
    a.cntvct = atomic_load_explicit(&vvar64[VVAR_OFF_ANCHOR_CNTVCT / 8],
                                    memory_order_relaxed);
    a.mono_sec = (int64_t) atomic_load_explicit(
        &vvar64[VVAR_OFF_ANCHOR_MONO_SEC / 8], memory_order_relaxed);
    a.mono_nsec = (int64_t) atomic_load_explicit(
        &vvar64[VVAR_OFF_ANCHOR_MONO_NSEC / 8], memory_order_relaxed);
    a.real_sec = (int64_t) atomic_load_explicit(
        &vvar64[VVAR_OFF_ANCHOR_REAL_SEC / 8], memory_order_relaxed);
    a.real_nsec = (int64_t) atomic_load_explicit(
        &vvar64[VVAR_OFF_ANCHOR_REAL_NSEC / 8], memory_order_relaxed);

    atomic_thread_fence(memory_order_acquire);
    if (vvar_seq_acquire(page) != snap)
        return false; /* host refresher raced the field reads */

    *out = a;
    return true;
}

bool vdso_anchor_age_exceeded(guest_t *g, uint64_t current_cntvct)
{
    uint8_t *page = vdso_host_page(g);
    if (!page)
        return false;
    vvar_anchor_t a;
    if (!vvar_snapshot_anchor(page, &a))
        return false;
    if (current_cntvct < a.cntvct)
        return true;
    return (current_cntvct - a.cntvct) >> VDSO_ANCHOR_AGE_SHIFT;
}

/* Drift threshold for REALTIME anchor invalidation. macOS NTP steps are
 * typically O(ms) to a few seconds. 100 ms is large enough to absorb the noise
 * from sampling host MONO/REAL back-to-back yet small enough that a stepped
 * wall clock is caught on the first SVC after the step.
 */
#define VDSO_ANCHOR_MAX_DRIFT_NS 100000000LL

bool vdso_realtime_drift_exceeded(guest_t *g,
                                  uint64_t current_cntvct,
                                  int64_t real_sec,
                                  int64_t real_nsec)
{
    uint8_t *page = vdso_host_page(g);
    if (!page)
        return false;
    vvar_anchor_t a;
    if (!vvar_snapshot_anchor(page, &a))
        return false;
    if (current_cntvct < a.cntvct)
        return true;

    /* An anchor past the age cap also needs a refresh, so declare drift up
     * front. Short-circuiting here also keeps the mult below uint64 even if a
     * caller invokes this helper with a multi-decade delta.
     */
    uint64_t delta_cycles = current_cntvct - a.cntvct;
    if (delta_cycles >> VDSO_ANCHOR_AGE_SHIFT)
        return true;

    /* Predict REALTIME from anchor + delta using the same mult+shift the
     * trampoline applies, so trampoline rounding never registers as a
     * host-clock step.
     */
    uint64_t delta_ns = (delta_cycles * 699050666ULL) >> 24;
    int64_t delta_sec = (int64_t) (delta_ns / 1000000000ULL);
    int64_t delta_nsec = (int64_t) (delta_ns % 1000000000ULL);

    /* anchor_sec is read from the vvar and could in principle be adversarial.
     * Catch signed overflow on every add/subtract that mixes it with the
     * freshly-sampled real_sec.
     */
    int64_t pred_sec;
    if (__builtin_add_overflow(a.real_sec, delta_sec, &pred_sec))
        return true;
    int64_t pred_nsec = a.real_nsec + delta_nsec;
    if (pred_nsec >= 1000000000) {
        if (__builtin_add_overflow(pred_sec, (int64_t) 1, &pred_sec))
            return true;
        pred_nsec -= 1000000000;
    }

    if (pred_sec > 0 && real_sec < INT64_MIN + pred_sec)
        return true;
    if (pred_sec < 0 && real_sec > INT64_MAX + pred_sec)
        return true;
    int64_t sec_diff = real_sec - pred_sec;

    /* Saturate against the drift threshold before multiplying by 1e9 so the
     * final diff_ns multiply cannot overflow int64.
     */
    const int64_t sat_sec = (VDSO_ANCHOR_MAX_DRIFT_NS / 1000000000LL) + 2;
    if (sec_diff > sat_sec || sec_diff < -sat_sec)
        return true;

    int64_t diff_ns = sec_diff * 1000000000LL + (real_nsec - pred_nsec);
    if (diff_ns < 0)
        diff_ns = -diff_ns;
    return diff_ns > VDSO_ANCHOR_MAX_DRIFT_NS;
}
