/*
 * ELF64 parser and loader
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Parses aarch64-linux ELF64 executables (static and dynamic), extracts PT_LOAD
 * segments, and copies them into guest memory.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* ELF64 structures (from Linux ABI) */

#define EI_NIDENT 16

/* ELF magic */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

/* e_ident indices */
#define EI_CLASS 4
#define EI_DATA 5

/* EI_CLASS values */
#define ELFCLASS64 2

/* EI_DATA values */
#define ELFDATA2LSB 1

/* e_type */
#define ET_EXEC 2
#define ET_DYN 3

/* e_machine */
#define EM_X86_64 62
#define EM_AARCH64 183

/* Program header types */
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4

/* Program header flags */
#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    uint8_t e_ident[EI_NIDENT];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} elf64_phdr_t;

/* Upper bound on the program header table, matching the Linux kernel's 64KiB
 * cap (fs/binfmt_elf.c). e_phnum and e_phentsize come straight from an
 * untrusted file, so the product is rejected before anything is allocated.
 */
#define ELF_PHDR_TABLE_MAX 65536

/* Loaded ELF info */

#define ELF_MAX_SEGMENTS 16

typedef struct {
    uint64_t gpa;    /* Guest physical address */
    uint64_t offset; /* File offset (p_offset, for /proc/self/maps) */
    uint64_t filesz; /* Bytes to load from file */
    uint64_t memsz;  /* Total memory size (filesz + bss) */
    int flags;       /* PF_R, PF_W, PF_X */
} elf_segment_t;

typedef struct {
    /* From ELF header */
    uint64_t entry;     /* e_entry: program entry point */
    uint16_t e_type;    /* ET_EXEC or ET_DYN */
    uint16_t e_machine; /* EM_AARCH64 or EM_X86_64 */
    uint16_t phnum;     /* Number of program headers */
    uint16_t phentsize; /* Size of each program header */

    /* PT_LOAD segment bounds (for page table coverage) */
    uint64_t load_min; /* Lowest loaded GPA (page-aligned) */
    uint64_t load_max; /* Highest loaded GPA + memsz (page-aligned up) */

    /* GPA of the program headers, derived from the PT_LOAD whose file data
     * contains them. Only meaningful when phdr_valid is set: an ET_DYN image
     * whose covering segment has p_vaddr == 0 and p_offset == e_phoff yields a
     * legitimate phdr_gpa of 0, which a zero sentinel could not tell apart from
     * "no segment covers the table".
     */
    uint64_t phdr_gpa;
    bool phdr_valid;

    /* PT_INTERP: dynamic linker path (empty if statically linked) */
    char interp_path[256];

    /* Segment details, in ascending gpa. elf_load_fd sorts them: the mapper's
     * page-tail zero fill runs past the end of one segment into the next, so
     * loading them in any other order lets the fill wipe bytes already placed.
     */
    int num_segments;
    elf_segment_t segments[ELF_MAX_SEGMENTS];
} elf_info_t;

/* Where a loaded image lands: a segment at p_vaddr goes to target_base +
 * (p_vaddr - va_base).
 *
 * A struct rather than two uint64_t parameters on purpose. They were adjacent
 * same-typed arguments once, and a signature change left three call sites
 * passing the old shape: identical arity, all integers, so it compiled clean
 * and broke every exec path. Naming the fields makes that a compile error.
 */
typedef struct {
    uint64_t va_base;     /* lowest p_vaddr the image is described against */
    uint64_t target_base; /* GPA that va_base maps to */
} elf_window_t;

/* API */

/* Load and parse an ELF64 file. Validates header, extracts PT_LOAD info.
 * Returns 0 on success, -1 on failure. Does NOT copy to guest yet.
 */
int elf_load(const char *path, elf_info_t *info);
int elf_load_fd(int fd, const char *display_path, elf_info_t *info);

/* Copy ELF segments into guest memory. Call after elf_load() and guest_init().
 *
 * Reads nothing from the file but the segment contents: the layout comes
 * entirely from info, filled by the single parse in elf_load(). The program
 * headers need no separate copy because elf_load() only sets phdr_gpa to an
 * address inside a PT_LOAD, so the segment read here delivers them.
 *
 * Guest images pass a window of {0, load_base} (load_base 0 for ET_EXEC at its
 * link address, non-zero for ET_DYN). Rosetta passes its own va_base so its
 * 0x800000000000 link address maps low without relying on unsigned wraparound.
 * infra_lo and infra_hi delimit the runtime infra reserve (page-table pool,
 * shim text, shim_data, vDSO). Any PT_LOAD copy whose destination intersects
 * [infra_lo, infra_hi) is rejected: those writes go through host_base directly
 * and would otherwise bypass the EL1-only page-table protection on shim_data.
 * Pass 0,0 only when the guest_t is not yet built.
 *
 * Returns 0 on success, -1 on failure.
 */
int elf_map_segments(const elf_info_t *info,
                     const char *path,
                     void *guest_base,
                     uint64_t guest_size,
                     elf_window_t window,
                     uint64_t infra_lo,
                     uint64_t infra_hi);
int elf_map_segments_fd(const elf_info_t *info,
                        int fd,
                        const char *display_path,
                        void *guest_base,
                        uint64_t guest_size,
                        elf_window_t window,
                        uint64_t infra_lo,
                        uint64_t infra_hi);

/* Answer the question elf_map_segments_fd answers, without writing anything:
 * does every PT_LOAD of info land inside guest memory and clear of the infra
 * reserve, under this window?
 *
 * Both take the same per-segment decision, so a caller that gets true here
 * cannot then have the mapper refuse its placement. That is what lets
 * sys_execve reject a badly placed image while it can still return ENOEXEC.
 * Placement only: the mapper still reads the file, and a short pread on an
 * image shrunk since the parse remains its to report.
 */
bool elf_check_placement(const elf_info_t *info,
                         const char *display_path,
                         uint64_t guest_size,
                         elf_window_t window,
                         uint64_t infra_lo,
                         uint64_t infra_hi);

/* True when info describes an image elfuse can load as a program interpreter.
 * Rejects a non-ET_DYN loader, which both load paths would place at the wrong
 * address, and one naming a PT_INTERP of its own. Logs the reason.
 */
bool elf_interp_is_loadable(const elf_info_t *info, const char *display_path);

/* Resolve a PT_INTERP path against a sysroot directory. Tries three strategies:
 *   1. sysroot + interp_path  (standard /lib/ld-musl-*.so.1)
 *   2. sysroot/lib/basename(interp_path)  (store-style paths)
 *   3. interp_path as-is  (no sysroot or fallback)
 * Writes the resolved path into out (must be at least out_sz bytes).
 */
void elf_resolve_interp(const char *sysroot,
                        const char *interp_path,
                        char *out,
                        size_t out_sz);

/* Maximum shebang resolutions before a chain is rejected with -ELOOP. Both the
 * execve path and startup honor this so a max-depth chain ending in a real ELF
 * still loads, matching the Linux kernel exec_binprm recursion limit.
 */
#define ELF_SHEBANG_MAX_DEPTH 5

/* Parse the first line of a file to check for a binfmt_script shebang
 * interpreter. Reads the first line into a local buffer and extracts the
 * interpreter path and a single optional argument. Trailing whitespace is
 * stripped.
 *
 * Supports LF (\n), CRLF (\r\n), and CR (\r) line endings. If the shebang line
 * is not terminated within the 511-byte buffer limit, returns -ENOEXEC.
 *
 * Returns:
 *   1 if a shebang script was successfully parsed
 *   0 if the file is not a shebang script
 *   Negative errno on failure (e.g. -ENOENT, -ENOEXEC, or insufficient
 *   buffer size)
 */
int elf_read_shebang(const char *host_path,
                     char *interp_out,
                     size_t interp_sz,
                     char *arg_out,
                     size_t arg_sz);
int elf_read_shebang_fd(int fd,
                        char *interp_out,
                        size_t interp_sz,
                        char *arg_out,
                        size_t arg_sz);

/* Translate ELF program-header flags (PF_R=4, PF_W=2, PF_X=1) into the
 * R=1/W=2/X=4 bitset shared by both MEM_PERM_R/W/X (page-table permissions) and
 * LINUX_PROT_READ/WRITE/EXEC (mmap prot bits).
 *
 * READ is implicit: every loaded segment gets the R bit even if PF_R is absent,
 * mirroring the kernel's behavior for ELF loading.
 */
static inline int elf_pf_to_prot(int pf)
{
    int r = 1; /* always readable */
    if (pf & PF_W)
        r |= 2;
    if (pf & PF_X)
        r |= 4;
    return r;
}
