/*
 * Hypervisor.framework declarations, for the analyzer only
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frama-C preprocesses with its own modeled libc and has no Apple SDK, so any
 * source reaching src/core/guest.h or src/runtime/thread.h stopped at
 * "Hypervisor/Hypervisor.h file not found" before it could be parsed at all.
 * That is not a libc modeling gap and does not need one: the two headers use a
 * small, closed set of HVF names, and declaring them is enough to let the
 * analyzer read the rest of the file.
 *
 * Deliberately outside src/. A compile resolves headers through -Isrc, so a
 * stub living there would sit on the real build's include path and could shadow
 * the SDK header the binary must link against. Up here nothing but
 * FRAMAC_STUB_DIR in mk/verify.mk can reach it.
 *
 * This is reached only through mk/verify.mk, never by a compile. Nothing proved
 * reads any constant defined here, so the values matter only in that they must
 * not collide: HV_REG_X0 + n is how src/hvutil.h names a register, which needs
 * the X registers consecutive and in order, and the rest are distinct
 * placeholders. A wrong value here cannot weaken a proof, but it can make a
 * walked switch look degenerate, so keep them apart.
 *
 * The set is what the parsing sources actually reference. Widening the proof
 * surface to a source that names one more will fail with "Cannot resolve
 * variable", which is the intended way to find out that it belongs here.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int hv_return_t;

#define HV_SUCCESS 0
#define HV_BAD_ARGUMENT 0xfae94003

typedef uint64_t hv_vcpu_t;
typedef uint32_t hv_reg_t;

/* X0 through X30 consecutive and in order: src/hvutil.h forms HV_REG_X0 + n.
 * The rest only have to be distinct from those and from each other.
 */
enum {
    HV_REG_X0 = 0,
    HV_REG_X1 = 1,
    HV_REG_X2 = 2,
    HV_REG_X3 = 3,
    HV_REG_X4 = 4,
    HV_REG_X5 = 5,
    HV_REG_X6 = 6,
    HV_REG_X7 = 7,
    HV_REG_X8 = 8,
    HV_REG_X9 = 9,
    HV_REG_X10 = 10,
    HV_REG_X11 = 11,
    HV_REG_X12 = 12,
    HV_REG_X13 = 13,
    HV_REG_X14 = 14,
    HV_REG_X15 = 15,
    HV_REG_X16 = 16,
    HV_REG_X17 = 17,
    HV_REG_X18 = 18,
    HV_REG_X19 = 19,
    HV_REG_X20 = 20,
    HV_REG_X21 = 21,
    HV_REG_X22 = 22,
    HV_REG_X23 = 23,
    HV_REG_X24 = 24,
    HV_REG_X25 = 25,
    HV_REG_X26 = 26,
    HV_REG_X27 = 27,
    HV_REG_X28 = 28,
    HV_REG_X29 = 29,
    HV_REG_X30 = 30,
    HV_REG_PC = 32,
    HV_REG_CPSR = 33,
    HV_REG_FPCR = 34,
    HV_REG_FPSR = 35,
};

typedef uint32_t hv_sys_reg_t;
typedef uint32_t hv_simd_fp_reg_t;

#define HV_SIMD_FP_REG_Q0 0

/* The real type is a 16-byte vector. Frama-C rejects the vector_size attribute,
 * and no proved function reads a lane, so a struct of the same width and
 * alignment stands in.
 */
typedef struct {
    unsigned char v[16];
} hv_simd_fp_uchar16_t;

typedef uint64_t hv_ipa_t;
typedef uint32_t hv_memory_flags_t;

#define HV_MEMORY_READ 1
#define HV_MEMORY_WRITE 2
#define HV_MEMORY_EXEC 4

typedef uint32_t hv_exit_reason_t;

/* hv_vcpu_types.h enumerates these in order from zero. CANCELED read 1 until it
 * was measured against the SDK, which put every analysis of the run loop's
 * dispatch on the wrong branch. check-stub-constants.py compiles each of these
 * against the SDK header, so the values are held rather than trusted.
 */
#define HV_EXIT_REASON_CANCELED 0
#define HV_EXIT_REASON_EXCEPTION 1
#define HV_EXIT_REASON_VTIMER_ACTIVATED 2
#define HV_EXIT_REASON_UNKNOWN 3

typedef struct {
    uint64_t syndrome;
    uint64_t virtual_address;
    uint64_t physical_address;
} hv_vcpu_exit_exception_t;

typedef struct {
    hv_exit_reason_t reason;
    hv_vcpu_exit_exception_t exception;
} hv_vcpu_exit_t;

hv_return_t hv_vcpu_destroy(hv_vcpu_t vcpu);
hv_return_t hv_vcpu_run(hv_vcpu_t vcpu);
hv_return_t hv_vcpus_exit(hv_vcpu_t *vcpus, unsigned int vcpu_count);

/* Contracts on the register accessors, not just declarations. Without an
 * assigns clause WP must assume the call writes anywhere, which defeats the
 * assigns clause of every caller it appears in. The frame is what the API
 * documents: the call fills the out-parameter and touches nothing else the
 * caller can name. HVF's vCPU state is not in the C memory model, so there is
 * nothing else to state.
 */
/*@
  requires \valid(value);
  assigns *value;
 */
hv_return_t hv_vcpu_get_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t *value);
hv_return_t hv_vcpu_set_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t value);
/*@
  requires \valid(value);
  assigns *value;
 */
hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t vcpu,
                                hv_sys_reg_t reg,
                                uint64_t *value);
hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t vcpu,
                                hv_sys_reg_t reg,
                                uint64_t value);
/*@
  requires \valid(value);
  assigns *value;
 */
hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t vcpu,
                                    hv_simd_fp_reg_t reg,
                                    hv_simd_fp_uchar16_t *value);
hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu,
                                    hv_simd_fp_reg_t reg,
                                    hv_simd_fp_uchar16_t value);
hv_return_t hv_vcpu_set_trap_debug_exceptions(hv_vcpu_t vcpu, int value);
hv_return_t hv_vm_map(void *addr,
                      hv_ipa_t ipa,
                      size_t size,
                      hv_memory_flags_t flags);
hv_return_t hv_vm_unmap(hv_ipa_t ipa, size_t size);
hv_return_t hv_vm_destroy(void);

/* System registers. Nothing in the tree does arithmetic on these, unlike the
 * GPRs above; they appear as array initialisers and switch labels, so distinct
 * values are the whole requirement. Generated from every HV_SYS_REG_ name the
 * tree references, so the set matches the code rather than a hand-kept list.
 */
enum {
    HV_SYS_REG_ACTLR_EL1 = 4096,
    HV_SYS_REG_CNTKCTL_EL1 = 4097,
    HV_SYS_REG_CONTEXTIDR_EL1 = 4098,
    HV_SYS_REG_CPACR_EL1 = 4099,
    HV_SYS_REG_DBGBCR0_EL1 = 4100,
    HV_SYS_REG_DBGBCR10_EL1 = 4101,
    HV_SYS_REG_DBGBCR11_EL1 = 4102,
    HV_SYS_REG_DBGBCR12_EL1 = 4103,
    HV_SYS_REG_DBGBCR13_EL1 = 4104,
    HV_SYS_REG_DBGBCR14_EL1 = 4105,
    HV_SYS_REG_DBGBCR15_EL1 = 4106,
    HV_SYS_REG_DBGBCR1_EL1 = 4107,
    HV_SYS_REG_DBGBCR2_EL1 = 4108,
    HV_SYS_REG_DBGBCR3_EL1 = 4109,
    HV_SYS_REG_DBGBCR4_EL1 = 4110,
    HV_SYS_REG_DBGBCR5_EL1 = 4111,
    HV_SYS_REG_DBGBCR6_EL1 = 4112,
    HV_SYS_REG_DBGBCR7_EL1 = 4113,
    HV_SYS_REG_DBGBCR8_EL1 = 4114,
    HV_SYS_REG_DBGBCR9_EL1 = 4115,
    HV_SYS_REG_DBGBVR0_EL1 = 4116,
    HV_SYS_REG_DBGBVR10_EL1 = 4117,
    HV_SYS_REG_DBGBVR11_EL1 = 4118,
    HV_SYS_REG_DBGBVR12_EL1 = 4119,
    HV_SYS_REG_DBGBVR13_EL1 = 4120,
    HV_SYS_REG_DBGBVR14_EL1 = 4121,
    HV_SYS_REG_DBGBVR15_EL1 = 4122,
    HV_SYS_REG_DBGBVR1_EL1 = 4123,
    HV_SYS_REG_DBGBVR2_EL1 = 4124,
    HV_SYS_REG_DBGBVR3_EL1 = 4125,
    HV_SYS_REG_DBGBVR4_EL1 = 4126,
    HV_SYS_REG_DBGBVR5_EL1 = 4127,
    HV_SYS_REG_DBGBVR6_EL1 = 4128,
    HV_SYS_REG_DBGBVR7_EL1 = 4129,
    HV_SYS_REG_DBGBVR8_EL1 = 4130,
    HV_SYS_REG_DBGBVR9_EL1 = 4131,
    HV_SYS_REG_DBGWCR0_EL1 = 4132,
    HV_SYS_REG_DBGWCR10_EL1 = 4133,
    HV_SYS_REG_DBGWCR11_EL1 = 4134,
    HV_SYS_REG_DBGWCR12_EL1 = 4135,
    HV_SYS_REG_DBGWCR13_EL1 = 4136,
    HV_SYS_REG_DBGWCR14_EL1 = 4137,
    HV_SYS_REG_DBGWCR15_EL1 = 4138,
    HV_SYS_REG_DBGWCR1_EL1 = 4139,
    HV_SYS_REG_DBGWCR2_EL1 = 4140,
    HV_SYS_REG_DBGWCR3_EL1 = 4141,
    HV_SYS_REG_DBGWCR4_EL1 = 4142,
    HV_SYS_REG_DBGWCR5_EL1 = 4143,
    HV_SYS_REG_DBGWCR6_EL1 = 4144,
    HV_SYS_REG_DBGWCR7_EL1 = 4145,
    HV_SYS_REG_DBGWCR8_EL1 = 4146,
    HV_SYS_REG_DBGWCR9_EL1 = 4147,
    HV_SYS_REG_DBGWVR0_EL1 = 4148,
    HV_SYS_REG_DBGWVR10_EL1 = 4149,
    HV_SYS_REG_DBGWVR11_EL1 = 4150,
    HV_SYS_REG_DBGWVR12_EL1 = 4151,
    HV_SYS_REG_DBGWVR13_EL1 = 4152,
    HV_SYS_REG_DBGWVR14_EL1 = 4153,
    HV_SYS_REG_DBGWVR15_EL1 = 4154,
    HV_SYS_REG_DBGWVR1_EL1 = 4155,
    HV_SYS_REG_DBGWVR2_EL1 = 4156,
    HV_SYS_REG_DBGWVR3_EL1 = 4157,
    HV_SYS_REG_DBGWVR4_EL1 = 4158,
    HV_SYS_REG_DBGWVR5_EL1 = 4159,
    HV_SYS_REG_DBGWVR6_EL1 = 4160,
    HV_SYS_REG_DBGWVR7_EL1 = 4161,
    HV_SYS_REG_DBGWVR8_EL1 = 4162,
    HV_SYS_REG_DBGWVR9_EL1 = 4163,
    HV_SYS_REG_ELR_EL1 = 4164,
    HV_SYS_REG_ESR_EL1 = 4165,
    HV_SYS_REG_FAR_EL1 = 4166,
    HV_SYS_REG_MAIR_EL1 = 4167,
    HV_SYS_REG_MDSCR_EL1 = 4168,
    HV_SYS_REG_SCTLR_EL1 = 4169,
    HV_SYS_REG_SPSR_EL1 = 4170,
    HV_SYS_REG_SP_EL0 = 4171,
    HV_SYS_REG_SP_EL1 = 4172,
    HV_SYS_REG_TCR_EL1 = 4173,
    HV_SYS_REG_TPIDR_EL0 = 4174,
    HV_SYS_REG_TPIDR_EL1 = 4175,
    HV_SYS_REG_TTBR0_EL1 = 4176,
    HV_SYS_REG_TTBR1_EL1 = 4177,
    HV_SYS_REG_VBAR_EL1 = 4178,
};
