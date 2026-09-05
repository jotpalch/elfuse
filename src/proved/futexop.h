/*
 * Operand decode for FUTEX_WAKE_OP, split out of futex_wake_op in
 * src/runtime/futex.c and proved here.
 *
 * The val3 word of a FUTEX_WAKE_OP call is entirely guest-supplied. Linux
 * carves two 12-bit signed operands out of it and sign-extends both
 * (sign_extend32 in include/linux/bitops.h, called from
 * futex_atomic_op_inuser). The obvious transcription of that,
 *
 *     int raw = (int) (val3 & 0xFFF);
 *     int arg = (raw << 20) >> 20;
 *
 * is undefined for every raw at or above 0x800: the left shift moves a set bit
 * into and past the sign bit of a positive int, which C11 6.5.7p4 leaves
 * undefined rather than wrapping. A guest reaches it by setting bit 11 of the
 * compare operand or bit 23 of the op operand, so the undefined case is not a
 * corner a caller can be trusted to avoid. It is the low half of the input
 * range. UBSan reports "left shift of 2048 by 20 places cannot be represented
 * in type 'int'".
 *
 * The form below never shifts a signed value. Masking bounds the operand to [0,
 * 0xFFF], and each branch then lands in [-2048, 2047] without an intermediate
 * that leaves the range of int.
 *
 * The mask is spelled as a remainder by 0x1000 rather than an and with 0xFFF.
 * The two are the same function on unsigned input and compile to the same and
 * instruction, but a remainder is modular arithmetic the provers already have,
 * while an and needs the bit-level theory: under the and form the overflow and
 * range obligations time out where the value ones discharge. futexhash.h takes
 * a remainder for the same reason.
 *
 * The branch is written as a comparison rather than the shorter xor-bias trick
 * (v ^ 0x800) - 0x800, which computes the same function. Both are defined; the
 * comparison is what the provers discharge. Under the xor form all four
 * obligations here time out at 30s on Alt-Ergo and Z3 rather than failing,
 * because relating a bitwise xor to the surrounding arithmetic needs the
 * bit-level theory. Nothing about the shipped code needs the trick.
 */
#pragma once

#include <stdint.h>

/* The operand is 12 bits wide. SPAN is the modulus that isolates it and the
 * bias that removes the sign; SIGN is the bit that decides which half it is in.
 * SPANU is the same value unsigned, for the remainder.
 */
#define FUTEX_OP_ARG_SIGN 0x800u
#define FUTEX_OP_ARG_SPAN 0x1000
#define FUTEX_OP_ARG_SPANU 0x1000u

/* Sign-extend the low 12 bits of raw to a full int32_t.
 *
 * The two ensures clauses below pin the value rather than only the range: a
 * body that returned a constant inside [-2048, 2047], or that dropped the bias
 * and returned the operand unextended, satisfies a bound but not these.
 */
/*@
  assigns \nothing;
  ensures bounded: -2048 <= \result <= 2047;
  ensures positive_half:
    (raw % 0x1000) < 0x800 ==> \result == (int32_t) (raw % 0x1000);
  ensures negative_half:
    (raw % 0x1000) >= 0x800 ==> \result == (int32_t) (raw % 0x1000) - 0x1000;
*/
static inline int32_t futex_op_sign_extend12(uint32_t raw)
{
    uint32_t v = raw % FUTEX_OP_ARG_SPANU;
    if (v < FUTEX_OP_ARG_SIGN)
        return (int32_t) v;
    return (int32_t) v - FUTEX_OP_ARG_SPAN;
}

/* A shift-flavored op operand (FUTEX_OP_OPARG_SHIFT) reduced to one 1u << arg
 * can evaluate. Linux masks an out-of-range operand to its low five bits and
 * warns rather than rejecting it, and its own comment says the EINVAL it would
 * prefer waits on userspace getting sane; the reference kernel measured here
 * (6.18.44, through the qemu lane) accepts both a negative operand and one
 * above 31. Matching that is what keeps this from breaking a guest Linux runs.
 *
 * The masking is what removes the undefined behavior: a negative or oversized
 * operand reaching the shift is the fault, and bounding it to [0, 31] fixes
 * that whether the caller is then rejected or not. Linux did the same in commit
 * 30d6e0a4190d, "futex: Remove duplicated code and fix undefined behaviour".
 * Not CVE-2018-6927, which an earlier revision of this comment cited: that one
 * is an integer overflow in futex_requeue reached through a negative wake or
 * requeue count, a different path and a different fix.
 *
 * Masking in the unsigned domain, because the value is a bit pattern here and
 * an implementation-defined signed one is not worth relying on. Spelled as a
 * remainder rather than an and, for the same reason futex_op_sign_extend12 next
 * door is: the bitwise form leaves the provers reasoning about bits and the two
 * postconditions below stay open, while the remainder discharges.
 */
/*@
  assigns \nothing;
  ensures 0 <= \result <= 31;
  ensures 0 <= arg <= 31 ==> \result == arg;
*/
static inline int32_t futex_op_shift_arg_mask(int32_t arg)
{
    return (int32_t) ((uint32_t) arg % 32u);
}
