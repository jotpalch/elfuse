/*
 * FUTEX_WAKE_OP operand decode and semantics
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The val3 word of a FUTEX_WAKE_OP call packs four fields, two of which are
 * 12-bit signed operands the kernel sign-extends. Before this test the only
 * caller in the tree was a benchmark that passed zero for both, so neither the
 * extension nor the operand validation had any coverage.
 *
 * What is checked here: that a set bit 11 reads back as a negative operand
 * rather than a large positive one, and that the shift flavor masks an operand
 * outside 0..31 to its low five bits the way Linux does, rather than rejecting
 * it. The signedness of the comparison is not: it is visible only in how many
 * waiters at uaddr2 wake, and this file parks none.
 */
#include <stdint.h>
#include <stdio.h>

#include <linux/futex.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef FUTEX_OP_SET
#define FUTEX_OP_SET 0
#define FUTEX_OP_ADD 1
#define FUTEX_OP_OR 2
#define FUTEX_OP_ANDN 3
#define FUTEX_OP_XOR 4
#define FUTEX_OP_OPARG_SHIFT 8
#define FUTEX_OP_CMP_EQ 0
#define FUTEX_OP_CMP_NE 1
#define FUTEX_OP_CMP_LT 2
#define FUTEX_OP_CMP_LE 3
#define FUTEX_OP_CMP_GT 4
#define FUTEX_OP_CMP_GE 5
#endif

/* Pack the four fields the way Linux's FUTEX_OP() macro does. */
static uint32_t futex_op_encode(unsigned op,
                                unsigned cmp,
                                unsigned oparg,
                                unsigned cmparg)
{
    return ((op & 0xF) << 28) | ((cmp & 0xF) << 24) | ((oparg & 0xFFF) << 12) |
           (cmparg & 0xFFF);
}

static long wake_op(uint32_t *w1, uint32_t *w2, uint32_t val3)
{
    return raw_syscall6(__NR_futex, (long) w1,
                        FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG, 0, 0, (long) w2,
                        (long) (int32_t) val3);
}

/* The four value cases differ only in what is encoded and what should land in
 * the second word, so they are a table rather than four copies of the same
 * five-line assertion.
 */
static const struct {
    const char *name;
    unsigned op;
    unsigned oparg;
    uint32_t seed;
    uint32_t want;
} value_cases[] = {
    /* An op operand with bit 11 set is -1, not 4095. FUTEX_OP_SET stores it
     * into the second word, so the stored value is the whole check: the
     * pre-existing signed-shift decode was undefined for exactly this input.
     */
    {"op operand sign-extends", FUTEX_OP_SET, 0xFFF, 0, 0xFFFFFFFFu},
    /* 0x800 is the most negative the field can hold, 0x7ff the most positive;
     * the second must not come back negative.
     */
    {"op operand 0x800 is -2048", FUTEX_OP_SET, 0x800, 0, (uint32_t) -2048},
    {"op operand 0x7ff is 2047", FUTEX_OP_SET, 0x7FF, 0, 2047},
    /* ADD of a negative operand walks the word down, not up. */
    {"ADD of a negative operand subtracts", FUTEX_OP_ADD, 0xFFB, 100, 95},
};

int main(void)
{
    uint32_t w1 = 0, w2 = 0;
    long rc;

    printf("FUTEX_WAKE_OP tests\n");

    for (size_t i = 0; i < sizeof(value_cases) / sizeof(value_cases[0]); i++) {
        TEST(value_cases[i].name);
        w2 = value_cases[i].seed;
        rc = wake_op(&w1, &w2,
                     futex_op_encode(value_cases[i].op, FUTEX_OP_CMP_EQ,
                                     value_cases[i].oparg, 0));
        if (rc < 0)
            FAIL("wake_op rejected a valid operation");
        else if (w2 != value_cases[i].want)
            FAIL("stored value is not the sign-extended operand");
        else
            PASS();
    }

    /* The shift flavor accepts 0..31. 1u<<31 is the top of that range and the
     * one most likely to be mishandled as a signed value.
     */
    TEST("OPARG_SHIFT accepts 31");
    w2 = 0;
    rc = wake_op(&w1, &w2,
                 futex_op_encode(FUTEX_OP_SET | FUTEX_OP_OPARG_SHIFT,
                                 FUTEX_OP_CMP_EQ, 31, 0));
    if (rc < 0)
        FAIL("wake_op rejected shift operand 31");
    else if (w2 != 0x80000000u)
        FAIL("1u<<31 did not land in the word");
    else
        PASS();

    /* Linux masks an out-of-range shift operand to its low five bits and warns;
     * it does not reject it. Its own comment says the EINVAL it would prefer
     * waits on userspace getting sane. So the assertion is that the call is
     * accepted, and that the operand it actually shifted by is the masked one:
     * -1 masks to 31 and 32 masks to 0, which the comparison value below
     * distinguishes.
     */
    TEST("OPARG_SHIFT masks a negative operand rather than rejecting it");
    w2 = 0;
    rc = wake_op(&w1, &w2,
                 futex_op_encode(FUTEX_OP_SET | FUTEX_OP_OPARG_SHIFT,
                                 FUTEX_OP_CMP_EQ, 0xFFF, 0));
    EXPECT_TRUE(rc >= 0 && w2 == 0x80000000u,
                "negative shift operand did not mask to 31");

    TEST("OPARG_SHIFT masks an operand above 31");
    w2 = 0;
    rc = wake_op(&w1, &w2,
                 futex_op_encode(FUTEX_OP_SET | FUTEX_OP_OPARG_SHIFT,
                                 FUTEX_OP_CMP_EQ, 32, 0));
    EXPECT_TRUE(rc >= 0 && w2 == 1u, "operand 32 did not mask to 0");

    /* The comparison branch is exercised, not adjudicated. Whether the compare
     * is signed decides only how many waiters at uaddr2 are woken, and with
     * nobody parked there the answer is 0 either way, so the return value
     * cannot separate the two. Observing the difference needs a waiter parked
     * on uaddr2 and a nonzero val2, which is a threaded test this file is not.
     * What is checked here is that a word the signed compare reads as negative
     * still completes rather than being rejected.
     */
    TEST("negative word completes a signed compare");
    w2 = (uint32_t) -1;
    rc = wake_op(&w1, &w2, futex_op_encode(FUTEX_OP_OR, FUTEX_OP_CMP_LT, 0, 0));
    if (rc < 0)
        FAIL("wake_op rejected a valid compare");
    else
        PASS();

    SUMMARY("test-futex-wake-op");
    return fails > 0 ? 1 : 0;
}
