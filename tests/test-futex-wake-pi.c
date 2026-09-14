/*
 * FUTEX_WAKE and FUTEX_WAKE_OP must refuse a PI waiter
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * futex_wake() and futex_wake_op() run the same test requeue does: a waiter
 * carrying a pi_state or an rt_waiter answers EINVAL from inside their walks,
 * because a PI waiter is not woken by a plain wake. Both of wake_op's loops
 * make the decision, the one at uaddr and the one at uaddr2, so this file puts
 * a case to each.
 *
 * The first wake is retried while it reports zero, which is the answer before
 * the waiter has parked: without that loop a slow thread start would pass by
 * never reaching the case.
 *
 * Syscalls exercised: futex(98), clone(220), exit(93), sched_yield(124)
 */

#include <limits.h>
#include <stdint.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

static int pi_lock;       /* the PI futex the waiter parks on */
static int plain_word;    /* a non-PI address for wake_op's other half */
static int holder_ready;  /* set once the holder has settled, either way */
static int holder_failed; /* set instead of owning it, when LOCK_PI refused */
static int release;       /* set to tell the holder to unlock */
static int waiter_done;   /* set once the waiter has taken and released it */

static int holder_stack[16384] __attribute__((aligned(16)));
static int waiter_stack[16384] __attribute__((aligned(16)));

/* Every op carries FUTEX_PRIVATE_FLAG, as the neighbouring futex tests do.
 * elfuse masks it off, but on a reference kernel private and shared hash to
 * different keys, and raw_futex_wake sets it.
 */
static long futex_lock_pi(int *addr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

static long futex_unlock_pi(int *addr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

static long futex_wake(int *addr, long nr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_WAKE | FUTEX_PRIVATE_FLAG, nr, 0, 0, 0);
}

/* val3 layout: bit 31 OPARG_SHIFT, 30-28 op, 27-24 cmp, 23-12 oparg, 11-0
 * cmparg. Spelled as in test-futex-wake-op-enosys.c.
 */
static uint32_t encode(unsigned op,
                       unsigned cmp,
                       uint32_t oparg,
                       uint32_t cmparg)
{
    return ((op & 7u) << 28) | ((cmp & 0xfu) << 24) | ((oparg & 0xfffu) << 12) |
           (cmparg & 0xfffu);
}

/* FUTEX_WAKE_OP reads its second wake count out of the timeout slot. */
static long futex_wake_op(int *addr, int *addr2, long nr, long nr2, uint32_t v)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG, nr, nr2,
                        (long) addr2, (long) v);
}

/* ADD 0, so the word at uaddr2 comes back as it was: uaddr2 is a live PI lock
 * in one of the cases below and must not be edited. The comparison is against
 * that old value and has to hold, or the second walk never runs: an owned PI
 * word is nonzero, so NE 0 is the one that fires.
 */
static uint32_t add0_ne0(void)
{
    return encode(1, 1, 0, 0);
}

static void set_and_wake(int *addr)
{
    __atomic_store_n(addr, 1, __ATOMIC_RELEASE);
    raw_futex_wake(addr, 1);
}

/* holder_ready has two readers, main and the waiter, and is set once; waking a
 * single one of them strands the other for good. test-futex-requeue-pi.c
 * records the qemu lane that made that visible.
 */
static void set_and_wake_all(int *addr)
{
    __atomic_store_n(addr, 1, __ATOMIC_RELEASE);
    raw_futex_wake(addr, INT_MAX);
}

static void wait_until_set(int *addr)
{
    while (__atomic_load_n(addr, __ATOMIC_ACQUIRE) == 0)
        raw_futex_wait(addr, 0);
}

/* Takes pi_lock, reports it, and holds it until told to let go. The waiter
 * cannot park until someone else owns the word.
 */
static void holder_fn(void)
{
    if (futex_lock_pi(&pi_lock) == 0) {
        set_and_wake_all(&holder_ready);
        wait_until_set(&release);
        futex_unlock_pi(&pi_lock);
    } else {
        set_and_wake(&holder_failed);
        set_and_wake_all(&holder_ready);
    }
    raw_exit(0);
}

/* Parks in FUTEX_LOCK_PI on the held word. This is the waiter every case below
 * aims a plain wake at.
 */
static void waiter_fn(void)
{
    wait_until_set(&holder_ready);
    if (futex_lock_pi(&pi_lock) == 0)
        futex_unlock_pi(&pi_lock);
    set_and_wake(&waiter_done);
    raw_exit(0);
}

int main(void)
{
    /* CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM, spelled as the value the way test-futex-pi.c does.
     */
    unsigned long flags = 0x50f00;

    printf("=== futex wake PI rejection tests ===\n\n");

    /* One clone at a time, each with its child branch immediately after it:
     * issuing both first lets the first child run the second raw_clone too.
     */
    TEST("clone holder and waiter");
    long holder = raw_clone(flags, holder_stack + 16384, 0, 0, 0);
    if (holder == 0) {
        holder_fn();
        __builtin_unreachable();
    }
    if (holder < 0) {
        FAIL("holder clone failed");
        goto done;
    }

    long waiter = raw_clone(flags, waiter_stack + 16384, 0, 0, 0);
    if (waiter == 0) {
        waiter_fn();
        __builtin_unreachable();
    }
    if (waiter < 0) {
        FAIL("waiter clone failed");
        goto done;
    }
    PASS();

    wait_until_set(&holder_ready);

    TEST("holder takes pi_lock");
    if (__atomic_load_n(&holder_failed, __ATOMIC_ACQUIRE) != 0) {
        FAIL("FUTEX_LOCK_PI refused the holder, nothing to wake against");
        goto done;
    }
    PASS();

    /* Zero is the answer before the waiter parks; anything else means the call
     * saw it, and EINVAL is the only correct one.
     */
    TEST("wake a parked PI waiter");
    long rc = 0;
    for (int i = 0; i < 100000 && rc == 0; i++) {
        rc = futex_wake(&pi_lock, 1);
        if (rc == 0)
            raw_syscall0(__NR_sched_yield);
    }
    EXPECT_RAW_ERRNO(rc, -EINVAL, "waking a PI waiter must be EINVAL");

    /* Still parked, so the two wake_op walks reuse it. */
    TEST("wake_op meets the PI waiter at uaddr");
    EXPECT_RAW_ERRNO(futex_wake_op(&pi_lock, &plain_word, 1, 1, add0_ne0()),
                     -EINVAL, "wake_op's first walk must refuse a PI waiter");

    TEST("wake_op meets the PI waiter at uaddr2");
    EXPECT_RAW_ERRNO(futex_wake_op(&plain_word, &pi_lock, 1, 1, add0_ne0()),
                     -EINVAL, "wake_op's second walk must refuse a PI waiter");

    set_and_wake(&release);
    wait_until_set(&waiter_done);

    /* Nobody is parked now, so a refused wake must not have left the waiter
     * somewhere a later wake still finds.
     */
    TEST("wake the drained address");
    for (int i = 0; i < 8; i++) {
        if (futex_wake(&pi_lock, 1) != 0) {
            FAIL("a drained address reported a woken waiter");
            goto done;
        }
    }
    PASS();

done:
    SUMMARY("test-futex-wake-pi");
    return fails > 0 ? 1 : 0;
}
