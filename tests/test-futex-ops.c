/*
 * A CLONE_THREAD worker's exit must not interrupt anybody
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * clone(2): a thread created with CLONE_THREAD sends no signal to its parent
 * when it terminates. Nothing is delivered, so a sibling parked in a blocking
 * call stays parked and its timeout is what ends the wait.
 *
 * Each case parks for PARK_MS with nothing to wake it. A timeout answer means
 * the exit went unnoticed, which is what Linux does; EINTR means the wait was
 * cut short by something the guest was never sent.
 *
 * Syscalls exercised: futex(98), ppoll(73), epoll_pwait(22), clone(220),
 * exit(93), clock_gettime(113)
 */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"
#include "test-util.h"

int passes = 0, fails = 0;

/* Long enough that an immediate return is unambiguous, short enough that four
 * of them do not slow the lane.
 */
#define PARK_MS 300
#define PARK_NS (PARK_MS * 1000L * 1000L)

/* A wait cut short by the exit returns well inside the park; the futex path
 * polls on a 100 ms quantum, so anything under half the park is early.
 */
#define EARLY_MS (PARK_MS / 2)

static int word;
static volatile int child_tid;
static char child_stack_buf[16384] __attribute__((aligned(16)));

struct k_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

static long now_ms(void)
{
    struct k_timespec ts;
    raw_syscall2(113, 1 /* CLOCK_MONOTONIC */, (long) &ts);
    return (long) (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void msleep(long ms)
{
    struct k_timespec ts = {0, ms * 1000L * 1000L};
    raw_syscall4(101 /* nanosleep */, (long) &ts, 0, 0, 0);
}

/* Spawn a CLONE_THREAD worker that exits at once, and wait until it is gone.
 * CLONE_PARENT_SETTID seeds child_tid so the CLEARTID store is an observable
 * edge rather than a word that was already zero.
 */
static int spawn_and_reap_worker(void)
{
    unsigned long flags = 0x00010000    /* CLONE_THREAD */
                          | 0x00000100  /* CLONE_VM */
                          | 0x00000200  /* CLONE_FS */
                          | 0x00000800  /* CLONE_SIGHAND */
                          | 0x00100000  /* CLONE_PARENT_SETTID */
                          | 0x00200000; /* CLONE_CHILD_CLEARTID */

    long r = raw_syscall5(220, (long) flags,
                          (long) (child_stack_buf + sizeof(child_stack_buf)),
                          (long) &child_tid, 0, (long) &child_tid);
    if (r == 0) {
        raw_exit(0);
        test_unreachable();
    }
    if (r < 0)
        return -1;

    /* Poll the CLEARTID store with msleep rather than a futex wait: any futex
     * wait, including one on this address, is a chance to consume the one-shot
     * phantom EINTR this test exists to catch, before the calls under test run.
     * Bounded, so a teardown that never publishes is a reported failure rather
     * than a driver timeout.
     */
    long deadline = now_ms() + 5000;
    while (__atomic_load_n((volatile int *) &child_tid, __ATOMIC_ACQUIRE) !=
           0) {
        msleep(100);
        if (now_ms() > deadline)
            return -1;
    }
    return 0;
}

/* Runs one park and reports whether it lasted. rc/err are the raw answer. */
static void expect_uninterrupted(const char *name, long rc, long elapsed)
{
    TEST(name);
    if (rc == -EINTR) {
        FAIL("a CLONE_THREAD exit interrupted a wait Linux leaves parked");
        return;
    }
    if (elapsed < EARLY_MS) {
        FAIL("the wait ended early without reporting an interruption");
        return;
    }
    PASS();
}

int main(void)
{
    printf("=== phantom EINTR on CLONE_THREAD exit ===\n\n");

    TEST("baseline park with no worker");
    {
        struct k_timespec ts = {0, PARK_NS};
        long t0 = now_ms();
        long rc =
            raw_syscall6(__NR_futex, (long) &word,
                         FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, (long) &ts, 0, 0);
        long elapsed = now_ms() - t0;
        if (rc != -ETIMEDOUT)
            FAIL("an unwoken park must report ETIMEDOUT");
        else if (elapsed < EARLY_MS)
            FAIL("the park did not last");
        else
            PASS();
    }

    /* One worker per case: the interrupt this test exists to catch is a
     * one-shot edge, so a second case would find it already consumed.
     */
    TEST("clone and reap a worker");
    if (spawn_and_reap_worker() < 0) {
        FAIL("worker never exited");
        goto done;
    }
    PASS();

    {
        struct k_timespec ts = {0, PARK_NS};
        long t0 = now_ms();
        long rc =
            raw_syscall6(__NR_futex, (long) &word,
                         FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, (long) &ts, 0, 0);
        expect_uninterrupted("futex wait survives the exit", rc, now_ms() - t0);
    }

    TEST("clone and reap a worker for ppoll");
    if (spawn_and_reap_worker() < 0) {
        FAIL("worker never exited");
        goto done;
    }
    PASS();

    {
        /* The raw ppoll writes the remaining time back, so it gets its own. */
        struct k_timespec ts = {0, PARK_NS};
        long t0 = now_ms();
        long rc = raw_syscall5(73, 0, 0, (long) &ts, 0, 8);
        expect_uninterrupted("ppoll survives the exit", rc, now_ms() - t0);
    }

    TEST("clone and reap a worker for epoll_pwait");
    long ep = raw_syscall1(20 /* epoll_create1 */, 0);
    if (ep < 0 || spawn_and_reap_worker() < 0) {
        FAIL("worker never exited");
        goto done;
    }
    PASS();

    {
        char evs[16];
        long t0 = now_ms();
        long rc = raw_syscall6(22 /* epoll_pwait */, ep, (long) evs, 1, PARK_MS,
                               0, 8);
        expect_uninterrupted("epoll_pwait survives the exit", rc,
                             now_ms() - t0);
    }

done:
    SUMMARY("test-futex-ops");
    return fails > 0 ? 1 : 0;
}
