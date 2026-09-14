/*
 * test-futex-requeue-samebucket.c -- FUTEX_REQUEUE(X, X) must terminate.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse's requeue walk moves a matched waiter by unlinking it from *pp, then
 * relinking it at the destination bucket's head. When uaddr and uaddr2 hash to
 * the same bucket, the destination is the source: relinking a waiter that *pp
 * still names puts it right back there, so the walk never advances past it.
 * futex(X, FUTEX_REQUEUE, 0, INT_MAX, X) against one parked waiter then
 * re-links that same waiter until the budget runs out instead of leaving the
 * loop once, holding the bucket lock the whole time.
 *
 * The fix takes the same path Linux's requeue_futex() does when hb1 == hb2:
 * rewrite the waiter's key in place and advance past it, without touching the
 * list. This test parks one waiter and requeues it onto itself with the largest
 * requeue budget a guest can pass, and asserts the call returns promptly with
 * the true count rather than spinning out the budget.
 *
 * FUTEX_WAIT_BITSET rather than FUTEX_WAIT: only the bitset form is guaranteed
 * to take the bucket queue this bug lives in, as test-futex-requeue-account.c
 * notes.
 */
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <linux/futex.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

static uint32_t addr;

static long wait_bitset(uint32_t *w, uint32_t expect)
{
    return raw_syscall6(__NR_futex, (long) w,
                        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, expect, 0, 0,
                        (long) (int32_t) FUTEX_BITSET_MATCH_ANY);
}

static long wake(uint32_t *w, int n)
{
    return raw_syscall6(__NR_futex, (long) w, FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
                        n, 0, 0, 0);
}

static long requeue_same(uint32_t *w, long nwake, long nrequeue)
{
    return raw_syscall6(__NR_futex, (long) w,
                        FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG, nwake, nrequeue,
                        (long) w, 0);
}

static void settle(void)
{
    struct timespec ts = {0, 50 * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static void *park_on_addr(void *arg)
{
    (void) arg;
    while (__atomic_load_n(&addr, __ATOMIC_SEQ_CST) == 0)
        wait_bitset(&addr, 0);
    return NULL;
}

int main(void)
{
    pthread_t t1;

    printf("FUTEX_REQUEUE(X, X) same-bucket termination test\n");

    TEST("requeue onto its own address terminates and counts one waiter");
    int rc1 = pthread_create(&t1, NULL, park_on_addr, NULL);
    if (rc1 != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(rc1));
        FAIL("pthread_create");
    } else {
        settle();

        struct timespec t0, t1s;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        long rc = requeue_same(&addr, 0, INT_MAX);
        clock_gettime(CLOCK_MONOTONIC, &t1s);
        long ms = (t1s.tv_sec - t0.tv_sec) * 1000 +
                  (t1s.tv_nsec - t0.tv_nsec) / 1000000;

        __atomic_store_n(&addr, 1, __ATOMIC_SEQ_CST);
        wake(&addr, 1);
        pthread_join(t1, NULL);

        if (ms >= 1000)
            (printf("FAIL: requeue took %ld ms, so it did not terminate\n", ms),
             fails++);
        else if (rc != 1)
            (printf("FAIL: requeue rc=%ld, want 1 (one waiter present)\n", rc),
             fails++);
        else
            PASS();
    }

    SUMMARY("test-futex-requeue-samebucket");
    return fails > 0 ? 1 : 0;
}
