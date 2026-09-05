/*
 * test-signal-in-shim.c -- a signal that arrives while the vCPU sits at EL1.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A guest signal raises the shim attention word and then kicks every vCPU out
 * of hv_vcpu_run. The kick can land while the target is inside the EL1 shim
 * rather than in EL0 code, and there the live GPRs are the shim's scratch: the
 * guest's own values are in the saved SVC frame, and the shim means to ERET
 * through ELR_EL1. A signal frame built from that state restores scratch into
 * the guest on rt_sigreturn, so the interrupted thread resumes with registers
 * it never wrote.
 *
 * Contended locking is what makes the window wide: every failed acquire enters
 * the shim's futex path, so a stream of signals aimed at threads that are
 * fighting over one mutex lands there repeatedly. The corruption shows up two
 * ways, and this file checks for both. Mutual exclusion breaks, because a
 * thread resumed on the wrong registers re-runs part of its critical section:
 * the shared counter then exceeds the sum of what the threads themselves
 * counted. And a callee-saved register the compiler parked a value in comes
 * back changed.
 *
 * Neither is a timing assertion, but the failure is a race, so the round count
 * is what makes it reliable rather than the checks. The third symptom, a guest
 * that wedges outright, is left to the harness timeout.
 *
 * Every assertion is plain POSIX, so the reference kernel adjudicates this file
 * unchanged.
 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* The signaller decides when the run ends, and the workers lock until it does.
 * A fixed iteration count per worker does not work here: the EL1 fast paths
 * make the loop fast enough that the workers can finish before the first signal
 * is handled, which passes the run vacuously. Enough rounds that the kick lands
 * inside the shim many times over, few enough that the file stays well under a
 * second.
 */
#define NTHREADS 4
#define SIGNAL_ROUNDS 4000

/* The value a worker parks in a callee-saved register across its lock/unlock
 * pair. x21 is not written by the loop, so anything that changes it came from
 * outside the guest's own code.
 */
#define CANARY_BASE 0xfeedfacecafe0000ULL

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static volatile long shared;
static long handled;
static int stop;
static pthread_t tid[NTHREADS];
static volatile int canary_broken;

static void handler(int signum)
{
    (void) signum;
    __atomic_fetch_add(&handled, 1, __ATOMIC_RELAXED);
}

static void *worker(void *arg)
{
    long id = (long) arg;
    long mine = 0;
    register uint64_t canary asm("x21") = CANARY_BASE + (uint64_t) id;

    while (!__atomic_load_n(&stop, __ATOMIC_RELAXED)) {
        pthread_mutex_lock(&mu);
        shared++;
        mine++;
        pthread_mutex_unlock(&mu);

        /* GCC only guarantees a local register variable keeps its register
         * across a call when it is an asm operand. Without this the check
         * quietly becomes a tautology the first time a compiler spills it.
         */
        __asm__ volatile("" : "+r"(canary));
        if (canary != CANARY_BASE + (uint64_t) id) {
            canary_broken = 1;
            break;
        }
    }

    return (void *) mine;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("sigaction failed\n");
        return 1;
    }

    for (long i = 0; i < NTHREADS; i++) {
        if (pthread_create(&tid[i], NULL, worker, (void *) i) != 0) {
            printf("pthread_create failed\n");
            return 1;
        }
    }

    /* Every worker is still running here, which pthread_kill requires: they
     * only leave their loop once stop is set below.
     */
    for (int r = 0; r < SIGNAL_ROUNDS; r++)
        for (int i = 0; i < NTHREADS; i++)
            pthread_kill(tid[i], SIGUSR1);
    __atomic_store_n(&stop, 1, __ATOMIC_RELAXED);

    long total = 0;
    for (int i = 0; i < NTHREADS; i++) {
        void *r;
        pthread_join(tid[i], &r);
        total += (long) r;
    }

    TEST("callee-saved regs survive");
    EXPECT_TRUE(!canary_broken, "x21 changed across a signal");

    TEST("mutual exclusion holds");
    if (shared == total)
        PASS();
    else
        printf("FAIL: shared=%ld but threads counted %ld\n", shared, total),
            fails++;

    /* Without this the run could pass vacuously: no signal delivered means no
     * kick landed in the shim and nothing was exercised. Counted atomically
     * because four handlers on four threads increment it.
     */
    TEST("signals were delivered");
    EXPECT_TRUE(__atomic_load_n(&handled, __ATOMIC_RELAXED) > 0,
                "no SIGUSR1 reached a handler");

    SUMMARY("test-signal-in-shim");
    return fails ? 1 : 0;
}
