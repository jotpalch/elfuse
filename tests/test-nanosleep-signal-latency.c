/*
 * Signal delivery latency to a thread parked in a sleep
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A sleeping thread is parked host-side, outside hv_vcpu_run, so hv_vcpus_exit
 * cannot reach it and the sleep has to join the wake itself. When it does not,
 * the sleep still ends at the right instant and still reports the right
 * remainder, and only notices a queued signal once its own recheck quantum
 * expires, so the defect is invisible to a test that checks the sleep's result.
 * Measure the delay instead: the gap between sending a signal to the sleeper
 * and its handler running.
 *
 * Both spellings are exercised because they reach the wait on different terms.
 * nanosleep owns a relative interval and writes back the remainder on EINTR;
 * clock_nanosleep with TIMER_ABSTIME re-derives the same instant instead and
 * stays restartable, which is a separate path through the restart gate.
 *
 * The delay the signal is sent after walks forward across iterations. A fixed
 * delay phase-locks every iteration to the same offset inside the quantum,
 * which reports one arbitrary point of the distribution as though it were the
 * whole of it.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Ten times the slowest gap seen with the sleep joined to the wake, and a fifth
 * of the 100 ms quantum that is the failure being ruled out. A machine would
 * have to be some hundred times slower than the reference to cross it from
 * below, and no machine speed moves the quantum above it.
 */
#define MAX_GAP_MS 20.0
#define ITERS 8
#define SLEEP_SEC 3

/* Out-of-band results, below any gap a real measurement can produce. */
#define GAP_NO_THREAD (-1.0)
#define GAP_NO_HANDLER (-2.0)

/* Written by the handler on the sleeper thread and read by the main thread's
 * wait loop. volatile carries no inter-thread ordering, and a lock-free atomic
 * store is what a handler may use.
 */
static _Atomic int handler_ran;
static _Atomic int64_t handler_ns;

/* Set by the sleeper immediately before it enters the sleep. */
static _Atomic int sleeper_armed;

static long long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long) t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void on_signal(int sig)
{
    (void) sig;
    atomic_store_explicit(&handler_ns, now_ns(), memory_order_relaxed);
    atomic_store_explicit(&handler_ran, 1, memory_order_release);
}

/* Park for SLEEP_SEC, long enough that no iteration ends by reaching its own
 * deadline. Either spelling returns EINTR here; the return is not the
 * measurement and is deliberately ignored.
 */
static void *sleep_relative(void *arg)
{
    (void) arg;
    struct timespec req = {SLEEP_SEC, 0}, rem;
    atomic_store_explicit(&sleeper_armed, 1, memory_order_release);
    nanosleep(&req, &rem);
    return NULL;
}

static void *sleep_absolute(void *arg)
{
    (void) arg;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += SLEEP_SEC;
    atomic_store_explicit(&sleeper_armed, 1, memory_order_release);
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    return NULL;
}

static void sort_gaps(double *v, int n)
{
    for (int i = 1; i < n; i++) {
        double key = v[i];
        int j = i - 1;
        while (j >= 0 && v[j] > key) {
            v[j + 1] = v[j];
            j--;
        }
        v[j + 1] = key;
    }
}

/* Median gap from sending the signal to the handler running, GAP_NO_THREAD if a
 * thread could not be started, or GAP_NO_HANDLER if one never ran its handler.
 *
 * The median rather than the minimum: an unjoined wake leaves the gap spread
 * across the quantum rather than pinned to its top, so a minimum would report
 * the one lucky iteration that arrived just before a recheck.
 */
static double median_gap(void *(*body)(void *) )
{
    double gaps[ITERS];

    for (int i = 0; i < ITERS; i++) {
        pthread_t th;
        atomic_store_explicit(&handler_ran, 0, memory_order_relaxed);
        atomic_store_explicit(&handler_ns, 0, memory_order_relaxed);
        atomic_store_explicit(&sleeper_armed, 0, memory_order_relaxed);

        int rc = pthread_create(&th, NULL, body, NULL);
        if (rc != 0) {
            errno = rc;
            return GAP_NO_THREAD;
        }

        /* Wait for the sleeper to arm, then let it reach the host wait. A
         * signal that arrives first is answered by the check at the top of the
         * sleep loop, which is fast whether or not the wait itself is joined,
         * and a slow pthread_create would otherwise put iterations there.
         */
        long long armed_by_ns = now_ns() + (long long) SLEEP_SEC * 1000000000LL;
        while (!atomic_load_explicit(&sleeper_armed, memory_order_acquire)) {
            if (now_ns() > armed_by_ns) {
                pthread_join(th, NULL);
                return GAP_NO_THREAD;
            }
        }
        struct timespec settle = {0, (150 + i * 11) * 1000000L};
        nanosleep(&settle, NULL);

        long long sent_ns = now_ns();
        rc = pthread_kill(th, SIGUSR1);
        if (rc != 0) {
            /* Joined even here: the sleeper is parked for SLEEP_SEC and would
             * otherwise still be in flight for the rest of the loop.
             */
            pthread_join(th, NULL);
            errno = rc;
            return GAP_NO_THREAD;
        }

        /* Bounded, so a regression that strands the sleeper fails the test
         * rather than hanging the lane it runs in.
         */
        long long give_up_ns = sent_ns + (long long) SLEEP_SEC * 2000000000LL;
        while (!atomic_load_explicit(&handler_ran, memory_order_acquire)) {
            if (now_ns() > give_up_ns) {
                pthread_join(th, NULL);
                return GAP_NO_HANDLER;
            }
        }

        gaps[i] =
            (double) (atomic_load_explicit(&handler_ns, memory_order_relaxed) -
                      sent_ns) /
            1e6;
        pthread_join(th, NULL);
    }

    sort_gaps(gaps, ITERS);
    return (gaps[ITERS / 2 - 1] + gaps[ITERS / 2]) / 2.0;
}

static void check(const char *name, void *(*body)(void *) )
{
    double gap = median_gap(body);
    TEST(name);
    if (gap == GAP_NO_THREAD) {
        FAIL("could not start or signal a sleeper");
        return;
    }
    if (gap == GAP_NO_HANDLER) {
        FAIL("the handler never ran");
        return;
    }
    if (gap < MAX_GAP_MS) {
        PASS();
        return;
    }
    char msg[96];
    snprintf(msg, sizeof(msg), "handler ran %.1fms after the signal (max %.0f)",
             gap, MAX_GAP_MS);
    FAIL(msg);
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("  sigaction failed, errno=%d\n", errno);
        return 1;
    }

    check("nanosleep wakes on a queued signal", sleep_relative);
    check("clock_nanosleep(ABSTIME) wakes on a queued signal", sleep_absolute);

    SUMMARY("test-nanosleep-signal-latency");
    return fails ? 1 : 0;
}
