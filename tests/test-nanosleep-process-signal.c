/*
 * A process-directed signal interrupts one sleeper
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * kill(2) queues one instance for the whole thread group, and Linux
 * complete_signal() wakes only the thread it picks to run the handler. Several
 * threads parked in nanosleep are woken together by the host wake, so each has
 * to take the signal for itself before reporting EINTR: every sibling that
 * merely sees it pending returns EINTR with no handler to run.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define SLEEPERS 4
#define SLEEP_SEC 3
#define ATTEMPTS 3

static _Atomic int handler_runs;
static _Atomic int armed;
static _Atomic int interrupted;
static _Atomic int returned[SLEEPERS];

static void on_signal(int sig)
{
    (void) sig;
    atomic_fetch_add_explicit(&handler_runs, 1, memory_order_relaxed);
}

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long) t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void *sleeper(void *arg)
{
    int idx = (int) (long) arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    struct timespec req = {SLEEP_SEC, 0}, rem;
    atomic_fetch_add_explicit(&armed, 1, memory_order_release);
    if (nanosleep(&req, &rem) != 0 && errno == EINTR)
        atomic_fetch_add_explicit(&interrupted, 1, memory_order_relaxed);
    atomic_store_explicit(&returned[idx], 1, memory_order_release);
    return NULL;
}

/* One kill() at SLEEPERS parked threads.
 *
 * Returns 0, or the pthread_create error, with the handler count and the EINTR
 * count in @runs and @woke.
 */
static int send_one_signal(int *runs, int *woke)
{
    atomic_store_explicit(&handler_runs, 0, memory_order_relaxed);
    atomic_store_explicit(&armed, 0, memory_order_relaxed);
    atomic_store_explicit(&interrupted, 0, memory_order_relaxed);
    for (int i = 0; i < SLEEPERS; i++)
        atomic_store_explicit(&returned[i], 0, memory_order_relaxed);

    pthread_t th[SLEEPERS];
    for (long i = 0; i < SLEEPERS; i++) {
        int rc = pthread_create(&th[i], NULL, sleeper, (void *) i);
        if (rc != 0) {
            for (long j = 0; j < i; j++) {
                pthread_kill(th[j], SIGUSR1);
                pthread_join(th[j], NULL);
            }
            return rc;
        }
    }

    long long give_up = now_ms() + 2000;
    while (atomic_load_explicit(&armed, memory_order_acquire) < SLEEPERS &&
           now_ms() < give_up)
        ;
    /* The flag is set just before nanosleep; this lets each reach the park. */
    usleep(150000);

    kill(getpid(), SIGUSR1);

    give_up = now_ms() + 2000;
    while (atomic_load_explicit(&handler_runs, memory_order_acquire) == 0 &&
           now_ms() < give_up)
        ;
    /* Long enough for every wrongly woken sibling to have returned too. */
    usleep(300000);

    *runs = atomic_load_explicit(&handler_runs, memory_order_acquire);
    *woke = atomic_load_explicit(&interrupted, memory_order_acquire);

    for (int i = 0; i < SLEEPERS; i++) {
        if (!atomic_load_explicit(&returned[i], memory_order_acquire))
            pthread_kill(th[i], SIGUSR1);
    }
    for (int i = 0; i < SLEEPERS; i++)
        pthread_join(th[i], NULL);
    return 0;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGUSR1, &sa, NULL);

    /* The main thread blocks the signal so kill() can only pick a sleeper. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    TEST("kill() interrupts exactly one of several sleepers");

    /* The settle cannot prove every sleeper reached the park. A signal that
     * lands on one still on its way runs the handler in user space and
     * interrupts nobody, which is the one outcome worth another attempt; more
     * than one EINTR fails at once.
     */
    int runs = 0, woke = 0;
    for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
        int rc = send_one_signal(&runs, &woke);
        if (rc != 0) {
            errno = rc;
            FAIL("pthread_create failed");
            return 1;
        }
        if (!(runs == 1 && woke == 0))
            break;
    }

    if (runs == 1 && woke == 1) {
        PASS();
    } else {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "handler ran %d times, %d sleepers returned EINTR (want 1/1)",
                 runs, woke);
        FAIL(msg);
    }

    SUMMARY("test-nanosleep-process-signal");
    return fails ? 1 : 0;
}
