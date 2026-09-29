/*
 * Signal delivery latency to a thread parked in select or epoll_wait
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The companion of test-nanosleep-signal-latency for the descriptor waits. A
 * waiter is parked host-side, outside hv_vcpu_run, so a queued signal reaches
 * it only through the wakeup pipe. A wait that does not watch the pipe still
 * returns EINTR, but only once its polling slice ends, so the defect shows as
 * delay rather than as a wrong result. Each wait watches an empty pipe, so
 * nothing but the signal can end it.
 *
 * select runs with a finite timeout, and epoll_wait with both a finite and an
 * indefinite one, because the two reach the host wait on different terms. The
 * last case fills the fd table first, which puts the host kqueue behind the
 * epoll instance past FD_SETSIZE.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* A tenth of the 200 ms slice that is the failure being ruled out, and far
 * above the sub-millisecond gap a joined wait shows.
 */
#define MAX_GAP_MS 20.0

/* A wait that spins instead of parking still answers the signal at once, so
 * only its CPU share gives it away. A parked waiter reads under 1% through
 * CLOCK_THREAD_CPUTIME_ID and a spinning one 10 to 13%.
 */
#define MAX_BUSY 0.05
#define ITERS 8
#define SLEEP_SEC 3

/* Out-of-band results, below any gap a real measurement can produce. */
#define GAP_NO_THREAD (-1.0)
#define GAP_NO_HANDLER (-2.0)

/* Written by the handler on the waiter thread and read by the main thread's
 * wait loop. volatile carries no inter-thread ordering, and a lock-free atomic
 * store is what a handler may use.
 */
static _Atomic int handler_ran;
static _Atomic int64_t handler_ns;

/* Set by the waiter immediately before it enters the wait. */
static _Atomic int waiter_armed;

/* The waiter's CPU share over its wait, stored before it exits. */
static _Atomic double waiter_busy;

static long long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long) t.tv_sec * 1000000000LL + t.tv_nsec;
}

static long long thread_cpu_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (long long) t.tv_sec * 1000000000LL + t.tv_nsec;
}

typedef struct {
    long long cpu_ns, wall_ns;
} wait_start_t;

static wait_start_t wait_arm(void)
{
    wait_start_t start = {thread_cpu_ns(), now_ns()};
    atomic_store_explicit(&waiter_armed, 1, memory_order_release);
    return start;
}

static void wait_done(wait_start_t start)
{
    double busy = (double) (thread_cpu_ns() - start.cpu_ns) /
                  (double) (now_ns() - start.wall_ns);
    atomic_store_explicit(&waiter_busy, busy, memory_order_release);
}

static void on_signal(int sig)
{
    (void) sig;
    atomic_store_explicit(&handler_ns, now_ns(), memory_order_relaxed);
    atomic_store_explicit(&handler_ran, 1, memory_order_release);
}

/* The read end of a pipe nothing writes to, and an epoll instance watching it.
 */
static int idle_fd = -1;
static int idle_epfd = -1;

/* Each wait returns EINTR here; the return is not the measurement and is
 * deliberately ignored.
 */
static void *select_finite(void *arg)
{
    (void) arg;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(idle_fd, &rfds);
    struct timeval tv = {SLEEP_SEC, 0};
    wait_start_t start = wait_arm();
    select(idle_fd + 1, &rfds, NULL, NULL, &tv);
    wait_done(start);
    return NULL;
}

static void epoll_wait_ms(int timeout_ms)
{
    struct epoll_event ev;
    wait_start_t start = wait_arm();
    epoll_wait(idle_epfd, &ev, 1, timeout_ms);
    wait_done(start);
}

static void *epoll_finite(void *arg)
{
    (void) arg;
    epoll_wait_ms(SLEEP_SEC * 1000);
    return NULL;
}

static void *epoll_indefinite(void *arg)
{
    (void) arg;
    epoll_wait_ms(-1);
    return NULL;
}

static void sort_doubles(double *v, int n)
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
 * @busy_out receives the median CPU share of the waiter over its wait.
 *
 * The median rather than the minimum: an unjoined wake leaves the gap spread
 * across the quantum rather than pinned to its top, so a minimum would report
 * the one lucky iteration that arrived just before a recheck.
 */
static double median_gap(void *(*body)(void *), double *busy_out)
{
    double gaps[ITERS], busy[ITERS];

    for (int i = 0; i < ITERS; i++) {
        pthread_t th;
        atomic_store_explicit(&handler_ran, 0, memory_order_relaxed);
        atomic_store_explicit(&handler_ns, 0, memory_order_relaxed);
        atomic_store_explicit(&waiter_armed, 0, memory_order_relaxed);

        int rc = pthread_create(&th, NULL, body, NULL);
        if (rc != 0) {
            errno = rc;
            return GAP_NO_THREAD;
        }

        /* Wait for the waiter to arm, then let it reach the host wait. A signal
         * that arrives first is answered by the check at the top of the wait
         * loop, which is fast whether or not the wait itself is joined, and a
         * slow pthread_create would otherwise put iterations there.
         */
        long long armed_by_ns = now_ns() + (long long) SLEEP_SEC * 1000000000LL;
        while (!atomic_load_explicit(&waiter_armed, memory_order_acquire)) {
            if (now_ns() > armed_by_ns) {
                /* Detached rather than joined on every failure path: a waiter
                 * in epoll_wait(-1) that no signal reaches never returns, and
                 * the exit after SUMMARY tears it down instead.
                 */
                pthread_detach(th);
                return GAP_NO_THREAD;
            }
        }
        struct timespec settle = {0, (150 + i * 11) * 1000000L};
        nanosleep(&settle, NULL);

        long long sent_ns = now_ns();
        rc = pthread_kill(th, SIGUSR1);
        if (rc != 0) {
            pthread_detach(th);
            errno = rc;
            return GAP_NO_THREAD;
        }

        /* Bounded, so a regression that strands the waiter fails the test
         * rather than hanging the lane it runs in.
         */
        long long give_up_ns = sent_ns + (long long) SLEEP_SEC * 2000000000LL;
        while (!atomic_load_explicit(&handler_ran, memory_order_acquire)) {
            if (now_ns() > give_up_ns) {
                pthread_detach(th);
                return GAP_NO_HANDLER;
            }
        }

        gaps[i] =
            (double) (atomic_load_explicit(&handler_ns, memory_order_relaxed) -
                      sent_ns) /
            1e6;
        pthread_join(th, NULL);
        busy[i] = atomic_load_explicit(&waiter_busy, memory_order_acquire);
    }

    sort_doubles(busy, ITERS);
    *busy_out = (busy[ITERS / 2 - 1] + busy[ITERS / 2]) / 2.0;
    sort_doubles(gaps, ITERS);
    return (gaps[ITERS / 2 - 1] + gaps[ITERS / 2]) / 2.0;
}

static void check(const char *name, void *(*body)(void *) )
{
    double busy = 0;
    double gap = median_gap(body, &busy);
    TEST(name);
    if (gap == GAP_NO_THREAD) {
        FAIL("could not start or signal a waiter");
        return;
    }
    if (gap == GAP_NO_HANDLER) {
        FAIL("the handler never ran");
        return;
    }
    char msg[96];
    if (gap >= MAX_GAP_MS) {
        snprintf(msg, sizeof(msg),
                 "handler ran %.1fms after the signal (max %.0f)", gap,
                 MAX_GAP_MS);
        FAIL(msg);
        return;
    }
    if (busy > MAX_BUSY) {
        snprintf(msg, sizeof(msg), "waiter spent %.0f%% of its wait on CPU",
                 busy * 100.0);
        FAIL(msg);
        return;
    }
    PASS();
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

    int pfd[2];
    struct epoll_event ev = {.events = EPOLLIN};
    if (pipe(pfd) != 0 || (idle_epfd = epoll_create1(0)) < 0 ||
        epoll_ctl(idle_epfd, EPOLL_CTL_ADD, pfd[0], &ev) != 0) {
        printf("  setup failed, errno=%d\n", errno);
        return 1;
    }
    idle_fd = pfd[0];

    check("select with a timeout wakes on a queued signal", select_finite);
    check("epoll_wait with a timeout wakes on a queued signal", epoll_finite);
    check("epoll_wait without a timeout wakes on a queued signal",
          epoll_indefinite);

    int full[2];
    while (pipe(full) == 0)
        ;
    int fill_errno = errno;
    close(full[0]);
    close(full[1]);
    if (fill_errno != EMFILE) {
        printf("  fd table not filled, errno=%d\n", fill_errno);
        return 1;
    }
    idle_epfd = epoll_create1(0);
    if (idle_epfd < 0 ||
        epoll_ctl(idle_epfd, EPOLL_CTL_ADD, idle_fd, &ev) != 0) {
        printf("  high epoll setup failed, errno=%d\n", errno);
        return 1;
    }
    check("epoll_wait on a full fd table wakes on a queued signal",
          epoll_indefinite);

    SUMMARY("test-wait-signal-latency");
    return fails ? 1 : 0;
}
