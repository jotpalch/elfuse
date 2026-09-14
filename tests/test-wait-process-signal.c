/*
 * A process-directed signal interrupts one blocked waiter
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * kill(2) queues one instance for the whole thread group, and Linux
 * complete_signal() wakes only the thread it picks to run the handler. The
 * elfuse waits behind read, ppoll, pselect6, epoll_pwait, flock and futex all
 * return together on one wakeup byte or on a shared polling slice, so each has
 * to take the signal for itself before reporting EINTR: every sibling that
 * merely sees it pending returns EINTR with no handler to run.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define WAITERS 4
#define ROUNDS 4

enum wait_kind {
    WAIT_READ,
    WAIT_PPOLL,
    WAIT_PSELECT,
    WAIT_EPOLL,
    WAIT_FLOCK,
    WAIT_FUTEX,
};

static int futex_word;

static enum wait_kind kind;
static char lock_path[] = "/tmp/elfuse-wait-process-signal-XXXXXX";
static int pipes[WAITERS][2];
static int epfds[WAITERS];
static _Atomic int handler_runs;
static _Atomic int armed;
static _Atomic int interrupted;

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

/* One blocking wait of the current kind; -1 with errno on failure. */
static int wait_once(int idx)
{
    int rfd = pipes[idx][0];
    switch (kind) {
    case WAIT_READ: {
        char c;
        return (int) read(rfd, &c, 1);
    }
    case WAIT_PPOLL: {
        struct pollfd p = {.fd = rfd, .events = POLLIN};
        return ppoll(&p, 1, NULL, NULL);
    }
    case WAIT_PSELECT: {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(rfd, &set);
        return pselect(rfd + 1, &set, NULL, NULL, NULL, NULL);
    }
    case WAIT_EPOLL: {
        struct epoll_event ev;
        return epoll_pwait(epfds[idx], &ev, 1, -1, NULL);
    }
    case WAIT_FLOCK: {
        int fd = open(lock_path, O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return -1;
        int rc = flock(fd, LOCK_EX);
        int saved = errno;
        close(fd);
        errno = saved;
        return rc;
    }
    case WAIT_FUTEX:
        return (int) syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0,
                             NULL);
    }
    return -1;
}

static void *waiter(void *arg)
{
    int idx = (int) (long) arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    atomic_fetch_add_explicit(&armed, 1, memory_order_release);
    if (wait_once(idx) < 0 && errno == EINTR)
        atomic_fetch_add_explicit(&interrupted, 1, memory_order_relaxed);
    return NULL;
}

/* Release the waiters still parked -- a byte for the fd waits, the lock for
 * flock, which each waiter takes and drops again in turn -- and join the
 * @started threads.
 */
static void release_waiters(pthread_t *th, int started, int holder)
{
    if (holder >= 0)
        close(holder);
    for (int i = 0; i < WAITERS; i++) {
        ssize_t n = write(pipes[i][1], "x", 1);
        (void) n;
    }
    futex_word = 1;
    syscall(SYS_futex, &futex_word, FUTEX_WAKE_PRIVATE, INT_MAX, NULL);
    for (int i = 0; i < started; i++)
        pthread_join(th[i], NULL);
    for (int i = 0; i < WAITERS; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
        if (kind == WAIT_EPOLL)
            close(epfds[i]);
    }
}

/* One kill() at WAITERS blocked threads.
 *
 * Returns 0, or the error number when setup failed, with the handler count and
 * the EINTR count in @runs and @woke.
 */
static int send_one_signal(int *runs, int *woke)
{
    atomic_store_explicit(&handler_runs, 0, memory_order_relaxed);
    atomic_store_explicit(&armed, 0, memory_order_relaxed);
    atomic_store_explicit(&interrupted, 0, memory_order_relaxed);
    futex_word = 0;

    int holder = -1;
    if (kind == WAIT_FLOCK) {
        holder = open(lock_path, O_RDWR | O_CLOEXEC);
        if (holder < 0 || flock(holder, LOCK_EX) < 0)
            return errno;
    }
    for (int i = 0; i < WAITERS; i++) {
        if (pipe(pipes[i]) < 0)
            return errno;
        if (kind == WAIT_EPOLL) {
            struct epoll_event ev = {.events = EPOLLIN};
            epfds[i] = epoll_create1(EPOLL_CLOEXEC);
            if (epfds[i] < 0 ||
                epoll_ctl(epfds[i], EPOLL_CTL_ADD, pipes[i][0], &ev) < 0)
                return errno;
        }
    }

    pthread_t th[WAITERS];
    for (int i = 0; i < WAITERS; i++) {
        int rc = pthread_create(&th[i], NULL, waiter, (void *) (long) i);
        if (rc != 0) {
            release_waiters(th, i, holder);
            return rc;
        }
    }

    long long give_up = now_ms() + 2000;
    while (atomic_load_explicit(&armed, memory_order_acquire) < WAITERS &&
           now_ms() < give_up)
        ;
    /* The flag is set just before the wait; this lets each reach the park. */
    usleep(100000);

    kill(getpid(), SIGUSR1);

    give_up = now_ms() + 2000;
    while (atomic_load_explicit(&handler_runs, memory_order_acquire) == 0 &&
           now_ms() < give_up)
        ;
    /* Longer than the 200 ms slice a wrongly woken sibling may sit out. */
    usleep(300000);

    *runs = atomic_load_explicit(&handler_runs, memory_order_acquire);
    *woke = atomic_load_explicit(&interrupted, memory_order_acquire);

    release_waiters(th, WAITERS, holder);
    return 0;
}

static void check_kind(enum wait_kind k, const char *name)
{
    kind = k;
    TEST(name);

    /* The settle cannot prove every waiter reached the park. A signal that
     * lands on one still on its way runs the handler in user space and
     * interrupts nobody, which passes; more than one EINTR fails at once. The
     * rounds are there because a wrong EINTR on these waits is a race rather
     * than a certainty.
     */
    int runs = 0, woke = 0;
    bool observed = false;
    for (int round = 0; round < ROUNDS; round++) {
        int rc = send_one_signal(&runs, &woke);
        if (rc != 0) {
            errno = rc;
            FAIL("setup failed");
            return;
        }
        if (runs != 1 || woke > 1)
            break;
        observed = observed || woke == 1;
    }

    if (runs == 1 && woke <= 1 && !observed) {
        FAIL("no round caught a waiter parked, so nothing was tested");
    } else if (runs == 1 && woke <= 1) {
        PASS();
    } else {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "handler ran %d times, %d waiters returned EINTR (want 1/<=1)",
                 runs, woke);
        FAIL(msg);
    }
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGUSR1, &sa, NULL);

    /* The main thread blocks the signal so kill() can only pick a waiter. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    int lock_fd = mkstemp(lock_path);
    if (lock_fd < 0) {
        TEST("mkstemp");
        FAIL("mkstemp failed");
        return 1;
    }
    close(lock_fd);

    check_kind(WAIT_READ, "read");
    check_kind(WAIT_PPOLL, "ppoll");
    check_kind(WAIT_PSELECT, "pselect6");
    check_kind(WAIT_EPOLL, "epoll_pwait");
    check_kind(WAIT_FLOCK, "flock");
    check_kind(WAIT_FUTEX, "futex");

    unlink(lock_path);
    SUMMARY("test-wait-process-signal");
    return fails ? 1 : 0;
}
