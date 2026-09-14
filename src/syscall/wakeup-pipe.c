/*
 * Blocking-wait wakeup pipe
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The self-pipe every indefinite host poll/select/kevent waits on alongside its
 * real fds. Free of syscall-layer dependencies, so the concurrency contract in
 * wakeup-pipe.h can be tested on its own.
 */

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "syscall/wakeup-pipe.h"

/* Read by the sigwait thread and by every guest thread while wakeup_pipe_init()
 * is still assigning them, which plain int would let the compiler tear or fold.
 * Relaxed suffices: each fd is read on its own and publishes no other state,
 * and pipe(2) creates the descriptors before either store.
 */
static _Atomic int wakeup_pipe_rd = -1, wakeup_pipe_wr = -1;

/* The condvar face of the same wake. wake_counter counts the wakes published so
 * far, and the bump stays inside wake_lock so it cannot land between a waiter's
 * own check of the counter and the park that check guards.
 *
 * Atomic so the read side needs no lock. A caller reads the counter once per
 * pass of its wait loop, and an exec handoff rings thousands of times a second:
 * with the read under wake_lock those callers serialize against the ringer, and
 * test-exec-handoff measured a 400 ms guest sleep taking 1800 ms rather than
 * 700 ms for the contention alone.
 *
 * wake_lock is a leaf (see the lock-order block in syscall/internal.h): it is
 * taken for a counter bump and a broadcast and acquires nothing itself, and
 * pthread_cond_timedwait releases it for the whole time a caller is parked, so
 * a waiter never holds it against a ringer.
 */
static pthread_mutex_t wake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake_cond = PTHREAD_COND_INITIALIZER;
static _Atomic uint64_t wake_counter;

void wakeup_pipe_init(void)
{
    /* Replacing a published pair strands every thread parked on the old fd. */
    if (atomic_load_explicit(&wakeup_pipe_rd, memory_order_relaxed) >= 0)
        return;

    int pipefd[2];
    if (pipe(pipefd) == 0) {
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
        fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
        atomic_store_explicit(&wakeup_pipe_rd, pipefd[0], memory_order_relaxed);
        atomic_store_explicit(&wakeup_pipe_wr, pipefd[1], memory_order_relaxed);
    }
}

void wakeup_pipe_signal(void)
{
    int wr = atomic_load_explicit(&wakeup_pipe_wr, memory_order_relaxed);
    if (wr >= 0) {
        uint8_t byte = 1;
        write(wr, &byte, 1);
    }

    pthread_mutex_lock(&wake_lock);
    atomic_fetch_add_explicit(&wake_counter, 1, memory_order_release);
    pthread_cond_broadcast(&wake_cond);
    pthread_mutex_unlock(&wake_lock);
}

uint64_t wakeup_counter(void)
{
    return atomic_load_explicit(&wake_counter, memory_order_acquire);
}

void wakeup_wait_ns(int64_t max_ns, uint64_t seen_counter)
{
    if (max_ns <= 0)
        return;

    /* Relative rather than an absolute CLOCK_REALTIME deadline: the callers are
     * sleeps whose length the guest asked for, and a wall-clock step must not
     * lengthen or cut one short.
     */
    struct timespec rel = {
        .tv_sec = (time_t) (max_ns / 1000000000),
        .tv_nsec = (long) (max_ns % 1000000000),
    };

    pthread_mutex_lock(&wake_lock);
    if (atomic_load_explicit(&wake_counter, memory_order_acquire) ==
        seen_counter)
        pthread_cond_timedwait_relative_np(&wake_cond, &wake_lock, &rel);
    pthread_mutex_unlock(&wake_lock);
}

int wakeup_pipe_read_fd(void)
{
    return atomic_load_explicit(&wakeup_pipe_rd, memory_order_relaxed);
}

void wakeup_pipe_drain(void)
{
    int rd = atomic_load_explicit(&wakeup_pipe_rd, memory_order_relaxed);
    if (rd < 0)
        return;

    uint8_t drain;
    while (read(rd, &drain, 1) > 0)
        ;
}
