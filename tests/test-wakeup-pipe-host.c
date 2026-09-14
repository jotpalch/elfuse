/*
 * Native-host unit test for the wakeup pipe's concurrency contract
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A reader thread runs wakeup_pipe_signal() and wakeup_pipe_read_fd() across
 * the main thread's wakeup_pipe_init(), the pairing ThreadSanitizer reported on
 * wakeup_pipe_wr under test-fork-exec. Only a -fsanitize=thread build has a
 * race detector; elsewhere this checks init, idempotency, and drain.
 *
 * The condvar face is checked here too, because the wake counter is the whole
 * of its lost-wake guard and the guard is invisible from the guest: a sleep
 * whose wake went missing still ends at the right instant, just a quantum late.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "host-test-util.h"

#include "syscall/wakeup-pipe.h"

/* Plain bool here would be the defect under test, blamed on the harness. */
static atomic_bool reader_run = true;

/* Pacing is what makes the race observable: an unpaced loop churns
 * ThreadSanitizer's history until a conflicting access is evicted before its
 * partner arrives. With the fds plain: unpaced 0 of 20 runs, paced 20 of 20.
 */
#define RACE_WINDOW_US 20000
#define READER_PACE_US 200

static void *reader_main(void *arg)
{
    (void) arg;
    while (atomic_load_explicit(&reader_run, memory_order_relaxed)) {
        wakeup_pipe_signal();
        (void) wakeup_pipe_read_fd();
        usleep(READER_PACE_US);
    }
    return NULL;
}

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long) t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Ring once, after long enough that the main thread is parked rather than still
 * on its way there.
 */
static void *ringer_main(void *arg)
{
    (void) arg;
    usleep(50000);
    wakeup_pipe_signal();
    return NULL;
}

int main(void)
{
    host_check(wakeup_pipe_read_fd() == -1, "unset read end",
               "the read end must be -1 before init");

    pthread_t reader;
    if (pthread_create(&reader, NULL, reader_main, NULL) != 0) {
        fprintf(stderr, "FAIL thread: cannot start the reader thread\n");
        return 1;
    }

    /* Bracket the one-shot store with loads already in flight: a race is
     * reported only when an access finds a conflicting one recorded.
     */
    usleep(RACE_WINDOW_US);

    wakeup_pipe_init();

    usleep(RACE_WINDOW_US);

    atomic_store_explicit(&reader_run, false, memory_order_relaxed);
    pthread_join(reader, NULL);

    int fd = wakeup_pipe_read_fd();
    host_check(fd >= 0, "init", "init must publish a read end");

    /* Regression guard: syscall_init() runs once per process. */
    wakeup_pipe_init();
    host_check(wakeup_pipe_read_fd() == fd, "idempotent init",
               "a second init must keep the first read end");

    wakeup_pipe_drain();
    char byte;
    host_check(read(fd, &byte, 1) == -1 && errno == EAGAIN, "drain",
               "drain must leave the pipe empty and nonblocking");

    wakeup_pipe_signal();
    host_check(read(fd, &byte, 1) == 1, "signal", "signal must queue a byte");

    uint64_t before = wakeup_counter();
    wakeup_pipe_signal();
    host_check(wakeup_counter() != before, "counter moves",
               "a signal must advance the wake counter");

    /* The stale counter stands for a wake that landed between a caller's
     * predicate check and its park. Parking on it would sleep out the whole
     * interval with the work already waiting.
     */
    long long t0 = now_ms();
    wakeup_wait_ns(2000000000LL, before);
    host_check(now_ms() - t0 < 500, "stale counter does not park",
               "a wake since the snapshot must return the wait at once");

    /* Snapshot before the ringer exists. Reading the counter after it has
     * already rung would hand the wait a counter that matches, so it would park
     * for the whole interval with the wake already spent.
     */
    uint64_t before_ring = wakeup_counter();
    pthread_t ringer;
    t0 = now_ms();
    if (pthread_create(&ringer, NULL, ringer_main, NULL) != 0) {
        fprintf(stderr, "FAIL thread: cannot start the ringer thread\n");
        return 1;
    }
    wakeup_wait_ns(5000000000LL, before_ring);
    long long waited_ms = now_ms() - t0;
    pthread_join(ringer, NULL);

    /* The lower bound is what shows the wait parked at all: the ringer sleeps
     * 50 ms after t0, so a wait that returns at once passes the upper bound and
     * the stale-counter check above alike.
     */
    host_check(waited_ms >= 40, "a parked wait holds until the wake",
               "the wait must park until the ringer signals");
    host_check(waited_ms < 1000, "a signal releases a parked wait",
               "the park must end on the wake, not on its own timeout");

    return host_summary("test-wakeup-pipe-host");
}
