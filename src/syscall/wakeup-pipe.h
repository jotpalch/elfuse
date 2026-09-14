/*
 * Blocking-wait wakeup pipe
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A process-wide self-pipe whose read end joins every host poll/select/kevent
 * that would otherwise wait forever, so exit_group, futex_interrupt, and guest
 * signal delivery reach a thread parked outside hv_vcpu_run(), where
 * hv_vcpus_exit() cannot.
 *
 * The same wake also drives a condition variable, for waits that have no real
 * descriptor to watch alongside it. A pure timeout is the case: nanosleep, and
 * the relative remainder clock_nanosleep reduces to, need to be woken rather
 * than told which fd is ready. Parking on the condvar rather than the pipe
 * keeps them out of the readable-state race the pipe carries, where a sibling's
 * drain can strand a waiter that had already been notified for the length of
 * its own recheck quantum.
 */

#pragma once

#include <stdint.h>

/* Create the pipe, once. Main thread only: the one-shot gate is an
 * unsynchronized check-then-act, and by the time syscall_init(), the only
 * caller, reaches it the sigwait thread is already reading the fds.
 */
void wakeup_pipe_init(void);

/* Wake every thread parked on the read end. Safe from a signal-handling thread;
 * a missing pipe is a no-op.
 */
void wakeup_pipe_signal(void);

/* The read end to add to a blocking wait, or -1 when the pipe is missing.
 * poll(2) ignores a negative fd, so callers can pass the result through.
 */
int wakeup_pipe_read_fd(void);

/* Consume every queued byte. The pipe is nonblocking, so this cannot park. */
void wakeup_pipe_drain(void);

/* The wake counter, read before testing whatever predicate the caller sleeps
 * on. wakeup_wait_ns() takes the value back and returns at once when the
 * counter has moved since, which is what closes the window between a caller's
 * predicate check and its park: a wake landing there bumps the counter instead
 * of being broadcast to nobody.
 */
uint64_t wakeup_counter(void);

/* Park the calling thread for at most @max_ns, or until the next
 * wakeup_pipe_signal(), whichever comes first. @seen_counter is the value
 * wakeup_counter() returned before the caller tested its predicate; a counter
 * that has moved since means the wait returns without parking.
 *
 * Spurious returns are permitted, as with any condition variable, so callers
 * re-test their predicate and recompute their own remaining time rather than
 * assuming @max_ns elapsed.
 */
void wakeup_wait_ns(int64_t max_ns, uint64_t seen_counter);
