/*
 * fork/wait round-trip latency
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A child's exit reaches its parent through the cross-process doorbell, and the
 * parent's wait4 sleeps on a condition variable with a 100 ms timeout behind
 * it. When the doorbell does not reach that sleeper, the wait still returns the
 * right answer, just a timeout late -- so the defect is invisible to a test
 * that only checks the status. Measure the delay instead: the gap between the
 * child's last instant and the parent's return from wait.
 *
 * Both spellings are exercised because they take different paths inside elfuse.
 * wait(2) settles from the lifecycle registry, waitpid(2) on one pid polls the
 * child's host process, and the host process outlives the guest exit by about a
 * millisecond -- so a wakeup that satisfies the first can still leave the
 * second waiting out the whole timeout.
 */

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Ten times the fastest gap seen with the notification path connected, and a
 * quarter of the 100 ms timeout that is the failure being ruled out. A machine
 * would have to be some fifty times slower than the reference to cross it from
 * below, and no machine speed moves the timeout above it.
 */
#define MAX_GAP_MS 20.0
#define ITERS 8

static double ms_between(const struct timespec *a, const struct timespec *b)
{
    return (double) (b->tv_sec - a->tv_sec) * 1000.0 +
           (double) (b->tv_nsec - a->tv_nsec) / 1e6;
}

/* Wait for one child, retrying the interrupted call rather than reporting the
 * gap it did not measure.
 *
 * Returns 0 once that child is reaped with a clean exit, -1 on anything else: a
 * wait that fails leaves the child unreaped and still records a fast gap, so an
 * unchecked error reads as a pass here and the leftover child is then visible
 * to the wait(-1) in the other case.
 */
static int wait_for(pid_t child, int specific_pid)
{
    for (;;) {
        int status = 0;
        pid_t got = specific_pid ? waitpid(child, &status, 0) : wait(&status);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got != child)
            return -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            return -1;
        return 0;
    }
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

/* Median gap from the child's final timestamp to the parent's return from wait,
 * or -1 if a child could not be run to completion.
 *
 * The child is held at a pipe read until the parent is about to wait, so the
 * exit cannot land before the parent reaches the syscall. Without that, a
 * parent that arrives late finds the exit already in the table and returns from
 * the lookup at the top of sys_wait4 without ever reaching the condition
 * variable -- a fast iteration on a tree where the wakeup is still missing.
 *
 * The median rather than the minimum for the same reason: one such iteration
 * would carry a minimum, while an unlucky scheduling delay in one trial cannot
 * move a median that half the trials have to cross.
 */
static double median_gap(int specific_pid)
{
    double gaps[ITERS];

    for (int i = 0; i < ITERS; i++) {
        int go[2], report[2];
        if (pipe(go) != 0)
            return -1;
        if (pipe(report) != 0) {
            close(go[0]);
            close(go[1]);
            return -1;
        }

        pid_t pid = fork();
        if (pid < 0) {
            close(go[0]);
            close(go[1]);
            close(report[0]);
            close(report[1]);
            return -1;
        }
        if (pid == 0) {
            char go_byte;
            struct timespec c;
            close(go[1]);
            close(report[0]);
            /* Park here until the parent is on its way into wait. */
            if (read(go[0], &go_byte, 1) != 1)
                _exit(1);
            clock_gettime(CLOCK_MONOTONIC, &c);
            if (write(report[1], &c, sizeof(c)) != (ssize_t) sizeof(c))
                _exit(1);
            _exit(0);
        }

        close(go[0]);
        close(report[1]);

        int failed = (write(go[1], "g", 1) != 1);
        close(go[1]);
        if (!failed)
            failed = (wait_for(pid, specific_pid) != 0);

        struct timespec parent;
        clock_gettime(CLOCK_MONOTONIC, &parent);

        struct timespec child;
        ssize_t got = read(report[0], &child, sizeof(child));
        close(report[0]);
        if (failed || got != (ssize_t) sizeof(child))
            return -1;

        gaps[i] = ms_between(&child, &parent);
    }

    sort_gaps(gaps, ITERS);
    return (gaps[ITERS / 2 - 1] + gaps[ITERS / 2]) / 2.0;
}

static void check(const char *name, int specific_pid)
{
    double gap = median_gap(specific_pid);
    TEST(name);
    if (gap < 0) {
        FAIL("could not run a child to completion");
        return;
    }
    if (gap < MAX_GAP_MS) {
        PASS();
        return;
    }
    char msg[96];
    snprintf(msg, sizeof(msg),
             "waited %.1fms after the child exited (max %.0f)", gap,
             MAX_GAP_MS);
    FAIL(msg);
}

int main(void)
{
    check("wait() returns as soon as the child exits", 0);
    check("waitpid(pid) returns as soon as the child exits", 1);

    SUMMARY("test-fork-wait-latency");
    return fails ? 1 : 0;
}
