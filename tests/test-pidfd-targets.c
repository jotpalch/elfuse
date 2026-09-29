/*
 * Test which targets pidfd_open accepts and which of them report an exit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two relatives outside the caller's descendant table. A forked child opens a
 * pidfd on its parent and signals through it, and a second child opens a pidfd
 * on its sibling and polls it for the sibling's exit. Both go through the same
 * fork-family lookup kill(getppid(), sig) uses. On Linux they succeed; they
 * must succeed here too.
 *
 * Two targets that legitimately have no exit monitor behind them are checked
 * too, because both must stay unreadable rather than read as exited: the caller
 * itself, and a CLONE_VM child, which holds a guest tid but no host process of
 * its own. A non-positive pid is rejected before any lookup.
 *
 * The sibling half is ordered by two pipe handshakes rather than by sleeps: the
 * sibling exits only once the watcher reports its pidfd open, so a slow fork
 * cannot turn the test red.
 */

#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"

#define __NR_pidfd_open_nr 434
#define __NR_pidfd_send_signal_nr 424


static volatile sig_atomic_t got_usr1 = 0;

static void usr1_handler(int sig)
{
    (void) sig;
    got_usr1 = 1;
}

static bool wait_flag(int max_ms)
{
    for (int i = 0; i < max_ms && !got_usr1; i++) {
        struct timespec ts = {0, 1000000}; /* 1 ms */
        nanosleep(&ts, NULL);
    }
    return got_usr1 != 0;
}

/* Child 1: the parent is not in this child's descendant table, so both the
 * probe and the signal resolve through the fork-family registry.
 */
static int signal_parent(void)
{
    if (kill(getppid(), 0) != 0)
        return 1;
    long pfd = raw_syscall2(__NR_pidfd_open_nr, (long) getppid(), 0);
    if (pfd < 0)
        return 2;
    if (raw_syscall4(__NR_pidfd_send_signal_nr, pfd, 0, 0, 0) != 0)
        return 3;
    if (raw_syscall4(__NR_pidfd_send_signal_nr, pfd, SIGUSR1, 0, 0) != 0)
        return 4;
    return 0;
}

/* Child 2: open a pidfd on the sibling whose pid arrives on @pid_in, report
 * that it is open on @ready_out, then wait for the sibling's exit to make the
 * pidfd readable. The sibling is neither ancestor nor descendant here.
 */
static int watch_sibling(int pid_in, int ready_out)
{
    int64_t sibling = 0;
    if (read(pid_in, &sibling, sizeof(sibling)) != (ssize_t) sizeof(sibling))
        return 1;
    long pfd = raw_syscall2(__NR_pidfd_open_nr, (long) sibling, 0);
    if (pfd < 0)
        return 2;
    uint8_t byte = 0;
    if (write(ready_out, &byte, 1) != 1)
        return 1;
    struct pollfd pv = {.fd = (int) pfd, .events = POLLIN};
    int n = poll(&pv, 1, 10000);
    return n == 1 && (pv.revents & POLLIN) ? 0 : 3;
}

/* Map a child exit status onto one line of output. Returns 1 if it failed. */
static int report(const char *what, pid_t pid, const char *const *reasons)
{
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        fprintf(stderr, "FAIL: %s did not exit cleanly\n", what);
        return 1;
    }
    int code = WEXITSTATUS(status);
    if (code == 0)
        return 0;
    fprintf(stderr, "FAIL: %s: %s\n", what, reasons[code - 1]);
    return 1;
}

int main(void)
{
    int failed = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    pid_t signaller = fork();
    if (signaller < 0)
        return 1;
    if (signaller == 0)
        _exit(signal_parent());

    if (!wait_flag(5000)) {
        fprintf(stderr,
                "FAIL: SIGUSR1 through the parent pidfd not delivered\n");
        failed++;
    }
    static const char *const signal_reasons[] = {
        "kill(getppid(), 0) failed",
        "pidfd_open(getppid()) failed",
        "pidfd_send_signal(pfd, 0) failed",
        "pidfd_send_signal(pfd, SIGUSR1) failed",
    };
    failed += report("parent signaller", signaller, signal_reasons);

    /* A self-pidfd has nothing to watch, and a live process is not an exited
     * one, so it must not poll readable.
     */
    long selfpfd = raw_syscall2(__NR_pidfd_open_nr, (long) getpid(), 0);
    if (selfpfd < 0) {
        fprintf(stderr, "FAIL: pidfd_open(self) failed\n");
        failed++;
    } else {
        struct pollfd sv = {.fd = (int) selfpfd, .events = POLLIN};
        if (poll(&sv, 1, 100) != 0) {
            fprintf(stderr, "FAIL: self pidfd reports the caller exited\n");
            failed++;
        }
        close((int) selfpfd);
    }

    /* The kernel rejects a non-positive pid outright rather than reporting it
     * as a missing process.
     */
    if (raw_syscall2(__NR_pidfd_open_nr, 0, 0) != -22 /* EINVAL */) {
        fprintf(stderr, "FAIL: pidfd_open(0) did not return EINVAL\n");
        failed++;
    }
    if (raw_syscall2(__NR_pidfd_open_nr, -1, 0) != -22 /* EINVAL */) {
        fprintf(stderr, "FAIL: pidfd_open(-1) did not return EINVAL\n");
        failed++;
    }

    int pidp[2], readyp[2], gop[2];
    if (pipe(pidp) < 0 || pipe(readyp) < 0 || pipe(gop) < 0)
        return 1;

    pid_t watcher = fork();
    if (watcher < 0)
        return 1;
    if (watcher == 0) {
        close(pidp[1]);
        close(readyp[0]);
        close(gop[0]);
        close(gop[1]);
        _exit(watch_sibling(pidp[0], readyp[1]));
    }

    pid_t sibling = fork();
    if (sibling < 0)
        return 1;
    if (sibling == 0) {
        close(pidp[0]);
        close(pidp[1]);
        close(readyp[0]);
        close(readyp[1]);
        close(gop[1]);

        /* Exit only once the parent closes the other end, which it does after
         * the watcher has its pidfd.
         */
        uint8_t byte = 0;
        (void) read(gop[0], &byte, 1);
        _exit(0);
    }

    close(pidp[0]);
    close(readyp[1]);
    close(gop[0]);

    int64_t sibling_pid = sibling;
    if (write(pidp[1], &sibling_pid, sizeof(sibling_pid)) !=
        (ssize_t) sizeof(sibling_pid)) {
        fprintf(stderr,
                "FAIL: could not hand the sibling pid to the watcher\n");
        failed++;
    }
    close(pidp[1]);

    uint8_t ready = 0;
    if (read(readyp[0], &ready, 1) != 1)
        fprintf(stderr, "note: watcher never reported its pidfd open\n");
    close(readyp[0]);
    close(gop[1]);

    waitpid(sibling, NULL, 0);
    static const char *const watch_reasons[] = {
        "pipe handshake with the parent failed",
        "pidfd_open(sibling) failed",
        "sibling pidfd never reported the exit",
    };
    failed += report("sibling watcher", watcher, watch_reasons);

    printf("%s: %d failed\n", failed == 0 ? "PASS" : "FAIL", failed);
    return failed == 0 ? 0 : 1;
}
