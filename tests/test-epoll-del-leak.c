/*
 * EPOLL_CTL_DEL removes every filter, including one whose sibling is gone
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * events names the filters a registration asked for, not the filters kqueue
 * still holds: EPOLLONESHOT removes only the filter that fired, and an ADD
 * drops a write filter the target refuses. Deleting them in one batched call
 * stops at the first change kqueue rejects and leaves the rest registered, and
 * a leftover knote wakes the next epoll_wait on that instance with an event for
 * an fd that is no longer registered. This pins the DEL path in
 * src/syscall/poll.c sys_epoll_ctl.
 *
 * Syscalls exercised: epoll_create1(20), epoll_ctl(21), epoll_pwait(22),
 *                     socketpair(199), fcntl(25), read(63), write(64)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static long elapsed_ms(const struct timespec *t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t0->tv_sec) * 1000 +
           (now.tv_nsec - t0->tv_nsec) / 1000000;
}

int main(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("socketpair failed\n");
        return 1;
    }
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    char buf[4096];
    memset(buf, 'x', sizeof(buf));
    while (write(sv[0], buf, sizeof(buf)) > 0)
        ;
    if (write(sv[1], "a", 1) != 1) {
        printf("peer send buffer full too\n");
        return 1;
    }

    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLONESHOT,
                             .data.fd = sv[0]};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) != 0) {
        printf("ADD failed errno=%d\n", errno);
        return 1;
    }

    struct epoll_event out[4];
    int n = epoll_wait(ep, out, 4, 1000);
    TEST("oneshot reports read only (write filter survives)");
    if (n == 1 && (out[0].events & EPOLLIN) && !(out[0].events & EPOLLOUT))
        PASS();
    else {
        char m[96];
        snprintf(m, sizeof(m), "n=%d events=0x%x", n,
                 n > 0 ? out[0].events : 0);
        FAIL(m);
    }

    TEST("DEL succeeds");
    if (epoll_ctl(ep, EPOLL_CTL_DEL, sv[0], NULL) == 0)
        PASS();
    else
        FAIL("DEL failed");

    while (read(sv[1], buf, sizeof(buf)) > 0)
        ;

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    n = epoll_wait(ep, out, 4, 300);
    long el = elapsed_ms(&t0);
    TEST("an emptied epoll is not woken by a leftover filter");
    if (n == 0 && el >= 250)
        PASS();
    else {
        char m[96];
        snprintf(m, sizeof(m), "n=%d after %ldms (expected 0 after ~300ms)", n,
                 el);
        FAIL(m);
    }

    SUMMARY("test-epoll-del-leak");
    return fails ? 1 : 0;
}
