/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>

#include "test-harness.h"

static int64_t timespec_ns(struct timespec value)
{
    if (value.tv_sec < 0 || value.tv_sec > INT64_MAX / 1000000000 ||
        value.tv_nsec < 0 || value.tv_nsec >= 1000000000)
        return -1;

    int64_t whole = value.tv_sec * 1000000000;
    if (value.tv_nsec > INT64_MAX - whole)
        return -1;
    return whole + value.tv_nsec;
}

int main(void)
{
    int passes = 0, fails = 0;
    const struct {
        const char *name;
        int clockid, flags;
        int64_t seconds, min_remaining_sec;
        bool interval, rearm;
    } cases[] = {
        {"relative nanosecond overflow", CLOCK_MONOTONIC, 0,
         INT64_MAX / 1000000000, 1000000000, false, false},
        {"relative microsecond overflow", CLOCK_MONOTONIC, 0,
         INT64_MAX / 1000000, 1000000000, false, false},
        {"relative maximum seconds", CLOCK_MONOTONIC, 0, INT64_MAX, 1000000000,
         false, false},
        {"interval nanosecond overflow", CLOCK_MONOTONIC, 0,
         INT64_MAX / 1000000000, 30, true, false},
        {"absolute monotonic overflow", CLOCK_MONOTONIC, TFD_TIMER_ABSTIME,
         INT64_MAX / 1000000000, 1000000000, false, false},
        {"absolute realtime overflow", CLOCK_REALTIME, TFD_TIMER_ABSTIME,
         INT64_MAX / 1000000000, 1000000000, false, false},
        {"large interval rearm", CLOCK_MONOTONIC, 0, INT64_MAX / 1000000000,
         1000000000, true, true},
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST(cases[i].name);
        int fd = timerfd_create(cases[i].clockid, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd < 0) {
            FAIL("timerfd_create");
            continue;
        }

        struct timespec large = {.tv_sec = cases[i].seconds,
                                 .tv_nsec = 999999999};
        struct itimerspec requested = {0};
        if (cases[i].interval) {
            if (cases[i].rearm)
                requested.it_value.tv_nsec = 20000000;
            else
                requested.it_value.tv_sec = 60;
            requested.it_interval = large;
        } else {
            requested.it_value = large;
        }
        int64_t before_ns = 0;
        if (cases[i].flags & TFD_TIMER_ABSTIME) {
            /* Bypass the vDSO so bounds use the timer backend's clock. */
            struct timespec before;
            if (syscall(SYS_clock_gettime, cases[i].clockid, &before) < 0 ||
                (before_ns = timespec_ns(before)) < 0) {
                FAIL("clock_gettime before settime");
                close(fd);
                continue;
            }
        }
        if (timerfd_settime(fd, cases[i].flags, &requested, NULL) < 0) {
            FAIL("timerfd_settime rejected a valid large timeout");
            close(fd);
            continue;
        }

        if (cases[i].rearm) {
            struct pollfd pfd = {.fd = fd, .events = POLLIN};
            if (poll(&pfd, 1, 5000) != 1 || !(pfd.revents & POLLIN)) {
                FAIL("first timer expiration not readable");
                close(fd);
                continue;
            }
            uint64_t expirations = 0;
            if (read(fd, &expirations, sizeof(expirations)) !=
                    (ssize_t) sizeof(expirations) ||
                expirations == 0) {
                FAIL("read first timer expiration");
                close(fd);
                continue;
            }
        }

        struct itimerspec current;
        if (timerfd_gettime(fd, &current) < 0) {
            FAIL("timerfd_gettime");
            close(fd);
            continue;
        }
        int64_t remaining_ns = timespec_ns(current.it_value);
        bool value_ok = remaining_ns >= 0 &&
                        current.it_value.tv_sec > cases[i].min_remaining_sec;
        if (cases[i].flags & TFD_TIMER_ABSTIME) {
            struct timespec after;
            if (syscall(SYS_clock_gettime, cases[i].clockid, &after) < 0) {
                FAIL("clock_gettime after gettime");
                close(fd);
                continue;
            }
            int64_t after_ns = timespec_ns(after);
            value_ok = value_ok && after_ns >= before_ns &&
                       remaining_ns >= INT64_MAX - after_ns &&
                       remaining_ns <= INT64_MAX - before_ns;
        }
        uint64_t count;
        errno = 0;
        ssize_t got = read(fd, &count, sizeof(count));
        int read_errno = errno;
        bool interval_ok =
            !cases[i].interval ||
            (current.it_interval.tv_sec == INT64_MAX / 1000000000 &&
             current.it_interval.tv_nsec == INT64_MAX % 1000000000);
        if (value_ok && interval_ok && got == -1 && read_errno == EAGAIN) {
            PASS();
        } else {
            FAIL("large timer returned an invalid remaining time or interval");
            printf("    remaining=%lld.%09ld interval=%lld.%09ld read=%ld\n",
                   (long long) current.it_value.tv_sec,
                   current.it_value.tv_nsec,
                   (long long) current.it_interval.tv_sec,
                   current.it_interval.tv_nsec, (long) got);
        }
        if (cases[i].rearm) {
            TEST("rearmed timer old value");
            struct itimerspec disarmed = {0}, old = {0};
            EXPECT_TRUE(timerfd_settime(fd, 0, &disarmed, &old) == 0 &&
                            timespec_ns(old.it_value) >= 0 &&
                            old.it_value.tv_sec > cases[i].min_remaining_sec &&
                            old.it_interval.tv_sec == INT64_MAX / 1000000000 &&
                            old.it_interval.tv_nsec == INT64_MAX % 1000000000,
                        "disarm returned invalid old timer state");
        }
        close(fd);
    }

    SUMMARY("test-timerfd-overflow");
    return fails > 0 ? 1 : 0;
}
