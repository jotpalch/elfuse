/*
 * getdents64 directory-stream lifetime stress: close(fd) racing a sibling's
 * getdents64
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Companion to test-getdents64-overlong.c. That test drives sys_getdents64's
 * dirent-translation edge cases. This one pins a different invariant: a
 * directory fd's DIR* stream must survive a concurrent close()/dup2() while
 * sys_getdents64() is still mid-loop reading it (src/syscall/fs.c dir_stream_t
 * / dir_stream_acquire / dir_stream_release).
 *
 * fd_table[fd].dir is a bare pointer for FD_DIR entries. Before this fix,
 * sys_getdents64() read it with no lock and no pin, then looped
 * readdir()/telldir()/seekdir() on it; a sibling's close(fd) ran
 * fd_cleanup_entry() -> closedir() outside fd_lock and freed the stream out
 * from under the in-flight loop -- the exact same use-after-free class the
 * companion epoll fix (src/syscall/poll.c epoll_instance_acquire/_release)
 * addresses for FD_EPOLL. dir_stream_acquire()/_release() close the gap by
 * refcounting the wrapper instead of freeing it the instant the fd-table's own
 * reference goes away.
 *
 * This test hammers that window: a long-lived sibling spins raw getdents64() on
 * a directory fd the main thread keeps recreating, publishing, and retiring --
 * once via close(), once via dup2() overwriting the slot (the fd_alloc_at path,
 * which also funnels through fd_cleanup_entry). Racing close()/dup2() with
 * getdents64() on the same fd is guest-undefined, so the sibling's return value
 * is not asserted; the contract under test is that elfuse never faults or
 * double-frees. Survival across all iterations with a clean exit is the pass
 * condition.
 *
 * Raw syscalls in the sibling (a CLONE_THREAD child has no libc TLS).
 *
 * Syscalls exercised: clone(220), openat(56), getdents64(61), close(57),
 *                     dup3(24), nanosleep(101), futex(98), exit(93)
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* Shared with the clone sibling; atomic because both threads touch them. */
static _Atomic int shared_fd = -1;
static _Atomic int sibling_stop = 0;
static char sibling_stack[32768] __attribute__((aligned(16)));

/* Private to this run: a shared directory would have a concurrent run adding
 * entries to the one this test is scanning.
 */
static char stress_dir[64];
#define STRESS_FILE_COUNT 800

/* Populate a directory with enough entries that a single getdents64() call
 * cannot drain it in one host readdir() burst, widening the window a sibling
 * close()/dup2() has to land mid-loop.
 */
static int make_stress_dir(void)
{
    snprintf(stress_dir, sizeof(stress_dir), "/tmp/elfuse-getdents-XXXXXX");
    if (!mkdtemp(stress_dir))
        return -1;
    for (int i = 0; i < STRESS_FILE_COUNT; i++) {
        char path[128];
        snprintf(path, sizeof(path), "%s/f%d", stress_dir, i);
        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd < 0)
            return -1;
        close(fd);
    }
    return 0;
}

/* Spin raw getdents64() on whatever directory fd the main thread has published.
 * The fd may be closed (or reused) concurrently; a raw syscall just returns an
 * error, which is exactly the window the refcount must make memory-safe.
 */
static int sibling_fn(void *arg)
{
    (void) arg;
    static char buf[65536];
    while (!sibling_stop) {
        int fd = shared_fd;
        if (fd >= 0) {
            raw_syscall3(__NR_getdents64, (long) fd, (long) buf, sizeof(buf));
        } else {
            struct {
                long tv_sec, tv_nsec;
            } ts = {0, 5000}; /* 5us -- react fast to a freshly published fd */
            raw_syscall2(__NR_nanosleep, (long) &ts, 0);
        }
    }
    raw_syscall1(__NR_exit, 0);
    return 0;
}

int main(void)
{
    printf("test-getdents-refcount: close(fd)/dup2 vs concurrent getdents64\n");

    TEST("stress directory fixture");
    EXPECT_TRUE(make_stress_dir() == 0, "failed to create stress directory");

    long flags = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 |
                 0x00010000 | 0x00200000; /* CLONE_VM|FS|FILES|SIGHAND|THREAD|
                                             CHILD_CLEARTID
                                             */
    volatile uint32_t child_tid = 1;
    long ret = raw_syscall5(__NR_clone, flags,
                            (long) (sibling_stack + sizeof(sibling_stack)), 0,
                            0, (long) &child_tid);
    if (ret == 0) {
        sibling_fn(NULL);
        return 0; /* unreachable */
    }

    TEST("clone sibling reader");
    EXPECT_TRUE(ret > 0, "clone failed");

    const int iterations = 4000;
    int completed = 0;
    for (int i = 0; i < iterations; i++) {
        int fd = open(stress_dir, O_RDONLY | O_DIRECTORY);
        if (fd < 0)
            break;

        /* Publish to the sibling with no synchronization delay: getdents64
         * (unlike epoll_pwait) never blocks, so there is no multi-millisecond
         * window to sleep into -- racing as tightly as possible and repeating
         * thousands of times is what actually lands the close()/dup2() inside
         * an in-flight readdir() loop often enough to matter.
         */
        shared_fd = fd;

        if (i % 2 == 0) {
            /* Retract, then close under the sibling's in-flight getdents64.
             * Fires the close hook (fd_cleanup_entry -> dir_stream_release) on
             * the stream the sibling is still reading.
             */
            shared_fd = -1;
            close(fd);
        } else {
            /* dup2 a fresh directory fd over the same slot number: retires the
             * old open file description via fd_alloc_at -> fd_cleanup_entry
             * without a close() syscall on fd itself -- the second chokepoint
             * dir_stream_release() must also cover.
             */
            int replacement = open(stress_dir, O_RDONLY | O_DIRECTORY);
            if (replacement >= 0) {
                shared_fd = -1;
                dup3(replacement, fd, 0);
                close(replacement);
                close(fd);
            } else {
                shared_fd = -1;
                close(fd);
            }
        }
        completed++;
    }

    TEST("all iterations survived close/dup2 vs getdents64 race");
    EXPECT_EQ(completed, iterations, "did not complete every iteration");

    /* A fresh directory fd still reads correctly after the churn (no
     * leaked/corrupt state, refcount returned to a clean baseline).
     */
    TEST("getdents64 still functional after churn");
    {
        int fd = open(stress_dir, O_RDONLY | O_DIRECTORY);
        int seen = 0;
        bool ok = fd >= 0;
        if (ok) {
            char buf[512];
            for (;;) {
                long n = raw_syscall3(__NR_getdents64, (long) fd, (long) buf,
                                      sizeof(buf));
                if (n <= 0)
                    break;
                seen++;
                if (seen > 4 * STRESS_FILE_COUNT)
                    break; /* corrupt stream would loop forever; bail out */
            }
            close(fd);
        }
        EXPECT_TRUE(ok && seen > 0, "getdents64 broken after stress");
    }

    /* Release the sibling and join via the CLONE_CHILD_CLEARTID futex. */
    sibling_stop = 1;
    for (int i = 0; i < 200 && child_tid != 0; i++) {
        struct {
            long tv_sec, tv_nsec;
        } ts = {0, 10000000}; /* 10ms */
        raw_syscall6(__NR_futex, (long) &child_tid, 0 /* FUTEX_WAIT */,
                     child_tid, (long) &ts, 0, 0);
    }

    /* 800 entries plus the directory. */
    if (stress_dir[0]) {
        for (int i = 0; i < STRESS_FILE_COUNT; i++) {
            char path[128];
            snprintf(path, sizeof(path), "%s/f%d", stress_dir, i);
            unlink(path);
        }
        rmdir(stress_dir);
    }

    SUMMARY("test-getdents-refcount");
    return fails > 0 ? 1 : 0;
}
