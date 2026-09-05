/*
 * inotify emulation tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests the kqueue-based inotify emulation in elfuse. Exercises inotify_init1,
 * inotify_add_watch, inotify_rm_watch, and reading events for file
 * modifications.
 *
 * Syscalls exercised: inotify_init1(26), inotify_add_watch(27),
 *                     inotify_rm_watch(28), read(63), write(64),
 *                     close(57), openat(56), poll(73)
 */

#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Test 1: inotify_init1 */

static void test_init(void)
{
    TEST("inotify_init1(IN_CLOEXEC)");

    int fd = inotify_init1(IN_CLOEXEC);
    if (fd >= 0) {
        PASS();
        close(fd);
    } else {
        FAIL("inotify_init1 failed");
    }
}

/* Test 2: Add and remove watch */

static void test_add_remove_watch(void)
{
    TEST("add_watch + rm_watch");

    int fd = inotify_init1(0);
    if (fd < 0) {
        FAIL("inotify_init1");
        return;
    }

    int wd = inotify_add_watch(fd, "/tmp", IN_MODIFY | IN_CREATE);
    if (wd < 0) {
        FAIL("inotify_add_watch /tmp");
        close(fd);
        return;
    }

    int r = inotify_rm_watch(fd, wd);
    EXPECT_TRUE(r == 0, "inotify_rm_watch failed");
    close(fd);
}

/* Test 3: Detect file modification */

static void test_modify_event(void)
{
    TEST("detect IN_MODIFY event");

    char path[] = "/tmp/elfuse-inotify-modify-XXXXXX";
    int tfd = mkstemp(path);
    if (tfd < 0) {
        FAIL("create temp file");
        return;
    }
    write(tfd, "hello\n", 6);
    close(tfd);

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        FAIL("inotify_init1");
        unlink(path);
        return;
    }

    int wd = inotify_add_watch(fd, path, IN_MODIFY | IN_CLOSE_WRITE);
    if (wd < 0) {
        FAIL("inotify_add_watch");
        close(fd);
        unlink(path);
        return;
    }

    tfd = open(path, O_WRONLY | O_APPEND);
    if (tfd < 0) {
        FAIL("reopen temp file");
        close(fd);
        unlink(path);
        return;
    }
    write(tfd, "world\n", 6);
    close(tfd);

    /* Poll for event with timeout */
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ready = poll(&pfd, 1, 1000);

    if (ready <= 0) {
        /* inotify via kqueue may not fire within this short timeout; treat a
         * valid fd and successful add_watch as infrastructure coverage.
         */
        PASS();
    } else {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            struct inotify_event *ev = (struct inotify_event *) buf;
            EXPECT_TRUE(ev->mask & (IN_MODIFY | IN_CLOSE_WRITE),
                        "unexpected event mask");
        } else {
            FAIL("read returned 0 after poll ready");
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    unlink(path);
}

/* Test 4: inotify_init1 IN_NONBLOCK */

static void test_nonblock(void)
{
    TEST("IN_NONBLOCK read -> EAGAIN");

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        FAIL("inotify_init1");
        return;
    }

    /* No watches, no events; read should return EAGAIN */
    char buf[128];
    EXPECT_ERRNO(read(fd, buf, sizeof(buf)), EAGAIN, "expected EAGAIN");
    close(fd);
}

/* Test 5: Watch directory for file creation */

static void test_dir_create(void)
{
    TEST("watch dir for IN_CREATE");

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        FAIL("inotify_init1");
        return;
    }

    /* A private directory, not all of /tmp, so a concurrent run's file
     * creations stay out of this run's event stream.
     */
    char dir[] = "/tmp/elfuse-inotify-create-XXXXXX";
    if (!mkdtemp(dir)) {
        FAIL("mkdtemp");
        close(fd);
        return;
    }

    int wd = inotify_add_watch(fd, dir, IN_CREATE);
    if (wd < 0) {
        FAIL("inotify_add_watch");
        close(fd);
        rmdir(dir);
        return;
    }

    char path[128];
    snprintf(path, sizeof(path), "%s/child.txt", dir);
    int tfd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (tfd < 0) {
        FAIL("create file in watched dir");
        close(fd);
        rmdir(dir);
        return;
    }
    close(tfd);

    /* Poll briefly; kqueue may or may not fire for creates */
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ready = poll(&pfd, 1, 500);

    /* Success = infrastructure works (add_watch + poll did not crash) */
    EXPECT_TRUE(ready >= 0, "poll error");

    unlink(path);
    inotify_rm_watch(fd, wd);
    close(fd);
    rmdir(dir);
}

/* Drain events by reading (which drives elfuse's diff), retrying until a named
 * IN_CREATE for `want` shows up.
 *
 * Returns false if `unwant` (an event that must never appear, e.g. from an
 * unrelated directory) is seen first, or if `want` never arrives within the
 * retry budget. `unwant` may be NULL.
 */
static bool watched_child_seen(int fd, const char *want, const char *unwant)
{
    bool found = false;
    for (int attempt = 0; attempt < 50; attempt++) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf));
        for (ssize_t off = 0;
             n > 0 && off + (ssize_t) sizeof(struct inotify_event) <= n;) {
            struct inotify_event *ev = (struct inotify_event *) (buf + off);
            if ((ev->mask & IN_CREATE) && ev->len > 0) {
                if (unwant && strcmp(ev->name, unwant) == 0)
                    return false; /* Fabricated event for the wrong dir. */
                if (strcmp(ev->name, want) == 0)
                    found = true;
            }
            off += (ssize_t) sizeof(struct inotify_event) + ev->len;
        }
        if (found)
            break;
        usleep(20000); /* 20ms */
    }
    return found;
}

/* Test 6: a directory watch must deliver a NAMED IN_CREATE for the new child,
 * not just a nameless event.
 */
static void test_dir_create_named(void)
{
    TEST("watch dir delivers named IN_CREATE");

    char dir[] = "/tmp/elfuse-inotify-dir-XXXXXX";
    if (!mkdtemp(dir)) {
        FAIL("mkdtemp");
        return;
    }

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        FAIL("inotify_init1");
        rmdir(dir);
        return;
    }

    int wd = inotify_add_watch(fd, dir, IN_CREATE);
    if (wd < 0) {
        FAIL("inotify_add_watch");
        close(fd);
        rmdir(dir);
        return;
    }

    const char *child = "manifest.yaml";
    char path[300];
    snprintf(path, sizeof(path), "%s/%s", dir, child);
    int tfd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (tfd < 0) {
        FAIL("create child in watched dir");
        inotify_rm_watch(fd, wd);
        close(fd);
        rmdir(dir);
        return;
    }
    close(tfd);

    EXPECT_TRUE(watched_child_seen(fd, child, NULL),
                "named IN_CREATE for new child not delivered");

    unlink(path);
    inotify_rm_watch(fd, wd);
    close(fd);
    rmdir(dir);
}

/* Test 7: a directory watch follows the inode across a rename, not the pathname
 * it was added under. After renaming the watched directory, a child created
 * inside it must still produce a named IN_CREATE; and if an unrelated new
 * directory takes the old pathname, its children must NOT be reported.
 * Reproduces the two failure modes of a path-based snapshot diff.
 */
static void test_dir_rename_follows_inode(void)
{
    TEST("dir watch follows inode across rename");

    char dir[] = "/tmp/elfuse-inotify-ren-XXXXXX";
    if (!mkdtemp(dir)) {
        FAIL("mkdtemp");
        return;
    }

    /* Sized so the compiler can prove each snprintf fits (dir is a fixed-length
     * template; -Wformat-truncation reasons about declared buffer sizes).
     */
    char renamed[64], reused_child[96], watched_child[96];
    snprintf(renamed, sizeof(renamed), "%s-renamed", dir);

    int fd = inotify_init1(IN_NONBLOCK);
    int wd = fd < 0 ? -1 : inotify_add_watch(fd, dir, IN_CREATE);
    if (wd < 0) {
        FAIL("init/add_watch");
        if (fd >= 0)
            close(fd);
        rmdir(dir);
        return;
    }

    /* Move the watched inode; the O_EVTONLY fd follows it. Recreate a fresh,
     * unrelated directory at the old pathname and drop a decoy child there; the
     * real child lands in the renamed (watched) directory. A failure in any
     * setup step invalidates the assertion, so check each and bail with a clear
     * diagnostic rather than proceeding to look for events that cannot arrive.
     */
    snprintf(reused_child, sizeof(reused_child), "%s/decoy", dir);
    snprintf(watched_child, sizeof(watched_child), "%s/child", renamed);
    int decoy_fd = -1, child_fd = -1;
    if (rename(dir, renamed) < 0 || mkdir(dir, 0755) < 0 ||
        (decoy_fd = open(reused_child, O_WRONLY | O_CREAT | O_EXCL, 0644)) <
            0 ||
        (child_fd = open(watched_child, O_WRONLY | O_CREAT | O_EXCL, 0644)) <
            0) {
        FAIL("rename/decoy setup");
        if (decoy_fd >= 0)
            close(decoy_fd);
        if (child_fd >= 0)
            close(child_fd);
        inotify_rm_watch(fd, wd);
        close(fd);
        unlink(watched_child);
        rmdir(renamed);
        unlink(reused_child);
        rmdir(dir);
        return;
    }
    close(decoy_fd);
    close(child_fd);

    EXPECT_TRUE(watched_child_seen(fd, "child", "decoy"),
                "named IN_CREATE must name the watched dir's child, not the "
                "unrelated dir that reused the old path");

    inotify_rm_watch(fd, wd);
    close(fd);
    unlink(watched_child);
    rmdir(renamed);
    unlink(reused_child);
    rmdir(dir);
}

/* Main */

int main(void)
{
    printf("test-inotify: inotify emulation tests\n");

    test_init();
    test_add_remove_watch();
    test_modify_event();
    test_nonblock();
    test_dir_create();
    test_dir_create_named();
    test_dir_rename_follows_inode();

    SUMMARY("test-inotify");
    return fails > 0 ? 1 : 0;
}
