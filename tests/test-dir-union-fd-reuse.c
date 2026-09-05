/*
 * A union walk answers for the directory it pinned, not for the fd number
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * getdents64 pins the directory stream for the length of the call, so a sibling
 * thread's close() -- or a close() and reopen that lands on the same number --
 * cannot free it underneath the walk. The stream survived that; the
 * descriptor's *identity* did not. The backing half of a union listing was
 * looked up by re-reading fd_table[fd] part-way through the call, which is a
 * different question from the one the pin answered: by then the number could
 * name nothing at all, or a different file.
 *
 * Both outcomes were silent. With the number closed, the backing lookup found
 * no stamped path, contributed nothing, and the walk ended -- handing back the
 * synthetic entries alone, with a success return and errno 0, which the guest
 * reads as a complete listing. With the number reused, the walk would have
 * drained some other directory's names into this one.
 *
 * The window is real and far too narrow to reach unaided (measured: no
 * cross-listing in 353k walks with two threads hammering close and dup2 on the
 * walked fd), so the lane widens it with ELFUSE_DIR_UNION_BACKING_DELAY_US and
 * closes the fd inside it. What is asserted is not the timing but the answer:
 * the walk must deliver the whole union -- synthetic names and the backing's
 * MARKER alike -- or say it could not. A short listing reported as success is
 * the one result that must never appear.
 *
 * Syscalls exercised: openat(56), getdents64(61), close(57), clone(220)
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* The union root: a /sys the USB layer synthesizes and the sysroot also has. */
#define UNION_DIR "/sys"

/* Planted in the sysroot's /sys by the lane, absent from the synthetic tree, so
 * its presence proves the backing half of the union was delivered.
 */
#define MARKER "elfuse-union-marker"

/* Synthesized by the USB layer and absent from the sysroot: the other half. */
#define SYNTH "bus"

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

/* A stream that never reports its end would spin this walk forever. */
#define MAX_CALLS 256

typedef struct {
    int fd;
    int delay_us;
    bool reopen;
} disturb_t;

/* Close the walked fd from under the walk, once the walk is inside the widened
 * drain window. With `reopen`, claim the freed number with a different
 * directory as well, which is the other half of the same defect.
 */
static void *disturb(void *arg)
{
    disturb_t *d = arg;
    usleep((useconds_t) (d->delay_us / 2));
    close(d->fd);
    if (d->reopen) {
        int other = open("/", O_RDONLY | O_DIRECTORY);
        if (other >= 0 && other != d->fd) {
            dup2(other, d->fd);
            close(other);
        }
    }
    return NULL;
}

/* Walk @fd to the end, recording what was seen and how it ended.
 *
 * The buffer is the size passed to the syscall, so a full call cannot write
 * past it. Every record is bounds-checked before its name is read.
 */
static bool walk(int fd,
                 bool *saw_marker,
                 bool *saw_synth,
                 long *end_ret,
                 int *end_errno)
{
    char buf[4096];
    int calls = 0;
    long n;
    *saw_marker = *saw_synth = false;
    for (;;) {
        if (++calls > MAX_CALLS)
            return false;
        errno = 0;
        n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        const long header = (long) offsetof(linux_dirent64_t, d_name);
        for (long off = 0; off < n;) {
            if (n - off < header)
                return false;
            linux_dirent64_t *de = (linux_dirent64_t *) (buf + off);
            long reclen = de->d_reclen;
            if (reclen <= header || reclen > n - off)
                return false;
            if (!memchr(de->d_name, '\0', (size_t) (reclen - header)))
                return false;
            if (!strcmp(de->d_name, MARKER))
                *saw_marker = true;
            if (!strcmp(de->d_name, SYNTH))
                *saw_synth = true;
            off += reclen;
        }
    }
    *end_ret = n;
    *end_errno = n < 0 ? errno : 0;
    return true;
}

static void one_case(const char *what, bool reopen, int delay_us)
{
    TEST(what);
    int fd = open(UNION_DIR, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        FAIL("could not open the union directory");
        return;
    }

    disturb_t d = {.fd = fd, .delay_us = delay_us, .reopen = reopen};
    pthread_t th;
    if (pthread_create(&th, NULL, disturb, &d) != 0) {
        close(fd);
        FAIL("could not start the disturbing thread");
        return;
    }

    bool saw_marker, saw_synth;
    long rc = 0;
    int err = 0;
    bool ok = walk(fd, &saw_marker, &saw_synth, &rc, &err);
    pthread_join(th, NULL);

    if (!ok) {
        FAIL("the walk did not terminate on a well-formed stream");
        return;
    }

    /* Two answers are allowed, and only two. Either the walk delivered the
     * whole union -- it pinned the directory before the number went away, so
     * this is what the fixed path does -- or it reported a failure. What must
     * never happen is a clean end of directory over a listing that lost a half.
     */
    if (rc < 0) {
        PASS();
        return;
    }
    if (saw_marker && saw_synth) {
        PASS();
        return;
    }
    fprintf(stderr, "  rc=%ld errno=%d marker=%d synthetic=%d\n", rc, err,
            (int) saw_marker, (int) saw_synth);
    FAIL("a listing that lost a half was reported as a clean end of directory");
}

int main(void)
{
    const char *env = getenv("ELFUSE_DIR_UNION_BACKING_DELAY_US");
    int delay_us = env ? atoi(env) : 0;
    if (delay_us <= 0) {
        fprintf(
            stderr,
            "ELFUSE_DIR_UNION_BACKING_DELAY_US must be set for this lane\n");
        return 2;
    }

    printf(
        "test-dir-union-fd-reuse: a union walk answers for what it pinned\n\n");

    /* A control first: undisturbed, the same walk must deliver both halves, or
     * the two cases below would pass on a listing that was never whole.
     */
    TEST("an undisturbed union walk delivers both halves");
    int fd = open(UNION_DIR, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        FAIL("could not open the union directory");
    } else {
        bool saw_marker, saw_synth;
        long rc = 0;
        int err = 0;
        bool ok = walk(fd, &saw_marker, &saw_synth, &rc, &err);
        close(fd);
        if (!ok || rc != 0 || !saw_marker || !saw_synth) {
            fprintf(stderr, "  rc=%ld errno=%d marker=%d synthetic=%d\n", rc,
                    err, (int) saw_marker, (int) saw_synth);
            FAIL("the control listing was not whole");
        } else {
            PASS();
        }
    }

    one_case("a close during the drain does not shorten the listing", false,
             delay_us);
    one_case("a close and reuse during the drain does not divert the listing",
             true, delay_us);

    SUMMARY("test-dir-union-fd-reuse");
    return fails == 0 ? 0 : 1;
}
