/*
 * A union listing that loses names must say so, never end quietly
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: dir_backing_drain and sys_getdents64 in src/syscall/fs.c.
 *
 * A synthetic /sys that extends its backing drains the backing's names into the
 * stream when the primary runs out (see usb_sysfs_dir_unions_backing). If that
 * drain cannot deliver the whole listing -- an allocation that fails, a readdir
 * that errors, a backing that exists but cannot be opened -- the guest must be
 * told. The one outcome that is not acceptable is a listing that comes back
 * short with errno 0, because the guest cannot tell it from a complete one and
 * there is nothing it can do about what it never saw.
 *
 * The first drain implementation produced exactly that. It reported the error
 * only from the call that hit it, and that call had usually already written
 * entries, so it returned their count instead; the recorded errno was never
 * read again, and the next call found the backing side empty and returned 0.
 * Measured before the fix, with the drain failed after two names against a
 * six-name backing: 3 of 9 names and errno 0, at every buffer size from 24
 * bytes to 32KiB. Never an error.
 *
 * The failure is driven rather than waited for. A real ENOMEM from malloc is
 * not something a test can arrange on demand, so ELFUSE_DIR_BACKING_FAULT makes
 * the drain fail after a set number of names; the lane in mk/tests.mk sets it.
 * The unreadable-backing mode needs no hook: the lane chmods the sysroot's /sys
 * to 000 and the drain's open fails for real.
 *
 * Modes, one per lane invocation:
 *   complete    no fault: the whole union listing arrives and ends at EOF.
 *   fault       the drain fails part-way: every walk must end in an error.
 *   unreadable  the backing cannot be opened: the walk must end in an error.
 *
 * Syscalls exercised: openat(56), getdents64(61), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* The union root: a /sys the USB layer synthesizes and the sysroot also has. */
#define UNION_DIR "/sys"

/* Planted in the sysroot's /sys by the lane, absent from the synthetic tree.
 * Seeing it is what proves the union is live and this test is measuring
 * something; the "complete" mode refuses to pass without it.
 */
#define MARKER "elfuse-union-marker"

/* Buffer sizes the walk is repeated at. The defect was invisible to a size
 * sweep -- it reported the same wrong answer at every one of these -- so the
 * sweep is here to show the fix is not a single-size accident. 24 is one dirent
 * record; 32768 takes the whole listing in one call.
 */
static const size_t kBufSizes[] = {24, 32, 48, 72, 96, 4096, 32768};
#define NBUFSIZES (sizeof(kBufSizes) / sizeof(kBufSizes[0]))

/* A stream that never reports its end would spin this walk forever and reach
 * the driver as a timeout rather than as a failure.
 */
#define MAX_CALLS 512

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

typedef struct {
    int names;     /* names handed to the guest before the walk ended */
    int end_errno; /* errno the walk ended with; 0 means it ended at EOF */
    bool saw_marker;
    bool runaway;
} walk_t;

/* Walk UNION_DIR to its end with a @bufsz-byte buffer, reporting how it ended.
 */
static walk_t walk_union(size_t bufsz)
{
    walk_t w = {0};
    char buf[32768];

    int fd = open(UNION_DIR, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        w.end_errno = errno;
        return w;
    }

    for (int call = 0; call < MAX_CALLS; call++) {
        errno = 0;
        long rc = syscall(SYS_getdents64, fd, buf, bufsz);
        if (rc < 0) {
            w.end_errno = errno ? errno : EIO;
            close(fd);
            return w;
        }
        if (rc == 0) { /* clean end of directory */
            close(fd);
            return w;
        }
        for (long off = 0; off < rc;) {
            linux_dirent64_t *de = (linux_dirent64_t *) (buf + off);
            if (!strcmp(de->d_name, MARKER))
                w.saw_marker = true;
            w.names++;
            off += de->d_reclen;
        }
    }

    w.runaway = true;
    close(fd);
    return w;
}

/* The longest name the fixture stages is MARKER, whose dirent record is 40
 * bytes. A buffer under that cannot carry it however the walk behaves, so the
 * completeness assertions below start at the first sweep size that can. What
 * elfuse does with a buffer too small for the next record is a separate
 * question about getdents64 itself, not about the union drain, and it is the
 * same on a plain directory: measured here, the walk ends at EOF, where Linux
 * (docker, gcc:13, Linux 6.10 aarch64) returns EINVAL. Untouched by this change
 * and not asserted either way.
 */
#define COMPLETE_MIN_BUFSIZE 48

/* The whole listing arrives, ends at EOF, and carries the sysroot's marker. */
static void mode_complete(void)
{
    int full = -1;

    for (size_t i = 0; i < NBUFSIZES; i++) {
        if (kBufSizes[i] < COMPLETE_MIN_BUFSIZE)
            continue;

        char label[64];
        snprintf(label, sizeof(label), "complete listing at %zu bytes",
                 kBufSizes[i]);
        TEST(label);

        walk_t w = walk_union(kBufSizes[i]);
        if (w.runaway) {
            FAIL("walk never ended");
            continue;
        }
        if (w.end_errno) {
            errno = w.end_errno;
            FAIL("walk failed with no fault injected");
            continue;
        }
        if (!w.saw_marker) {
            /* Without the marker the sysroot is not backing /sys here and every
             * other assertion in this file would be vacuous.
             */
            FAIL("sysroot marker missing: the union is not live");
            continue;
        }

        /* Every size that can carry the listing must agree with every other on
         * how many names it carried.
         */
        if (full < 0)
            full = w.names;
        else if (w.names != full) {
            fprintf(stderr, "  %d names here, %d at the previous size\n",
                    w.names, full);
            FAIL("buffer size changed the number of names");
            continue;
        }
        PASS();
    }
}

/* A drain that failed part-way is reported, at every buffer size, and is never
 * allowed to look like the end of the directory.
 *
 * EINVAL is the one other answer a size may legitimately give. A buffer too
 * small to hold one record of the directory's own names ends the walk there,
 * before the primary is exhausted and so before the drain runs at all, and
 * Linux answers that with EINVAL (tests/test-getdents64-small-buf). The
 * synthetic tree's widest name decides which sizes that covers, so it is a
 * property of the build under test rather than of this fixture, and the sizes
 * it swallows are counted rather than asserted on. What is asserted at every
 * size regardless is the thing this lane exists for: the walk never ends at
 * EOF. And at least one size must reach the drain, or the lane has measured
 * nothing.
 */
static void mode_error(const char *what, int want_errno)
{
    int reached_drain = 0;

    for (size_t i = 0; i < NBUFSIZES; i++) {
        char label[64];
        snprintf(label, sizeof(label), "%s reported at %zu bytes", what,
                 kBufSizes[i]);
        TEST(label);

        walk_t w = walk_union(kBufSizes[i]);
        if (w.runaway) {
            FAIL("walk never ended");
        } else if (w.end_errno == 0) {
            /* The defect, exactly: a short listing that ends at EOF. */
            fprintf(stderr, "  walk ended at EOF after %d names\n", w.names);
            FAIL("truncated listing ended cleanly instead of reporting");
        } else if (w.end_errno == EINVAL && want_errno != EINVAL) {
            fprintf(stderr,
                    "  buffer too small for this tree's own names; the walk "
                    "reported EINVAL before reaching the drain\n");
            PASS();
        } else if (w.end_errno != want_errno) {
            errno = w.end_errno;
            FAIL("walk reported the wrong errno");
        } else {
            reached_drain++;
            PASS();
        }
    }

    TEST("some buffer size actually reached the drain");
    if (!reached_drain)
        FAIL("every size stopped short of the drain; nothing was measured");
    else
        PASS();
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";

    printf("test-dir-backing-drain-error: a lost union listing is reported\n");

    if (!strcmp(mode, "complete")) {
        mode_complete();
    } else if (!strcmp(mode, "fault")) {
        mode_error("drain failure", ENOMEM);
    } else if (!strcmp(mode, "unreadable")) {
        mode_error("unreadable backing", EACCES);
    } else {
        TEST("mode argument");
        FAIL("expected one of: complete, fault, unreadable");
    }

    SUMMARY("test-dir-backing-drain-error");
    return fails == 0 ? 0 : 1;
}
