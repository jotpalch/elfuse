/*
 * A synthetic listing that failed part-way is reported, not ended
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The union walk has two halves: the synthetic (primary) directory elfuse
 * materialized, and the backing directory the sysroot carries under the same
 * name. test-dir-backing-drain-error pins what the guest is told when the
 * second half cannot be delivered. This pins the first.
 *
 * readdir() reports end-of-stream and failure the same way -- NULL -- and only
 * errno separates them. The primary walk did not look: a readdir that failed
 * part-way was taken for exhaustion, so the walk moved on to the backing as if
 * the synthetic half were finished, dropped every synthetic name past the
 * failure, and returned the result with a success code and errno 0. The guest
 * saw a shorter directory, not a broken one -- which is the same silent
 * truncation the backing half was repaired for, re-made on the other side.
 *
 * The failure cannot be provoked from a guest -- the primary is a scratch tree
 * elfuse owns and readdir does not fail on it -- so ELFUSE_DIR_PRIMARY_READ_
 * FAULT drives it after a chosen number of entries, exactly as the drain's
 * fault hook does. Linux's shape is the one being matched: a call that has
 * written entries returns their count and the error arrives on the next call; a
 * call that has written nothing returns -1 with the errno; and the error is
 * sticky, because the stream has lost names it can no longer produce.
 *
 * Syscalls exercised: openat(56), getdents64(61), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* The union root: a /sys the USB layer synthesizes and the sysroot also has. */
#define UNION_DIR "/sys"

/* Planted in the sysroot's /sys and nowhere in the synthetic tree. Its arrival
 * is what "the walk went on to the backing" looks like from the guest.
 */
#define MARKER "elfuse-union-marker"

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

#define MAX_CALLS 256

typedef struct {
    int names;       /* names delivered before the walk stopped */
    bool saw_marker; /* a backing name reached the guest */
    long end_ret;    /* what the call that ended the walk returned */
    int end_errno;   /* and with what errno */
    bool sticky;     /* a further call answered the same way */
    bool malformed;
} walk_t;

/* Walk UNION_DIR to whatever end it reaches, then ask once more.
 *
 * The buffer is the size handed to the syscall, and every record is
 * bounds-checked before its name is read.
 */
static void walk(walk_t *w)
{
    char buf[4096];
    memset(w, 0, sizeof(*w));

    int fd = open(UNION_DIR, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        w->malformed = true;
        return;
    }

    long n = 0;
    for (int calls = 0; calls <= MAX_CALLS; calls++) {
        errno = 0;
        n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        const long header = (long) offsetof(linux_dirent64_t, d_name);
        for (long off = 0; off < n;) {
            if (n - off < header) {
                w->malformed = true;
                close(fd);
                return;
            }
            linux_dirent64_t *de = (linux_dirent64_t *) (buf + off);
            long reclen = de->d_reclen;
            if (reclen <= header || reclen > n - off) {
                w->malformed = true;
                close(fd);
                return;
            }
            if (!memchr(de->d_name, '\0', (size_t) (reclen - header))) {
                w->malformed = true;
                close(fd);
                return;
            }
            if (!strcmp(de->d_name, MARKER))
                w->saw_marker = true;
            w->names++;
            off += reclen;
        }
    }
    w->end_ret = n;
    w->end_errno = n < 0 ? errno : 0;

    /* Ask again. A stream that has lost names must keep saying so rather than
     * fall through to an end of directory the guest cannot tell from a real
     * one.
     */
    errno = 0;
    long again = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    w->sticky = again < 0 && errno == w->end_errno;
    close(fd);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s complete|fault\n", argv[0]);
        return 2;
    }
    bool fault = !strcmp(argv[1], "fault");

    printf(
        "test-dir-primary-read-error: a failed synthetic read is reported "
        "(%s)\n\n",
        argv[1]);

    walk_t w;
    walk(&w);
    if (w.malformed) {
        TEST("the walk ran on a well-formed stream");
        FAIL("the listing was malformed or the directory would not open");
        SUMMARY("test-dir-primary-read-error");
        return 1;
    }

    if (!fault) {
        /* The control. Without it, the assertions below would also hold for a
         * union that never worked.
         */
        TEST("an undisturbed union listing ends cleanly and is whole");
        if (w.end_ret != 0 || w.end_errno != 0) {
            fprintf(stderr, "  names=%d ret=%ld errno=%d\n", w.names, w.end_ret,
                    w.end_errno);
            FAIL("a complete union listing did not end cleanly");
        } else if (!w.saw_marker) {
            FAIL("the backing half never reached the guest");
        } else if (w.names < 4) {
            fprintf(stderr, "  names=%d\n", w.names);
            FAIL("the union listing was too short to be the whole thing");
        } else {
            PASS();
        }
        SUMMARY("test-dir-primary-read-error");
        return fails == 0 ? 0 : 1;
    }

    TEST("a failed synthetic read is not spelled as an end of directory");
    if (w.end_ret != -1) {
        fprintf(stderr, "  names=%d ret=%ld errno=%d marker=%d\n", w.names,
                w.end_ret, w.end_errno, (int) w.saw_marker);
        FAIL("the walk ended with success over a listing that lost names");
    } else if (w.end_errno != EIO) {
        fprintf(stderr, "  errno=%d\n", w.end_errno);
        FAIL("the walk reported an errno other than the one that happened");
    } else {
        PASS();
    }

    /* The specific harm: with the primary mistaken for exhausted, the walk went
     * on to the backing and handed its names over as if the synthetic half had
     * finished. The backing must not appear in a listing whose synthetic half
     * failed.
     */
    TEST("a failed synthetic read does not fall through to the backing");
    if (w.saw_marker) {
        FAIL("the backing was unioned in after the synthetic half failed");
    } else {
        PASS();
    }

    TEST("the failure outlives the call that hit it");
    if (!w.sticky) {
        FAIL("a later call on the same fd no longer reported the failure");
    } else {
        PASS();
    }

    SUMMARY("test-dir-primary-read-error");
    return fails == 0 ? 0 : 1;
}
