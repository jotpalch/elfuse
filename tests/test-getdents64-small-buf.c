/*
 * A getdents64 buffer too small for one entry reports, it does not end
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: sys_getdents64 in src/syscall/fs.c.
 *
 * A dirent64 record is a 19-byte header plus the name and its NUL, rounded up,
 * so a 24-byte buffer holds a name of four bytes and nothing longer. Asked for
 * a listing in a buffer that cannot hold its next name, sys_getdents64 used to
 * break out of the walk with nothing written and return 0. The guest reads 0 as
 * the end of the directory, so every name too long for the buffer disappeared
 * with nothing said, and no larger call was ever made because the stream looked
 * finished.
 *
 * Linux answers that call with EINVAL. Measured in docker (gcc:13, Linux 6.19
 * aarch64) over a directory holding one twelve-byte name and one two-byte name:
 * getdents64 with a 24-byte buffer returns the short name and then -1 EINVAL,
 * and buffers of 8 and 16 return -1 EINVAL immediately, while a buffer large
 * enough for the longest name delivers the whole listing.
 *
 * The two halves of the shape are both pinned here: a call that has already
 * written entries returns their count and leaves the error for the next call,
 * and a call that writes nothing returns -1 with the errno.
 *
 * The buffer that stops the walk part-way is pinned here too. A guest buffer
 * whose tail is unmapped takes the entries that fit and faults on the next one,
 * and the entry that could not be written has already been read off the host
 * stream. Linux delivers it on the following call; elfuse used to leave it
 * behind, so the guest saw a listing one name short that ended at 0 -- the
 * silent truncation this file's other cases exist to close, reached through the
 * one exit from the walk that never rewound.
 *
 * The fixture directory is passed as argv[1] by the lane in mk/tests.mk.
 *
 * Syscalls exercised: openat(56), getdents64(61), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_getdents64
#define SYS_getdents64 61
#endif

int passes = 0, fails = 0;

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

/* The lane plants exactly these two names beside "." and ".." */
#define LONG_NAME "aaaaaaaaaaaa" /* 12 bytes: needs 32, not 24 */
#define SHORT_NAME "bb"          /* 2 bytes: fits 24 */

/* A stream that never reports its end would spin this walk forever. */
#define MAX_CALLS 256

/* The walk buffer is the largest request any caller below makes, and the walk
 * refuses anything larger. getdents64 writes up to the size it is given, so a
 * buffer smaller than that size is a buffer the guest kernel is invited to
 * overrun -- which stayed invisible only because the fixture was small enough
 * that no call ever filled it. The wide fixture makes it visible.
 */
#define WALK_BUF_MAX 4096


/* Names delivered by a walk, so two walks can be compared by name rather than
 * by count: an entry dropped at a fault and an entry never reached both lower
 * the count, and only the names say which happened.
 */
#define NAME_CAP 64
#define NAMES_MAX 256

typedef struct {
    char name[NAMES_MAX][NAME_CAP];
    int count;
    int overflow;
} names_t;

static void names_add(names_t *ns, const char *name)
{
    if (ns->count >= NAMES_MAX) {
        ns->overflow = 1;
        return;
    }
    snprintf(ns->name[ns->count++], NAME_CAP, "%s", name);
}

static int names_has(const names_t *ns, const char *name)
{
    for (int i = 0; i < ns->count; i++)
        if (!strcmp(ns->name[i], name))
            return 1;
    return 0;
}

/* Collect one getdents64 result into @ns. */
static void names_collect(names_t *ns, const char *buf, long rc)
{
    for (long off = 0; off < rc;) {
        const linux_dirent64_t *de = (const linux_dirent64_t *) (buf + off);
        names_add(ns, de->d_name);
        off += de->d_reclen;
    }
}

/* Walk @dir with @bufsz-byte calls.
 *
 * Returns the number of names delivered, and writes how the walk ended into
 * *@end_ret / *@end_errno.
 */
static int walk(const char *dir,
                size_t bufsz,
                long *end_ret,
                int *end_errno,
                int *saw_long)
{
    char buf[WALK_BUF_MAX];

    /* Never hand the syscall a length this buffer cannot absorb. */
    if (bufsz > sizeof(buf)) {
        *end_ret = -1;
        *end_errno = 0;
        return -1;
    }

    int fd = (int) syscall(SYS_openat, -100, dir, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        *end_ret = -1;
        *end_errno = errno;
        return -1;
    }

    int names = 0, calls = 0;
    long rc;
    *saw_long = 0;
    for (;;) {
        if (++calls > MAX_CALLS) {
            close(fd);
            *end_ret = -1;
            *end_errno = 0;
            return -1;
        }
        errno = 0;
        rc = syscall(SYS_getdents64, fd, buf, bufsz);
        if (rc <= 0)
            break;
        for (long off = 0; off < rc;) {
            linux_dirent64_t *de = (linux_dirent64_t *) (buf + off);
            names++;
            if (!strcmp(de->d_name, LONG_NAME))
                *saw_long = 1;
            off += de->d_reclen;
        }
    }
    *end_ret = rc;
    *end_errno = rc < 0 ? errno : 0;
    close(fd);
    return names;
}


/* Read @dir into @ns through a buffer whose tail is not mapped.
 *
 * Two pages are mapped and the second one dropped, so the buffer handed to the
 * kernel starts @gap bytes before a hole. The call writes the entries that fit
 * and faults on the first one that crosses; the rest of the listing is then
 * read through a buffer that is entirely mapped, which is what a guest does
 * after a short return. What must survive is the entry the faulting call read
 * off the host stream and could not place.
 *
 * Returns 0, or -1 when the fixture could not be set up.
 */
static int walk_faulting(const char *dir, size_t gap, names_t *ns)
{
    long pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0 || gap >= (size_t) pagesz)
        return -1;

    char *m = mmap(NULL, (size_t) pagesz * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
        return -1;
    if (munmap(m + pagesz, (size_t) pagesz) < 0) {
        munmap(m, (size_t) pagesz * 2);
        return -1;
    }
    char *buf = m + pagesz - gap;

    int fd = (int) syscall(SYS_openat, -100, dir, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        munmap(m, (size_t) pagesz);
        return -1;
    }

    errno = 0;
    long rc = syscall(SYS_getdents64, fd, buf, (size_t) pagesz);
    if (rc > 0)
        names_collect(ns, buf, rc);
    munmap(m, (size_t) pagesz);

    /* Whatever the faulting call answered, the guest reads on. */
    if (rc > 0) {
        char safe[WALK_BUF_MAX];
        int calls = 0;
        for (;;) {
            if (++calls > MAX_CALLS)
                break;
            errno = 0;
            rc = syscall(SYS_getdents64, fd, safe, sizeof(safe));
            if (rc <= 0)
                break;
            names_collect(ns, safe, rc);
        }
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <fixture-dir> <wide-dir> <wide-names>\n",
                argv[0]);
        return 2;
    }
    const char *dir = argv[1];

    /* A second fixture, wide enough that one full-size call writes more than a
     * few hundred bytes. The narrow fixture cannot serve here: it is sized so
     * that exactly one of its names fails to fit a 24-byte record, and adding
     * names to it would put that one name at a host-chosen position in the
     * listing and make the 24-byte count below depend on enumeration order.
     */
    const char *wide_dir = argv[2];
    const int wide_names = atoi(argv[3]);
    long rc;
    int err, names, saw_long;

    /* A buffer smaller than any record: the very first call writes nothing. */
    for (size_t bufsz = 8; bufsz <= 16; bufsz += 8) {
        TEST("a buffer too small for any entry reports EINVAL");
        names = walk(dir, bufsz, &rc, &err, &saw_long);
        if (names != 0 || rc != -1 || err != EINVAL) {
            fprintf(stderr, "  bufsz=%zu names=%d ret=%ld errno=%d\n", bufsz,
                    names, rc, err);
            FAIL("did not report EINVAL on an entry-sized-buffer failure");
        } else {
            PASS();
        }
    }

    /* 24 bytes holds ".", "..", "bb" and not LONG_NAME. The calls that wrote
     * those entries returned their counts; the call that can write nothing
     * reports.
     */
    TEST("a listing cut short by the buffer reports rather than ending");
    names = walk(dir, 24, &rc, &err, &saw_long);
    if (rc != -1 || err != EINVAL) {
        fprintf(stderr, "  names=%d ret=%ld errno=%d saw_long=%d\n", names, rc,
                err, saw_long);
        FAIL("truncated listing ended cleanly instead of reporting");
    } else if (saw_long) {
        FAIL("the long name fitted a 24-byte buffer; fixture is wrong");
    } else if (names < 3) {
        fprintf(stderr, "  names=%d\n", names);
        FAIL("the entries that did fit were not delivered before the error");
    } else {
        PASS();
    }

    /* The other half of the shape: room for the longest name, whole listing. */
    TEST("a buffer that fits every entry delivers the whole listing");
    names = walk(dir, WALK_BUF_MAX, &rc, &err, &saw_long);
    if (rc != 0 || err != 0) {
        fprintf(stderr, "  names=%d ret=%ld errno=%d\n", names, rc, err);
        FAIL("a listing that fits did not end cleanly");
    } else if (!saw_long) {
        FAIL("the long name is missing from a listing with room for it");
    } else if (names != 4) {
        fprintf(stderr, "  names=%d\n", names);
        FAIL("unexpected visible entry count");
    } else {
        PASS();
    }

    /* A full-size call over a directory whose listing needs more than a few
     * hundred bytes. The count is order-independent -- every name is delivered
     * whatever order the host enumerates them in -- and what it pins is that
     * the walk survives writing a full buffer at all.
     */
    TEST("a full-size call absorbs a listing that fills its buffer");
    names = walk(wide_dir, WALK_BUF_MAX, &rc, &err, &saw_long);
    if (rc != 0 || err != 0) {
        fprintf(stderr, "  names=%d ret=%ld errno=%d\n", names, rc, err);
        FAIL("a wide listing did not end cleanly");
    } else if (names != wide_names + 2) {
        fprintf(stderr, "  names=%d want=%d\n", names, wide_names + 2);
        FAIL("the wide listing lost or gained entries");
    } else {
        PASS();
    }


    /* A buffer that faults part-way. The entry the call could not place was
     * already taken off the host stream, so unless the walk rewinds, the next
     * call resumes past it and the name is gone from a listing that still ends
     * at 0. The gap is swept because where the hole falls decides which entry
     * is the one that cannot be written, and a single gap could land on "."
     * where the loss is easy to miss.
     */
    for (size_t gap = 120; gap <= 700; gap += 290) {
        TEST("an entry a faulting buffer could not take is delivered later");
        names_t whole = {0}, faulted = {0};
        int fd = (int) syscall(SYS_openat, -100, wide_dir,
                               O_RDONLY | O_DIRECTORY, 0);
        if (fd < 0) {
            FAIL("could not open the wide fixture");
            continue;
        }
        char big[WALK_BUF_MAX];
        long r;
        while ((r = syscall(SYS_getdents64, fd, big, sizeof(big))) > 0)
            names_collect(&whole, big, r);
        close(fd);

        if (walk_faulting(wide_dir, gap, &faulted) < 0) {
            FAIL("could not stage a buffer that ends in an unmapped page");
            continue;
        }
        if (whole.overflow || faulted.overflow) {
            FAIL("the fixture holds more names than the lane can record");
            continue;
        }
        const char *lost = NULL;
        for (int i = 0; i < whole.count; i++) {
            if (!names_has(&faulted, whole.name[i])) {
                lost = whole.name[i];
                break;
            }
        }
        if (whole.count != wide_names + 2) {
            fprintf(stderr, "  reference names=%d want=%d\n", whole.count,
                    wide_names + 2);
            FAIL("the reference listing is not the whole fixture");
        } else if (lost) {
            fprintf(stderr, "  gap=%zu delivered %d of %d, first missing %s\n",
                    gap, faulted.count, whole.count, lost);
            FAIL("the entry the faulting call could not write was dropped");
        } else {
            PASS();
        }
    }

    SUMMARY("test-getdents64-small-buf");
    return fails == 0 ? 0 : 1;
}
