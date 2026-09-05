/*
 * A union directory fd must cost one host descriptor, the way a plain one does
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * test-dir-fd-budget asserts the invariant elfuse's host budget is sized on:
 * FD_TABLE_SIZE guest fds plus HOST_FD_RESERVE, one host descriptor per guest
 * fd (src/elfuse-limits.h). It measures that on a plain directory, which is why
 * it could not see the one directory shape that broke the invariant.
 *
 * A synthetic directory that extends its backing instead of replacing it -- a
 * /sys or /dev/bus name the USB layer does not own, see
 * usb_sysfs_dir_unions_backing -- lists two directories through one guest fd.
 * The first implementation held the backing open as a second stream for the
 * lifetime of the guest fd, so such a directory cost two host descriptors as
 * soon as anything read it to the end. Nothing caught it: the budget test never
 * opens a union directory, and a union directory that is opened but not read
 * never reaches the backing at all.
 *
 * The measurement here is therefore a difference, not an absolute: how many
 * union directory fds the guest can hold when it only opens them, against how
 * many it can hold when it also reads each one to the end. Driving the listing
 * is what makes the backing appear, so a descriptor charged for the backing
 * shows up as capacity lost between the two numbers and nowhere else. A plain
 * sysroot directory is measured the same way as the control: it has no backing
 * to union in, so its two numbers are what "costs nothing to read" looks like
 * on this host.
 *
 * Both absolute capacities are left to the runtime rather than written down.
 * The union root and a plain directory do not reach the same ceiling -- the
 * synthetic tree has its own costs at open time -- so a test that compared them
 * to each other, or to a constant, would be measuring the wrong difference.
 *
 * Runs with the host limit at exactly what elfuse asks for, so the extra
 * descriptor has nowhere to hide, against a sysroot that populates /sys (see
 * the lane in mk/tests.mk). MARKER is planted there and nowhere in the
 * synthetic tree, so its presence in the listing proves the union is live and
 * this lane is measuring something.
 *
 * Syscalls exercised: openat(56), getdents64(61), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* The union root: a /sys the USB layer synthesizes and the sysroot also has. */
#define UNION_DIR "/sys"

/* A sysroot directory under /sys with nothing synthetic in it. Reading it is
 * the plain-directory control.
 */
#define PLAIN_DIR "/sys/class/net"

/* Planted in the sysroot's /sys by the lane, absent from the synthetic tree. */
#define MARKER "elfuse-union-marker"

/* Descriptors already spoken for -- stdio, whatever the harness holds -- plus
 * room for run-to-run jitter in where the ceiling lands. It cannot hide the
 * defect this test exists to catch: a second descriptor per handle costs a
 * fraction of the whole capacity (nearly a third, measured), not a fixed few.
 */
#define SLACK 24

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

/* A stream that never reports its end would spin this walk forever and reach
 * the driver as a timeout rather than as a failure.
 */
#define MAX_ENTRIES 4096

/* Read fd's whole listing through raw getdents64.
 *
 * Returns false on an unreadable or malformed stream; sets *saw_marker when
 * MARKER was listed.
 *
 * Spends no second descriptor of its own -- these walks run while the guest fd
 * table is deep into the budget being measured, and an fdopendir() here would
 * fail with EMFILE for reasons that have nothing to do with what is under test.
 *
 * Every record is bounds-checked before any of it is read: reading a name that
 * does not terminate inside its own record would run strcmp off the end of buf.
 */
static bool drain_dir(int fd, bool *saw_marker)
{
    char buf[4096];
    int seen = 0;
    for (;;) {
        long n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (n < 0)
            return false;
        if (n == 0)
            return true;
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
            if (saw_marker && !strcmp(de->d_name, MARKER))
                *saw_marker = true;
            if (++seen > MAX_ENTRIES)
                return false;
            off += reclen;
        }
    }
}

static int *fds;
static int slots;

/* How many fds on @path the guest can hold at once. With @drive, each one is
 * also read to its end before the next is opened, which is what pulls a union
 * directory's backing into the picture.
 *
 * Returns -1 when a listing came back broken; a capacity of zero is reported as
 * zero and left for the caller to judge.
 */
static int capacity(const char *path, bool drive, bool *saw_marker)
{
    int held = 0;
    bool ok = true;

    for (; held < slots; held++) {
        fds[held] = open(path, O_RDONLY | O_DIRECTORY);
        if (fds[held] < 0)
            break;
        if (drive && !drain_dir(fds[held], saw_marker)) {
            ok = false;
            held++;
            break;
        }
    }

    for (int i = 0; i < held; i++)
        close(fds[i]);
    return ok ? held : -1;
}

int main(void)
{
    printf(
        "test-dir-fd-budget-union: a union directory costs one "
        "host descriptor\n\n");

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        fprintf(stderr, "getrlimit: %s\n", strerror(errno));
        return 2;
    }
    int limit = rl.rlim_cur > INT_MAX ? INT_MAX : (int) rl.rlim_cur;
    if (limit <= SLACK * 4) {
        fprintf(stderr,
                "guest RLIMIT_NOFILE is %d, too low to measure a "
                "descriptor budget\n",
                limit);
        return 2;
    }

    slots = limit + SLACK;
    fds = calloc((size_t) slots, sizeof(*fds));
    if (!fds) {
        fprintf(stderr, "out of memory sizing the fd array\n");
        return 2;
    }

    bool saw_marker = false;
    int union_open = capacity(UNION_DIR, false, NULL);
    int union_read = capacity(UNION_DIR, true, &saw_marker);
    int plain_open = capacity(PLAIN_DIR, false, NULL);
    int plain_read = capacity(PLAIN_DIR, true, NULL);

    printf("  RLIMIT_NOFILE %d\n", limit);
    printf("  %-16s open-only %5d   open+read %5d\n", UNION_DIR, union_open,
           union_read);
    printf("  %-16s open-only %5d   open+read %5d\n\n", PLAIN_DIR, plain_open,
           plain_read);

    /* Without this the rest of the lane would pass on a host where the union
     * never happens, and say nothing while doing it.
     */
    TEST("the union is live in this lane");
    EXPECT_TRUE(saw_marker,
                "the sysroot's " MARKER " is missing from " UNION_DIR
                ", so nothing here measured a union");

    TEST("a plain directory reads for free");
    EXPECT_TRUE(plain_open > SLACK && plain_read >= plain_open - SLACK,
                "reading a plain directory cost capacity, so the "
                "measurement itself is unsound");

    TEST("a union directory reads for free");
    if (union_open <= SLACK) {
        FAIL("too few union directory fds to measure");
    } else {
        EXPECT_TRUE(union_read >= union_open - SLACK,
                    "reading union directories cost host descriptors: "
                    "the backing stream is being held across the "
                    "getdents64 return");
    }

    free(fds);
    SUMMARY("test-dir-fd-budget-union");
    return fails ? 1 : 0;
}
