/*
 * fstatfs answers for the descriptor it pinned, not for the fd number
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: sys_fstatfs in src/syscall/fs-stat.c.
 *
 * A descriptor's filesystem identity is decided from two things: the virtual
 * path stamped on its slot when this layer served the open, and, when there is
 * no stamp, the host path the descriptor itself resolves to. Those used to be
 * two separate lookups of the same guest fd -- fd_snapshot for the stamp, then
 * host_fd_ref_open for the descriptor -- so a close and reopen in between gave
 * the stamp of one open file description and the descriptor of another, and the
 * answer belonged to neither.
 *
 * The lane drives it in the direction that shows: a plain sysroot file, whose
 * slot carries no stamp, is replaced during the window by a descriptor on a
 * /sys directory that fell through to the sysroot. Split, the call reads "no
 * stamp" off the plain file and then resolves the /sys descriptor that took the
 * number, and reports SYSFS_MAGIC for a call that latched onto a plain file.
 * Taken together, the two agree and it reports the sysroot's own filesystem.
 *
 * The window is far too narrow to reach unaided -- over 160 runs at four
 * delays, a sibling swap between the two lookups was never distinguishable in
 * the answer -- so the lane widens it with ELFUSE_FD_IDENTITY_WINDOW_US and
 * swaps the slot inside it. What is asserted is not the timing: whichever
 * description the call latches, the filesystem it names has to be that one's.
 * The control run, with no sibling at all, pins both answers this file relies
 * on being different.
 *
 * The paths are passed by the lane in mk/tests.mk: argv[1] is a plain file in
 * the sysroot, argv[2] a /sys directory the sysroot supplies and this layer
 * does not synthesize.
 *
 * Syscalls exercised: openat(56), fstatfs(44), dup3(24), clone(220)
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define SYSFS_MAGIC 0x62656572

/* Long enough that the swap lands inside the widened window with room on both
 * sides, and short enough that the lane stays quick. The lane sets the delay to
 * WINDOW_US; the sibling waits SWAP_AFTER_US into it.
 */
#define SWAP_AFTER_US 40000

typedef struct {
    const char *sys_dir; /* opened and dup2'd onto the target */
    int target_fd;       /* the guest fd number being answered for */
    volatile int go;     /* raised by the main thread just before the call */
    int swapped;         /* the sibling's dup2 result */
} swap_arg_t;

static void *swapper(void *p)
{
    swap_arg_t *a = p;
    while (!a->go)
        usleep(1000);
    usleep(SWAP_AFTER_US);
    int n = open(a->sys_dir, O_RDONLY | O_DIRECTORY);
    if (n < 0) {
        a->swapped = -1;
        return NULL;
    }
    a->swapped = dup2(n, a->target_fd);
    close(n);
    return NULL;
}

/* The filesystem fstatfs reports for @fd: 1 for sysfs, 0 for anything else, -1
 * when the call failed.
 */
static int fs_is_sysfs(int fd)
{
    struct statfs sf;
    if (fstatfs(fd, &sf) < 0)
        return -1;
    return (unsigned long) sf.f_type == SYSFS_MAGIC ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <plain-file> <sys-dir>\n", argv[0]);
        return 2;
    }
    const char *plain = argv[1];
    const char *sys_dir = argv[2];

    /* The control. Neither answer is assumed: the lane is only meaningful if a
     * plain sysroot file and a fallen-through /sys directory report different
     * filesystems, so both are measured here before anything is raced.
     */
    TEST("a plain sysroot file is not sysfs");
    int fd = open(plain, O_RDONLY);
    if (fd < 0) {
        FAIL("could not open the plain file");
        return 1;
    }
    int plain_fs = fs_is_sysfs(fd);
    close(fd);
    if (plain_fs != 0) {
        fprintf(stderr, "  fstatfs said %d\n", plain_fs);
        FAIL("the plain file did not report an ordinary filesystem");
    } else {
        PASS();
    }

    TEST("a /sys directory the sysroot supplies is sysfs");
    fd = open(sys_dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        FAIL("could not open the /sys directory");
        return 1;
    }
    int sys_fs = fs_is_sysfs(fd);
    close(fd);
    if (sys_fs != 1) {
        fprintf(stderr, "  fstatfs said %d\n", sys_fs);
        FAIL("the /sys directory did not report sysfs");
    } else {
        PASS();
    }

    /* The race. The descriptor the call latches is the plain file, because the
     * swap happens after it has entered the call; whatever it reports has to be
     * that file's filesystem and not the one that took the number afterwards.
     */
    TEST("a swap inside the window does not decide the answer");
    int target = open(plain, O_RDONLY);
    if (target < 0) {
        FAIL("could not open the plain file");
        return 1;
    }
    swap_arg_t arg = {
        .sys_dir = sys_dir, .target_fd = target, .go = 0, .swapped = -2};
    pthread_t th;
    if (pthread_create(&th, NULL, swapper, &arg) != 0) {
        close(target);
        FAIL("could not start the swapping thread");
        return 1;
    }
    arg.go = 1;
    int raced = fs_is_sysfs(target);
    pthread_join(th, NULL);

    /* The swap has to have happened, or the run proves nothing. */
    bool swapped = arg.swapped == target;
    int after = fs_is_sysfs(target);
    close(target);

    if (!swapped) {
        fprintf(stderr, "  the sibling's dup2 returned %d\n", arg.swapped);
        FAIL("the slot was never replaced, so the window was not exercised");
    } else if (after != 1) {
        fprintf(stderr, "  after the swap fstatfs said %d\n", after);
        FAIL("the slot does not hold the /sys descriptor after the swap");
    } else if (raced != 0) {
        fprintf(stderr, "  the raced call said %d, the plain file is %d\n",
                raced, plain_fs);
        FAIL("fstatfs reported the filesystem of the slot's replacement");
    } else {
        PASS();
    }

    SUMMARY("test-fstatfs-fd-identity");
    return fails == 0 ? 0 : 1;
}
