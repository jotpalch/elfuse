/*
 * Test open file description (OFD) locking via fcntl(F_OFD_GETLK/SETLK/SETLKW)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OFD locks (Linux F_OFD_GETLK=36/F_OFD_SETLK=37/F_OFD_SETLKW=38) are owned by
 * the open file description rather than by a process, so Linux always reports
 * l_pid=-1 for a conflicting F_OFD_GETLK lock. Passing the host's raw l_pid
 * straight through leaks a host PID to the guest and breaks software (e.g.
 * SQLite) that checks for the OFD-lock -1 sentinel.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "test-harness.h"

static int ofd_lock(int fd, int cmd, short type, off_t start, off_t len)
{
    struct flock fl = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = start,
        .l_len = len,
    };
    return fcntl(fd, cmd, &fl);
}

/* Linux rejects F_OFD_* requests carrying a nonzero l_pid with EINVAL: the
 * field is reserved on input since OFD locks are not owned by a process.
 */
static int ofd_lock_with_pid(int fd, int cmd, short type, pid_t pid)
{
    struct flock fl = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
        .l_pid = pid,
    };
    return fcntl(fd, cmd, &fl);
}

int main(void)
{
    int passes = 0, fails = 0;

    /* Unique per invocation: OFD locks contend across processes on one inode.
     */
    char path[] = "/tmp/elfuse-test-ofd-lock.XXXXXX";

    int fd1 = mkstemp(path);
    if (fd1 < 0) {
        perror("mkstemp");
        return 1;
    }

    /* A second open() yields a distinct open file description, so OFD locks
     * taken on fd1 can conflict with a query made through fd2 even though both
     * fds live in the same process.
     */
    int fd2 = open(path, O_RDWR);
    if (fd2 < 0) {
        perror("open fd2");
        close(fd1);
        unlink(path);
        return 1;
    }

    TEST("F_OFD_SETLK F_WRLCK");
    EXPECT_EQ(ofd_lock(fd1, F_OFD_SETLK, F_WRLCK, 0, 16), 0,
              "OFD write lock rejected");

    TEST("F_OFD_GETLK reports conflict from other OFD");
    struct flock gfl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
    };
    int gr = fcntl(fd2, F_OFD_GETLK, &gfl);
    EXPECT_TRUE(gr == 0 && gfl.l_type == F_WRLCK,
                "F_OFD_GETLK did not report the conflicting write lock");

    /* This is the behavior issue #129 reports as broken: l_pid must be -1 for
     * an OFD lock conflict, never a real (host or guest) PID.
     */
    TEST("F_OFD_GETLK l_pid is -1 on conflict");
    EXPECT_EQ(gfl.l_pid, -1, "F_OFD_GETLK leaked a non -1 l_pid");

    TEST("F_OFD_SETLK F_UNLCK");
    EXPECT_EQ(ofd_lock(fd1, F_OFD_SETLK, F_UNLCK, 0, 16), 0,
              "OFD unlock rejected");

    TEST("F_OFD_GETLK reports no conflict after unlock");
    struct flock gfl2 = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 16,
    };
    int gr2 = fcntl(fd2, F_OFD_GETLK, &gfl2);
    EXPECT_TRUE(gr2 == 0 && gfl2.l_type == F_UNLCK,
                "F_OFD_GETLK still reported a lock after unlock");

    /* Blocking variant must take the same translation path. */
    TEST("F_OFD_SETLKW F_WRLCK");
    EXPECT_EQ(ofd_lock(fd2, F_OFD_SETLKW, F_WRLCK, 0, 16), 0,
              "F_OFD_SETLKW rejected");
    EXPECT_EQ(ofd_lock(fd2, F_OFD_SETLK, F_UNLCK, 0, 16), 0,
              "OFD unlock (fd2) rejected");

    /* A nonzero l_pid in the request is reserved/invalid for all three OFD
     * commands, matching fs/locks.c fcntl_getlk/fcntl_setlk.
     */
    TEST("F_OFD_SETLK rejects nonzero l_pid");
    errno = 0;
    EXPECT_EQ(ofd_lock_with_pid(fd1, F_OFD_SETLK, F_WRLCK, getpid()), -1,
              "F_OFD_SETLK accepted a nonzero l_pid");
    EXPECT_EQ(errno, EINVAL, "F_OFD_SETLK with nonzero l_pid: wrong errno");

    TEST("F_OFD_SETLKW rejects nonzero l_pid");
    errno = 0;
    EXPECT_EQ(ofd_lock_with_pid(fd1, F_OFD_SETLKW, F_WRLCK, getpid()), -1,
              "F_OFD_SETLKW accepted a nonzero l_pid");
    EXPECT_EQ(errno, EINVAL, "F_OFD_SETLKW with nonzero l_pid: wrong errno");

    TEST("F_OFD_GETLK rejects nonzero l_pid");
    errno = 0;
    EXPECT_EQ(ofd_lock_with_pid(fd1, F_OFD_GETLK, F_WRLCK, getpid()), -1,
              "F_OFD_GETLK accepted a nonzero l_pid");
    EXPECT_EQ(errno, EINVAL, "F_OFD_GETLK with nonzero l_pid: wrong errno");

    close(fd1);
    close(fd2);
    unlink(path);

    SUMMARY("test-ofd-lock");
    return fails == 0 ? 0 : 1;
}
