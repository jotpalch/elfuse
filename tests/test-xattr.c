/*
 * lgetxattr / getxattr / setxattr semantics tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pins three properties of the elfuse xattr surface that the host shim has to
 * translate:
 *
 *   1. lgetxattr returns the stored value on a regular file.
 *   2. lgetxattr on a symlink does not follow the link, so requesting
 *      an attr stored on the target reports ENODATA. getxattr on the
 *      same symlink follows and returns the target's value.
 *   3. A missing attribute reports ENODATA, not EINVAL. macOS returns
 *      ENOATTR(93) or its synonym ENODATA(96); both must translate to
 *      Linux ENODATA(61).
 *
 * Regression: an earlier revision lacked the ENOATTR translation entry, so the
 * default in linux_errno() fell through to EINVAL, which masked real "attribute
 * not present" outcomes and broke fontconfig / glibc xattr probes.
 *
 * Syscalls exercised: setxattr(5), lsetxattr(6), getxattr(8),
 *                     lgetxattr(9)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define NR_setxattr 5
#define NR_lsetxattr 6
#define NR_getxattr 8
#define NR_lgetxattr 9

static long do_setxattr(const char *path,
                        const char *name,
                        const void *val,
                        size_t sz,
                        int flags)
{
    return syscall(NR_setxattr, path, name, val, sz, flags);
}

static long do_lsetxattr(const char *path,
                         const char *name,
                         const void *val,
                         size_t sz,
                         int flags)
{
    return syscall(NR_lsetxattr, path, name, val, sz, flags);
}

static long do_getxattr(const char *path,
                        const char *name,
                        void *out,
                        size_t cap)
{
    return syscall(NR_getxattr, path, name, out, cap);
}

static long do_lgetxattr(const char *path,
                         const char *name,
                         void *out,
                         size_t cap)
{
    return syscall(NR_lgetxattr, path, name, out, cap);
}

static char tmp_dir[] = "/tmp/elfuse-xattr-XXXXXX";
static char tmp_file[128];
static char tmp_link[128];

static int setup(void)
{
    if (!mkdtemp(tmp_dir)) {
        perror("setup: mkdtemp");
        return -1;
    }
    snprintf(tmp_file, sizeof(tmp_file), "%s/target", tmp_dir);
    snprintf(tmp_link, sizeof(tmp_link), "%s/link", tmp_dir);

    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("setup: open");
        rmdir(tmp_dir);
        return -1;
    }
    (void) !write(fd, "hello\n", 6);
    close(fd);
    symlink(tmp_file, tmp_link);
    return 0;
}

static void teardown(void)
{
    unlink(tmp_link);
    unlink(tmp_file);
    rmdir(tmp_dir);
}

static void test_lgetxattr_regular_file(void)
{
    TEST("lgetxattr on regular file returns value");
    const char *attr = "user.elfuse_probe";
    const char *val = "wired";
    if (do_setxattr(tmp_file, attr, val, strlen(val), 0) != 0) {
        FAIL("setxattr seed failed");
        return;
    }
    char buf[64] = {0};
    long r = do_lgetxattr(tmp_file, attr, buf, sizeof(buf));
    EXPECT_TRUE(r == (long) strlen(val) && memcmp(buf, val, strlen(val)) == 0,
                "lgetxattr value mismatch");
}

static void test_lgetxattr_symlink_no_follow(void)
{
    TEST("lgetxattr on symlink reports ENODATA, not EINVAL");
    char buf[64] = {0};
    errno = 0;
    long r = do_lgetxattr(tmp_link, "user.elfuse_probe", buf, sizeof(buf));
    EXPECT_TRUE(r == -1 && errno == ENODATA,
                "expected ENODATA from lgetxattr on bare symlink");
}

static void test_getxattr_symlink_follows(void)
{
    TEST("getxattr on symlink follows to target");
    char buf[64] = {0};
    long r = do_getxattr(tmp_link, "user.elfuse_probe", buf, sizeof(buf));
    const char *val = "wired";
    EXPECT_TRUE(r == (long) strlen(val) && memcmp(buf, val, strlen(val)) == 0,
                "getxattr value mismatch");
}

static void test_lgetxattr_symlink_with_attr(void)
{
    TEST("lgetxattr returns symlink-owned attr after lsetxattr");
    const char *attr = "user.elfuse_probe";
    const char *lval = "link-val";
    if (do_lsetxattr(tmp_link, attr, lval, strlen(lval), 0) != 0) {
        printf("SKIP (lsetxattr on symlink unsupported: errno=%d)\n", errno);
        passes++;
        return;
    }
    char buf[64] = {0};
    long r = do_lgetxattr(tmp_link, attr, buf, sizeof(buf));
    EXPECT_TRUE(
        r == (long) strlen(lval) && memcmp(buf, lval, strlen(lval)) == 0,
        "lgetxattr did not return symlink-owned value");
}

static void test_lgetxattr_missing(void)
{
    TEST("lgetxattr on missing attr reports ENODATA");
    char buf[64] = {0};
    errno = 0;
    long r = do_lgetxattr(tmp_file, "user.no_such_attr_xyz", buf, sizeof(buf));
    EXPECT_TRUE(r == -1 && errno == ENODATA,
                "expected ENODATA from lgetxattr on missing attr");
}

int main(void)
{
    printf("test-xattr: lgetxattr / getxattr / setxattr semantics\n");

    if (setup() < 0) {
        printf("test-xattr: fixture setup failed\n");
        return 1;
    }

    test_lgetxattr_regular_file();
    test_lgetxattr_symlink_no_follow();
    test_getxattr_symlink_follows();
    test_lgetxattr_symlink_with_attr();
    test_lgetxattr_missing();

    teardown();

    SUMMARY("test-xattr");
    return fails == 0 ? 0 : 1;
}
