/*
 * fchownat AT_EMPTY_PATH tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * fchownat(fd, "", uid, gid, AT_EMPTY_PATH) chowns fd itself instead of a name
 * beneath it. This is the only way to chown an O_PATH descriptor -- plain
 * fchown() rejects FD_PATH with EBADF, matching Linux -- and AT_FDCWD resolves
 * to the current directory rather than being an error.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

int passes = 0, fails = 0;

static char tmp_file[] = "/tmp/elfuse-fchownat-empty-XXXXXX";
static char tmp_dir[] = "/tmp/elfuse-fchownat-empty-dir-XXXXXX";

static int setup_fixtures(void)
{
    int fd = mkstemp(tmp_file);
    if (fd < 0) {
        perror("setup: mkstemp tmp_file");
        return -1;
    }
    close(fd);

    /* The AT_FDCWD case below needs a writable cwd; the process's inherited cwd
     * may not be (e.g. a read-only rootfs in a VM test image).
     */
    if (!mkdtemp(tmp_dir)) {
        perror("setup: mkdtemp tmp_dir");
        return -1;
    }
    if (chdir(tmp_dir) < 0) {
        perror("setup: chdir tmp_dir");
        return -1;
    }
    return 0;
}

static void teardown_fixtures(void)
{
    unlink(tmp_file);
    chdir("/tmp");
    rmdir(tmp_dir);
}

static void test_empty_path_via_opath_fd(void)
{
    TEST("fchownat(O_PATH fd, \"\", AT_EMPTY_PATH) chowns the file");
    int fd = open(tmp_file, O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    if (fchownat(fd, "", 4001, 4002, AT_EMPTY_PATH) != 0) {
        FAIL("fchownat");
        close(fd);
        return;
    }
    struct stat st;
    int ok = fstat(fd, &st) == 0 && st.st_uid == 4001 && st.st_gid == 4002;
    close(fd);
    EXPECT_TRUE(ok, "uid/gid mismatch");
}

static void test_plain_fchown_still_rejects_opath(void)
{
    TEST("fchown(O_PATH fd) still returns EBADF");
    int fd = open(tmp_file, O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    int rc = fchown(fd, 0, 0);
    int err = errno;
    close(fd);
    EXPECT_TRUE(rc == -1 && err == EBADF, "fchown should reject O_PATH");
}

static void test_empty_path_via_regular_fd(void)
{
    TEST("fchownat(regular fd, \"\", AT_EMPTY_PATH) chowns the file");
    int fd = open(tmp_file, O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    if (fchownat(fd, "", 5001, 5002, AT_EMPTY_PATH) != 0) {
        FAIL("fchownat");
        close(fd);
        return;
    }
    struct stat st;
    int ok = fstat(fd, &st) == 0 && st.st_uid == 5001 && st.st_gid == 5002;
    close(fd);
    EXPECT_TRUE(ok, "uid/gid mismatch");
}

static void test_empty_path_at_fdcwd_targets_cwd(void)
{
    TEST("fchownat(AT_FDCWD, \"\", AT_EMPTY_PATH) chowns cwd");
    if (fchownat(AT_FDCWD, "", 6001, 6002, AT_EMPTY_PATH) != 0) {
        FAIL("fchownat");
        return;
    }
    struct stat st;
    int ok = stat(".", &st) == 0 && st.st_uid == 6001 && st.st_gid == 6002;
    EXPECT_TRUE(ok, "uid/gid mismatch");
}

int main(void)
{
    printf("test-fchownat-empty-path: AT_EMPTY_PATH chown-by-fd semantics\n");

    if (setup_fixtures() < 0) {
        printf("test-fchownat-empty-path: fixture setup failed\n");
        return 1;
    }

    test_empty_path_via_opath_fd();
    test_plain_fchown_still_rejects_opath();
    test_empty_path_via_regular_fd();
    test_empty_path_at_fdcwd_targets_cwd();

    teardown_fixtures();

    SUMMARY("test-fchownat-empty-path");
    return fails == 0 ? 0 : 1;
}
