/*
 * fchmodat AT_EMPTY_PATH tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * fchmodat(fd, "", mode, AT_EMPTY_PATH) chmods fd itself instead of a name
 * beneath it. This is the only way to chmod an O_PATH descriptor -- plain
 * fchmod() rejects FD_PATH with EBADF, matching Linux -- and AT_FDCWD resolves
 * to the current directory rather than being an error.
 *
 * The classic fchmodat(2) syscall predates any flags argument, so libc's
 * fchmodat() wrapper (glibc and musl both) rejects any flag other than
 * AT_SYMLINK_NOFOLLOW in userspace without ever making a syscall. Reaching
 * AT_EMPTY_PATH support requires the flags-aware fchmodat2(2) (Linux 6.6),
 * invoked here directly via syscall() since libc has no wrapper for it yet.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

static int fchmodat2(int dirfd, const char *path, mode_t mode, int flags)
{
    return (int) syscall(SYS_fchmodat2, dirfd, path, (long) mode, (long) flags);
}

/* fchmodat2(2) is Linux 6.6+ and reached here via a raw syscall() with no libc
 * fallback. A host kernel that predates it (or any environment where syscall
 * 452 is simply unwired) returns ENOSYS; treat that as a skip instead of
 * failing the whole binary.
 */
static int fchmodat2_supported(const char *probe_path)
{
    errno = 0;
    int rc = fchmodat2(AT_FDCWD, probe_path, 0644, 0);
    return !(rc < 0 && errno == ENOSYS);
}

int passes = 0, fails = 0;

static char tmp_file[] = "/tmp/elfuse-fchmodat-empty-XXXXXX";
static char tmp_dir[] = "/tmp/elfuse-fchmodat-empty-dir-XXXXXX";

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

    /* Off mkdtemp's 0700, because test_empty_path_at_fdcwd_targets_cwd chmods
     * the cwd to 0700 and asserts it: starting there, that assertion would pass
     * on a no-op. The sibling fchownat test reads no directory mode and needs
     * no equivalent.
     */
    if (chmod(tmp_dir, 0755) < 0) {
        perror("setup: chmod tmp_dir");
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
    TEST("fchmodat(O_PATH fd, \"\", AT_EMPTY_PATH) chmods the file");
    int fd = open(tmp_file, O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    if (fchmodat2(fd, "", 0600, AT_EMPTY_PATH) != 0) {
        FAIL("fchmodat");
        close(fd);
        return;
    }
    struct stat st;
    int ok = fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0600;
    close(fd);
    EXPECT_TRUE(ok, "mode mismatch");
}

static void test_plain_fchmod_still_rejects_opath(void)
{
    TEST("fchmod(O_PATH fd) still returns EBADF");
    int fd = open(tmp_file, O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    int rc = fchmod(fd, 0644);
    int err = errno;
    close(fd);
    EXPECT_TRUE(rc == -1 && err == EBADF, "fchmod should reject O_PATH");
}

static void test_empty_path_via_regular_fd(void)
{
    TEST("fchmodat(regular fd, \"\", AT_EMPTY_PATH) chmods the file");
    int fd = open(tmp_file, O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    if (fchmodat2(fd, "", 0640, AT_EMPTY_PATH) != 0) {
        FAIL("fchmodat");
        close(fd);
        return;
    }
    struct stat st;
    int ok = fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0640;
    close(fd);
    EXPECT_TRUE(ok, "mode mismatch");
}

static void test_empty_path_at_fdcwd_targets_cwd(void)
{
    TEST("fchmodat(AT_FDCWD, \"\", AT_EMPTY_PATH) chmods cwd");
    if (fchmodat2(AT_FDCWD, "", 0700, AT_EMPTY_PATH) != 0) {
        FAIL("fchmodat");
        return;
    }
    struct stat st;
    int ok = stat(".", &st) == 0 && (st.st_mode & 0777) == 0700;
    /* Restore a mode that still lets teardown_fixtures rmdir it. */
    chmod(".", 0755);
    EXPECT_TRUE(ok, "mode mismatch");
}

int main(void)
{
    printf("test-fchmodat-empty-path: AT_EMPTY_PATH chmod-by-fd semantics\n");

    if (setup_fixtures() < 0) {
        printf("test-fchmodat-empty-path: fixture setup failed\n");
        return 1;
    }

    if (!fchmodat2_supported(tmp_file)) {
        printf(
            "test-fchmodat-empty-path: SKIP (fchmodat2 not supported by "
            "host kernel)\n");
        teardown_fixtures();
        return 0;
    }

    test_empty_path_via_opath_fd();
    test_plain_fchmod_still_rejects_opath();
    test_empty_path_via_regular_fd();
    test_empty_path_at_fdcwd_targets_cwd();

    teardown_fixtures();

    SUMMARY("test-fchmodat-empty-path");
    return fails == 0 ? 0 : 1;
}
