/*
 * fstatat/statx AT_EMPTY_PATH tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * fstatat(fd, "", &st, AT_EMPTY_PATH) stats fd itself rather than a name
 * beneath it, so it has to work for descriptors that name no path at all: a
 * pipe, a socket, an eventfd. glibc has spelled fstat(fd) exactly that way
 * since 2.33, which is what makes this ordinary rather than exotic -- a program
 * that never mentions AT_EMPTY_PATH still arrives here through plain fstat().
 *
 * The interesting failure is a resolver reached before the empty path is
 * recognized: the empty path is relative, so measuring it against dirfd owes
 * ENOTDIR for a dirfd that is not a directory, which is right for a name and
 * wrong for the descriptor itself. Every case below therefore asserts the
 * fstatat answer against the plain fstat answer for the same descriptor, since
 * the two are the same question and a divergence is the bug.
 *
 * statx(2) shares the same resolution path and is checked on the same
 * descriptors. AT_FDCWD is checked too: it names the current directory, which
 * always has a path, so it is the case that keeps working when the rest breaks.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef SYS_statx
#define SYS_statx 291
#endif

/* STATX_BASIC_STATS. Spelled out because the mask is what the guest sends and
 * the header's name for it is not present on every libc this cross-builds
 * against.
 */
#define STATX_MASK_BASIC 0x7ff

int passes = 0, fails = 0;

static char tmp_file[] = "/tmp/elfuse-fstatat-empty-XXXXXX";

/* Both spellings of the same question must return the same answer. st_dev and
 * st_ino identify the object, st_mode carries the type the caller switches on,
 * and nothing else is stable enough across descriptor kinds to compare.
 */
static void expect_agrees_with_fstat(const char *what, int fd, mode_t want_fmt)
{
    TEST(what);

    struct stat direct;
    memset(&direct, 0, sizeof(direct));
    if (fstat(fd, &direct) != 0) {
        FAIL("fstat failed, nothing to compare against");
        return;
    }

    struct stat viaat;
    memset(&viaat, 0, sizeof(viaat));
    errno = 0;
    if (fstatat(fd, "", &viaat, AT_EMPTY_PATH) != 0) {
        FAIL("fstatat with AT_EMPTY_PATH failed");
        return;
    }

    if (want_fmt && (viaat.st_mode & S_IFMT) != want_fmt) {
        FAIL("wrong file type");
        return;
    }
    EXPECT_TRUE(viaat.st_mode == direct.st_mode &&
                    viaat.st_dev == direct.st_dev &&
                    viaat.st_ino == direct.st_ino,
                "fstatat disagreed with fstat on the same descriptor");
}

/* statx shares the resolution path, so it breaks and recovers with fstatat.
 *
 * Identity is compared, not just the type: an answer that carries the right
 * type from the wrong object is exactly what a resolver reached too early
 * produces, and a type-only check would pass it. statx is also where dev is
 * split into major and minor, so the two halves are checked against the dev
 * fstat reports for the same descriptor.
 */
static void expect_statx_agrees(const char *what, int fd)
{
    TEST(what);

    struct stat direct;
    memset(&direct, 0, sizeof(direct));
    if (fstat(fd, &direct) != 0) {
        FAIL("fstat failed, nothing to compare against");
        return;
    }

    struct statx sx;
    memset(&sx, 0, sizeof(sx));
    errno = 0;
    long rc = syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_MASK_BASIC, &sx);
    if (rc != 0) {
        FAIL("statx with AT_EMPTY_PATH failed");
        return;
    }
    EXPECT_TRUE((sx.stx_mode & S_IFMT) == (direct.st_mode & S_IFMT) &&
                    sx.stx_ino == direct.st_ino &&
                    sx.stx_dev_major == major(direct.st_dev) &&
                    sx.stx_dev_minor == minor(direct.st_dev),
                "statx disagreed with fstat on the same descriptor");
}

/* A pipe, a socket and an eventfd have no host path behind them, which is what
 * separates them from every other descriptor here.
 */
static void test_pathless_descriptors(void)
{
    int p[2];
    if (pipe(p) == 0) {
        expect_agrees_with_fstat("pipe read end", p[0], S_IFIFO);
        expect_agrees_with_fstat("pipe write end", p[1], S_IFIFO);
        expect_statx_agrees("statx on a pipe", p[0]);
        close(p[0]);
        close(p[1]);
    } else {
        TEST("pipe read end");
        FAIL("pipe");
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        expect_agrees_with_fstat("socketpair fd", sv[0], S_IFSOCK);
        expect_statx_agrees("statx on a socket", sv[0]);
        close(sv[0]);
        close(sv[1]);
    } else {
        TEST("socketpair fd");
        FAIL("socketpair");
    }

    /* No expected type: an eventfd is an anonymous inode and its st_mode is not
     * something a program should be reading a promise out of. That it answers
     * at all, and answers the same as fstat, is the whole claim.
     */
    int efd = eventfd(0, 0);
    if (efd >= 0) {
        expect_agrees_with_fstat("eventfd", efd, 0);
        expect_statx_agrees("statx on an eventfd", efd);
        close(efd);
    } else {
        TEST("eventfd");
        FAIL("eventfd");
    }
}

/* Descriptors that do name a path. These worked before and have to keep
 * working: the fix moves them onto a different branch.
 */
static void test_descriptors_with_a_path(void)
{
    int fd = open(tmp_file, O_RDONLY);
    if (fd >= 0) {
        expect_agrees_with_fstat("regular file fd", fd, S_IFREG);
        expect_statx_agrees("statx on a regular file", fd);
        close(fd);
    } else {
        TEST("regular file fd");
        FAIL("open");
    }

    /* O_PATH is the case plain fstat() cannot serve on Linux for every
     * operation, so AT_EMPTY_PATH is the only spelling some callers have.
     */
    int pfd = open(tmp_file, O_PATH);
    if (pfd >= 0) {
        expect_agrees_with_fstat("O_PATH fd", pfd, S_IFREG);
        expect_statx_agrees("statx on an O_PATH fd", pfd);
        close(pfd);
    } else {
        TEST("O_PATH fd");
        FAIL("open O_PATH");
    }

    int dfd = open("/", O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        expect_agrees_with_fstat("directory fd", dfd, S_IFDIR);
        close(dfd);
    } else {
        TEST("directory fd");
        FAIL("open directory");
    }
}

static void test_at_fdcwd_names_the_cwd(void)
{
    TEST("AT_FDCWD with an empty path stats the cwd");

    struct stat dot;
    memset(&dot, 0, sizeof(dot));
    if (stat(".", &dot) != 0) {
        FAIL("stat(\".\") failed, nothing to compare against");
        return;
    }

    struct stat viaat;
    memset(&viaat, 0, sizeof(viaat));
    errno = 0;
    if (fstatat(AT_FDCWD, "", &viaat, AT_EMPTY_PATH) != 0) {
        FAIL("fstatat(AT_FDCWD, \"\", AT_EMPTY_PATH) failed");
        return;
    }
    EXPECT_TRUE(viaat.st_dev == dot.st_dev && viaat.st_ino == dot.st_ino,
                "AT_FDCWD did not resolve to the current directory");
}

/* A closed descriptor still owes EBADF, not the ENOTDIR that a resolver would
 * produce for it. The two are easy to confuse from the outside, which is why
 * this is asserted rather than assumed.
 */
static void test_closed_fd_is_ebadf(void)
{
    TEST("a closed fd reports EBADF");

    int p[2];
    if (pipe(p) != 0) {
        FAIL("pipe");
        return;
    }
    close(p[0]);
    close(p[1]);

    struct stat st;
    errno = 0;
    int rc = fstatat(p[0], "", &st, AT_EMPTY_PATH);
    EXPECT_TRUE(rc == -1 && errno == EBADF, "expected EBADF for a closed fd");
}

/* The flag is what turns the empty name into "this descriptor", so without it
 * the call must not answer for the descriptor. Only that it fails is asserted:
 * which errno an empty path earns without the flag is a separate question from
 * this one, and elfuse does not answer it the way Linux does today.
 */
static void test_the_flag_is_what_selects_the_fd(void)
{
    TEST("an empty path without the flag does not stat the fd");

    int p[2];
    if (pipe(p) != 0) {
        FAIL("pipe");
        return;
    }

    struct stat st;
    errno = 0;
    int rc = fstatat(p[0], "", &st, 0);
    close(p[0]);
    close(p[1]);
    EXPECT_TRUE(rc == -1, "an empty path without the flag stat'ed the fd");
}

int main(void)
{
    printf("test-fstatat-empty-path: AT_EMPTY_PATH stat-by-fd semantics\n");

    int seed = mkstemp(tmp_file);
    if (seed < 0) {
        perror("setup: mkstemp");
        return 1;
    }
    close(seed);

    test_pathless_descriptors();
    test_descriptors_with_a_path();
    test_at_fdcwd_names_the_cwd();
    test_closed_fd_is_ebadf();
    test_the_flag_is_what_selects_the_fd();

    unlink(tmp_file);

    SUMMARY("test-fstatat-empty-path");
    return fails == 0 ? 0 : 1;
}
