/*
 * Virtual chown overlay round-trip tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * An emulated-root guest expects chown(2)/fchown(2)/fchownat(2) to succeed even
 * when rootless macOS cannot satisfy the change, and the follow-up
 * stat(2)/statx(2)/fstat(2) must observe the intended owner/group rather than
 * the host's real owner.
 *
 * Exercises the round-trip across the chown family, the -1 sentinel,
 * AT_SYMLINK_NOFOLLOW on a symlink, the regression guard for non-EPERM
 * failures, and survival across fork/execve.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static char tmp_root[] = "/tmp/elfuse-chown-XXXXXX";
static char tmp_file[256];
static char tmp_link[256];
static char tmp_target[256];
static char tmp_dir[256];

static int setup_fixtures(void)
{
    if (!mkdtemp(tmp_root)) {
        perror("setup: mkdtemp");
        return -1;
    }
    snprintf(tmp_file, sizeof(tmp_file), "%s/file.txt", tmp_root);
    snprintf(tmp_target, sizeof(tmp_target), "%s/target.txt", tmp_root);
    snprintf(tmp_link, sizeof(tmp_link), "%s/link", tmp_root);
    snprintf(tmp_dir, sizeof(tmp_dir), "%s/dir", tmp_root);

    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("setup: open tmp_file");
        return -1;
    }
    if (write(fd, "x\n", 2) != 2) {
        perror("setup: write tmp_file");
        close(fd);
        return -1;
    }
    close(fd);

    fd = open(tmp_target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("setup: open tmp_target");
        return -1;
    }
    close(fd);

    if (symlink(tmp_target, tmp_link) < 0) {
        perror("setup: symlink");
        return -1;
    }
    if (mkdir(tmp_dir, 0755) < 0) {
        perror("setup: mkdir tmp_dir");
        return -1;
    }
    return 0;
}

static void teardown_fixtures(void)
{
    unlink(tmp_file);
    unlink(tmp_link);
    unlink(tmp_target);
    rmdir(tmp_dir);
    rmdir(tmp_root);
}

static void test_chown_then_stat(void)
{
    TEST("chown(uid,gid) then stat reflects both");
    if (chown(tmp_file, 1000, 1001) != 0) {
        FAIL("chown");
        return;
    }
    struct stat st;
    if (stat(tmp_file, &st) != 0) {
        FAIL("stat");
        return;
    }
    EXPECT_TRUE(st.st_uid == 1000 && st.st_gid == 1001, "uid/gid mismatch");
}

static void test_chown_minus_one_keeps_gid(void)
{
    /* The earlier test already set (1000, 1001). chown(uid, -1) must change uid
     * only and keep the prior gid override visible to stat.
     */
    TEST("chown(uid,-1) keeps prior gid override");
    if (chown(tmp_file, 2000, (gid_t) -1) != 0) {
        FAIL("chown");
        return;
    }
    struct stat st;
    if (stat(tmp_file, &st) != 0) {
        FAIL("stat");
        return;
    }
    EXPECT_TRUE(st.st_uid == 2000 && st.st_gid == 1001, "uid/gid mismatch");
}

static void test_successful_group_chown_keeps_virtual_uid(void)
{
    TEST("chown(-1,gid) host success keeps prior uid override");
    if (chown(tmp_file, 3000, 3001) != 0) {
        FAIL("chown setup");
        return;
    }
    gid_t gid = getgid();
    if (chown(tmp_file, (uid_t) -1, gid) != 0) {
        FAIL("chown group");
        return;
    }
    struct stat st;
    if (stat(tmp_file, &st) != 0) {
        FAIL("stat");
        return;
    }
    EXPECT_TRUE(st.st_uid == 3000 && st.st_gid == gid, "uid/gid mismatch");
}

static void test_fchown_then_fstat(void)
{
    TEST("fchown(fd) then fstat(fd) reflects override");
    int fd = open(tmp_file, O_RDONLY);
    if (fd < 0) {
        FAIL("open");
        return;
    }
    if (fchown(fd, 0, 0) != 0) {
        FAIL("fchown");
        close(fd);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        FAIL("fstat");
        close(fd);
        return;
    }
    close(fd);
    EXPECT_TRUE(st.st_uid == 0 && st.st_gid == 0, "uid/gid mismatch");
}

static void test_open_removed_dir_keeps_overlay_until_last_close(void)
{
    TEST("open removed dir keeps overlay until last close");
    int fd = open(tmp_dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        FAIL("open dir");
        return;
    }
    int dupfd = dup(fd);
    if (dupfd < 0) {
        FAIL("dup dir");
        close(fd);
        return;
    }
    if (fchown(fd, 6060, 7070) != 0) {
        FAIL("fchown dir");
        close(dupfd);
        close(fd);
        return;
    }
    if (rmdir(tmp_dir) != 0) {
        FAIL("rmdir dir");
        close(dupfd);
        close(fd);
        return;
    }
    close(fd);

    struct stat st;
    if (fstat(dupfd, &st) != 0) {
        FAIL("fstat removed dir");
        close(dupfd);
        return;
    }
    close(dupfd);
    EXPECT_TRUE(st.st_uid == 6060 && st.st_gid == 7070, "uid/gid mismatch");
}

static void test_lchown_on_symlink(void)
{
    TEST("lchown(link) leaves target unchanged");

    /* Reset target ownership through the existing path so test ordering does
     * not leak overrides from earlier asserts.
     */
    if (chown(tmp_target, 100, 100) != 0) {
        FAIL("chown target");
        return;
    }
    if (fchownat(AT_FDCWD, tmp_link, 9, 9, AT_SYMLINK_NOFOLLOW) != 0) {
        FAIL("fchownat link");
        return;
    }
    struct stat link_st, tgt_st;
    if (lstat(tmp_link, &link_st) != 0 || stat(tmp_target, &tgt_st) != 0) {
        FAIL("stat");
        return;
    }
    EXPECT_TRUE(link_st.st_uid == 9 && link_st.st_gid == 9 &&
                    tgt_st.st_uid == 100 && tgt_st.st_gid == 100,
                "symlink override leaked to target");
}

static void test_enoent_propagates(void)
{
    TEST("chown on missing file returns ENOENT");
    EXPECT_ERRNO(chown("/tmp/elfuse-chown-no-such-file", 0, 0), ENOENT,
                 "chown");
}

static void test_fork_inherits_overlay(void)
{
    TEST("forked child observes parent's override");

    /* Re-establish a known override so the child's assertion is precise. */
    if (chown(tmp_file, 4242, 4243) != 0) {
        FAIL("chown");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        return;
    }
    if (pid == 0) {
        struct stat st;
        if (stat(tmp_file, &st) != 0)
            _exit(2);
        if (st.st_uid != 4242 || st.st_gid != 4243)
            _exit(3);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid");
        return;
    }
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "child saw wrong uid/gid");
}

int main(void)
{
    printf("test-chown-overlay: chown round-trip via virtual ownership\n");

    if (setup_fixtures() < 0) {
        printf("test-chown-overlay: fixture setup failed\n");

        /* Safe on paths never created, and the only thing that removes tmp_root
         * after a partial setup.
         */
        teardown_fixtures();
        return 1;
    }
    test_chown_then_stat();
    test_chown_minus_one_keeps_gid();
    test_successful_group_chown_keeps_virtual_uid();
    test_fchown_then_fstat();
    test_open_removed_dir_keeps_overlay_until_last_close();
    test_lchown_on_symlink();
    test_enoent_propagates();
    test_fork_inherits_overlay();
    teardown_fixtures();

    SUMMARY("test-chown-overlay");
    return fails == 0 ? 0 : 1;
}
