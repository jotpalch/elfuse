/*
 * Test synthetic /proc/self/oom_* sendfile/copy_file_range interception
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse backs /proc/self/oom_adj, oom_score_adj, and oom_score with a per-open
 * host temp file materialized at open() time, plus a separate read-intercept
 * path (proc_intercept_read) that serves live atomic state to guest
 * read/pread/readv so a write through a sibling fd is visible without
 * reopening. sendfile(2) and copy_file_range(2) do not go through that read
 * path -- they go through copy_fd_range's own, independently wired
 * proc_try_chunk_read_intercept call. These tests pin that second wiring: open
 * the source fd, mutate the value through a sibling fd, then
 * sendfile/copy_file_range from the already-open fd and require the fresh
 * value, not the stale open-time snapshot.
 *
 * This is elfuse-internal plumbing with no Linux-kernel counterpart -- no real
 * program sendfile()s or copy_file_range()s out of procfs -- so unlike
 * test-io-opt this suite is not run against the QEMU reference kernel; see
 * tests/test-matrix.sh.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static void reset_oom_score_adj(void)
{
    int fd = open("/proc/self/oom_score_adj", O_RDWR);
    if (fd >= 0) {
        write(fd, "0\n", 2);
        close(fd);
    }
}

/* Copy up to 32 bytes from in_fd to out_fd, returning the byte count and
 * reporting via *offsets_ok whether the syscall's offset bookkeeping advanced
 * to the expected 3 bytes. sendfile tracks one (source) offset; copy_file_range
 * tracks both a source and a destination offset.
 */
typedef ssize_t (*oom_copy_fn)(int out_fd, int in_fd, int *offsets_ok);

static ssize_t copy_via_sendfile(int out_fd, int in_fd, int *offsets_ok)
{
    off_t offset = 0;
    ssize_t copied = sendfile(out_fd, in_fd, &offset, 32);
    *offsets_ok = (offset == 3);
    return copied;
}

static ssize_t copy_via_copy_file_range(int out_fd, int in_fd, int *offsets_ok)
{
    off_t off_in = 0, off_out = 0;
    ssize_t copied = copy_file_range(in_fd, &off_in, out_fd, &off_out, 32, 0);
    *offsets_ok = (off_in == 3 && off_out == 3);
    return copied;
}

/* Open the synthetic oom_adj source, bump the value through a sibling
 * oom_score_adj fd, then `copy` 32 bytes from the already-open source into a
 * fresh temp file and require the updated "15\n" (3 bytes) instead of the stale
 * open-time snapshot. The copy method and its offset bookkeeping differ, so the
 * caller supplies them; everything else is shared.
 */
static void run_oom_copy_test(const char *label,
                              const char *dst,
                              oom_copy_fn copy)
{
    TEST(label);
    reset_oom_score_adj();

    int in_fd = open("/proc/self/oom_adj", O_RDONLY);
    int score_fd = open("/proc/self/oom_score_adj", O_RDWR);
    int out_fd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (in_fd >= 0 && score_fd >= 0 && out_fd >= 0) {
        char buf[32] = {0};
        int offsets_ok = 0;
        ssize_t wrote = write(score_fd, "1000\n", 5);
        ssize_t copied = wrote == 5 ? copy(out_fd, in_fd, &offsets_ok) : -1;
        close(out_fd);
        close(score_fd);
        close(in_fd);

        int verify_fd = open(dst, O_RDONLY);
        if (copied >= 0 && verify_fd >= 0) {
            ssize_t n = read(verify_fd, buf, sizeof(buf) - 1);
            close(verify_fd);
            if (copied == 3 && offsets_ok && n == 3 &&
                memcmp(buf, "15\n", 3) == 0)
                PASS();
            else
                FAIL("unexpected proc content");
        } else {
            if (verify_fd >= 0)
                close(verify_fd);
            FAIL("proc copy setup failed");
        }
    } else {
        if (in_fd >= 0)
            close(in_fd);
        if (score_fd >= 0)
            close(score_fd);
        if (out_fd >= 0)
            close(out_fd);
        FAIL("open failed");
    }
    reset_oom_score_adj();
    unlink(dst);
}

int main(void)
{
    printf(
        "test-oom-proc: synthetic oom proc source sendfile/copy_file_range "
        "interception\n");

    char sendfile_dst[] = "/tmp/elfuse-oom-sendfile-XXXXXX";
    char cfr_dst[] = "/tmp/elfuse-oom-cfr-XXXXXX";
    int seed = mkstemp(sendfile_dst);
    if (seed < 0) {
        perror("mkstemp");
        return 1;
    }
    close(seed);
    seed = mkstemp(cfr_dst);
    if (seed < 0) {
        perror("mkstemp");
        unlink(sendfile_dst);
        return 1;
    }
    close(seed);

    run_oom_copy_test("sendfile rereads synthetic oom proc source",
                      sendfile_dst, copy_via_sendfile);
    run_oom_copy_test("copy_file_range rereads synthetic oom proc source",
                      cfr_dst, copy_via_copy_file_range);

    SUMMARY("test-oom-proc");
    return fails > 0 ? 1 : 0;
}
