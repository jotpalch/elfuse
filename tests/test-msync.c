/*
 * MAP_SHARED msync tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: MAP_SHARED write-back to shm backing files.
 *
 * Syscalls exercised: openat, ftruncate, mmap, msync, pread64
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

int passes = 0, fails = 0;

/* These tests open /dev/shm paths directly rather than calling shm_open, which
 * returns ENOSYS without trying on glibc 2.28 static.
 */

static void test_shared_msync_writes_file(void)
{
    TEST("MAP_SHARED msync writes backing file");

    char name[] = "/dev/shm/elfuse-msync-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        close(fd);
        return;
    }

    const char msg[] = "elfuse-msync";
    memcpy(p, msg, sizeof(msg));

    if (msync(p, 4096, MS_SYNC) != 0) {
        FAIL("msync failed");
        munmap(p, 4096);
        close(fd);
        return;
    }

    char buf[sizeof(msg)] = {0};
    if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf)) {
        FAIL("pread failed");
    } else if (!memcmp(buf, msg, sizeof(msg))) {
        PASS();
    } else {
        FAIL("backing file did not receive MAP_SHARED writes");
    }

    munmap(p, 4096);
    close(fd);
}

static void test_shared_msync_refreshes_peer_mapping(void)
{
    TEST("MAP_SHARED msync refreshes peer mapping");

    char name[] = "/dev/shm/elfuse-msync-peer-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) {
        FAIL("mmap failed");
        if (a != MAP_FAILED)
            munmap(a, 4096);
        if (b != MAP_FAILED)
            munmap(b, 4096);
        close(fd);
        return;
    }

    a[128] = 'Q';
    if (msync(a, 4096, MS_SYNC) != 0) {
        FAIL("msync failed");
    } else if (b[128] == 'Q') {
        PASS();
    } else {
        FAIL("peer MAP_SHARED mapping did not observe write after msync");
    }

    munmap(a, 4096);
    munmap(b, 4096);
    close(fd);
}

static void test_shared_msync_preserves_alias_writes(void)
{
    TEST("MAP_SHARED msync preserves peer alias writes");

    char name[] = "/dev/shm/elfuse-msync-alias-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) {
        FAIL("mmap failed");
        if (a != MAP_FAILED)
            munmap(a, 4096);
        if (b != MAP_FAILED)
            munmap(b, 4096);
        close(fd);
        return;
    }

    a[0] = 'A';
    b[1] = 'B';

    if (msync(a, 4096, MS_SYNC) != 0) {
        FAIL("msync failed");
    } else {
        char buf[2] = {0};
        if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf))
            FAIL("pread failed");
        else if (buf[0] == 'A' && buf[1] == 'B' && a[1] == 'B')
            PASS();
        else
            FAIL("msync lost dirty bytes from peer alias");
    }

    munmap(a, 4096);
    munmap(b, 4096);
    close(fd);
}

static void test_shm_name_visible_after_fork(void)
{
    TEST("/dev/shm name visible after fork");

    /* The name outlives the fork: it is not unlinked until the child has opened
     * it.
     */
    char name[] = "/dev/shm/elfuse-msync-fork-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("parent mkstemp /dev/shm failed");
        return;
    }

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        unlink(name);
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("parent mmap failed");
        unlink(name);
        close(fd);
        return;
    }
    p[0] = 'P';
    msync(p, 4096, MS_SYNC);

    pid_t child = fork();
    if (child < 0) {
        FAIL("fork failed");
    } else if (child == 0) {
        int cfd = open(name, O_RDWR);
        if (cfd < 0)
            _exit(2);
        char *cp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, 0);
        if (cp == MAP_FAILED)
            _exit(3);
        int ok = cp[0] == 'P';
        if (ok) {
            cp[1] = 'C';
            ok = msync(cp, 4096, MS_SYNC) == 0;
        }
        _exit(ok ? 0 : 4);
    } else {
        int status;
        if (waitpid(child, &status, 0) < 0) {
            FAIL("waitpid failed");
        } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            FAIL("child could not reopen shared shm name");
        } else {
            char buf[2] = {0};
            if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf))
                FAIL("parent pread failed");
            else if (buf[1] == 'C')
                PASS();
            else
                FAIL("parent did not observe child shm write");
        }
    }

    munmap(p, 4096);
    close(fd);
    unlink(name);
}

/* Real MAP_SHARED requires that host writes to the backing file are observable
 * through the mapping without the guest calling msync. The pre-overlay
 * implementation snapshotted file contents into private guest pages and only
 * reconciled on msync, so this is the regression lock-in for the overlay path.
 */
static void test_shared_host_write_visible_without_msync(void)
{
    TEST("MAP_SHARED host pwrite visible without msync");

    char name[] = "/dev/shm/elfuse-msync-host-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    /* Seed the file with a known pattern before mmap. */
    char seed[16];
    memset(seed, 0x11, sizeof(seed));
    if (pwrite(fd, seed, sizeof(seed), 0) != (ssize_t) sizeof(seed)) {
        FAIL("seed pwrite failed");
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        close(fd);
        return;
    }

    /* Confirm the initial seed is visible through the mapping. */
    if (p[0] != 0x11) {
        FAIL("initial seed not visible through mapping");
        munmap(p, 4096);
        close(fd);
        return;
    }

    /* Mutate the file via pwrite (host-side write). The mapping must reflect
     * the new bytes immediately, with no msync from the guest.
     */
    char update[16];
    memset(update, 0x22, sizeof(update));
    if (pwrite(fd, update, sizeof(update), 0) != (ssize_t) sizeof(update)) {
        FAIL("update pwrite failed");
        munmap(p, 4096);
        close(fd);
        return;
    }

    bool ok = true;
    for (int i = 0; i < (int) sizeof(update); i++) {
        if ((unsigned char) p[i] != 0x22) {
            ok = false;
            break;
        }
    }
    if (ok)
        PASS();
    else
        FAIL("mapping did not reflect host pwrite without msync");

    munmap(p, 4096);
    close(fd);
}

/* Guest writes to a MAP_SHARED file mapping must reach the file immediately so
 * other readers (here, a sibling pread) see them without the guest needing to
 * call msync. This is the converse of the host-write-visible test.
 */
static void test_shared_guest_write_lands_in_file(void)
{
    TEST("MAP_SHARED guest write lands in file without msync");

    char name[] = "/dev/shm/elfuse-msync-guest-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        close(fd);
        return;
    }

    /* Write through the mapping; do NOT call msync. */
    const char marker[] = "elfuse-overlay";
    memcpy(p, marker, sizeof(marker));

    char buf[sizeof(marker)] = {0};
    if (pread(fd, buf, sizeof(buf), 0) != (ssize_t) sizeof(buf))
        FAIL("pread failed");
    else if (!memcmp(buf, marker, sizeof(marker)))
        PASS();
    else
        FAIL("guest write did not reach file without msync");

    munmap(p, 4096);
    close(fd);
}

/* On hosts with pages larger than the guest's 4 KiB granule, a MAP_SHARED
 * overlay of one guest page can alias adjacent guest pages in the same host
 * page. Replacing the adjacent guest page must tear down the shared overlay
 * first so the new mapping cannot write through into the file.
 */
static void test_shared_adjacent_fixed_mapping_does_not_alias_file(void)
{
    TEST("MAP_FIXED neighbor does not inherit shared-file overlay");

    size_t hps = (size_t) sysconf(_SC_PAGESIZE);
    size_t file_len = hps > 8192 ? hps : 8192;

    char name[] = "/dev/shm/elfuse-msync-neighbor-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, (off_t) file_len) != 0) {
        FAIL("ftruncate failed");
        close(fd);
        return;
    }

    unsigned char seed = 0x33;
    if (pwrite(fd, &seed, 1, 4096) != 1) {
        FAIL("seed pwrite failed");
        close(fd);
        return;
    }

    unsigned char *shared =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared == MAP_FAILED) {
        FAIL("shared mmap failed");
        close(fd);
        return;
    }

    unsigned char *adjacent =
        mmap(shared + 4096, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (adjacent == MAP_FAILED) {
        FAIL("adjacent MAP_FIXED mmap failed");
        munmap(shared, 4096);
        close(fd);
        return;
    }

    adjacent[0] = 0x7a;

    unsigned char file_byte = 0;
    if (pread(fd, &file_byte, 1, 4096) != 1)
        FAIL("pread failed");
    else if (file_byte == seed)
        PASS();
    else
        FAIL("adjacent anonymous write leaked into file");

    munmap(shared, 4096);
    munmap(adjacent, 4096);
    close(fd);
}

static void test_shared_large_mapping_crosses_split_hvf_segments(void)
{
    TEST("large MAP_SHARED mmap crosses split HVF segments");

    const size_t reserve_len = 8u * 1024u * 1024u;
    const size_t large_len = 4u * 1024u * 1024u;
    const size_t split_offset = 2u * 1024u * 1024u;
    char small_name[] = "/dev/shm/elfuse-msync-split-XXXXXX";
    char large_name[] = "/dev/shm/elfuse-msync-large-XXXXXX";
    int small_fd = -1;
    int large_fd = -1;
    char *reserve;
    char *small = MAP_FAILED;
    char *large = MAP_FAILED;

    reserve =
        mmap(NULL, reserve_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserve == MAP_FAILED) {
        FAIL("reserve mmap failed");
        return;
    }
    if (munmap(reserve, reserve_len) != 0) {
        FAIL("reserve munmap failed");
        return;
    }

    small_fd = mkstemp(small_name);
    large_fd = mkstemp(large_name);
    if (small_fd >= 0)
        unlink(small_name);
    if (large_fd >= 0)
        unlink(large_name);
    if (small_fd < 0 || large_fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        goto out;
    }
    if (ftruncate(small_fd, 4096) != 0 ||
        ftruncate(large_fd, (off_t) large_len) != 0) {
        FAIL("ftruncate failed");
        goto out;
    }

    small = mmap(reserve + split_offset, 4096, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_FIXED_NOREPLACE, small_fd, 0);
    if (small == MAP_FAILED) {
        FAIL("splitter mmap failed");
        goto out;
    }
    small[0] = 0x5a;
    if (munmap(small, 4096) != 0) {
        FAIL("splitter munmap failed");
        small = MAP_FAILED;
        goto out;
    }
    small = MAP_FAILED;

    large = mmap(reserve, large_len, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_FIXED_NOREPLACE, large_fd, 0);
    if (large == MAP_FAILED) {
        FAIL("large mmap failed");
        goto out;
    }

    large[0] = 0x11;
    large[split_offset] = 0x22;
    unsigned char first = 0;
    unsigned char across_split = 0;
    if (pread(large_fd, &first, 1, 0) != 1 ||
        pread(large_fd, &across_split, 1, (off_t) split_offset) != 1) {
        FAIL("pread failed");
    } else if (first == 0x11 && across_split == 0x22) {
        PASS();
    } else {
        FAIL("large shared mapping did not stay file-backed");
    }

out:
    if (large != MAP_FAILED)
        munmap(large, large_len);
    if (small != MAP_FAILED)
        munmap(small, 4096);
    if (small_fd >= 0)
        close(small_fd);
    if (large_fd >= 0)
        close(large_fd);
}

/* Consecutive non-fixed MAP_SHARED file-backed mmap allocations must succeed
 * even when a previous shared mmap split an HVF stage-2 segment. The overlay
 * path tolerates multi-segment ranges and the gap finder keeps shared
 * file-backed allocations aligned to 2 MiB so subsequent mmaps do not re-split
 * mid-segment. Cover both: each chunk must mmap, accept guest writes, and stay
 * backed by its own memfd.
 */
static void test_shared_back_to_back_memfd_mappings(void)
{
    TEST("back-to-back non-fixed MAP_SHARED memfd mappings stay file-backed");
#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif
#define CHUNKS 4
    const size_t chunk_len = (size_t) 16 * 1024 * 1024;
    int fds[CHUNKS];
    void *maps[CHUNKS];
    for (int i = 0; i < CHUNKS; i++) {
        fds[i] = -1;
        maps[i] = MAP_FAILED;
    }

    bool ok = true;
    for (int i = 0; i < CHUNKS; i++) {
        char name[32];
        snprintf(name, sizeof(name), "elfuse-msync-bb-%d", i);
        fds[i] = (int) syscall(SYS_memfd_create, name, 0u);
        if (fds[i] < 0) {
            FAIL("memfd_create failed");
            ok = false;
            goto out;
        }
        if (ftruncate(fds[i], (off_t) chunk_len) != 0) {
            FAIL("ftruncate failed");
            ok = false;
            goto out;
        }
        maps[i] = mmap(NULL, chunk_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                       fds[i], 0);
        if (maps[i] == MAP_FAILED) {
            FAIL("consecutive shared mmap failed");
            ok = false;
            goto out;
        }
    }

    for (int i = 0; i < CHUNKS; i++) {
        unsigned char *p = (unsigned char *) maps[i];
        p[0] = (unsigned char) (0xA0 + i);
        p[chunk_len - 1] = (unsigned char) (0xB0 + i);
    }
    for (int i = 0; i < CHUNKS; i++) {
        unsigned char first = 0, last = 0;
        if (pread(fds[i], &first, 1, 0) != 1 ||
            pread(fds[i], &last, 1, (off_t) (chunk_len - 1)) != 1) {
            FAIL("pread failed");
            ok = false;
            goto out;
        }
        if (first != (unsigned char) (0xA0 + i) ||
            last != (unsigned char) (0xB0 + i)) {
            FAIL("shared write did not reach its own memfd");
            ok = false;
            goto out;
        }
    }
    if (ok)
        PASS();

out:
    for (int i = 0; i < CHUNKS; i++) {
        if (maps[i] != MAP_FAILED)
            munmap(maps[i], chunk_len);
        if (fds[i] >= 0)
            close(fds[i]);
    }
}

int main(void)
{
    printf("test-msync: MAP_SHARED msync tests\n\n");

    test_shared_msync_writes_file();
    test_shared_msync_refreshes_peer_mapping();
    test_shared_msync_preserves_alias_writes();
    test_shared_host_write_visible_without_msync();
    test_shared_guest_write_lands_in_file();
    test_shared_adjacent_fixed_mapping_does_not_alias_file();
    test_shared_large_mapping_crosses_split_hvf_segments();
    test_shared_back_to_back_memfd_mappings();
    test_shm_name_visible_after_fork();

    SUMMARY("test-msync");
    return fails ? 1 : 0;
}
