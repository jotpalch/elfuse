/*
 * Sysroot containment regression: relative-path symlink escape
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * proc_resolve_sysroot_path_flags() only runs its sysroot-prefix + realpath()
 * containment check on absolute guest paths, since it has no dirfd context to
 * rebuild a host location from a relative one. That left openat(dirfd, name) to
 * the host kernel's own resolution, unconfined to dirfd's subtree: a symlink
 * reachable through a sysroot-contained dirfd with a relative target holding
 * enough ".." components could walk straight out of the sysroot with no check
 * at all. path_translate_at() now reconstructs the absolute guest path from the
 * dirfd's guest base path and re-validates it through the same resolver the
 * absolute-path surface uses.
 *
 * The Makefile target stages an absolute-target symlink and a relative-target
 * (deep "..") symlink under $sysroot/d1, both pointing at a host file outside
 * the sysroot, plus a normal in-sysroot file. The absolute target is a host
 * bridge and should follow; the relative climb-out is still blocked.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

int main(void)
{
    printf("test-sysroot-symlink-escape: relative-dirfd symlink containment\n");

    int dirfd = open("/d1", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /d1 failed");
        SUMMARY("test-sysroot-symlink-escape");
        return 1;
    }

    TEST("legitimate relative open still works");
    {
        int fd = openat(dirfd, "normal.txt", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            PASS();
        } else {
            FAIL("openat(dirfd, normal.txt) failed");
        }
    }

    TEST("absolute-target symlink bridge via dirfd is followed");
    {
        int fd = openat(dirfd, "abs-link", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            PASS();
        } else
            FAIL("openat(dirfd, abs-link) failed");
    }

    TEST("relative link to absolute-target bridge via dirfd is followed");
    {
        int fd = openat(dirfd, "chain-link", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            PASS();
        } else
            FAIL("openat(dirfd, chain-link) failed");
    }

    TEST("relative \"..\" symlink escape via dirfd is blocked");
    {
        int fd = openat(dirfd, "rel-link", O_RDONLY);
        if (fd < 0 && errno == ELOOP)
            PASS();
        else {
            if (fd >= 0)
                close(fd);
            FAIL("openat(dirfd, rel-link) did not fail with ELOOP");
        }
    }

    /* A bridge to a host *directory* outside the sysroot, walked relatively.
     *
     * The host openat fails -- macOS has no /dev/bus and no /dev/shm -- and the
     * ENOENT fallback that exists for systemd's chase() then rebuilds a
     * guest-absolute spelling from the descriptor. path_host_to_guest passes a
     * host path that is not under the sysroot through unchanged, so the
     * descriptor on the host's /dev rebased to the guest-absolute "/dev" and
     * the retry handed the walk to the /dev/bus/usb and /dev/shm intercepts: a
     * name resolved outside the guest namespace came back answered from inside
     * it. Both names must stay ENOENT, which is what the host already said.
     */
    int devfd = openat(dirfd, "dev-bridge", O_RDONLY | O_DIRECTORY);
    TEST("a bridge to a host directory outside the sysroot opens");
    if (devfd < 0) {
        FAIL("openat(dirfd, dev-bridge) failed");
    } else {
        PASS();
        static const char *const names[] = {"bus/usb", "shm", "bus"};
        for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            TEST(
                "a relative walk off it is not retargeted into the intercepts");
            errno = 0;
            int fd = openat(devfd, names[i], O_RDONLY);
            if (fd >= 0) {
                close(fd);
                printf("      %s answered from the intercept namespace\n",
                       names[i]);
                FAIL("openat off the host bridge was retargeted");
            } else if (errno != ENOENT) {
                printf("      %s: errno=%d\n", names[i], errno);
                FAIL("openat off the host bridge answered the wrong errno");
            } else {
                PASS();
            }
        }
        close(devfd);
    }

    close(dirfd);

    TEST("AT_FDCWD relative escape is blocked after chdir");
    {
        if (chdir("/d1") < 0) {
            FAIL("chdir /d1 failed");
        } else {
            int fd = open("rel-link", O_RDONLY);
            if (fd < 0 && errno == ELOOP)
                PASS();
            else {
                if (fd >= 0)
                    close(fd);
                FAIL("open(AT_FDCWD, rel-link) did not fail with ELOOP");
            }
        }
    }

    SUMMARY("test-sysroot-symlink-escape");
    return fails > 0 ? 1 : 0;
}
