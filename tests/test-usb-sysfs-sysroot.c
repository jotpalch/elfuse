/*
 * The synthetic USB /sys view sharing /sys with a populated sysroot
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: the /sys ours/not-ours split in src/runtime/usb-sysfs.c and
 * the /sys + /dev/bus arms of sys_fchdir (src/syscall/fs.c) and
 * resolve_proc_cwd_path (src/syscall/path.c).
 *
 * Run under --sysroot over a tree that carries a real /sys skeleton
 * (/sys/class/net/eth0/address, /sys/kernel/mm/transparent_hugepage/enabled,
 * /sys/devices/system/node/online) and with ELFUSE_USB_FIXTURE set so the USB
 * tree carries two deterministic devices with no hardware attached.
 *
 * Two regressions are pinned here.
 *
 * F1: the USB layer synthesizes only /sys/bus/usb. A name it does not model
 * (everything under /sys/class, /sys/kernel, /sys/devices) must fall through to
 * the sysroot rather than be answered ENOENT, which would shadow the backing
 * /sys and leave the layer self-contradicting -- access() reading the sysroot
 * file as present while open() reports it absent. The cubic behavior that must
 * survive: /sys/bus/usb still serves the synthetic tree, and its attributes are
 * still epoll-addable (a real sysfs attribute is pollable through kernfs).
 *
 * F2: a descriptor opened on a synthetic /sys or /dev/bus directory is stamped
 * with the guest spelling. fchdir() onto it must publish that spelling as the
 * virtual cwd, or getcwd leaks the /tmp scratch location, a relative create
 * lands in the read-only tree, and fstatfs reports the /tmp filesystem instead
 * of sysfs. The cubic behavior that must survive: a relative walk resolved
 * against that cwd still reaches the synthetic attributes.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define SYSFS_MAGIC 0x62656572

/* Read a whole small file; returns bytes read or -1. */
static ssize_t read_file(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n >= 0)
        buf[n] = '\0';
    return n;
}

static bool dir_has_entry(const char *dir, const char *name)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, name)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

int main(void)
{
    char buf[256];

    printf(
        "test-usb-sysfs-sysroot: /sys fall-through and fchdir containment\n");

    /* F1: sysroot-backed /sys names reach the sysroot again */

    TEST("a /sys attribute we do not model opens from the sysroot");
    {
        ssize_t n = read_file("/sys/class/net/eth0/address", buf, sizeof(buf));
        if (n < 0)
            FAIL("open/read /sys/class/net/eth0/address");
        else if (strcmp(buf, "02:42:ac:11:00:02\n") != 0)
            FAIL("wrong /sys/class/net/eth0/address content");
        else
            PASS();
    }

    TEST("access() and open() agree on the sysroot /sys file");
    {
        int a = access("/sys/class/net/eth0/address", R_OK);
        int fd = open("/sys/class/net/eth0/address", O_RDONLY);
        if (a == 0 && fd >= 0)
            PASS();
        else
            FAIL("access/open disagree (readable but unopenable)");
        if (fd >= 0)
            close(fd);
    }

    TEST("readdir(/sys/class) lists the sysroot's entries");
    EXPECT_TRUE(dir_has_entry("/sys/class", "net"),
                "/sys/class did not list net");

    TEST("/sys/kernel attribute reaches the sysroot");
    EXPECT_TRUE(read_file("/sys/kernel/mm/transparent_hugepage/enabled", buf,
                          sizeof(buf)) > 0,
                "open /sys/kernel/mm/transparent_hugepage/enabled");

    TEST("/sys/devices attribute reaches the sysroot");
    EXPECT_TRUE(
        read_file("/sys/devices/system/node/online", buf, sizeof(buf)) > 0,
        "open /sys/devices/system/node/online");

    /* F1 cubic: /sys/bus/usb is still ours and still pollable */

    TEST("/sys/bus/usb/devices still serves the synthetic tree");
    {
        struct stat st;
        if (stat("/sys/bus/usb/devices", &st) == 0 && S_ISDIR(st.st_mode))
            PASS();
        else
            FAIL("stat /sys/bus/usb/devices");
    }

    TEST("a synthetic USB attribute reads its value");
    {
        ssize_t n =
            read_file("/sys/bus/usb/devices/1-1/idVendor", buf, sizeof(buf));
        if (n < 0)
            FAIL("open /sys/bus/usb/devices/1-1/idVendor");
        else if (strcmp(buf, "1d6b\n") != 0)
            FAIL("wrong idVendor");
        else
            PASS();
    }

    TEST("a synthetic USB attribute is still epoll-addable");
    {
        int afd = open("/sys/bus/usb/devices/1-1/idVendor", O_RDONLY);
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN};
        int rc = -1;
        if (afd >= 0 && ep >= 0)
            rc = epoll_ctl(ep, EPOLL_CTL_ADD, afd, &ev);
        if (rc == 0)
            PASS();
        else
            FAIL("epoll_ctl ADD on a sysfs attribute (cubic 3862484162)");
        if (afd >= 0)
            close(afd);
        if (ep >= 0)
            close(ep);
    }

    /* A missing name under the subtree we own stays ENOENT, not a fall-through
     * (nothing in the sysroot carries it either, but the answer is ours).
     */
    TEST("a missing device under /sys/bus/usb is ENOENT");
    EXPECT_ERRNO(open("/sys/bus/usb/devices/9-9/idVendor", O_RDONLY), ENOENT,
                 "missing owned name should be ENOENT");

    /* F2: fchdir onto a synthetic /sys directory is contained */

    TEST("fchdir onto /sys/bus/usb/devices keeps the guest cwd");
    {
        int fd = open("/sys/bus/usb/devices", O_RDONLY | O_DIRECTORY);
        char cwd[256];
        if (fd < 0) {
            FAIL("open /sys/bus/usb/devices O_DIRECTORY");
        } else if (fchdir(fd) < 0) {
            FAIL("fchdir onto /sys/bus/usb/devices");
            close(fd);
        } else if (!getcwd(cwd, sizeof(cwd))) {
            FAIL("getcwd after fchdir");
            close(fd);
        } else if (strcmp(cwd, "/sys/bus/usb/devices") != 0) {
            FAIL("getcwd leaked the scratch tree location");
            close(fd);
        } else {
            PASS();
            close(fd);
        }
    }

    /* cwd is /sys/bus/usb/devices from here on. */

    TEST("a relative create against the /sys cwd cannot write the tree");
    EXPECT_ERRNO(open("intruder", O_WRONLY | O_CREAT, 0644), EACCES,
                 "relative O_CREAT should be refused, not land in the tree");

    TEST("fstatfs of a fd opened at the /sys cwd reports sysfs");
    {
        int fd = open(".", O_RDONLY | O_DIRECTORY);
        struct statfs sfs;
        if (fd < 0) {
            FAIL("open . at /sys cwd");
        } else if (fstatfs(fd, &sfs) < 0) {
            FAIL("fstatfs");
            close(fd);
        } else if ((unsigned) sfs.f_type != SYSFS_MAGIC) {
            FAIL("fstatfs did not report SYSFS_MAGIC (leaked /tmp fs)");
            close(fd);
        } else {
            PASS();
            close(fd);
        }
    }

    TEST("a relative walk against the /sys cwd reaches the attribute");
    {
        ssize_t n = read_file("1-1/idVendor", buf, sizeof(buf));
        if (n > 0 && strcmp(buf, "1d6b\n") == 0)
            PASS();
        else
            FAIL("relative 1-1/idVendor against the /sys cwd");
    }

    SUMMARY("test-usb-sysfs-sysroot");
    return fails ? 1 : 0;
}
