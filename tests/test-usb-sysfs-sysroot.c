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
 *
 * F3: the same ownership question on the /dev half, which the serial aliases
 * put names into. /dev is the sysroot's directory, not this layer's, so an
 * alias-shaped name with no device behind it belongs to whatever the sysroot
 * has there -- the lane's sysroot plants a regular file at /dev/ttyACM7, a
 * regular file at /dev/ttyUSB9 and a foreign symlink in /dev/serial/by-id, and
 * every entry point has to reach them. Claiming the whole shape and answering
 * ENOENT left readdir listing names that no lookup would resolve, and made a
 * rootfs image's own /dev/ttyUSB0 unreachable. The listing and the lookups are
 * asserted together, and through a dirfd as well as absolutely: a descriptor on
 * /dev has to carry its guest spelling or openat(dirfd, "ttyACM0") reaches the
 * placeholder file the alias node sits on top of.
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
#include <sys/sysmacros.h>
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

/* Read one attribute of the USB device an alias hangs off. The device link
 * lands on the interface dir for ttyACM and one level deeper for ttyUSB, so
 * both spellings are tried; the walk itself is the thing under test in the /sys
 * assertions above.
 */
static ssize_t alias_dev_attr(const char *alias,
                              const char *attr,
                              char *buf,
                              size_t bufsz)
{
    char p[512];
    snprintf(p, sizeof(p), "/sys/class/tty/%s/device/../%s", alias, attr);
    ssize_t n = read_file(p, buf, bufsz);
    if (n >= 0)
        return n;
    snprintf(p, sizeof(p), "/sys/class/tty/%s/device/../../%s", alias, attr);
    return read_file(p, buf, bufsz);
}

/* The by-id leaf naming @alias, or NULL. */
static bool byid_link_for(const char *alias, char *leaf, size_t leafsz)
{
    DIR *dp = opendir("/dev/serial/by-id");
    if (!dp)
        return false;
    char want[64];
    snprintf(want, sizeof(want), "../../%s", alias);
    bool found = false;
    struct dirent *e;
    while (!found && (e = readdir(dp))) {
        if (strncmp(e->d_name, "usb-", 4))
            continue;
        char full[512], tgt[128];
        snprintf(full, sizeof(full), "/dev/serial/by-id/%s", e->d_name);
        ssize_t n = readlink(full, tgt, sizeof(tgt) - 1);
        if (n <= 0)
            continue;
        tgt[n] = '\0';
        if (strcmp(tgt, want))
            continue;
        snprintf(leaf, leafsz, "%s", e->d_name);
        found = true;
    }
    closedir(dp);
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

    /* /sys/class is synthesized (it holds the tty aliases) AND backed, so its
     * listing is a union: the deleted version of this assertion was replaced
     * with the one below it on the premise that the directory is served from
     * the tree instead of the sysroot, which measurement contradicts --
     * usb_sysfs_dir_unions_backing unions every unowned /sys name, and the
     * listing carries tty next to net.
     */
    TEST("readdir(/sys/class) lists the sysroot's entries");
    EXPECT_TRUE(dir_has_entry("/sys/class", "net"),
                "/sys/class did not list net");

    TEST("readdir(/sys/class) lists the synthesized entries too");
    EXPECT_TRUE(dir_has_entry("/sys/class", "tty"),
                "/sys/class did not list tty");

    TEST("an unsynthesized /sys/class subtree reaches the sysroot");
    EXPECT_TRUE(dir_has_entry("/sys/class/net", "eth0"),
                "/sys/class/net did not list eth0");

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

    if (chdir("/") != 0)
        FAIL("chdir back to /");

    /* F3: the /dev half of the ownership question */

    TEST("an alias-shaped name the sysroot owns reaches the sysroot");
    {
        ssize_t n = read_file("/dev/ttyACM7", buf, sizeof(buf));
        if (n < 0)
            FAIL(
                "open /dev/ttyACM7 (the layer claimed a name it does not "
                "serve)");
        else if (strcmp(buf, "planted-acm7\n") != 0)
            FAIL("wrong /dev/ttyACM7 content");
        else
            PASS();
    }

    TEST("stat of a sysroot-owned alias-shaped name reports its file");
    {
        struct stat st;
        EXPECT_TRUE(stat("/dev/ttyUSB9", &st) == 0 && S_ISREG(st.st_mode),
                    "/dev/ttyUSB9 should be the sysroot's regular file");
    }

    TEST("an alias-shaped name nothing carries is ENOENT");
    EXPECT_ERRNO(open("/dev/ttyACM31", O_RDONLY), ENOENT,
                 "an unserved, unbacked alias name should be ENOENT");

    TEST("a foreign by-id entry reaches the sysroot's own link");
    {
        char tgt[128];
        ssize_t n = readlink("/dev/serial/by-id/usb-Planted_Link-if00", tgt,
                             sizeof(tgt) - 1);
        if (n <= 0) {
            FAIL("readlink the sysroot's own by-id entry");
        } else {
            tgt[n] = '\0';
            EXPECT_TRUE(strcmp(tgt, "../../ttyACM7") == 0,
                        "wrong target for the sysroot's by-id entry");
        }
    }

    /* Every name a directory lists has to be a name its lookups resolve, and
     * the relative spelling has to reach the same object as the absolute one.
     */
    TEST("every name /dev lists is reachable, absolutely and through a dirfd");
    {
        DIR *dp = opendir("/dev");
        char bad[256];
        bad[0] = '\0';
        if (!dp) {
            FAIL("opendir /dev");
        } else {
            int dfd = dirfd(dp);
            struct dirent *e;
            while ((e = readdir(dp))) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                    continue;
                if (strncmp(e->d_name, "tty", 3) && strcmp(e->d_name, "serial"))
                    continue;
                char full[512];
                snprintf(full, sizeof(full), "/dev/%s", e->d_name);
                struct stat a, b;
                if (lstat(full, &a) != 0) {
                    snprintf(bad, sizeof(bad), "%s listed but lstat says %s",
                             e->d_name, strerror(errno));
                    break;
                }
                if (fstatat(dfd, e->d_name, &b, AT_SYMLINK_NOFOLLOW) != 0) {
                    snprintf(bad, sizeof(bad), "%s: dirfd lookup says %s",
                             e->d_name, strerror(errno));
                    break;
                }
                if (a.st_ino != b.st_ino ||
                    (a.st_mode & S_IFMT) != (b.st_mode & S_IFMT)) {
                    snprintf(bad, sizeof(bad),
                             "%s: absolute and dirfd name different objects",
                             e->d_name);
                    break;
                }
            }
            closedir(dp);
            if (bad[0])
                FAIL(bad);
            else
                PASS();
        }
    }

    TEST("every name /dev/serial/by-id lists is reachable");
    {
        DIR *dp = opendir("/dev/serial/by-id");
        char bad[256];
        bad[0] = '\0';
        if (!dp) {
            FAIL("opendir /dev/serial/by-id");
        } else {
            struct dirent *e;
            while ((e = readdir(dp))) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                    continue;
                char full[512], tgt[128];
                snprintf(full, sizeof(full), "/dev/serial/by-id/%s", e->d_name);
                struct stat st;
                if (lstat(full, &st) != 0 ||
                    readlink(full, tgt, sizeof(tgt) - 1) <= 0) {
                    snprintf(bad, sizeof(bad), "%s listed but not resolvable",
                             e->d_name);
                    break;
                }
            }
            closedir(dp);
            if (bad[0])
                FAIL(bad);
            else
                PASS();
        }
    }

    /* The by-id layer, from every end. A leaf is a symlink to lstat and to
     * readlink, the character device it points at to stat and to a descriptor's
     * fstat, and ELOOP to O_NOFOLLOW -- the shapes Linux gives a symlink onto a
     * device node. Reported as a link by stat() it was not: no Linux stat()
     * returns S_IFLNK, and a by-id fd used to carry the macOS callout identity
     * while the alias fd for the same device carried the Linux one.
     */
    {
        DIR *dp = opendir("/sys/class/tty");
        int seen = 0;
        struct dirent *e;
        while (dp && (e = readdir(dp))) {
            if (strncmp(e->d_name, "ttyACM", 6) &&
                strncmp(e->d_name, "ttyUSB", 6))
                continue;

            char leaf[256], link[512], node[128], why[512];
            char man[256], prod[256];
            ssize_t mn =
                alias_dev_attr(e->d_name, "manufacturer", man, sizeof(man));
            ssize_t pn =
                alias_dev_attr(e->d_name, "product", prod, sizeof(prod));
            bool have = byid_link_for(e->d_name, leaf, sizeof(leaf));

            /* A leaf that cannot hold the strings AND the -ifNN suffix gets no
             * link at all, the way an unbuildable name already did. Truncating
             * it instead gave two interfaces of one device the same 223-byte
             * name, so the second link replaced the first while lookups kept
             * answering with the first.
             */
            if (mn > 100 && pn > 100) {
                TEST(
                    "an over-long by-id leaf yields no link rather than a "
                    "truncated one");
                snprintf(why, sizeof(why),
                         "%s: manufacturer %zd + product %zd bytes, link %s",
                         e->d_name, mn, pn, have ? leaf : "(none)");
                EXPECT_TRUE(!have, why);
                continue;
            }
            if (!have) {
                TEST("every alias has a by-id link");
                snprintf(why, sizeof(why), "%s has none", e->d_name);
                FAIL(why);
                continue;
            }
            seen++;
            snprintf(link, sizeof(link), "/dev/serial/by-id/%s", leaf);
            snprintf(node, sizeof(node), "/dev/%s", e->d_name);

            struct stat lst, bst, ast;
            TEST("lstat of a by-id leaf reports the link");
            EXPECT_TRUE(lstat(link, &lst) == 0 && S_ISLNK(lst.st_mode), leaf);

            TEST("stat of a by-id leaf reports the alias character device");
            int rb = stat(link, &bst), ra = stat(node, &ast);
            snprintf(why, sizeof(why), "%s: stat %s", leaf,
                     rb == 0 ? "ok" : strerror(errno));
            EXPECT_TRUE(rb == 0 && ra == 0 && S_ISCHR(bst.st_mode) &&
                            bst.st_rdev == ast.st_rdev &&
                            bst.st_ino == ast.st_ino,
                        why);

            TEST("a by-id fd fstats as the alias node, not the host tty");
            int fd = open(link, O_RDONLY | O_NONBLOCK | O_NOCTTY);
            if (fd < 0) {
                snprintf(why, sizeof(why), "%s: %s", leaf, strerror(errno));
                FAIL(why);
            } else {
                struct stat fst;
                int rc = fstat(fd, &fst);
                snprintf(why, sizeof(why),
                         "%s: node rdev %u:%u, by-id fd rdev %u:%u", leaf,
                         (unsigned) major(ast.st_rdev),
                         (unsigned) minor(ast.st_rdev),
                         (unsigned) major(fst.st_rdev),
                         (unsigned) minor(fst.st_rdev));
                EXPECT_TRUE(rc == 0 && S_ISCHR(fst.st_mode) &&
                                fst.st_rdev == ast.st_rdev &&
                                fst.st_ino == ast.st_ino,
                            why);
                close(fd);
            }

            TEST("O_NOFOLLOW on a by-id leaf is ELOOP");
            int nf = open(link, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
            int nferr = errno;
            snprintf(why, sizeof(why), "%s: %s", leaf,
                     nf >= 0 ? "opened" : strerror(nferr));
            EXPECT_TRUE(nf < 0 && nferr == ELOOP, why);
            if (nf >= 0)
                close(nf);
        }
        if (dp)
            closedir(dp);
        printf("  by-id links examined: %d\n", seen);
    }

    SUMMARY("test-usb-sysfs-sysroot");
    return fails ? 1 : 0;
}
