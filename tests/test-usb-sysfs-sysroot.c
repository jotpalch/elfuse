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
 * Three cases are pinned here, the first two after regressions.
 *
 * F1: the USB layer synthesizes /sys/bus/usb and the alias entries of
 * /sys/class/tty. A name it does not model (the rest of /sys/class,
 * /sys/kernel, /sys/devices) must fall through to the sysroot rather than be
 * answered ENOENT, which would shadow the backing /sys and leave the layer
 * self-contradicting: access() reading the sysroot file as present while open()
 * reports it absent. The cubic behavior that must survive: /sys/bus/usb still
 * serves the synthetic tree, and its attributes are still epoll-addable (a real
 * sysfs attribute is pollable through kernfs).
 *
 * F2: a descriptor opened on a synthetic /sys or /dev/bus directory is stamped
 * with the guest spelling. fchdir() onto it must publish that spelling as the
 * virtual cwd, or getcwd leaks the /tmp scratch location, a relative create
 * lands in the read-only tree, and fstatfs reports the /tmp filesystem instead
 * of sysfs. The cubic behavior that must survive: a relative walk resolved
 * against that cwd still reaches the synthetic attributes.
 *
 * F3: the same ownership question for the alias names in /dev. The lane's
 * sysroot carries a regular file at /dev/ttyACM7 and /dev/ttyUSB9 and a foreign
 * link in /dev/serial/by-id, alias-shaped names with no device behind them, and
 * every entry point has to reach them. Listing and lookup are asserted
 * together, absolutely, through a dirfd and through a cwd, and a '..' after the
 * sysroot's /dev/sub lands on the served /dev.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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

/* Whether a by-id leaf names @alias; @leaf receives it. */
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

    /* /sys/class is synthesized (it holds the tty aliases) and backed, so its
     * listing is the union of both.
     */
    TEST("readdir(/sys/class) lists the sysroot's entries");
    EXPECT_TRUE(dir_has_entry("/sys/class", "net"),
                "/sys/class did not list net");

    /* Both sides carry tty, the layer for the aliases and the sysroot for
     * ttyS0, and the union names it once.
     */
    TEST("readdir(/sys/class) lists tty once");
    {
        int ntty = 0;
        DIR *d = opendir("/sys/class");
        struct dirent *e;
        while (d && (e = readdir(d)))
            ntty += !strcmp(e->d_name, "tty");
        if (d)
            closedir(d);
        EXPECT_TRUE(ntty == 1, "/sys/class did not list tty exactly once");
    }

    TEST("an unsynthesized /sys/class subtree reaches the sysroot");
    EXPECT_TRUE(dir_has_entry("/sys/class/net", "eth0"),
                "/sys/class/net did not list eth0");

    /* /sys/class/tty is synthesized for the aliases and backed too, and a tty
     * the sysroot carries is one the layer does not model, so it falls through.
     * A '..' that walks into /sys/class/tty from a backing name still follows
     * the alias link, so the walk lands in the tty directory's parent rather
     * than in /sys/class/tty.
     */
    TEST("/sys/kernel/../class/tty/ttyACM0/.. follows the alias link");
    {
        struct stat via, direct, lexical;
        EXPECT_TRUE(
            stat("/sys/kernel/../class/tty/ttyACM0/..", &via) == 0 &&
                stat("/sys/class/tty/ttyACM0/..", &direct) == 0 &&
                stat("/sys/class/tty", &lexical) == 0 &&
                via.st_ino == direct.st_ino && via.st_ino != lexical.st_ino,
            "the walk did not land where /sys/class/tty/ttyACM0/.. does");
    }

    TEST("/sys/class/tty lists the sysroot's tty next to an alias");
    EXPECT_TRUE(dir_has_entry("/sys/class/tty", "ttyS0") &&
                    dir_has_entry("/sys/class/tty", "ttyACM0"),
                "/sys/class/tty did not list both ttyS0 and ttyACM0");

    TEST("the sysroot's own /sys/class/tty entry reaches the sysroot");
    {
        ssize_t n = read_file("/sys/class/tty/ttyS0/dev", buf, sizeof(buf));
        EXPECT_TRUE(n > 0 && !strcmp(buf, "4:64\n"),
                    "/sys/class/tty/ttyS0/dev did not read 4:64");
    }

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

    /* Every listed name resolves, and a relative spelling through a descriptor
     * or a cwd (chdir and fchdir both) reaches what the absolute one does.
     */
    const char *want[] = {"ttyACM0", "ttyUSB0", "ttyACM7", "ttyUSB9"};
    const size_t nwant = sizeof(want) / sizeof(want[0]);
    bool seen[sizeof(want) / sizeof(want[0])] = {false};
    TEST("every name /dev lists is reachable: absolute, dirfd, chdir, fchdir");
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
                for (size_t i = 0; i < nwant; i++)
                    seen[i] |= !strcmp(e->d_name, want[i]);
                char full[512];
                snprintf(full, sizeof(full), "/dev/%s", e->d_name);
                struct stat a, b, c, f;
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
                if (chdir("/dev") != 0 || fstatat(AT_FDCWD, e->d_name, &c,
                                                  AT_SYMLINK_NOFOLLOW) != 0) {
                    snprintf(bad, sizeof(bad), "%s: chdir lookup says %s",
                             e->d_name, strerror(errno));
                    break;
                }
                if (chdir("/") != 0 || fchdir(dfd) != 0 ||
                    fstatat(AT_FDCWD, e->d_name, &f, AT_SYMLINK_NOFOLLOW) !=
                        0) {
                    snprintf(bad, sizeof(bad), "%s: fchdir lookup says %s",
                             e->d_name, strerror(errno));
                    break;
                }
                if (chdir("/") != 0) {
                    snprintf(bad, sizeof(bad), "chdir back to / says %s",
                             strerror(errno));
                    break;
                }
                if (a.st_ino != b.st_ino || a.st_ino != c.st_ino ||
                    a.st_ino != f.st_ino ||
                    (a.st_mode & S_IFMT) != (b.st_mode & S_IFMT) ||
                    (a.st_mode & S_IFMT) != (c.st_mode & S_IFMT) ||
                    (a.st_mode & S_IFMT) != (f.st_mode & S_IFMT)) {
                    snprintf(bad, sizeof(bad),
                             "%s: absolute, dirfd, chdir and fchdir do not all "
                             "name one object",
                             e->d_name);
                    break;
                }
            }
            closedir(dp);
            if (chdir("/") != 0 && !bad[0])
                snprintf(bad, sizeof(bad), "chdir back to / failed");
            if (bad[0])
                FAIL(bad);
            else
                PASS();
        }
    }

    TEST("/dev lists the aliases and the sysroot's alias-shaped files");
    {
        const char *missing = NULL;
        for (size_t i = 0; i < nwant && !missing; i++)
            if (!seen[i])
                missing = want[i];
        EXPECT_TRUE(!missing, missing ? missing : "");
    }

    TEST("/dev/sub/.. is the served /dev and reaches the alias");
    {
        struct stat dev, up, node;
        EXPECT_TRUE(stat("/dev", &dev) == 0 && stat("/dev/sub/..", &up) == 0 &&
                        dev.st_dev == up.st_dev && dev.st_ino == up.st_ino &&
                        stat("/dev/sub/../ttyACM0", &node) == 0 &&
                        S_ISCHR(node.st_mode),
                    "/dev/sub/.. or /dev/sub/../ttyACM0");
    }

    TEST("chdir /dev/sub/.. publishes /dev");
    {
        char cwd[64];
        EXPECT_TRUE(chdir("/dev/sub/..") == 0 && getcwd(cwd, sizeof(cwd)) &&
                        !strcmp(cwd, "/dev"),
                    "getcwd after chdir(/dev/sub/..)");
        if (chdir("/") != 0)
            FAIL("chdir back to /");
    }

    TEST("every name /dev/serial/by-id lists is reachable");
    {
        DIR *dp = opendir("/dev/serial/by-id");
        char bad[256];
        bool planted = false;
        bad[0] = '\0';
        if (!dp) {
            FAIL("opendir /dev/serial/by-id");
        } else {
            struct dirent *e;
            while ((e = readdir(dp))) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                    continue;
                planted |= !strcmp(e->d_name, "usb-Planted_Link-if00");
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
            if (!bad[0] && !planted)
                snprintf(bad, sizeof(bad), "usb-Planted_Link-if00 not listed");
            if (bad[0])
                FAIL(bad);
            else
                PASS();
        }
    }

    /* A by-id leaf is a symlink to lstat and readlink, the character device to
     * stat and fstat, and ELOOP to O_NOFOLLOW, as on Linux.
     */
    {
        DIR *dp = opendir("/sys/class/tty");
        int seen = 0;
        bool longdev = false;
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

            /* usb_id cuts the manufacturer and product strings to 63 bytes each
             * and drops a serial number holding a comma (systemd
             * src/udev/udev-builtin-usb_id.c), and 60-serial.rules appends
             * -ifNN, so an over-long pair still gets a link. The byidlong
             * device's serial is "A,1".
             */
            if (mn > 100 && pn > 100) {
                longdev = true;
                char want[200];
                man[strcspn(man, "\n")] = '\0';
                prod[strcspn(prod, "\n")] = '\0';
                snprintf(want, sizeof(want), "usb-%.63s_%.63s-if00", man, prod);
                TEST("a manufacturer string past 127 bytes reads whole");
                EXPECT_TRUE(strlen(man) > 127, e->d_name);
                TEST(
                    "an over-long by-id leaf has its strings cut as udev cuts");
                snprintf(why, sizeof(why), "%s: want %s, link %s", e->d_name,
                         want, have ? leaf : "(none)");
                EXPECT_TRUE(have && !strcmp(leaf, want), why);
                continue;
            }

            /* A leaf past NAME_MAX gets no link, whatever APFS would hold: the
             * byidlong device whose serial is 120 bytes. The listing drops such
             * a name anyway, so the lookup is what is asked.
             */
            char ser[256];
            if (alias_dev_attr(e->d_name, "serial", ser, sizeof(ser)) > 120) {
                char lp[640];
                struct stat lst;
                man[strcspn(man, "\n")] = '\0';
                prod[strcspn(prod, "\n")] = '\0';
                ser[strcspn(ser, "\n")] = '\0';
                snprintf(lp, sizeof(lp), "/dev/serial/by-id/usb-%s_%s_%s-if00",
                         man, prod, ser);
                TEST("a by-id leaf past 255 bytes gets no link");
                EXPECT_TRUE(!have && lstat(lp, &lst) != 0, e->d_name);
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

            /* fs/namei.c do_open answers EEXIST and ENOTDIR before may_open
             * answers ELOOP for the symlink.
             */
            TEST("O_DIRECTORY and O_CREAT|O_EXCL win over ELOOP on a leaf");
            int dn = open(link, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            int dnerr = errno;
            int xn = open(link, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            int xnerr = errno;
            snprintf(why, sizeof(why), "%s: O_DIRECTORY %s, O_CREAT|O_EXCL %s",
                     leaf, dn >= 0 ? "opened" : strerror(dnerr),
                     xn >= 0 ? "opened" : strerror(xnerr));
            EXPECT_TRUE(dn < 0 && dnerr == ENOTDIR && xn < 0 && xnerr == EEXIST,
                        why);
            if (dn >= 0)
                close(dn);
            if (xn >= 0)
                close(xn);
        }
        if (dp)
            closedir(dp);
        printf("  by-id links examined: %d\n", seen);
        const char *fixture = getenv("ELFUSE_USB_FIXTURE");
        TEST("the by-id links examined include the fixture's");
        EXPECT_TRUE(
            seen > 0 && (!fixture || strcmp(fixture, "byidlong") || longdev),
            "no by-id link examined, or no long-string device");
    }

    SUMMARY("test-usb-sysfs-sysroot");
    return fails ? 1 : 0;
}
