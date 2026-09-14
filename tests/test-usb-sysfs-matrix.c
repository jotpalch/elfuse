/*
 * Entry-point x path-class matrix for the synthetic /sys and /dev/bus views
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: the ours/not-ours decision in src/runtime/usb-sysfs.c
 * (classify_and_normalize + usb_resolve_or_disown), the getdents64 union in
 * src/syscall/fs.c, the access arm of sys_faccessat, and the fd-side sysfs
 * identity in sys_fstatfs (src/syscall/fs-stat.c).
 *
 * The layer synthesizes /sys/bus/usb, /sys/class/tty, /sys/bus/usb-serial and
 * /dev/bus/usb whole, and plants individual names -- ttyACM<n>, ttyUSB<n> and
 * the by-id leaves -- into /dev and /dev/serial/by-id, which stay the sysroot's
 * directories. Everything else on both sides is the sysroot's. Its contract is
 * not per-syscall: a name is this layer's or it is not, and every entry point
 * has to answer from that one decision. Four regressions all came from an entry
 * point re-deriving it -- lstat/open(O_NOFOLLOW)/readlink shadowed the backing
 * because their resolve succeeded where stat's failed, getdents64 replaced the
 * backing listing instead of extending it, /dev/bus had no fall-through arm at
 * all while access(2) fell through anyway, fstatfs never saw the sysfs identity
 * statfs was handing out, and the alias names were claimed by shape so an
 * alias-shaped file the sysroot really had answered ENOENT to every lookup
 * while readdir went on listing it. Pinning them one assertion at a time is
 * what let them appear, so this is a matrix instead: every entry point against
 * every path class, so a fix that unifies one pair and splits another cannot
 * pass.
 *
 * EXPECTED VALUES ARE MEASURED, NOT ASSUMED. Every cell below was recorded by
 * running this same binary natively on Linux (docker gcc:14, aarch64) with
 * MATRIX_RECORD=1, over a /sys that is a real sysfs and a /dev carrying a
 * mknod'd usb node next to a foreign bus directory, an alias node, an
 * alias-shaped regular file and a by-id link onto the alias. Re-record with:
 *
 *   docker run --rm -v "$PWD:/w" -w /w gcc:14 sh -c \
 *     'mkdir -p /dev/bus/usb/001 /dev/bus/other /dev/serial/by-id && \
 *      : > /dev/bus/other/f && mknod /dev/bus/usb/001/001 c 189 0 && \
 *      mknod /dev/ttyACM0 c 166 0 && printf planted > /dev/ttyACM7 && \
 *      ln -sf ../../ttyACM0 /dev/serial/by-id/usb-Rec_Device_0001-if00 && \
 *      gcc -D MATRIX_STANDALONE -o /tmp/m tests/test-usb-sysfs-matrix.c && \
 *      MATRIX_RECORD=1 /tmp/m'
 *
 * The block was first recorded on a 6.x Linux kernel and re-recorded on a 7.0
 * one for the tty-dot-node column. Comparing that recording against this file,
 * 19 of the 23 rows come back byte-identical; open, open_nofollow, openat_dirfd
 * and epoll_ctl differ in 31 cells, every one of them a cell this file writes
 * as "-" where the recorder printed E1. That is the per-class case the notes on
 * COL_SUBSYS and COL_NODE describe rather than a kernel difference, and reading
 * both markers back in makes the two recordings agree, so no value here rests
 * on one Linux kernel version alone.
 *
 * Cells the guest cannot match byte-for-byte are recorded per class rather than
 * per spelling; see the notes on COL_SUBSYS and COL_NODE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifdef MATRIX_STANDALONE
/* Recording build: runs natively on Linux with no elfuse harness. The four
 * harness macros the assertions below use are spelled out here rather than
 * included, because test-harness.h is built for the guest side.
 */
#include <sys/syscall.h>
static int passes, fails;
#define TEST(name) printf("  %-30s ", name)
#define PASS() (printf("OK\n"), passes++)
#define FAIL(msg) (printf("FAIL: %s\n", msg), fails++)
#define EXPECT_TRUE(cond, msg)                    \
    do {                                          \
        if (cond)                                 \
            passes++;                             \
        else                                      \
            (fails++, printf("FAIL: %s\n", msg)); \
    } while (0)
#else
#include "test-harness.h"
int passes = 0, fails = 0;
#endif

#define SYSFS_MAGIC 0x62656572
#define CELL_MAX 40

/* path classes (columns) */
enum {
    COL_SYNTH_DIR,  /* a directory this layer synthesizes */
    COL_BACK_SYS,   /* a /sys name the backing owns and we do not */
    COL_BACK_DEV,   /* a /dev/bus name the backing owns and we do not */
    COL_SUBSYS,     /* a subsystem symlink inside a device directory */
    COL_ESCAPE,     /* a '..' chain that leaves the tree entirely */
    COL_ESCAPE_SYN, /* the same, but transiting the synthetic subtree */
    COL_NODE,       /* a /dev/bus/usb device node */
    COL_ABSENT,     /* a name absent on both sides */
    COL_LONG,       /* a /sys spelling longer than the 63-byte fd stamp */
    COL_SYS_ROOT,   /* /sys itself: synthetic and backed at once */
    COL_DEV_BUS,    /* /dev/bus itself: synthetic and backed at once */
    COL_SHADOW,     /* a backing name inside a subtree this layer owns */
    COL_SUBSYS_OUT, /* a walk through the subsystem link and back out of usb */
    COL_FOLD_OUT, /* a '..' out of /dev/bus/usb onto a name the backing owns */
    COL_FOLD_IN,  /* a '..' out of a foreign bus and back into /dev/bus/usb */
    COL_SYS_FOLD_IN,  /* a '..' out of a backing /sys name and back into ours */
    COL_SYS_FOLD_IN2, /* the same, through a /sys name the scratch tree lacks */
    COL_TTY,          /* a live ttyACM alias node */
    COL_TTY_BACK,     /* an alias-shaped name only the backing has */
    COL_TTY_ABSENT,   /* an alias-shaped name absent on both sides */
    COL_BYID,         /* a /dev/serial/by-id leaf, discovered */
    COL_TTY_FOLD,     /* the alias node spelled through a '..' */
    COL_SLASH_DIR,    /* a /dev/bus/usb directory spelled with a leading "//" */
    COL_DOT_DIR,      /* the same directory spelled with a "." component */
    COL_SLASH_NODE,   /* a usbfs node spelled with a leading "//" */
    COL_DOT_NODE,     /* the same node spelled with a "." component */
    COL_FOLD2_DIR,    /* the same directory, "." and "//" interleaved */
    COL_FOLD2_NODE,   /* the same node, "." and "//" interleaved */
    COL_FOLD2_SYS,    /* a /sys directory, "." and "//" interleaved */
    COL_FOLD3_DIR,    /* the same directory, two "." before the "//" */
    COL_SUBSYS_OUT_SLASH, /* subsys-out spelled with a leading "//" */
    COL_TTY_DOT_NODE,     /* an alias node with a trailing "." component */
    COL_COUNT,
};

static const char *col_name[COL_COUNT] = {
    "synth-dir",    "back-sys",     "back-dev",         "subsys",
    "escape",       "escape-syn",   "usb-node",         "absent",
    "long-sys",     "sys-root",     "dev-bus",          "shadow",
    "subsys-out",   "dev-fold-out", "dev-fold-in",      "sys-fold-in",
    "sys-fold-in2", "tty-alias",    "tty-planted",      "tty-absent",
    "byid-link",    "tty-fold",     "slash-dir",        "dot-dir",
    "slash-node",   "dot-node",     "fold2-dir",        "fold2-node",
    "fold2-sys",    "fold3-dir",    "subsys-out-slash", "tty-dot-node",
};

/* The fold2/fold3 columns spell the objects of the four columns above them with
 * a "." component and a "//" run interleaved rather than one or the other.
 * "/.//x" is the shortest name where stepping over the "." uncovers a "//" that
 * was not there to be seen first, and "/././/x" is the same one turn deeper, so
 * a fold that runs one pass of each rather than to a fixpoint leaves "//x" and
 * every literal prefix test behind it misses. That is not hypothetical: the
 * commit that taught the gates to fold introduced exactly that shape, and these
 * spellings then stat'd, access'd and opened as ENOENT while statfs answered
 * TMPFS_MAGIC and chdir landed the process inside the tree. The statfs row
 * stays green through all of that, folding every component rather than the
 * leading run; fstatfs is the row that reddens with the three above it, needing
 * the open that failed. fold2-sys walks the /sys half of the same split, which
 * parted the same way.
 *
 * Like the four columns above, every cell here is the cell of the canonical
 * spelling beside it, because a leading "." or "//" run never changes which
 * object a path names however many times the two alternate. Leading: a trailing
 * "." carries Linux's directory requirement the way a trailing slash does, and
 * no column here spells one.
 */

/* COL_TTY_DOT_NODE is the alias node with a trailing "." component, and it is
 * the column that holds chdir to the answer the other entry points give for a
 * device node used as a directory. The gate that routes a chdir into the
 * synthetic trees used to spell its own prefix list -- /sys and /dev/bus --
 * while the alias names sit directly under /dev, so a chdir onto one matched
 * neither arm and fell through to the host, where the name is a placeholder
 * file in the sysroot or nothing at all: chdir answered ENOENT where open,
 * fchdir and getdents answered ENOTDIR, and where the /dev/bus node beside it
 * has answered ENOTDIR since before this series. The gate asks the USB layer
 * the ownership question now, so the two spellings agree.
 *
 * Thirteen of its cells are the inherited trailing-"." divergence, recorded as
 * XFAIL: the component fold drops the "." and the node is served where Linux
 * answers ENOTDIR, exactly as it is for /dev/bus/usb/001/001/. on main. That
 * divergence is what leaves the four cells below it -- getdents64, chdir,
 * fchdir and getcwd -- as the ones this column asserts, and chdir is the one
 * that was wrong: with the gate's literal put back, chdir and the getcwd that
 * follows it go red and the rest stay green.
 */

/* COL_SUBSYS is the one spelling that cannot be shared: the recording host's
 * bus carries whatever devices it has, and the guest's carries the fixture's.
 * Both are "the subsystem link of some /sys/bus/usb/devices/<dev>", which is
 * the class under test, so the spelling is discovered rather than hardcoded.
 */
static char subsys_path[512];

/* COL_SUBSYS_OUT is the same link walked *through* rather than named: the
 * kernel applies the '..' after it to what the link resolved to, so
 * <dev>/subsystem/.. is /sys/bus and <dev>/subsystem/../pci is /sys/bus/pci --
 * a bus this layer does not model, which only the backing has.
 *
 * It is the column that catches ownership being decided on the lexical fold.
 * That fold reads the same name as <dev>/pci, which starts with bus/usb and so
 * looks like ours, and an absence under our own subtree is authoritative: every
 * lookup answered ENOENT while the *listing* of <dev>/subsystem/.. was offering
 * `pci` from the backing in the same breath. Derived from subsys_path so it
 * follows whichever device the host actually has.
 */
static char subsys_out_path[512];

/* COL_SUBSYS_OUT_SLASH is subsys-out with a leading "//", and it is the cell
 * that holds the link-rewrite gate to the fold the entry points behind it do.
 * That gate reads a literal deeper than the first component, so it has to fold
 * the whole name; the gates in front of it step over the leading run, so an
 * unfolded spelling reaches the layer with the link unresolved and each entry
 * point then answers from whatever it folds for itself.
 *
 * What this column holds is that failure in its uniform form, not a split
 * between entry points. It walks out onto /sys/bus/pci, a bus only the sysroot
 * has, so an unresolved link leaves nothing for any entry point to find:
 * measured with the gate fold reverted, //sys/bus/usb/devices/<dev>/subsystem/
 * ../pci answers ENOENT at every entry point with a sysroot and without one,
 * and seventeen of its cells go red. fold2-sys cannot hold that: it spells a
 * directory no synthetic link is walked through, so the gate literal matches it
 * before and after.
 *
 * The split itself is one cell further along and no column spells it. It needs
 * a name that ends inside the subtree this layer owns, so the entry points that
 * fold for themselves can still find it: with the same gate fold reverted,
 * //sys/bus/usb/devices/<dev>/subsystem/../usb is served by stat, lstat,
 * access, fstatat, open, fstat, fstatfs, chdir, fchdir and getdents while
 * statfs alone answers ENOENT -- ten entry points in, one out, with a sysroot
 * and without one, and under the fixture this lane runs and against an attached
 * board alike, each with the device key its own source presents. The two
 * spellings are the same defect seen at two depths, and the one that reddens
 * seventeen cells is the one worth asserting.
 *
 * Every cell is subsys-out's, for the reason the fold columns give: a leading
 * "//" run never changes which object a path names.
 */

static char subsys_out_slash_path[512];

/* COL_LONG is a >63-byte spelling of a synthetic sysfs *attribute*, not of a
 * backing file: the 63-byte virtual-path stamp a descriptor carries is only
 * written for the names this layer serves, so that is where a truncation would
 * cut a component in half. It is built by repeating "<dev>/.." until the
 * spelling passes the stamp's width, which also puts a '..' behind the
 * devices/<dev> symlink -- Linux applies it to what the link resolved to, and
 * the same object has to come back out. The device name differs between the
 * recording host and the guest fixture, so it is discovered too.
 */
static char long_path[512];

/* COL_BYID is discovered for the same reason COL_SUBSYS is: the leaf udev
 * builds carries the device's own strings, so the recording host's spelling and
 * the guest fixture's are different names for the same class of object -- a
 * symlink in /dev/serial/by-id pointing at a ttyACM node.
 */
static char byid_path[512];

static const char *col_path(int c)
{
    switch (c) {
    case COL_SYNTH_DIR:
        return "/sys/bus/usb/devices";
    case COL_BACK_SYS:
        return "/sys/class";
    case COL_BACK_DEV:
        return "/dev/bus/other/f";
    case COL_SUBSYS:
        return subsys_path;
    case COL_ESCAPE:
        return "/sys/class/../../etc/hostname";
    case COL_ESCAPE_SYN:
        return "/sys/bus/usb/../../../etc/hostname";
    case COL_NODE:
        return "/dev/bus/usb/001/001";
    case COL_ABSENT:
        return "/sys/no-such-name-here";
    case COL_LONG:
        return long_path;
    case COL_SYS_ROOT:
        return "/sys";
    case COL_SHADOW:
        return "/dev/bus/usb/099/001";
    case COL_SUBSYS_OUT:
        return subsys_out_path;
    case COL_FOLD_OUT:
        return "/dev/bus/usb/../other/f";
    case COL_FOLD_IN:
        return "/dev/bus/other/../usb/001/001";
    case COL_SYS_FOLD_IN:
        return "/sys/class/../bus/usb/devices";
    case COL_SYS_FOLD_IN2:
        return "/sys/devices/../bus/usb/devices";
    case COL_TTY:
        return "/dev/ttyACM0";
    case COL_TTY_BACK:
        return "/dev/ttyACM7";
    case COL_TTY_ABSENT:
        return "/dev/ttyACM31";
    case COL_BYID:
        return byid_path;
    case COL_TTY_FOLD:
        return "/dev/serial/by-id/../../ttyACM0";
    case COL_SLASH_DIR:
        return "//dev/bus/usb/001";
    case COL_DOT_DIR:
        return "/dev/./bus/usb/001";
    case COL_SLASH_NODE:
        return "//dev/bus/usb/001/001";
    case COL_DOT_NODE:
        return "/dev/./bus/usb/001/001";
    case COL_FOLD2_DIR:
        return "/.//dev/bus/usb/001";
    case COL_FOLD2_NODE:
        return "/.//dev/bus/usb/001/001";
    case COL_FOLD2_SYS:
        return "/.//sys/bus/usb/devices";
    case COL_FOLD3_DIR:
        return "/././/dev/bus/usb/001";
    case COL_SUBSYS_OUT_SLASH:
        return subsys_out_slash_path;
    case COL_TTY_DOT_NODE:
        return "/dev/ttyACM0/.";
    default:
        return "/dev/bus";
    }
}

/* COL_SHADOW is the mirror of COL_BACK_DEV: a name the *backing* carries inside
 * /dev/bus/usb, one of the two subtrees this layer owns, on a bus number no
 * device has. Ownership runs both ways -- the layer falls through for the
 * backing's names outside its subtrees, and the backing must not surface inside
 * them -- so the sysroot fixture plants this file and every entry point still
 * has to report what Linux reports for a name that is simply not there.
 *
 * It is the column that holds the "claimed and then failed" arm. Only
 * PROC_NOT_INTERCEPTED means "ask the backing"; taking a claimed name's failure
 * as one too let access(2), and then statfs(2), answer from the backing here
 * while open and stat reported ENOENT for the same path.
 */

/* COL_FOLD_OUT and COL_FOLD_IN are the two spellings that cross the /dev/bus
 * ownership boundary through a '..'. They are the same two names COL_BACK_DEV
 * and COL_NODE already carry, written so that the component deciding ownership
 * is not the one the object ends up under: /dev/bus/usb/../other/f is
 * COL_BACK_DEV's file reached through the subtree this layer owns, and
 * /dev/bus/other/../usb/001/001 is COL_NODE's node reached through a bus it
 * does not.
 *
 * They exist because the /sys half of the classifier folds the name before
 * deciding whose it is and the /dev/bus half used to decide on the guest's
 * spelling, so both spellings went wrong and in opposite directions: the first
 * was claimed and answered ENOENT for a file the sysroot really has, the second
 * was disowned and missed the synthetic node. One column each way, so a fold
 * applied to only one direction cannot pass.
 */

/* COL_SYS_FOLD_IN and COL_SYS_FOLD_IN2 are the /sys mirror of COL_FOLD_IN, and
 * they are the same spelling through two different intermediate components:
 * /sys/class is a directory this layer materializes, /sys/devices is one only
 * the sysroot has. Both fold to a name this layer owns and serves, so ownership
 * is decided correctly for both -- but the resolve behind it joins the unfolded
 * suffix onto the scratch tree, so the first walks and the second answers the
 * layer's own authoritative ENOENT for a directory it does serve. The second
 * stays an XFAIL; it is not this series' doing, and the vectors header carries
 * the reason a fold cannot fix this half the way it fixed the /dev one.
 *
 * Two columns rather than one because the first was an XFAIL until the alias
 * layer put a class directory in the tree, and eighteen of its cells then went
 * green without the resolver changing at all. A pair holds the distinction the
 * defect actually turns on.
 */

/* COL_TTY, COL_TTY_BACK, COL_TTY_ABSENT, COL_BYID and COL_TTY_FOLD are the /dev
 * half of the ownership question for the names this layer plants in a directory
 * it does not own. COL_TTY is one it serves; COL_TTY_BACK is an alias-shaped
 * name the backing carries and this layer must not shadow; COL_TTY_ABSENT is
 * alias-shaped and on neither side; COL_BYID is the symlink spelling of
 * COL_TTY, which Linux stats as the device and lstats as the link; COL_TTY_FOLD
 * is COL_TTY reached through a '..' out of /dev/serial/by-id, the spelling that
 * used to name the placeholder file instead of the node.
 *
 * COL_TTY_BACK is the column that holds the fall-through: claiming every
 * parseable alias name and answering ENOENT for the ones with no device made a
 * rootfs image's own /dev/ttyUSB0 unreachable and left readdir listing names
 * that no lookup resolved.
 */

/* Names that must be listed by the union directories, one comma-free name per
 * entry, NULL-terminated. Empty for the columns where enumeration is not the
 * property under test.
 */
static const char *col_union_names[COL_COUNT][5] = {
    [COL_SYS_ROOT] = {"bus", "class", "kernel", "devices", NULL},
    [COL_DEV_BUS] = {"usb", "other", NULL},
};


static void discover_long(void)
{
    strcpy(long_path, "/sys/bus/usb/devices/@none@/bInterfaceNumber");
    DIR *d = opendir("/sys/bus/usb/devices");
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        char cand[512];
        struct stat st;
        snprintf(cand, sizeof(cand), "/sys/bus/usb/devices/%s/bInterfaceNumber",
                 e->d_name);
        if (stat(cand, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        char acc[512];
        snprintf(acc, sizeof(acc), "/sys/bus/usb/devices/%s", e->d_name);
        while (strlen(acc) + strlen(e->d_name) + 21 <= 63) {
            char next[512];
            snprintf(next, sizeof(next), "%s/../%s", acc, e->d_name);
            strcpy(acc, next);
        }
        snprintf(long_path, sizeof(long_path), "%s/../%s/bInterfaceNumber", acc,
                 e->d_name);
        break;
    }
    closedir(d);
}

static void discover_byid(void)
{
    strcpy(byid_path, "/dev/serial/by-id/@none@");
    DIR *d = opendir("/dev/serial/by-id");
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        char cand[512], tgt[128];
        snprintf(cand, sizeof(cand), "/dev/serial/by-id/%s", e->d_name);
        ssize_t n = readlink(cand, tgt, sizeof(tgt) - 1);
        if (n <= 0)
            continue;
        tgt[n] = '\0';
        if (strncmp(tgt, "../../tty", 9))
            continue;
        strcpy(byid_path, cand);
        break;
    }
    closedir(d);
}

static void discover_subsys(void)
{
    strcpy(subsys_path, "/sys/bus/usb/devices/@none@/subsystem");
    DIR *d = opendir("/sys/bus/usb/devices");
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        char cand[512];
        struct stat st;
        snprintf(cand, sizeof(cand), "/sys/bus/usb/devices/%s/subsystem",
                 e->d_name);
        if (lstat(cand, &st) == 0 && S_ISLNK(st.st_mode)) {
            strcpy(subsys_path, cand);
            break;
        }
    }
    closedir(d);
    snprintf(subsys_out_path, sizeof(subsys_out_path), "%s/../pci",
             subsys_path);
    snprintf(subsys_out_slash_path, sizeof(subsys_out_slash_path), "/%s",
             subsys_out_path);
}

/* cell encodings */

static void enc_rc(char *out, int rc)
{
    if (rc >= 0)
        snprintf(out, CELL_MAX, "ok");
    else
        snprintf(out, CELL_MAX, "E%d", errno);
}

static char type_char(mode_t m)
{
    if (S_ISDIR(m))
        return 'd';
    if (S_ISLNK(m))
        return 'l';
    if (S_ISCHR(m))
        return 'c';
    if (S_ISREG(m))
        return 'f';
    return '?';
}

static void enc_stat(char *out, int rc, const struct stat *st)
{
    if (rc < 0)
        snprintf(out, CELL_MAX, "E%d", errno);
    else
        snprintf(out, CELL_MAX, "ok:%c", type_char(st->st_mode));
}

static void enc_fs(char *out, int rc, const struct statfs *sf)
{
    if (rc < 0)
        snprintf(out, CELL_MAX, "E%d", errno);
    else
        snprintf(out, CELL_MAX, "%s",
                 (unsigned long) sf->f_type == SYSFS_MAGIC ? "sysfs" : "other");
}

/* Split a path into a parent directory fd and the trailing component, for the
 * *at() rows: they must reach the same answer through a relative walk that the
 * absolute spelling reaches directly.
 */
static bool parent_name(const char *path,
                        char *dir,
                        size_t dirsz,
                        char *base,
                        size_t basesz)
{
    const char *slash = strrchr(path, '/');
    if (!slash || slash == path)
        return false;
    size_t n = (size_t) (slash - path);
    if (n >= dirsz || strlen(slash + 1) >= basesz)
        return false;
    memcpy(dir, path, n);
    dir[n] = '\0';
    snprintf(base, basesz, "%s", slash + 1);
    return true;
}

static int parent_fd(const char *path, char *base, size_t basesz)
{
    char dir[512];
    if (!parent_name(path, dir, sizeof(dir), base, basesz))
        return -1;
    return open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

/* rows */

typedef void (*row_fn)(const char *path, char *out);

static void r_open(const char *p, char *out)
{
    int fd = open(p, O_RDONLY);
    enc_rc(out, fd);
    if (fd >= 0)
        close(fd);
}

static void r_open_nofollow(const char *p, char *out)
{
    int fd = open(p, O_RDONLY | O_NOFOLLOW);
    enc_rc(out, fd);
    if (fd >= 0)
        close(fd);
}

static void r_openat(const char *p, char *out)
{
    char base[256];
    int dfd = parent_fd(p, base, sizeof(base));
    if (dfd < 0) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    int fd = openat(dfd, base, O_RDONLY);
    enc_rc(out, fd);
    if (fd >= 0)
        close(fd);
    close(dfd);
}

static void r_stat(const char *p, char *out)
{
    struct stat st;
    enc_stat(out, stat(p, &st), &st);
}

static void r_lstat(const char *p, char *out)
{
    struct stat st;
    enc_stat(out, lstat(p, &st), &st);
}

static void r_fstatat_nofollow(const char *p, char *out)
{
    struct stat st;
    enc_stat(out, fstatat(AT_FDCWD, p, &st, AT_SYMLINK_NOFOLLOW), &st);
}

static void r_fstatat_dirfd(const char *p, char *out)
{
    char base[256];
    int dfd = parent_fd(p, base, sizeof(base));
    if (dfd < 0) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    struct stat st;
    int rc = fstatat(dfd, base, &st, 0);
    enc_stat(out, rc, &st);
    close(dfd);
}

/* The subset of Linux's struct statx this row reads. Declared here rather than
 * taken from the guest libc's headers, which do not all carry it; the syscall
 * itself is what the row exists to exercise, and it is present on every kernel
 * elfuse targets. Only the leading fields up to st_mode are named -- the rest
 * is reserved space the kernel fills and this row does not read -- and the
 * whole struct is 256 bytes, which the kernel requires.
 */
struct linux_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t stx_pad1;
    uint64_t stx_ino;
    uint8_t stx_rest[256 - 40];
};

#ifndef SYS_statx
#define SYS_statx 291
#endif
#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x000007ffU
#endif

static void r_statx(const char *p, char *out)
{
    /* The real syscall, not fstatat. statx has its own handler in elfuse -- its
     * own AT_* validation and its own result writer -- so a row that reached it
     * through fstatat proved nothing about it: a regression isolated to statx
     * would have left this row green while claiming to cover it.
     */
    struct linux_statx stx;
    memset(&stx, 0, sizeof(stx));
    int rc = (int) syscall(SYS_statx, AT_FDCWD, p, AT_NO_AUTOMOUNT,
                           STATX_BASIC_STATS, &stx);
    if (rc < 0)
        snprintf(out, CELL_MAX, "E%d", errno);
    else
        snprintf(out, CELL_MAX, "ok:%c", type_char((mode_t) stx.stx_mode));
}

static void r_access(const char *p, char *out)
{
    enc_rc(out, access(p, F_OK));
}

static void r_faccessat_nofollow(const char *p, char *out)
{
    enc_rc(out, faccessat(AT_FDCWD, p, F_OK, AT_SYMLINK_NOFOLLOW));
}

static void r_readlink(const char *p, char *out)
{
    char buf[512];
    ssize_t n = readlink(p, buf, sizeof(buf));
    enc_rc(out, n < 0 ? -1 : 0);
}

static void r_readlinkat(const char *p, char *out)
{
    char base[256], buf[512];
    int dfd = parent_fd(p, base, sizeof(base));
    if (dfd < 0) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    ssize_t n = readlinkat(dfd, base, buf, sizeof(buf));
    enc_rc(out, n < 0 ? -1 : 0);
    close(dfd);
}

static void r_getdents(const char *p, char *out)
{
    DIR *d = opendir(p);
    if (!d) {
        enc_rc(out, -1);
        return;
    }
    while (readdir(d))
        ;
    closedir(d);
    snprintf(out, CELL_MAX, "ok");
}

static void r_statfs(const char *p, char *out)
{
    struct statfs sf;
    enc_fs(out, statfs(p, &sf), &sf);
}

static void r_fstatfs(const char *p, char *out)
{
    /* O_PATH so a symlink column reports its own filesystem rather than its
     * target's, and so a device node is not opened for I/O.
     */
    int fd = open(p, O_RDONLY | O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        enc_rc(out, -1);
        return;
    }
    struct statfs sf;
    enc_fs(out, fstatfs(fd, &sf), &sf);
    close(fd);
}

static void r_fstat_type(const char *p, char *out)
{
    /* The identity an opened descriptor reports has to be the identity the path
     * side gave the same name: libusb fstats the node it just opened and
     * refuses anything that is not a character device.
     */
    int fd = open(p, O_RDONLY | O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        enc_rc(out, -1);
        return;
    }
    struct stat st;
    enc_stat(out, fstat(fd, &st), &st);
    close(fd);
}

static void r_chdir(const char *p, char *out)
{
    int rc = chdir(p);
    enc_rc(out, rc);
    if (rc == 0 && chdir("/") != 0)
        snprintf(out, CELL_MAX, "stuck");
}

static void r_fchdir(const char *p, char *out)
{
    int fd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        enc_rc(out, -1);
        return;
    }
    int rc = fchdir(fd);
    enc_rc(out, rc);
    close(fd);
    if (rc == 0 && chdir("/") != 0)
        snprintf(out, CELL_MAX, "stuck");
}

/* The spelling a correct getcwd reports for a chdir onto @p: "//" runs and "."
 * components folded away, ".." left alone. Computed rather than tabulated so
 * the expected cell is one string on the recording host and in the guest.
 */
static void fold_spelling(const char *p, char *out, size_t outsz)
{
    size_t len = 0;
    out[len++] = '/';
    for (const char *q = p; *q;) {
        while (*q == '/')
            q++;
        const char *seg = q;
        while (*q && *q != '/')
            q++;
        size_t seglen = (size_t) (q - seg);
        if (seglen == 0)
            break;
        if (seglen == 1 && seg[0] == '.')
            continue;
        if (len > 1 && len + 1 < outsz)
            out[len++] = '/';
        if (len + seglen >= outsz)
            break;
        memcpy(out + len, seg, seglen);
        len += seglen;
    }
    out[len] = '\0';
}

/* Where a chdir onto this name leaves the process, by name rather than by
 * return code. chdir alone cannot see the defect this row exists for: a
 * descriptor opened through an unfolded spelling of a synthetic directory
 * carried no guest-path stamp, so getcwd reported the host scratch directory
 * behind the tree -- a path the guest must never see, and one a relative open
 * measured against it would then write into. "self" is the folded spelling of
 * the column, "at:<path>" anything else (a chdir onto a symlink legitimately
 * lands elsewhere).
 */
static void r_getcwd(const char *p, char *out)
{
    if (chdir(p) != 0) {
        enc_rc(out, -1);
        return;
    }
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) {
        enc_rc(out, -1);
        if (chdir("/") != 0)
            snprintf(out, CELL_MAX, "stuck");
        return;
    }
    char folded[4096];
    fold_spelling(p, folded, sizeof(folded));
    if (!strcmp(cwd, folded))
        snprintf(out, CELL_MAX, "self");
    else
        snprintf(out, CELL_MAX, "at:%s", cwd);
    if (chdir("/") != 0)
        snprintf(out, CELL_MAX, "stuck");
}

/* The cwd spellings of the two *at rows above. openat(dirfd, base) and
 * fstatat(dirfd, base) ask whether a descriptor on the parent keeps a relative
 * lookup on the intercepts; these ask the same of a cwd, which is decided by a
 * different predicate and so can part from them. It did: with the alias
 * directories missing from that predicate, chdir("/dev") followed by
 * stat("ttyACM0") reached the placeholder file the alias node sits on top of
 * where /dev/ttyACM0 and openat(dirfd_of_dev, "ttyACM0") reached the character
 * device, and with no sysroot to plant a placeholder it answered ENOENT.
 *
 * fchdir is measured beside chdir rather than assumed to follow it, because the
 * two publish the cwd through different code: chdir names the directory and
 * fchdir has only a descriptor, so a repair that reaches one need not reach the
 * other.
 *
 * "skip" is a parent this host cannot chdir onto, matching the *at rows, which
 * skip a parent they cannot open.
 */
static void r_cwd_stat(const char *p, char *out)
{
    char dir[512], base[256];
    if (!parent_name(p, dir, sizeof(dir), base, sizeof(base)) ||
        chdir(dir) != 0) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    struct stat st;
    enc_stat(out, stat(base, &st), &st);
    if (chdir("/") != 0)
        snprintf(out, CELL_MAX, "stuck");
}

static void r_fcwd_stat(const char *p, char *out)
{
    char dir[512], base[256];
    if (!parent_name(p, dir, sizeof(dir), base, sizeof(base))) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    int rc = fchdir(dfd);
    close(dfd);
    if (rc != 0) {
        snprintf(out, CELL_MAX, "skip");
        return;
    }
    struct stat st;
    enc_stat(out, stat(base, &st), &st);
    if (chdir("/") != 0)
        snprintf(out, CELL_MAX, "stuck");
}

static void r_epoll_ctl(const char *p, char *out)
{
    int ep = epoll_create1(0);
    if (ep < 0) {
        enc_rc(out, -1);
        return;
    }
    int fd = open(p, O_RDONLY);
    if (fd < 0) {
        enc_rc(out, -1);
        close(ep);
        return;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    enc_rc(out, epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev));
    close(fd);
    close(ep);
}

/* The union rows do not encode "how many entries"; they encode whether each
 * name that must survive the merge is listed. Counts differ between the
 * recording host and the guest fixture, presence does not.
 */
static void r_union(const char *p, char *out)
{
    snprintf(out, CELL_MAX, "n/a");
}

static const struct {
    const char *name;
    row_fn fn;
} rows[] = {
    {"open", r_open},
    {"open_nofollow", r_open_nofollow},
    {"openat_dirfd", r_openat},
    {"stat", r_stat},
    {"lstat", r_lstat},
    {"fstatat_nofollow", r_fstatat_nofollow},
    {"fstatat_dirfd", r_fstatat_dirfd},
    {"statx", r_statx},
    {"access", r_access},
    {"faccessat_nofollow", r_faccessat_nofollow},
    {"readlink", r_readlink},
    {"readlinkat_dirfd", r_readlinkat},
    {"getdents64", r_getdents},
    {"statfs", r_statfs},
    {"fstatfs", r_fstatfs},
    {"fstat_type", r_fstat_type},
    {"chdir", r_chdir},
    {"fchdir", r_fchdir},
    {"getcwd", r_getcwd},
    {"cwd_stat", r_cwd_stat},
    {"fcwd_stat", r_fcwd_stat},
    {"epoll_ctl", r_epoll_ctl},
    {"union_listing", r_union},
};
#define NROWS ((int) (sizeof(rows) / sizeof(rows[0])))

/* The measured Linux answers. Rows in the order above, columns in col_name
 * order. "-" means the recording host could not present this class (noted per
 * cell below) and the guest is not held to a value it was never measured
 * against.
 */
static const char *expect[NROWS][COL_COUNT] = {
#include "usb-sysfs-matrix-vectors.h"
};

static bool listed(const char *dir, const char *name)
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

static void record(void)
{
    for (int r = 0; r < NROWS; r++) {
        printf("    /* %-18s */ {", rows[r].name);
        for (int c = 0; c < COL_COUNT; c++) {
            char cell[CELL_MAX];
            errno = 0;
            if (!strcmp(rows[r].name, "union_listing")) {
                if (!col_union_names[c][0])
                    snprintf(cell, sizeof(cell), "n/a");
                else {
                    bool all = true;
                    for (int i = 0; col_union_names[c][i]; i++)
                        all = all && listed(col_path(c), col_union_names[c][i]);
                    snprintf(cell, sizeof(cell), all ? "all" : "missing");
                }
            } else {
                rows[r].fn(col_path(c), cell);
            }
            printf("\"%s\"%s", cell, c + 1 < COL_COUNT ? ", " : "");
        }
        printf("},\n");
    }
}

int main(void)
{
    discover_subsys();
    discover_long();
    discover_byid();

    if (getenv("MATRIX_RECORD")) {
        record();
        return 0;
    }

    for (int r = 0; r < NROWS; r++) {
        for (int c = 0; c < COL_COUNT; c++) {
            const char *want = expect[r][c];
            if (!want || !strcmp(want, "-"))
                continue;

            /* A leading '?' marks a cell whose Linux value was measured but is
             * knowingly not met here; the header names each one and why. It is
             * reported rather than asserted, so a divergence stays visible in
             * the lane's output instead of being deleted from the matrix.
             */
            bool xfail = want[0] == '?';
            if (xfail)
                want++;

            char cell[CELL_MAX], msg[256];
            errno = 0;
            if (!strcmp(rows[r].name, "union_listing")) {
                if (!col_union_names[c][0])
                    snprintf(cell, sizeof(cell), "n/a");
                else {
                    /* Collect the missing names; do not assert on them. The
                     * cell comparison below is the one assertion for this cell,
                     * and asserting here as well reported a single broken
                     * listing as two failures -- once per absent name and once
                     * for "want all got missing" -- which overstates what the
                     * lane found. The names are printed so the one failure
                     * still says which they were.
                     */
                    char missing[192];
                    size_t mlen = 0;
                    missing[0] = '\0';
                    for (int i = 0; col_union_names[c][i]; i++) {
                        if (listed(col_path(c), col_union_names[c][i]))
                            continue;
                        const char *sep = mlen ? "," : "";
                        int n = snprintf(missing + mlen, sizeof(missing) - mlen,
                                         "%s%s", sep, col_union_names[c][i]);
                        if (n < 0 || (size_t) n >= sizeof(missing) - mlen) {
                            mlen = strlen(missing);
                            break;
                        }
                        mlen += (size_t) n;
                    }
                    if (missing[0])
                        printf("  union_listing [%s] %s: not listed: %s\n",
                               col_name[c], col_path(c), missing);
                    snprintf(cell, sizeof(cell),
                             missing[0] ? "missing" : "all");
                }
            } else {
                rows[r].fn(col_path(c), cell);
            }

            /* Both directions are printed. A '?' cell that starts matching is
             * an XPASS and says so: eighteen of them went green when the
             * scratch tree gained a /sys/class directory, and the silent
             * "continue" that used to cover it meant the recorded expectation
             * and the comment explaining it stayed false with nothing in the
             * lane's output to say the fact had changed.
             */
            if (xfail) {
                if (strcmp(cell, want))
                    printf("XFAIL: %s [%s] %s: Linux %s, elfuse %s\n",
                           rows[r].name, col_name[c], col_path(c), want, cell);
                else
                    printf("XPASS: %s [%s] %s: Linux %s, elfuse %s\n",
                           rows[r].name, col_name[c], col_path(c), want, cell);
                continue;
            }
            snprintf(msg, sizeof(msg), "%s [%s] %s: want %s got %s",
                     rows[r].name, col_name[c], col_path(c), want, cell);
            EXPECT_TRUE(!strcmp(cell, want), msg);
        }
    }

    /* The same invariant on the one directory that is reached *through* a
     * synthetic symlink: /sys/bus, named as <dev>/subsystem/.. . Every name it
     * lists has to be openable by the spelling that listed it. No measurement
     * is needed -- it holds on every filesystem -- and it is the disagreement
     * itself rather than a consequence of it: the listing here offered `pci`
     * from the backing while every lookup of <dev>/subsystem/../pci answered
     * ENOENT, because enumeration asked whose the resolved name was and the
     * lookups asked whose the lexically folded one was.
     */
    {
        char parent[512];
        snprintf(parent, sizeof(parent), "%s/..", subsys_path);
        TEST("every name listed through the subsystem link opens");
        DIR *d = opendir(parent);
        if (!d) {
            FAIL("the directory behind the subsystem link would not list");
        } else {
            struct dirent *e;
            char denied[256];
            denied[0] = '\0';
            while ((e = readdir(d))) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                    continue;
                char full[1024];
                snprintf(full, sizeof(full), "%s/%s", parent, e->d_name);
                struct stat st;
                if (stat(full, &st) == 0)
                    continue;
                snprintf(denied, sizeof(denied), "%s (errno %d)", e->d_name,
                         errno);
                break;
            }
            closedir(d);
            if (denied[0]) {
                fprintf(stderr, "  %s listed %s but the lookup denied it\n",
                        parent, denied);
                FAIL("a listed name could not be looked up");
            } else {
                PASS();
            }
        }
    }

    /* One invariant rather than a recorded cell, because it holds on every
     * filesystem and needs no measurement: the descriptor open() returns names
     * the object stat() described, so their (st_dev, st_ino) and file type
     * agree. It is not implied by the fstat_type row above, which opens with
     * O_PATH -- the read-only open is the one libusb makes, and it was the one
     * that used to hand back elfuse's staging file: S_IFREG with a zero rdev
     * where stat reported the character device 189:minor.
     *
     * The recording host cannot open its device-less usb node, so the pair is
     * simply skipped wherever either call fails; every column that opens is
     * checked on both sides.
     */
    for (int c = 0; c < COL_COUNT; c++) {
        struct stat by_name, by_fd;
        if (stat(col_path(c), &by_name) != 0)
            continue;
        int fd = open(col_path(c), O_RDONLY);
        if (fd < 0)
            continue;
        if (fstat(fd, &by_fd) != 0) {
            close(fd);
            continue;
        }
        close(fd);

        char msg[256];
        snprintf(msg, sizeof(msg),
                 "fd identity [%s] %s: stat says %c dev/ino %llu/%llu, fstat "
                 "says %c %llu/%llu",
                 col_name[c], col_path(c), type_char(by_name.st_mode),
                 (unsigned long long) by_name.st_dev,
                 (unsigned long long) by_name.st_ino, type_char(by_fd.st_mode),
                 (unsigned long long) by_fd.st_dev,
                 (unsigned long long) by_fd.st_ino);
        EXPECT_TRUE(type_char(by_name.st_mode) == type_char(by_fd.st_mode) &&
                        by_name.st_dev == by_fd.st_dev &&
                        by_name.st_ino == by_fd.st_ino,
                    msg);
    }

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
