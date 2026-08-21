/*
 * Filesystem stat/statx/statfs handlers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "debug/log.h"

#include "runtime/procemu.h"
#include "runtime/usb-sysfs.h"

#include "syscall/linux-wire.h"
#include "syscall/chown-overlay.h"
#include "syscall/fuse.h"
#include "syscall/fs.h"
#include "syscall/internal.h"
#include "syscall/usbdev.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "utils.h"

static uint64_t mac_to_linux_dev(dev_t dev)
{
    unsigned int maj = ((unsigned int) dev >> 24) & 0xFF;
    unsigned int min = (unsigned int) dev & 0xFFFFFF;
    return (uint64_t) ((min & 0xFF) | (maj << 8) | ((min & ~0xFFU) << 12));
}

static uint32_t linux_dev_major(uint64_t dev)
{
    return (uint32_t) (((dev & 0x00000000000FFF00ULL) >> 8) |
                       ((dev & 0xFFFFF00000000000ULL) >> 32));
}

static uint32_t linux_dev_minor(uint64_t dev)
{
    return (uint32_t) ((dev & 0x00000000000000FFULL) |
                       ((dev & 0x00000FFFFFF00000ULL) >> 12));
}

static void translate_stat(const struct stat *mac, linux_stat_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->st_dev = mac_to_linux_dev(mac->st_dev);
    lin->st_ino = mac->st_ino;
    lin->st_mode = mac->st_mode;
    lin->st_nlink = (uint32_t) mac->st_nlink;
    lin->st_uid = mac->st_uid;
    lin->st_gid = mac->st_gid;
    lin->st_rdev = mac_to_linux_dev(mac->st_rdev);
    lin->st_size = mac->st_size;
    lin->st_blksize = (int32_t) mac->st_blksize;
    lin->st_blocks = mac->st_blocks;
    lin->st_atime_sec = mac->st_atimespec.tv_sec;
    lin->st_atime_nsec = mac->st_atimespec.tv_nsec;
    lin->st_mtime_sec = mac->st_mtimespec.tv_sec;
    lin->st_mtime_nsec = mac->st_mtimespec.tv_nsec;
    lin->st_ctime_sec = mac->st_ctimespec.tv_sec;
    lin->st_ctime_nsec = mac->st_ctimespec.tv_nsec;
}

static uint32_t normalize_statx_mask(unsigned int requested_mask)
{
    uint32_t mask = requested_mask & (STATX_BASIC_STATS | STATX_BTIME);
    if (mask == 0)
        mask = STATX_BASIC_STATS;
    return mask;
}

static void translate_statx(const struct stat *mac,
                            linux_statx_t *sx,
                            uint32_t mask)
{
    uint64_t linux_rdev = mac_to_linux_dev(mac->st_rdev);
    uint64_t linux_dev = mac_to_linux_dev(mac->st_dev);

    memset(sx, 0, sizeof(*sx));
    sx->stx_mask = mask;
    sx->stx_blksize = (uint32_t) mac->st_blksize;

    if (mask & (STATX_TYPE | STATX_MODE))
        sx->stx_mode = (uint16_t) mac->st_mode;
    if (mask & STATX_NLINK)
        sx->stx_nlink = (uint32_t) mac->st_nlink;
    if (mask & STATX_UID)
        sx->stx_uid = mac->st_uid;
    if (mask & STATX_GID)
        sx->stx_gid = mac->st_gid;
    if (mask & STATX_INO)
        sx->stx_ino = mac->st_ino;
    if (mask & STATX_SIZE)
        sx->stx_size = mac->st_size;
    if (mask & STATX_BLOCKS)
        sx->stx_blocks = mac->st_blocks;
    if (mask & STATX_ATIME) {
        sx->stx_atime_sec = mac->st_atimespec.tv_sec;
        sx->stx_atime_nsec = (uint32_t) mac->st_atimespec.tv_nsec;
    }
    if (mask & STATX_MTIME) {
        sx->stx_mtime_sec = mac->st_mtimespec.tv_sec;
        sx->stx_mtime_nsec = (uint32_t) mac->st_mtimespec.tv_nsec;
    }
    if (mask & STATX_CTIME) {
        sx->stx_ctime_sec = mac->st_ctimespec.tv_sec;
        sx->stx_ctime_nsec = (uint32_t) mac->st_ctimespec.tv_nsec;
    }
    if (mask & STATX_BTIME) {
        sx->stx_btime_sec = mac->st_birthtimespec.tv_sec;
        sx->stx_btime_nsec = (uint32_t) mac->st_birthtimespec.tv_nsec;
    }

    sx->stx_rdev_major = linux_dev_major(linux_rdev);
    sx->stx_rdev_minor = linux_dev_minor(linux_rdev);
    sx->stx_dev_major = linux_dev_major(linux_dev);
    sx->stx_dev_minor = linux_dev_minor(linux_dev);
}

static int write_linux_stat(guest_t *g,
                            uint64_t stat_gva,
                            const struct stat *mac_st)
{
    struct stat overlaid = *mac_st;
    chown_overlay_apply(&overlaid);

    linux_stat_t lin_st;

    translate_stat(&overlaid, &lin_st);
    return guest_write_small(g, stat_gva, &lin_st, sizeof(lin_st));
}

static int write_linux_statx(guest_t *g,
                             uint64_t statx_gva,
                             const struct stat *mac_st,
                             unsigned int mask)
{
    struct stat overlaid = *mac_st;
    chown_overlay_apply(&overlaid);

    linux_statx_t sx;

    translate_statx(&overlaid, &sx, normalize_statx_mask(mask));
    return guest_write_small(g, statx_gva, &sx, sizeof(sx));
}

static void translate_statfs(const struct statfs *mac, linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = mac->f_type;
    lin->f_bsize = mac->f_bsize;
    lin->f_blocks = mac->f_blocks;
    lin->f_bfree = mac->f_bfree;
    lin->f_bavail = mac->f_bavail;
    lin->f_files = mac->f_files;
    lin->f_ffree = mac->f_ffree;
    lin->f_fsid[0] = mac->f_fsid.val[0];
    lin->f_fsid[1] = mac->f_fsid.val[1];
    lin->f_namelen = 255;
    lin->f_frsize = mac->f_bsize;
}

/* Resolve the directory + path arguments of a *at-style stat operation and fill
 * *mac_st via the appropriate host call (proc intercept where applicable).
 * Shared by sys_newfstatat and sys_statx; the caller copies the result into the
 * guest's struct stat or struct statx layout.
 * Returns 0 on success or a negative Linux errno.
 */
static int64_t stat_at_path(guest_t *g,
                            int dirfd,
                            uint64_t path_gva,
                            int flags,
                            struct stat *mac_st)
{
    if (dirfd == LINUX_AT_FDCWD) {
        char dot_path[2];
        if (guest_read_small(g, path_gva, dot_path, sizeof(dot_path)) == 0 &&
            dot_path[0] == '.' && dot_path[1] == '\0') {
            int mac_flags = translate_at_flags(flags);
            if (fstatat(AT_FDCWD, ".", mac_st, mac_flags) < 0)
                return linux_errno();
            return 0;
        }
    }

    char short_path[64];
    char path[LINUX_PATH_MAX];
    const char *pathp;
    if (guest_read_path(g, path_gva, short_path, sizeof(short_path), path,
                        sizeof(path), &pathp) < 0)
        return -LINUX_EFAULT;

    if (pathp[0] == '/' && fuse_path_matches_mount(pathp)) {
        int frc = fuse_stat_path(pathp, mac_st, flags);
        if (frc < 0)
            return frc;
        return 0;
    }

    path_translation_t tx;
    if (path_translate_at(dirfd, pathp,
                          path_tr_nofollow(flags & LINUX_AT_SYMLINK_NOFOLLOW),
                          &tx) < 0)
        return linux_errno();

    if (tx.fuse_path) {
        int frc = fuse_stat_path(tx.intercept_path, mac_st, flags);
        if (frc < 0)
            return frc;
        return 0;
    }

    if (tx.proc_resolved == 0 && dirfd == LINUX_AT_FDCWD && pathp[0] != '/' &&
        pathp[0] != '\0' && !proc_get_sysroot()) {
        int mac_flags = translate_at_flags(flags);
        if (fstatat(AT_FDCWD, pathp, mac_st, mac_flags) < 0)
            return linux_errno();
        return 0;
    }

    int64_t rc = 0;
    host_fd_ref_t dir_ref = {.fd = -1, .owned = false};
    if ((flags & LINUX_AT_EMPTY_PATH) && pathp[0] == '\0') {
        /* Linux: AT_EMPTY_PATH with dirfd == AT_FDCWD operates on the current
         * working directory.
         */
        if (dirfd == LINUX_AT_FDCWD) {
            dir_ref.fd = AT_FDCWD;
            int mac_flags = translate_at_flags(flags);
            if (fstatat(AT_FDCWD, ".", mac_st, mac_flags) < 0) {
                rc = linux_errno();
                goto done;
            }
        } else {
            fd_entry_t snap;
            dir_ref.fd = fd_snapshot_and_dup(dirfd, &snap);
            dir_ref.owned = true;
            if (dir_ref.fd < 0) {
                rc = -LINUX_EBADF;
                goto done;
            }

            /* Same routing as sys_fstat: FD_PATH identity comes from the stamp,
             * and a serial alias fd must report its Linux char-dev numbers
             * rather than the macOS cu.* node behind it.
             */
            if (snap.proc_path[0] != '\0' &&
                (snap.type == FD_PATH || usb_tty_alias_path(snap.proc_path))) {
                int intercepted = proc_intercept_stat(snap.proc_path, mac_st);
                if (intercepted == 0)
                    goto done;
                if (intercepted == -1 && snap.type == FD_PATH) {
                    rc = linux_errno();
                    goto done;
                }
            }
            if (fstat(dir_ref.fd, mac_st) < 0) {
                rc = linux_errno();
                goto done;
            }
        }
    } else {
        if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
            return -LINUX_EBADF;

        int intercepted = PROC_NOT_INTERCEPTED;
        if (path_might_use_stat_intercept(tx.intercept_path)) {
            intercepted = proc_intercept_stat(tx.intercept_path, mac_st);
            if (intercepted == -1) {
                rc = linux_errno();
                goto done;
            }
        }
        if (intercepted == PROC_NOT_INTERCEPTED) {
            int mac_flags =
                path_translation_at_flags(&tx, translate_at_flags(flags));
            if (fstatat(path_translation_dirfd(&tx, &dir_ref), tx.host_path,
                        mac_st, mac_flags) < 0) {
                rc = linux_errno();
                goto done;
            }
        }
    }

done:
    host_fd_ref_close(&dir_ref);
    return rc;
}

int64_t sys_fstat(guest_t *g, int fd, uint64_t stat_gva)
{
    /* Zero-init so callees that fill only matched fields (FUSE shim, /proc
     * emulators) leave the rest as defined zeros. Also keeps clang's
     * core.CallAndMessage checker happy: it cannot see across fuse_fstat_fd /
     * fstat to verify the buffer is fully written before translate_stat reads
     * from it.
     */
    struct stat mac_st = {0};
    int frc = fuse_fstat_fd(fd, &mac_st);
    if (frc == 0) {
        if (write_linux_stat(g, stat_gva, &mac_st) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    if (frc != -LINUX_EBADF)
        return frc;

    fd_entry_t snap;
    bool have_snap = fd_snapshot(fd, &snap);

    /* FD_PATH fds carry their guest identity in the stamped path. A serial
     * alias fd (/dev/ttyACM<n>, /dev/ttyUSB<n>) is an ordinary host fd on the
     * macOS cu.* callout node, but its fstat must show the Linux char-dev
     * identity (166/188:<n>) the path stat shows, not the host tty's.
     */
    if (have_snap && snap.proc_path[0] != '\0' &&
        (snap.type == FD_PATH || usb_tty_alias_path(snap.proc_path))) {
        int intercepted = proc_intercept_stat(snap.proc_path, &mac_st);
        if (intercepted == 0) {
            if (write_linux_stat(g, stat_gva, &mac_st) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
        if (intercepted == -1 && snap.type == FD_PATH)
            return linux_errno();

        /* An alias fd whose device vanished mid-run: Linux fstat still answers
         * on an open fd, so fall through to the host fstat rather than
         * inventing an ENOENT.
         */
    }

    /* usbdevfs fds are char device 189:minor; the host fd behind them is a
     * pipe, whose fstat must not leak through.
     */
    if (have_snap && snap.type == FD_USBDEV) {
        int64_t urc = usbdev_fstat(fd, &mac_st);
        if (urc < 0)
            return urc;
        if (write_linux_stat(g, stat_gva, &mac_st) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0) {
        log_debug("fstat(%d): invalid guest fd", fd);
        return -LINUX_EBADF;
    }
    if (fstat(host_ref.fd, &mac_st) < 0) {
        log_debug("fstat(%d->%d): host fstat failed errno=%d", fd, host_ref.fd,
                  errno);
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    if (write_linux_stat(g, stat_gva, &mac_st) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_newfstatat(guest_t *g,
                       int dirfd,
                       uint64_t path_gva,
                       uint64_t stat_gva,
                       int flags)
{
    if (!validate_at_flags(flags, LINUX_AT_SYMLINK_NOFOLLOW |
                                      LINUX_AT_EMPTY_PATH |
                                      LINUX_AT_NO_AUTOMOUNT))
        return -LINUX_EINVAL;

    /* See sys_fstat comment on the zero-init rationale. */
    struct stat mac_st = {0};
    int64_t rc = stat_at_path(g, dirfd, path_gva, flags, &mac_st);
    if (rc < 0)
        return rc;

    if (write_linux_stat(g, stat_gva, &mac_st) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* True when path (already translated/normalized by path_translate_at) names
 * /proc itself or something under it. Boundary-checked so "/procfoo" does not
 * false-positive the way a bare strncmp(path, "/proc", 5) would.
 */
static bool statfs_path_is_proc(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    return !strncmp(path, "/proc", 5) && (path[5] == '\0' || path[5] == '/');
}

/* /dev/pts itself and the pty slaves under it. /dev/ptmx is the multiplexer
 * that hands out those slaves; Linux reports devpts for a master fd too. How
 * statfs should answer for a path under the virtual devpts mount.
 */
typedef enum {
    DEVPTS_UNRELATED = 0, /* not under /dev/pts; carry on */
    DEVPTS_MOUNT,         /* the mount point or a live slave: synthesize */
    DEVPTS_ABSENT,        /* under /dev/pts but no such slave: ENOENT */
} devpts_class_t;

static devpts_class_t statfs_devpts_class(const char *path)
{
    if (!path || strncmp(path, "/dev/pts", 8) != 0)
        return DEVPTS_UNRELATED;
    if (path[8] != '\0' && path[8] != '/')
        return DEVPTS_UNRELATED; /* "/dev/ptsfoo" is an ordinary name */

    const char *tail = path + 8;
    while (*tail == '/')
        tail++;
    if (!*tail)
        return DEVPTS_MOUNT; /* "/dev/pts", "/dev/pts/", "/dev/pts//" */

    /* The mount point exists for as long as the pty layer does. A particular
     * slave does not: Linux answers ENOENT for an unallocated or malformed
     * /dev/pts/N. Report that rather than falling through to the host, so the
     * answer cannot depend on whether the sysroot happens to carry a file of
     * the same name -- the devpts mount shadows whatever is underneath it, and
     * the stat and open intercepts already treat the directory that way.
     *
     * Only the canonical spelling of a slave resolves, matching those
     * intercepts: "/dev/pts/0" is the dentry, "/dev/pts/00" and "/dev/pts/./0"
     * are not. Non-canonical spellings land here as ENOENT rather than
     * resolving, which diverges from a real kernel for the "." form and is
     * consistent across every /dev/pts intercept.
     *
     * /dev/ptmx is deliberately not claimed. Which filesystem backs it depends
     * on whether it resolves to /dev/pts/ptmx or to the devtmpfs node, the same
     * ambiguity that keeps sys_fstatfs from answering for a master fd, and
     * nothing asks: glibc's getpt statfs's /dev/pts and /dev, never /dev/ptmx.
     */
    return proc_pty_slave_stat(path, NULL) ? DEVPTS_MOUNT : DEVPTS_ABSENT;
}

/* devpts is virtualized rather than host-backed, so answer synthetically.
 * Matches what Linux reports for a devpts mount: no blocks, no inodes.
 */
static void fill_devpts_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x1cd1; /* DEVPTS_SUPER_MAGIC */
    lin->f_bsize = 4096;
    lin->f_blocks = 0;
    lin->f_bfree = 0;
    lin->f_bavail = 0;
    lin->f_files = 0;
    lin->f_ffree = 0;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

static void fill_proc_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x9fa0; /* PROC_SUPER_MAGIC */
    lin->f_bsize = 4096;
    lin->f_blocks = 0;
    lin->f_bfree = 0;
    lin->f_bavail = 0;
    lin->f_files = 0;
    lin->f_ffree = 0;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

/* Boundary-checked "/sys or under it", mirroring statfs_path_is_proc. */
static bool statfs_path_is_sysfs(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    return !strncmp(path, "/sys", 4) && (path[4] == '\0' || path[4] == '/');
}

static void fill_sysfs_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x62656572; /* SYSFS_MAGIC */
    lin->f_bsize = 4096;
    lin->f_blocks = 0;
    lin->f_bfree = 0;
    lin->f_bavail = 0;
    lin->f_files = 0;
    lin->f_ffree = 0;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

static int64_t sys_statfs_impl(guest_t *g,
                               const char *path,
                               uint64_t buf_gva,
                               int depth)
{
    if (depth > 40)
        return -LINUX_ELOOP;

    path_translation_t tx;
    if (path_translate_at(LINUX_AT_FDCWD, path, PATH_TR_NONE, &tx) < 0)
        return linux_errno();
    if (tx.fuse_path)
        return -LINUX_ENOSYS;

    if (statfs_path_is_proc(tx.intercept_path)) {
        if (proc_path_is_symlink(tx.intercept_path)) {
            char link[LINUX_PATH_MAX];
            int len = proc_intercept_readlink(tx.intercept_path, link,
                                              sizeof(link) - 1);
            if (len < 0)
                return linux_errno();
            link[len] = '\0';
            return sys_statfs_impl(g, link, buf_gva, depth + 1);
        }

        struct stat mac_st;
        int intercepted = proc_intercept_stat(tx.intercept_path, &mac_st);
        if (intercepted == 0) {
            linux_statfs_t lin_st;
            fill_proc_statfs(&lin_st);
            if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
        if (intercepted == -1)
            return linux_errno();

        /* It might be /proc itself or a host-backed file/directory under /proc
         */
        if (stat(tx.host_path, &mac_st) == 0) {
            linux_statfs_t lin_st;
            fill_proc_statfs(&lin_st);
            if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
    }

    /* /sys is sysfs. libusb refuses to enumerate through the synthetic
     * /sys/bus/usb tree unless statfs("/sys") reports SYSFS_MAGIC
     * (linux_usbfs.c:398-408), and passing through to the host either fails (no
     * /sys on macOS) or leaks the sysroot's filesystem magic. The mount point
     * itself always answers; paths under it answer when the intercept layer (or
     * the host/sysroot backing, e.g. an empty /sys skeleton) knows them, and
     * report the same ENOENT a real Linux kernel would for the rest.
     */
    if (statfs_path_is_sysfs(tx.intercept_path)) {
        bool exists = tx.intercept_path[4] == '\0' ||
                      *(tx.intercept_path + 5) == '\0'; /* "/sys", "/sys/" */
        if (!exists) {
            struct stat sys_st;
            int intercepted = proc_intercept_stat(tx.intercept_path, &sys_st);
            if (intercepted == 0)
                exists = true;
            else if (intercepted == -1)
                return linux_errno();
            else
                exists = stat(tx.host_path, &sys_st) == 0;
        }
        if (!exists)
            return -LINUX_ENOENT;
        linux_statfs_t lin_st;
        fill_sysfs_statfs(&lin_st);
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* glibc's posix_openpt() opens /dev/ptmx and then confirms devpts is
     * mounted before handing the master back (sysdeps/unix/sysv/linux/getpt.c).
     * /dev/pts has no host backing here, so a pass-through statfs fails and
     * glibc closes a perfectly good master -- breaking Unix98 pty allocation
     * for every glibc program. Answer from the virtual filesystem instead.
     */
    devpts_class_t devpts = statfs_devpts_class(tx.intercept_path);
    if (devpts == DEVPTS_ABSENT)
        return -LINUX_ENOENT;
    if (devpts == DEVPTS_MOUNT) {
        linux_statfs_t lin_st;
        fill_devpts_statfs(&lin_st);
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* Report /dev/shm and its leaves as tmpfs, from the backing dir. statfs()
     * on the leaf would follow a symlink onto the host and leak the host fs
     * identity, so answer synthetically; lstat is the nofollow existence probe.
     */
    bool shm_root = !strcmp(tx.intercept_path, "/dev/shm") ||
                    !strcmp(tx.intercept_path, "/dev/shm/");
    if (tx.is_dev_shm || shm_root) {
        const char *shm_dir = proc_get_shm_dir();
        if (!shm_dir)
            return linux_errno();
        if (tx.is_dev_shm) {
            struct stat leaf_st;
            if (lstat(tx.host_path, &leaf_st) < 0)
                return linux_errno();
        }
        struct statfs shm_fs;
        if (statfs(shm_dir, &shm_fs) < 0)
            return linux_errno();
        linux_statfs_t lin_st;
        translate_statfs(&shm_fs, &lin_st); /* sets f_namelen = 255 */
        lin_st.f_type = 0x01021994;         /* TMPFS_MAGIC */
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    struct statfs mac_st;
    if (statfs(tx.host_path, &mac_st) < 0)
        return linux_errno();

    linux_statfs_t lin_st;
    translate_statfs(&mac_st, &lin_st);
    if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_statfs(guest_t *g, uint64_t path_gva, uint64_t buf_gva)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str_small(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    return sys_statfs_impl(g, path, buf_gva, 0);
}

int64_t sys_fstatfs(guest_t *g, int fd, uint64_t buf_gva)
{
    /* Deliberately no devpts case for a pty master fd: Linux answers from
     * whatever filesystem provides /dev/ptmx, which is devpts only when it is
     * the bind-mounted /dev/pts/ptmx and tmpfs or devtmpfs otherwise. There is
     * no single correct value to report, and nothing needs one.
     */
    fd_entry_t snap;
    memset(&snap, 0, sizeof(snap));
    if (fd_snapshot(fd, &snap) && statfs_path_is_proc(snap.proc_path)) {
        linux_statfs_t proc_st;
        fill_proc_statfs(&proc_st);
        if (guest_write_small(g, buf_gva, &proc_st, sizeof(proc_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* Descriptors opened under /sys are scratch-dir backed; the host fstatfs
     * would leak the /tmp filesystem's magic. systemd's sd-device gates every
     * enumerated syspath on fstatfs(fd) == SYSFS_MAGIC, so answer as sysfs
     * exactly like path statfs("/sys") does.
     */
    if (snap.proc_path[0] && statfs_path_is_sysfs(snap.proc_path)) {
        linux_statfs_t sys_st;
        fill_sysfs_statfs(&sys_st);
        if (guest_write_small(g, buf_gva, &sys_st, sizeof(sys_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    struct statfs mac_st;
    if (fstatfs(host_ref.fd, &mac_st) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    linux_statfs_t lin_st;
    translate_statfs(&mac_st, &lin_st);
    if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_statx(guest_t *g,
                  int dirfd,
                  uint64_t path_gva,
                  int flags,
                  unsigned int mask,
                  uint64_t statxbuf_gva)
{
    if (!validate_at_flags(
            flags, LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH |
                       LINUX_AT_NO_AUTOMOUNT | LINUX_AT_STATX_SYNC_TYPE))
        return -LINUX_EINVAL;

    /* See sys_fstat comment on the zero-init rationale. */
    struct stat mac_st = {0};
    int64_t rc = stat_at_path(g, dirfd, path_gva, flags, &mac_st);
    if (rc < 0)
        return rc;

    if (write_linux_statx(g, statxbuf_gva, &mac_st, mask) < 0)
        return -LINUX_EFAULT;
    return 0;
}
