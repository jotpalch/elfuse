/*
 * Shared helpers for syscall modules
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cross-domain declarations: shared locks, the FD table, and translation
 * helpers used by multiple syscall modules.
 *
 * Lock ordering (acquire in ascending order to prevent deadlocks). This is
 * every file-scope lock in the tree that is ever held across another
 * acquisition, whether the inner one is taken directly or through a call. The
 * leaf list below closes it: a lock named there holds nothing beneath it, so
 * the pair of lists is exhaustive rather than "the ones that seemed worth
 * writing down". Adding a mutex or an rwlock means placing it here or in the
 * leaf list, and a leaf that grows a call to another locker moves up here.
 *
 * Per-instance locks (one per epoll instance, futex bucket, FUSE session) are
 * named beside the file-scope lock they nest under. That pairing is the whole
 * of their ordering except for the FUSE session lock, which also holds fd_lock
 * and sig_lock beneath it: fuse_queue_request_locked runs with the session lock
 * held and reaches asyncio_fire, which snapshots an fd and queues a signal.
 * fuse_lock is always dropped before the session lock is used that way, so the
 * two claims do not meet.
 *
 * The numbered "Lock order: N" comments at the definitions predate this list
 * and are not indices into it. This list is the document; a number there says
 * only which locks that one was known to precede when it was written.
 *
 *   proc_tmpdir_lock (runtime/procemu.c): lazy /proc snapshot tree; holds
 *                                     mmap_lock beneath it, because
 *                                     ensure_proc_tmpdir builds the
 *                                     /proc/self/maps and smaps snapshots
 *                                     through proc_intercept_open while the
 *                                     lock is held. Above mmap_lock, so
 *                                     mmap_lock's "1" means first among the
 *                                     locks a syscall path takes, not that
 *                                     nothing precedes it
 *   mmap_lock    (syscall/mem.c):     mmap/brk allocators + page tables
 *   pt_lock      (core/guest.c):      page table pool allocator
 *   pty_keepalive_lock (runtime/procemu-pty.c): pty master keepalive table;
 *                                     holds fd_lock beneath it in
 *                                     proc_pty_master_adopt's joint publish
 *                                     window and in duplicate_guest_fd, which
 *                                     brackets fd_snapshot_and_dup. Both paths
 *                                     take it in this direction, which is what
 *                                     keeps them from deadlocking each other
 *   oom_write_lock (runtime/procemu.c): /proc/self/oom_score_adj writer; holds
 *                                     fd_lock beneath it through
 *                                     proc_oom_refresh_live_fds_locked
 *   fd_lock      (syscall/fdtable.c): FD table (alloc/close/dup)
 *   epoll inst   (syscall/poll.c):    per-epoll-instance regs[]; taken under
 *                                     fd_lock by the close hook, taken alone
 *                                     (no fd_lock held) by epoll_ctl/pwait
 *   exec_handoff_lock (syscall/exec.c): the one execve handoff slot; nested
 *                                     under mmap_lock only by
 *                                     exec_handoff_reset, and holds sig_lock
 *                                     beneath it through
 *                                     signal_restore_blocked. A requester drops
 *                                     mmap_lock before taking it: waiting for
 *                                     the slot under mmap_lock deadlocks
 *                                     against the leader, which needs that lock
 *                                     to run the request that frees the slot
 *   sig_lock     (syscall/signal.c):  signal handlers/pending/blocked
 *   thread_lock  (runtime/thread.c):  thread table
 *   sfd_lock     (syscall/fd.c):      special fd (never held with thread_lock)
 *   autoreap_lock (syscall/proc.c):   serializes the whole no-zombie reap
 *                                     sequence against rt_sigaction; holds
 *                                     pid_lock and, through
 *                                     proc_pidfd_notify_exit, pidfd_lock
 *   elf_path_lock (syscall/proc-state.c): cached /proc/self/exe path; holds
 *                                     cwd_lock beneath it through
 *                                     proc_get_cwd, and sysroot_lock through
 *                                     the proc_cwd_refresh that runs with
 *                                     cwd_lock dropped
 *   pid_lock     (syscall/proc.c):    process table / wait state
 *   pidfd_lock   (syscall/proc-pidfd.c): pidfd registry
 *   futex bucket (runtime/futex.c):   per-bucket, index-ordered if >1
 *   cwd_lock     (syscall/proc-state.c): cached guest cwd. A leaf on every
 *                                     path but one: proc_acquire_cwd_view
 *                                     returns still holding it, and both
 *                                     callers that inspect view.path in place
 *                                     (sys_faccessat, fuse_resolve_at_path)
 *                                     call fuse_path_matches_mount inside the
 *                                     view, so fuse_lock nests beneath it
 *   fuse_lock    (syscall/fuse.c):    mount/session registry; holds the
 *                                     per-session session->lock beneath it,
 *                                     which is what pins a session against
 *                                     daemon exit while a request is in flight
 *   inotify_lock (syscall/inotify.c): inotify watch table
 *   usbdev_table_lock (syscall/usbdev.c): FD_USBDEV side table; holds the
 *                                     per-entry usbdev lock beneath it
 *                                     (usbdev_acquire and usbdev_fd_cleanup
 *                                     take entry locks under it so a slot
 *                                     cannot be torn down and reused between
 *                                     lookup and lock). Never held together
 *                                     with any other file-scope lock in this
 *                                     list, in either direction, so its
 *                                     position here is nominal
 *
 * Leaves. Each of these is the innermost lock on every path that takes it, so
 * it has no position in the order above and cannot be half of an inversion:
 *
 *   absock_lock (net-absock.c)       rlimit_lock (sys.c)
 *   log_mutex (debug/log.c)          rosettad_path_lock (rosetta.c)
 *   nl_lock (netlink.c)              session_lock (proc-identity.c)
 *   overlay_lock (chown-overlay.c)   shm_dir_lock (procemu.c)
 *   proc_scratch_lock (procemu.c)    shm_lock (sysvipc.c)
 *   removed_overlay_lock (fs.c)      syscpu_dir_lock (procemu.c)
 *                                    sysinfo_lock (sys.c)
 *                                    sysroot_lock (proc-state.c)
 *                                    usb_lock (runtime/usb-sysfs.c)
 *
 * log_mutex is the one leaf every other entry may hold: a lock anywhere in
 * either list can log while held. It sits below the whole order rather than
 * beside the rest of the leaves, and it acquires nothing itself, so it closes
 * no cycle.
 *
 * pt_lock, thread_lock, sfd_lock, pid_lock and pidfd_lock are leaves today too.
 * They stay in the ordered list because each is named as an inner lock above,
 * so the order they would be acquired in is the load-bearing fact about them.
 * sig_lock is not one of them: signal_queue_thread_common takes thread_lock
 * under it.
 */

#pragma once

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <unistd.h>

#include "proved/iov.h"
#include "proved/timespec.h"

#include "syscall/linux-wire.h"
#include "syscall/linux-limits.h"
#include "runtime/thread.h"

typedef int guest_fd_t;
typedef int host_fd_t;

/* Cross-module locks. */
extern pthread_mutex_t mmap_lock; /* Lock order: 1, mmap/brk + page tables */
extern pthread_mutex_t fd_lock;   /* Lock order: 3, FD table */

/* FD table (defined in syscall/fdtable.c). */
extern fd_entry_t fd_table[FD_TABLE_SIZE];

/* FD table init. */

/* Initialize FD table: clear bitmap, pre-open stdin/stdout/stderr. */
void fdtable_init(void);

/* FD helpers. */

/* Allocate the lowest available FD.
 *
 * Returns -1 if table is full. cleanup is set atomically under fd_lock (pass
 * NULL for plain fds).
 */
int fd_alloc(int type, int host_fd, void (*cleanup)(int));

/* Allocate the lowest available FD and publish type, host_fd, dir, and
 * linux_flags in one fd_lock critical section, so the slot never becomes
 * visible to a concurrent close/scan as type-set-but-dir-NULL. For fds (epoll)
 * whose close hook and refcount rely on dir being present the instant the slot
 * reads FD_EPOLL.
 *
 * Returns -1 (EMFILE) if the table is full.
 */
int fd_alloc_dir(int type,
                 int host_fd,
                 void (*cleanup)(int),
                 void *dir,
                 int linux_flags);

/* fd_alloc_from()/fd_alloc_at() variants that publish dir + linux_flags in the
 * same fd_lock section as the slot identity (see fd_alloc_dir). Used by
 * epoll_dup_fd() so a duped epoll fd never appears as FD_EPOLL with a NULL dir.
 */
int fd_alloc_dir_from(int minfd,
                      int type,
                      int host_fd,
                      void (*cleanup)(int),
                      void *dir,
                      int linux_flags);
int fd_alloc_dir_at(int fd,
                    int type,
                    int host_fd,
                    void (*cleanup)(int),
                    void *dir,
                    int linux_flags);

/* Allocate the lowest available FD >= minfd.
 *
 * Returns -1 if none available. cleanup is set atomically under fd_lock (pass
 * NULL for plain fds). out_gen (nullable) receives the generation stamped on
 * the new slot, captured inside the allocating fd_lock critical section so dup
 * can later prove the slot still holds this allocation and was not
 * closed+reopened in the window.
 */
int fd_alloc_from(int minfd,
                  int type,
                  int host_fd,
                  void (*cleanup)(int),
                  uint64_t *out_gen);

/* Allocate the lowest available FD >= minfd with a single-thread fast path.
 * Falls back to fd_alloc_from() when multiple guest threads are active.
 */
int fd_alloc_from_relaxed(int minfd,
                          int type,
                          int host_fd,
                          void (*cleanup)(int),
                          uint64_t *out_gen);

/* Allocate a specific FD slot.
 * Returns -1 if out of range. cleanup is set atomically under fd_lock (pass
 * NULL for plain fds). out_gen: see fd_alloc_from().
 */
int fd_alloc_at(int fd,
                int type,
                int host_fd,
                void (*cleanup)(int),
                uint64_t *out_gen);

/* Allocate a specific FD slot with a single-thread fast path. Falls back to
 * fd_alloc_at() when replacement/cleanup must stay serialized.
 */
int fd_alloc_at_relaxed(int fd,
                        int type,
                        int host_fd,
                        void (*cleanup)(int),
                        uint64_t *out_gen);

/* Report whether a guest FD slot >= minfd will be free after execve's CLOEXEC
 * sweep runs (free now, or open-but-CLOEXEC). sys_execve uses this before
 * guest_reset so a Rosetta re-bootstrap that would fail fd_alloc_from past the
 * point of no return is rejected gracefully with -EMFILE instead.
 */
bool fd_reexec_slot_available(int minfd);

/* Look up a guest FD.
 *
 * Returns host FD or -1 if invalid. Unsafe for concurrent use; see
 * fd_snapshot/fd_to_host_dup.
 */
int fd_to_host(int guest_fd);

/* Snapshot an fd entry under fd_lock. Thread-safe alternative to direct
 * fd_table[] access.
 * Returns true on success, false if closed.
 */
bool fd_snapshot(int guest_fd, fd_entry_t *out);

/* Read the generation currently published for a guest fd.
 *
 * Returns 0 when the slot is closed or out of range. Generations start at 1 and
 * only ever increase, so 0 never compares equal to a live one and a slot that
 * changed can never compare equal to an earlier reading. Use this to re-check a
 * generation pinned earlier, not to pin one against a host fd resolved in a
 * separate window -- see host_fd_ref_open_io_gen() for that.
 */
uint64_t fd_current_generation(int guest_fd);

/* Snapshot an fd entry AND dup its host fd in a single fd_lock critical
 * section. Eliminates the TOCTOU window between reading the type/metadata and
 * duplicating the host fd in the dup(2) path.
 *
 * Returns the dup'd host fd (owned by the caller) on success, -1 on failure. On
 * success the snapshot in *out is consistent with the dup'd host fd.
 */
int fd_snapshot_and_dup(int guest_fd, fd_entry_t *out);

/* Read just the fd type under fd_lock.
 *
 * Returns FD_CLOSED for out-of-range or closed slots. Cheaper than fd_snapshot
 * when only the type is needed for dispatch (sys_read/sys_readv/sys_writev fast
 * paths).
 */
int fd_get_type(int guest_fd);

/* True when a host read/write on this guest fd may block (pipe, socket, fifo,
 * char/tty). Regular files and directories never block. Callers use this to
 * decide whether to route a blocking I/O through the interruptible wait path.
 */
bool fd_can_block(int guest_fd);

/* Publish linux_flags for a guest fd under fd_lock. Use after fd_alloc when the
 * creating syscall needs to set linux_flags atomically with respect to a
 * concurrent fcntl(F_SETFL/F_SETFD) on the same slot. The fd_alloc-then-
 * publish window is small (the new gfd is not communicated to other threads
 * until the syscall returns) but the lock removes the structural race and keeps
 * every linux_flags writer on one lock domain.
 */
void fd_publish_linux_flags(int guest_fd, int linux_flags);

/* Republish the EL1 urandom read fast-path bit for this fd from the current
 * fd_table type and access mode. Only readable /dev/urandom descriptors are
 * eligible for the bitmap.
 */
void fd_refresh_urandom_bitmap(int fd);

/* Type -> cleanup registry. Modules that own a synthetic fd type register their
 * cleanup at init time; dup and fork-restore paths look up the cleanup from the
 * type so the binding stays consistent without each path re-deriving the
 * dispatch table.
 */
void fd_register_cleanup(int type, void (*cleanup)(int));
void (*fd_cleanup_for_type(int type))(int);

/* True for fd types whose host backing (kqueue for timerfd/inotify, pipe halves
 * for eventfd/signalfd/netlink/pidfd, epoll instance) cannot be meaningfully
 * inherited across fork IPC: macOS SCM_RIGHTS rejects kqueue fds, and the
 * per-class side-table state (eventfd counter, signalfd mask, pidfd target,
 * epoll set, ...) is not serialized. The child must recreate such fds via the
 * appropriate syscall, so the parent filters them from the SCM_RIGHTS payload
 * and the receiver drops any that still arrive.
 */
static inline bool fd_type_is_synthetic(int type)
{
    return type == FD_EVENTFD || type == FD_SIGNALFD || type == FD_TIMERFD ||
           type == FD_INOTIFY || type == FD_NETLINK || type == FD_PIDFD ||
           type == FD_EPOLL || type == FD_USBDEV;
}

/* Look up a guest FD and return a dup'd host fd owned by the caller.
 * Thread-safe: dup is performed under fd_lock.
 *
 * Returns -1 on failure. Caller MUST close() the returned fd when done.
 */
int fd_to_host_dup(int guest_fd);

/* Mark an FD slot as closed (set type = FD_CLOSED and update bitmap). Does NOT
 * close the host FD or free type-specific resources (DIR*, epoll instance);
 * caller must do that first.
 */
void fd_mark_closed(int fd);

/* Same as fd_mark_closed but requires fd_lock to be already held. Used by
 * sys_execve CLOEXEC loop which holds fd_lock for the entire scan.
 */
void fd_mark_closed_unlocked(int fd);

/* Atomically snapshot an fd entry and mark it closed.
 *
 * Returns true if the slot was open (snapshot written to *out), false if
 * already closed. Prevents the TOCTOU race where two concurrent close() calls
 * both snapshot the same open entry and double-close the host fd.
 */
bool fd_snapshot_and_close(int fd, fd_entry_t *out);

/* Snapshot and close with a single-thread fast path. Uses the unlocked table
 * update when exactly one guest thread is active, otherwise falls back to
 * fd_snapshot_and_close().
 */
bool fd_snapshot_and_close_relaxed(int fd, fd_entry_t *out);

/* Fast-path close for single-threaded plain regular files.
 * Returns true when the slot was closed and the host fd written to
 * *host_fd_out, false when the caller should fall back to the generic close
 * path.
 */
bool fd_close_regular_relaxed(int fd, int *host_fd_out);

/* Release all type-specific resources for a closed FD entry (DIR*, epoll
 * instance, emulated subsystem state) and close the host fd. Caller must have
 * already removed the entry from fd_table.
 */
void fd_cleanup_entry(int guest_fd, const fd_entry_t *snap);

/* Reference-counted wrapper around a directory stream, stored in fd_table[].dir
 * for FD_DIR entries (see syscall/fs.c). A raw DIR* would let a sibling's
 * close()/dup2()/fork-restore free it via closedir() while sys_getdents64() is
 * still mid-loop reading it; the wrapper defers the closedir() until every
 * acquirer -- the fd-table's own reference, plus any in-flight sys_getdents64
 * -- has released it. Guarded by fd_lock, mirroring poll.c's epoll_instance_t
 * refcount.
 *
 * dir_stream_create() takes ownership of dir and returns the wrapper, or NULL
 * on allocation failure (caller still owns dir and must closedir() it itself).
 * dir_stream_release() drops a reference and is a no-op when passed NULL.
 */
void *dir_stream_create(DIR *dir);
void dir_stream_release(void *ds);

/* Translation helpers. */

/* Convert macOS errno to negative Linux errno. */
int64_t linux_errno(void);

/* Translate Linux AT_* flags to macOS equivalents. For unlinkat, fstatat,
 * linkat, fchmodat, fchownat, utimensat.
 */
int translate_at_flags(int linux_flags);

/* Reject any flag bits outside the allowed mask. Caller returns -LINUX_EINVAL
 * on failure. Shared by every *at() handler that validates its flags argument.
 */
static inline int validate_at_flags(int flags, int allowed)
{
    return (flags & ~allowed) == 0;
}

/* Translate Linux faccessat flags to macOS equivalents. Separate from
 * translate_at_flags because Linux AT_EACCESS (0x200) shares the same numeric
 * value as AT_REMOVEDIR; the meaning is context-dependent.
 */
int translate_faccessat_flags(int linux_flags);

/* Translate Linux open flags to macOS equivalents. */
int translate_open_flags(int linux_flags);

/* Translate macOS status flags (F_GETFL result) to Linux equivalents. */
int mac_to_linux_status_flags(int mac_flags);

/* Translate Linux status flags (F_SETFL arg) to macOS equivalents. */
int linux_to_mac_status_flags(int linux_flags);

/* Anonymous mmap for other modules. */

/* Allocate anonymous guest memory. Wraps the static sys_mmap with
 * MAP_PRIVATE|MAP_ANONYMOUS. Caller must hold mmap_lock.
 */
int64_t sys_mmap_anon(guest_t *g, uint64_t addr, uint64_t length, int prot);

/* RLIMIT_NOFILE tracking. */

/* Update the guest RLIMIT_NOFILE soft limit. Called from prlimit64 when
 * resource == RLIMIT_NOFILE. fd_alloc checks this.
 */
void fd_set_rlimit_nofile(int cur);

/* Borrowed-or-owned host fd reference.
 *
 * Single-threaded guests borrow the raw host fd directly (no dup, no close).
 * Multi-threaded guests dup under fd_lock to prevent TOCTOU races with
 * concurrent close() from CLONE_THREAD siblings.
 */
typedef struct {
    host_fd_t fd;
    bool owned;
} host_fd_ref_t;

static inline int host_fd_ref_open(guest_fd_t guest_fd, host_fd_ref_t *ref)
{
    ref->fd = -1;
    ref->owned = false;

    if (thread_is_single_active()) {
        int host_fd = fd_to_host(guest_fd);
        if (host_fd < 0)
            return -1;
        ref->fd = host_fd;
        return 0;
    }

    int host_fd = fd_to_host_dup(guest_fd);
    if (host_fd < 0)
        return -1;
    ref->fd = host_fd;
    ref->owned = true;
    return 0;
}

static inline void host_fd_ref_close(host_fd_ref_t *ref)
{
    /* Preserve errno across close(2). Callers commonly invoke this on the
     * cleanup path after a syscall failed and then read errno to translate the
     * failure; a non-zero close error must not clobber that value.
     */
    int saved_errno = errno;
    if (ref->owned && ref->fd >= 0)
        close(ref->fd);
    ref->fd = -1;
    ref->owned = false;
    errno = saved_errno;
}

/* Open a dirfd reference, treating LINUX_AT_FDCWD as AT_FDCWD. */
static inline int host_dirfd_ref_open(guest_fd_t dirfd, host_fd_ref_t *ref)
{
    if (dirfd == LINUX_AT_FDCWD) {
        ref->fd = AT_FDCWD;
        ref->owned = false;
        return 0;
    }
    return host_fd_ref_open(dirfd, ref);
}

/* Open a host fd reference, rejecting O_PATH (FD_PATH) entries with -EBADF. Use
 * this for syscalls that operate on the underlying file -- read/write, lseek,
 * ftruncate, fsync/fdatasync, flock, fsetxattr/fremovexattr, ioctl, etc. Linux
 * returns EBADF on those calls when the fd was opened O_PATH; the host fd here
 * is a plain O_RDONLY descriptor, so without this gate the host call would
 * silently succeed and diverge from Linux semantics.
 *
 * Calls that are explicitly allowed on O_PATH (fstat, fstatfs, fchdir, close,
 * dup, fcntl get/set CLOEXEC, *at() dirfd) keep using host_{fd,dirfd}_ref_open
 * helpers above.
 */
static inline int64_t host_fd_ref_open_io(guest_fd_t guest_fd,
                                          host_fd_ref_t *ref)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return -LINUX_EBADF;
    if (snap.type == FD_PATH)
        return -LINUX_EBADF;
    if (host_fd_ref_open(guest_fd, ref) < 0)
        return -LINUX_EBADF;
    return 0;
}

/* host_fd_ref_open_io() that also reports the fd generation the reference was
 * resolved against.
 *
 * The generation is captured in the same fd_lock window as the host fd, so the
 * two always describe one open file. Callers that later re-resolve the guest fd
 * -- the pty hangup checks -- need exactly that pairing: a generation sampled
 * in a separate window can already belong to a replacement file while the
 * reference still points at the original, and the replacement's state would
 * then be reported against the original. fd_entry_t.host_fd is only ever
 * written together with a fresh generation, so the generation alone pins the
 * identity of the file behind ref->fd.
 *
 * *out_gen is 0 on failure.
 *
 * Returns 0 on success, -LINUX_EBADF otherwise.
 */
static inline int64_t host_fd_ref_open_io_gen(guest_fd_t guest_fd,
                                              host_fd_ref_t *ref,
                                              uint64_t *out_gen)
{
    ref->fd = -1;
    ref->owned = false;
    *out_gen = 0;

    fd_entry_t snap;
    if (thread_is_single_active()) {
        /* No sibling can race the slot, so a plain snapshot is already
         * consistent with the borrowed host fd.
         */
        if (!fd_snapshot(guest_fd, &snap) || snap.type == FD_PATH ||
            snap.host_fd < 0)
            return -LINUX_EBADF;
        ref->fd = snap.host_fd;
        *out_gen = snap.generation;
        return 0;
    }

    int host_fd = fd_snapshot_and_dup(guest_fd, &snap);
    if (host_fd < 0)
        return -LINUX_EBADF;
    if (snap.type == FD_PATH) {
        int saved_errno = errno;
        close(host_fd);
        errno = saved_errno;
        return -LINUX_EBADF;
    }
    ref->fd = host_fd;
    ref->owned = true;
    *out_gen = snap.generation;
    return 0;
}

/* A guest timeout at or above this many seconds means "wait indefinitely", and
 * the wait path spells indefinite as timeout_ms = -1.
 *
 * That -1 is load-bearing, not a rounding convenience. sys_epoll_pwait reads
 * timeout_ms < 0 as has_timeout = false, which selects the 200 ms re-arm loop
 * that re-checks exit_group, futex interrupts, pending signals and pty hangup
 * between kevent calls. The epoll path registers no wakeup-pipe fd, so that
 * loop is its ONLY interruption mechanism: converting a huge timeout into a
 * finite one instead parks the thread in a single uninterruptible kevent, and a
 * sibling exit_group can no longer wake it.
 *
 * 2000000 seconds is about 23 days, comfortably past any real timeout and short
 * of the arithmetic limits.
 */
#define SYSCALL_TIMEOUT_FOREVER_SEC 2000000LL

/* Guest timespec to a poll(2)/kevent millisecond timeout, mapping an
 * effectively-infinite request onto the -1 that selects the interruptible path.
 *
 * epoll_pwait2 is the only caller, and the mapping is only safe there. ppoll
 * and pselect6 never spelled a timespec as indefinite, and recvmmsg waits in a
 * single poll with nothing to re-arm it, so -1 would strand it rather than
 * making it interruptible. A caller without a re-arm loop wants the saturating
 * conversion instead.
 */
static inline int syscall_timeout_ms_or_forever(int64_t sec, int64_t nsec)
{
    if (sec >= SYSCALL_TIMEOUT_FOREVER_SEC)
        return -1;
    return timespec_to_poll_ms(sec, nsec);
}

/* iov limits shared between readv/writev/preadv/pwritev and sendmsg/recvmsg.
 * SYSCALL_IOV_MAX matches the Linux UIO_MAXIOV cap; SYSCALL_IOV_STACK_MAX keeps
 * the typical case on the call-site stack.
 *
 * The cap is stated twice because the proved copy in proved/iov.h cannot
 * include this header (Frama-C's libc does not model the macOS uio headers it
 * pulls in). The assertion below is what keeps the two from drifting: a proof
 * about a 1024 cap says nothing about a 2048 one.
 */
#define SYSCALL_IOV_MAX 1024
#define SYSCALL_IOV_STACK_MAX 64

_Static_assert(SYSCALL_IOV_MAX == IOV_COUNT_MAX,
               "the iovcnt cap the code enforces must be the one proved");

/* Resolved host iov vector backed by an inline stack buffer with a heap
 * fallback for large iovcnt. Pair host_iov_prepare with host_iov_free.
 */
typedef struct {
    struct iovec stack[SYSCALL_IOV_STACK_MAX];
    struct iovec *iov;
    struct iovec *heap; /* non-NULL only when iov was heap-allocated */
} host_iov_buf_t;

static inline bool host_iov_has_payload(const host_iov_buf_t *buf, int iovcnt)
{
    for (int i = 0; i < iovcnt; i++) {
        if (buf->iov[i].iov_len > 0)
            return true;
    }
    return false;
}

/* Translate a guest iovec array at iov_gva (iovcnt entries) into the host iovec
 * layout in buf->iov, resolving each guest_base to a contiguous host pointer
 * with the requested permissions. On a non-contiguous iov entry the helper
 * truncates that entry to the contiguous prefix and zeros every subsequent
 * entry; the host readv/writev/sendmsg/recvmsg then returns a POSIX-compliant
 * short I/O instead of silently packing bytes from the next guest buffer into
 * the truncated tail.
 *
 * iovcnt <= 0 or > SYSCALL_IOV_MAX returns -LINUX_EINVAL.
 *
 * Returns 0 on success or a negative Linux errno on failure. The caller must
 * pair every successful prepare with host_iov_free to release any heap
 * spillover.
 */
int64_t host_iov_prepare(guest_t *g,
                         uint64_t iov_gva,
                         int iovcnt,
                         int required_perms,
                         host_iov_buf_t *buf);

/* sendmsg/recvmsg variant: iovcnt == 0 is legal for ancillary-only messages. */
int64_t host_iov_prepare_msg(guest_t *g,
                             uint64_t iov_gva,
                             int iovcnt,
                             int required_perms,
                             host_iov_buf_t *buf);

void host_iov_free(host_iov_buf_t *buf);
bool proc_path_is_symlink(const char *path);

/* Read a guest path string with small-buffer optimization.
 *
 * Tries the stack-allocated short_buf first; falls back to long_buf for paths >
 * short_sz bytes. On success, *out points to whichever buffer contains the path
 * (caller must not free).
 *
 * Returns 0 on success, or -LINUX_EFAULT on failure.
 */
static inline int guest_read_path(guest_t *g,
                                  uint64_t gva,
                                  char *short_buf,
                                  size_t short_sz,
                                  char *long_buf,
                                  size_t long_sz,
                                  const char **out)
{
    int rc = guest_read_str_small(g, gva, short_buf, short_sz);
    if (rc >= 0) {
        *out = short_buf;
        return 0;
    }

    /* -2 means a host SIGBUS on the guest page rather than running out of
     * short_buf. Retrying the same address through the long buffer would only
     * fault again. guest_read_str_small reports it for both its own fast path
     * and the boundary-crossing fallback it delegates to.
     */
    if (rc == -2)
        return -LINUX_EFAULT;

    if (guest_read_str(g, gva, long_buf, long_sz) >= 0) {
        *out = long_buf;
        return 0;
    }
    return -LINUX_EFAULT;
}
