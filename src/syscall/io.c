/*
 * Core I/O syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Read/write, ioctl, splice, sendfile, and copy_file_range operations. All
 * functions are called from syscall_dispatch() in syscall/syscall.c.
 *
 * Poll/select/epoll handlers are in syscall/poll.c. Special FD types (eventfd,
 * signalfd, timerfd) are in syscall/fd.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <termios.h>

#include "utils.h"

#include "proved/slice.h"

#include "core/rosetta.h"
#include "core/shim-globals.h"
#include "hvutil.h"
#include "runtime/procemu.h"
#include "runtime/futex.h"
#include "runtime/thread.h"

#include "syscall/linux-wire.h"
#include "syscall/asyncio.h"
#include "syscall/fd.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/inotify.h"
#include "syscall/io.h"
#include "syscall/net.h"
#include "syscall/net-identity.h"
#include "syscall/net-sockopt.h"
#include "syscall/usbdev.h"
#include "syscall/proc.h"
#include "syscall/signal.h"
#include "syscall/wakeup-pipe.h"

#define URANDOM_CACHE_SIZE 4096

/* Linux terminal struct types. */

/* Linux struct winsize (same layout as macOS) */
typedef struct {
    uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel;
} linux_winsize_t;

/* Linux struct termios used by TCGETS/TCSETS on aarch64. Speed fields live in
 * Linux termios2, not in this ioctl ABI.
 */
typedef struct {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
} linux_termios_t;

typedef struct {
    uint16_t sa_family;
    char sa_data[14];
} linux_sockaddr_t;

typedef struct {
    char ifr_name[LINUX_IFNAMSIZ];
    linux_sockaddr_t ifr_hwaddr;
} linux_ifreq_hwaddr_t;

/* Per-fd lock embedded in the cache so a urandom read on fd A does not
 * serialize behind a concurrent urandom read on fd B. The previous design used
 * a single global mutex covering the whole cache array, which made the per-fd
 * cache pointless under any sibling-vCPU urandom traffic. The lock array is
 * initialized at startup by io_init().
 */
typedef struct {
    pthread_mutex_t lock;
    uint8_t buf[URANDOM_CACHE_SIZE];
    size_t off;
    size_t len;
} urandom_cache_t;

static urandom_cache_t urandom_cache[FD_TABLE_SIZE];

void io_init(void)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++)
        pthread_mutex_init(&urandom_cache[i].lock, NULL);
}

_Static_assert(sizeof(linux_termios_t) == 36,
               "aarch64 Linux TCGETS struct termios must be 36 bytes");

/* Linux struct termios2 used by TCGETS2/TCSETS2 on aarch64. Same layout as
 * termios but adds c_ispeed and c_ospeed at the end.
 */
typedef struct {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
    uint32_t c_ispeed, c_ospeed;
} linux_termios2_t;

_Static_assert(sizeof(linux_termios2_t) == 44,
               "aarch64 Linux TCGETS2 struct termios2 must be 44 bytes");

/* Linux <-> macOS c_cc index mapping: linux_mac_cc[linux_idx] = mac_idx. Shared
 * by TCGETS/TCSETS and their termios2 variants.
 *
 * Linux: VINTR=0 VQUIT=1 VERASE=2 VKILL=3 VEOF=4 VTIME=5
 *        VMIN=6 VSWTC=7 VSTART=8 VSTOP=9 VSUSP=10 VEOL=11
 *        VREPRINT=12 VDISCARD=13 VWERASE=14 VLNEXT=15 VEOL2=16
 * macOS: VEOF=0 VEOL=1 VEOL2=2 VERASE=3 VWERASE=4 VKILL=5
 *        VREPRINT=6 (7=spare) VINTR=8 VQUIT=9 VSUSP=10 VDSUSP=11
 *        VSTART=12 VSTOP=13 VLNEXT=14 VDISCARD=15 VMIN=16 VTIME=17
 */
static const int linux_mac_cc[19] = {
    8, 9, 3, 5, 0, 17, 16, -1, 12, 13, 10, 1, 6, 15, 4, 14, 2, -1, -1,
};

static void termios_copy_cc_to_linux(uint8_t linux_cc[19], const cc_t mac_cc[])
{
    for (int i = 0; i < 19; i++) {
        int mac_idx = linux_mac_cc[i];
        /* cppcheck-suppress negativeIndex
         * RANGE_CHECK guards mac_idx >= 0 before the array access.
         */
        linux_cc[i] = RANGE_CHECK(mac_idx, 0, NCCS) ? mac_cc[mac_idx] : 0;
    }
}

static void termios_copy_cc_to_mac(cc_t mac_cc[], const uint8_t linux_cc[19])
{
    for (int i = 0; i < 19; i++) {
        int mac_idx = linux_mac_cc[i];
        if (RANGE_CHECK(mac_idx, 0, NCCS))
            mac_cc[mac_idx] = linux_cc[i];
    }
}

static int termios_action_for(unsigned long request)
{
    return (request == LINUX_TCSETSF || request == LINUX_TCSETSF2)   ? TCSAFLUSH
           : (request == LINUX_TCSETSW || request == LINUX_TCSETSW2) ? TCSADRAIN
                                                                     : TCSANOW;
}

static int64_t io_return_zero(host_fd_ref_t *host_ref)
{
    host_fd_ref_close(host_ref);
    return 0;
}

static int64_t linux_siocgifhwaddr(guest_t *g, uint64_t arg)
{
    char raw_name[LINUX_IFNAMSIZ];
    if (guest_read_small(g, arg, raw_name, sizeof(raw_name)) < 0)
        return -LINUX_EFAULT;

    char name[LINUX_IFNAMSIZ + 1];
    memcpy(name, raw_name, LINUX_IFNAMSIZ);
    name[LINUX_IFNAMSIZ] = '\0';

    linux_ifreq_hwaddr_t ifr = {0};
    memcpy(ifr.ifr_name, raw_name, sizeof(ifr.ifr_name));

    uint16_t family = 0;
    uint8_t mac[NET_IDENTITY_MAC_LEN];
    if (net_identity_hwaddr(name, &family, mac) < 0)
        return -LINUX_ENODEV;

    ifr.ifr_hwaddr.sa_family = family;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, sizeof(mac));

    if (guest_write_small(g, arg, &ifr, sizeof(ifr)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t io_retry_backoff(unsigned *backoff_us)
{
    /* Materialize an expired guest interval timer first. ITIMER_REAL is virtual
     * and only becomes a pending SIGALRM when this runs, and the syscall
     * epilogue that would otherwise do it cannot run while the caller is
     * looping here. Without this a guest whose alarm fires during a contended
     * lock waits for the lock rather than for the signal. The interruptible fd
     * wait below does the same thing for the same reason.
     */
    signal_check_timer_real();

    /* Teardown, or a signal Linux would have delivered: semop, flock and
     * F_SETLKW are all interruptible, and the blocking host calls these replace
     * were reachable by neither. signal_pending_interruption already filters
     * SIG_IGN, default-ignore, and SA_RESTART, so it cannot manufacture an
     * EINTR the guest would not have seen.
     */
    if (thread_stop_requested() || signal_pending_interruption(NULL))
        return -LINUX_EINTR;

    /* First miss: yield rather than sleep. A lock or semaphore released inside
     * the current scheduling quantum is the common case, and a sleep would turn
     * it into a timer round trip that macOS rounds up well past the request.
     */
    if (*backoff_us == 0) {
        sched_yield();
        *backoff_us = IO_RETRY_BACKOFF_START_US;
        return 0;
    }

    unsigned us = *backoff_us;
    usleep(us);

    us *= 2;
    *backoff_us = us > IO_RETRY_BACKOFF_MAX_US ? IO_RETRY_BACKOFF_MAX_US : us;
    return 0;
}

int64_t io_wait_fd_or_interrupted(int host_fd, short events)
{
    int wake_fd = wakeup_pipe_read_fd();

    /* poll() ignores entries with a negative fd, so a missing wakeup pipe just
     * drops the second slot.
     */
    struct pollfd fds[2] = {
        {.fd = host_fd, .events = events},
        {.fd = wake_fd, .events = POLLIN},
    };

    for (;;) {
        /* Materialize expired guest interval timers first: ITIMER_REAL is
         * virtual and only converted to a pending SIGALRM by the syscall
         * epilogue, which cannot run while this thread is parked here. The
         * futex wait loops do the same.
         */
        signal_check_timer_real();

        /* Teardown leaves before polling: this thread is going away and has
         * nobody to report readiness to. An execve handed to this leader is
         * different, because the thread keeps running and the dispatcher
         * restarts the SVC, so leaving without looking throws away a wait whose
         * fd may already be ready and pays for a whole syscall re-entry to
         * discover it. Look first, with a zero timeout so the run loop still
         * reaches the handoff promptly, and leave only if there is nothing.
         *
         * Correctness does not depend on this: the restart re-polls either way,
         * and a connect loop under a sibling exec loop completes 4000/4000 with
         * or without it. Progress does. Measured over four runs of that loop,
         * median 1.8 s here against 2.9 s when the wait leaves before polling.
         */
        bool leader_only = thread_stop_is_leader_work_only();
        if (!leader_only && thread_stop_requested())
            return -LINUX_EINTR;

        /* Ignored/default-ignore signals do not interrupt; restartable handlers
         * still need to run promptly through the syscall epilogue.
         *
         * The futex interrupt is left alone on the leader-work path, which the
         * single ||-chain this replaced did by short-circuiting. It is a
         * process-wide one-shot standing in for SIGCHLD when the last
         * clone-thread exits, and consuming it here would hand its EINTR to a
         * restart that swallows it, so no thread would ever observe the edge.
         * Left set, it is still there for the next interruptible wait in any
         * thread, which is the ordering this wants: a ready fd is reported
         * first and the one-shot keeps until something waits again.
         */
        if ((!leader_only && futex_interrupt_consume()) ||
            signal_pending_interruption(NULL))
            return -LINUX_EINTR;

        /* Bounded wait even when the wakeup pipe exists: the pipe is a
         * single-consumer channel, so a sibling thread blocked in read/poll can
         * drain the byte meant to wake this one. The 200 ms recheck guarantees
         * every waiter re-evaluates its own interrupt conditions.
         */
        int ret = poll(fds, 2, leader_only ? 0 : 200);
        if (ret < 0)
            return linux_errno();

        if (wake_fd >= 0 && (fds[1].revents & POLLIN))
            wakeup_pipe_drain();
        if (fds[0].revents)
            return 0;

        if (leader_only)
            return -LINUX_EINTR;
    }
}

/* Route a blocking read/write on a fd that can block (pipe, socket, fifo,
 * char/tty) through the interruptible wait so the vCPU thread stays reachable
 * by hv_vcpus_exit + the wakeup pipe. No-op for regular files, nonblocking fds,
 * and direction mismatches (a POLLIN wait on an O_WRONLY fd would hang; the
 * read then fails EBADF like Linux).
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR) to abort.
 */
static int64_t io_block_wait(int fd, int host_fd, short events)
{
    if (!fd_can_block(fd))
        return 0;
    int fl = fcntl(host_fd, F_GETFL);
    if (fl < 0 || (fl & O_NONBLOCK))
        return 0;
    int acc = fl & O_ACCMODE;
    if ((events & POLLIN) && acc == O_WRONLY)
        return 0;
    if ((events & POLLOUT) && acc == O_RDONLY)
        return 0;
    return io_wait_fd_or_interrupted(host_fd, events);
}

static int64_t io_check_access(int host_fd, short events)
{
    int fl = fcntl(host_fd, F_GETFL);
    if (fl < 0)
        return linux_errno();
    int acc = fl & O_ACCMODE;
    if ((events & POLLIN) && acc == O_WRONLY)
        return -LINUX_EBADF;
    if ((events & POLLOUT) && acc == O_RDONLY)
        return -LINUX_EBADF;
    return 0;
}

/* Interruptible output drain, mirroring tty_wait_until_sent(): the Linux kernel
 * waits for pending output before TCSBRK, TCSBRKP and TIOCSBRK, and a pending
 * signal aborts the wait with a plain -EINTR that reaches the guest without a
 * restart (tty_io.c "Factor out some common prep work" block). macOS tcdrain()
 * would park the vCPU thread beyond the reach of guest signals -- a serial port
 * stalled by flow control would hang the guest unkillably -- so poll TIOCOUTQ
 * in short slices with the same interruption checks as
 * io_wait_fd_or_interrupted(). Fds without an output-queue count (macOS returns
 * ENOTTY for non-ttys; ptys do implement TIOCOUTQ) fall back to a single
 * tcdrain(), which returns immediately for those.
 */
static int64_t tty_drain_interruptible(int host_fd)
{
    int wake_fd = wakeup_pipe_read_fd();
    struct pollfd fds[1] = {
        {.fd = wake_fd, .events = POLLIN},
    };

    for (;;) {
        int outq = 0;
        if (ioctl(host_fd, TIOCOUTQ, &outq) < 0)
            return tcdrain(host_fd) < 0 ? linux_errno() : 0;
        if (outq == 0)
            return 0;

        signal_check_timer_real();
        bool leader_only = thread_stop_is_leader_work_only();
        bool interrupted = (!leader_only && thread_stop_requested()) ||
                           (!leader_only && futex_interrupt_consume()) ||
                           signal_pending_interruption(NULL);
        if (!interrupted) {
            int ret = poll(fds, 1, leader_only ? 0 : 20);
            if (ret < 0 && errno != EINTR)
                return linux_errno();

            /* Consume the wakeup byte like io_wait_fd_or_interrupted() does:
             * the interruption conditions it announces are re-checked at the
             * top of every iteration, and a byte left in the pipe would turn
             * each subsequent poll into an immediate return and this loop into
             * a busy spin for as long as output stays queued.
             */
            if (ret > 0 && wake_fd >= 0 && (fds[0].revents & POLLIN))
                wakeup_pipe_drain();
            interrupted = leader_only;
        }
        if (interrupted) {
            /* Linux returns a plain -EINTR here (not ERESTARTSYS), and part of
             * the interval has already drained: no restart.
             */
            syscall_restart_forbid();
            return -LINUX_EINTR;
        }
    }
}

void urandom_fd_reset_cache(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    /* Preserve the embedded lock; reset only the entropy fields. memset of the
     * whole struct would clobber the mutex state.
     */
    urandom_cache_t *c = &urandom_cache[guest_fd];
    pthread_mutex_lock(&c->lock);
    memset(c->buf, 0, sizeof(c->buf));
    c->off = 0;
    c->len = 0;
    pthread_mutex_unlock(&c->lock);
}

void urandom_fd_cleanup(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    urandom_fd_reset_cache(guest_fd);
}

static int64_t urandom_check_readable(int guest_fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap) || snap.type != FD_URANDOM)
        return -LINUX_EBADF;
    if ((snap.linux_flags & 3) == LINUX_O_WRONLY)
        return -LINUX_EBADF;
    return 0;
}

static int64_t urandom_fill_iov(int guest_fd,
                                const struct iovec *iov,
                                int iovcnt)
{
    int64_t err = urandom_check_readable(guest_fd);
    if (err < 0)
        return err;

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (!iov_total_add(total, iov[i].iov_len, &total))
            return -LINUX_EINVAL;
    }
    if (total == 0)
        return 0;

    urandom_cache_t *c = &urandom_cache[guest_fd];
    pthread_mutex_lock(&c->lock);
    size_t done = 0;
    for (int i = 0; i < iovcnt && done < total; i++) {
        uint8_t *dst = iov[i].iov_base;
        size_t iov_done = 0;
        size_t iov_len = iov[i].iov_len;
        if (iov_len > total - done)
            iov_len = total - done;
        while (iov_done < iov_len) {
            if (c->off == c->len) {
                arc4random_buf(c->buf, sizeof(c->buf));
                c->off = 0;
                c->len = sizeof(c->buf);
            }
            size_t chunk = c->len - c->off;
            if (chunk > iov_len - iov_done)
                chunk = iov_len - iov_done;
            memcpy(dst + iov_done, c->buf + c->off, chunk);
            c->off += chunk;
            iov_done += chunk;
            done += chunk;
        }
    }
    pthread_mutex_unlock(&c->lock);
    return (int64_t) done;
}

static int64_t validate_iov_total(guest_t *g,
                                  uint64_t iov_gva,
                                  int iovcnt,
                                  linux_iovec_t *iov)
{
    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (guest_read_small(g, iov_gva + (uint64_t) i * sizeof(*iov), &iov[i],
                             sizeof(*iov)) < 0)
            return -LINUX_EFAULT;
        if (!iov_total_add(total, iov[i].iov_len, &total))
            return -LINUX_EINVAL;
    }
    return 0;
}

/* Fill count guest bytes at gva with entropy, staged through a host buffer.
 *
 * urandom_fill_iov holds the per-fd cache lock while it copies, so it cannot be
 * handed a guest pointer: see the lock rule on HOST_SIGBUS_GUARD.
 *
 * Returns the byte count transferred, or a negative Linux errno when nothing
 * moved.
 */
static int64_t urandom_fill_guest(guest_t *g,
                                  int guest_fd,
                                  uint64_t gva,
                                  uint64_t count)
{
    if (gva > UINT64_MAX - count)
        return -LINUX_EFAULT;

    uint8_t stage[512];
    uint64_t done = 0, chunk;
    while (slice_clamp(count, done, sizeof(stage), &chunk)) {
        /* Clamp again to the contiguous writable window. Resolving the guest
         * pointer purely to read its extent, never to dereference, keeps the
         * short read a mapping boundary has always produced -- see
         * tests/test-large-io-boundary.c -- instead of turning a straddling
         * request into EFAULT.
         */
        uint64_t avail = 0;
        if (!guest_ptr_bound(g, gva + done, &avail, MEM_PERM_W, chunk))
            return done > 0 ? (int64_t) done : -LINUX_EFAULT;
        if (avail < chunk)
            chunk = avail;

        /* Keep the chunk inside one guest page. A page is the granularity at
         * which backing vanishes, so a chunk that cannot straddle one either
         * lands whole or faults whole, and the count below is never short of
         * what actually reached the guest. avail runs to the end of the region
         * and can cross many pages, so without this the write could report less
         * progress than it made.
         */
        uint64_t to_page_end =
            GUEST_PAGE_SIZE - ((gva + done) & (GUEST_PAGE_SIZE - 1));
        if (chunk > to_page_end)
            chunk = to_page_end;
        if (chunk == 0)
            break;

        struct iovec iov = {.iov_base = stage, .iov_len = (size_t) chunk};
        int64_t got = urandom_fill_iov(guest_fd, &iov, 1);
        if (got <= 0)
            return done > 0 ? (int64_t) done : got;
        if (guest_write(g, gva + done, stage, (size_t) got) < 0)
            return done > 0 ? (int64_t) done : -LINUX_EFAULT;
        done += (uint64_t) got;
        if ((uint64_t) got < chunk)
            break;
    }
    return (int64_t) done;
}

static int64_t urandom_read(guest_t *g,
                            int guest_fd,
                            uint64_t buf_gva,
                            uint64_t count)
{
    if (count > SSIZE_MAX)
        count = SSIZE_MAX;
    if (count == 0) {
        struct iovec empty = {0};
        return urandom_fill_iov(guest_fd, &empty, 1);
    }

    int64_t rc = urandom_fill_guest(g, guest_fd, buf_gva, count);
    if (rc < 0)
        return rc;

    /* This slow path runs when the shim's identity-class fast path could not
     * serve the read: either the request was larger than the shim's inline
     * limit, or the ring was empty. Refill the shim's entropy ring before
     * returning so a subsequent read(/dev/urandom) from the same vCPU sees a
     * populated ring and stays on the fast path.
     */
    shim_globals_refill_urandom_ring(g);
    return rc;
}

static bool rosetta_ioctl_target_fd(guest_t *g, int host_fd)
{
    if (!g->is_rosetta)
        return false;

    /* Rosetta opens /proc/self/exe (which under rosetta resolves to the rosetta
     * translator, not elfuse) and issues the VZ probe ioctls on that
     * descriptor. Match against ROSETTA_PATH so the gate triggers regardless of
     * where elfuse itself lives on disk.
     */
    char resolved[PATH_MAX];
    if (fcntl(host_fd, F_GETPATH, resolved) < 0)
        return false;
    if (strcmp(resolved, ROSETTA_PATH) != 0)
        return false;

    /* Defense in depth: require the syscall to originate from inside the
     * rosetta translator image. The /proc/self/exe redirection makes the
     * launcher fd reachable to any code running under a rosetta-enabled VM, so
     * without this check a guest-launched helper that opened /proc/self/exe
     * could exercise the synthetic VZ probe path. Today the responses are
     * public constants, but the gate guards against future synthetic responses
     * that leak host state. ELR_EL1 carries the EL0 return PC captured at SVC
     * entry on aarch64.
     *
     * Skip if the rosetta image bounds are not yet known (pre-finalize); the
     * F_GETPATH match above is the only gate in that window, and
     * rosetta_finalize publishes the bounds before issuing any ioctl.
     */
    if (g->rosetta_va_base && g->rosetta_size) {
        if (!current_thread)
            return false;
        uint64_t pc = vcpu_get_sysreg(current_thread->vcpu, HV_SYS_REG_ELR_EL1);
        if (pc < g->rosetta_va_base ||
            pc - g->rosetta_va_base >= g->rosetta_size)
            return false;
    }
    return true;
}

/* Returns true if request matches one of the Rosetta VZ probe ioctls. */
static bool rosetta_vz_request(uint64_t request)
{
    return request == ROSETTA_VZ_CHECK || request == ROSETTA_VZ_CAPS ||
           request == ROSETTA_VZ_ACTIVATE;
}

/* Handle the Rosetta VZ probe ioctl trio. Writes synthetic responses to the
 * guest buffer at arg and returns the value the guest sees (1 on success,
 * negative Linux errno on a guest_write fault). Caller is responsible for
 * dispatch gating (see rosetta_vz_request + rosetta_ioctl_target_fd).
 */
static int64_t rosetta_vz_ioctl(guest_t *g, uint64_t request, uint64_t arg)
{
    switch (request) {
    case ROSETTA_VZ_CHECK: {
        static const char rosetta_sig[ROSETTA_VZ_SIG_LEN] =
            "Our hard work\nby these words guarded\n"
            "please don't steal\n\xc2\xa9 Apple Inc";
        if (guest_write(g, arg, rosetta_sig, sizeof(rosetta_sig)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }
    case ROSETTA_VZ_CAPS: {
        /* caps is zero-initialized: VZ_SECONDARY and the trailing NUL of any
         * partially-copied binary path are already in place.
         */
        uint8_t caps[ROSETTA_CAPS_SIZE] = {0};
        caps[ROSETTA_CAPS_VZ_ENABLE] = 1;
        static const char fake_sock_path[] = ROSETTAD_SOCKET_PATH;
        memcpy(&caps[ROSETTA_CAPS_SOCKET_PATH], fake_sock_path,
               sizeof(fake_sock_path));

        /* Snapshot the caps binary path under the rosetta path lock so a
         * concurrent execve cannot tear the string between length probe and
         * copy. Inline buffer matches the cap exactly; the snapshot helper
         * bounds the write itself.
         */
        char bin[ROSETTA_CAPS_BINARY_PATH_LEN];
        size_t bin_n = rosettad_snapshot_caps_binary_path(bin, sizeof(bin));
        if (bin_n > 0)
            memcpy(&caps[ROSETTA_CAPS_BINARY_PATH], bin, bin_n);
        if (guest_write(g, arg, caps, sizeof(caps)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }
    case ROSETTA_VZ_ACTIVATE:
        return 1;
    }
    /* Caller gates dispatch; this is unreachable in practice. */
    return -LINUX_ENOTTY;
}

/* termios flag translation helpers. */

/* Which Linux bit means which macOS bit is one fact per flag word, and both
 * directions need it. Stating it once as a table and walking that table forward
 * or backward is what keeps the pair consistent: the two directions used to be
 * written out separately, so a bit added to one could silently miss the other,
 * and nothing would have failed.
 *
 * A bit with no counterpart is simply absent from the table, which drops it in
 * both directions. Where that asymmetry is deliberate the wrapper says so.
 */
typedef struct {
    uint32_t linux_bit;
    tcflag_t mac_bit;
} termios_flag_pair_t;

static tcflag_t termios_flags_to_mac(uint32_t lf,
                                     const termios_flag_pair_t *map,
                                     size_t count)
{
    tcflag_t mf = 0;
    for (size_t i = 0; i < count; i++) {
        if (lf & map[i].linux_bit)
            mf |= map[i].mac_bit;
    }
    return mf;
}

static uint32_t termios_flags_to_linux(tcflag_t mf,
                                       const termios_flag_pair_t *map,
                                       size_t count)
{
    uint32_t lf = 0;
    for (size_t i = 0; i < count; i++) {
        if (mf & map[i].mac_bit)
            lf |= map[i].linux_bit;
    }
    return lf;
}

/* CSIZE is a multi-bit field rather than independent bits, and its Linux CS5
 * encoding is zero, so it cannot ride the bit tables above: a zero mask never
 * matches. Same idea, matched on the field value.
 */
typedef struct {
    uint32_t linux_value;
    tcflag_t mac_value;
} termios_field_pair_t;

static tcflag_t termios_field_to_mac(uint32_t lf,
                                     uint32_t linux_mask,
                                     const termios_field_pair_t *map,
                                     size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if ((lf & linux_mask) == map[i].linux_value)
            return map[i].mac_value;
    }
    return 0;
}

static uint32_t termios_field_to_linux(tcflag_t mf,
                                       tcflag_t mac_mask,
                                       const termios_field_pair_t *map,
                                       size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if ((mf & mac_mask) == map[i].mac_value)
            return map[i].linux_value;
    }
    return 0;
}

/* Linux aarch64 c_iflag bits (from asm-generic/termbits-common.h). Low 9 bits
 * (IGNBRK..ICRNL) match macOS exactly. Bits from 0x200 onward differ: Linux
 * IUCLC=0x200 has no macOS equivalent; Linux IXON=0x400/IXOFF=0x1000 vs macOS
 * IXON=0x200/IXOFF=0x400.
 */
#define LINUX_IFLAG_LOW_MASK 0x1ff /* bits 0-8: same on Linux and macOS */
#define LINUX_IXON 0x0400
#define LINUX_IXOFF 0x1000
#define LINUX_IMAXBEL 0x2000 /* same value on both */
#define LINUX_IUTF8 0x4000   /* same value on both */

/* IUCLC (Linux 0x200) has no macOS equivalent and is absent on purpose. */
static const termios_flag_pair_t iflag_map[] = {
    {0x800, IXANY}, /* same value on both */
    {LINUX_IXON, IXON},       {LINUX_IXOFF, IXOFF},
    {LINUX_IMAXBEL, IMAXBEL}, {LINUX_IUTF8, IUTF8},
};

/* Translate Linux c_iflag to macOS c_iflag. */
static tcflag_t linux_iflag_to_mac(uint32_t lf)
{
    /* IGNBRK..ICRNL are identical, so the low bits pass through untranslated.
     */
    return (lf & LINUX_IFLAG_LOW_MASK) |
           termios_flags_to_mac(lf, iflag_map, ARRAY_SIZE(iflag_map));
}

/* Translate macOS c_iflag to Linux c_iflag. */
static uint32_t mac_iflag_to_linux(tcflag_t mf)
{
    return (uint32_t) (mf & LINUX_IFLAG_LOW_MASK) |
           termios_flags_to_linux(mf, iflag_map, ARRAY_SIZE(iflag_map));
}

/* Linux aarch64 c_oflag bits (asm-generic/termbits-common.h + termbits.h). Only
 * OPOST (0x01) has the same value on both platforms. macOS 0x02 = ONLCR; Linux
 * 0x02 = OLCUC (output lowercase->uppercase, rare). macOS 0x04 = OXTABS; Linux
 * 0x04 = ONLCR. All other bits shift by one. OLCUC (Linux 0x002, output
 * lowercase->uppercase) has no macOS equivalent and is silently dropped. macOS
 * uses 0x002 for ONLCR.
 */
#define LINUX_OPOST 0x001
#define LINUX_ONLCR 0x004  /* macOS ONLCR=0x002 */
#define LINUX_OCRNL 0x008  /* macOS OCRNL=0x010 */
#define LINUX_ONOCR 0x010  /* macOS ONOCR=0x020 */
#define LINUX_ONLRET 0x020 /* macOS ONLRET=0x040 */
#define LINUX_OFILL 0x040  /* macOS OFILL=0x080 */
#define LINUX_OFDEL 0x080  /* macOS OFDEL=0x020000 */
/* Linux NLDLY/CRDLY/TABDLY/BSDLY/VTDLY/FFDLY have no macOS equivalents */

/* OLCUC (Linux 0x002) and the delay fields NLDLY, CRDLY, TABDLY, BSDLY, VTDLY,
 * and FFDLY have no macOS equivalents and are absent on purpose.
 */
static const termios_flag_pair_t oflag_map[] = {
    {LINUX_OPOST, OPOST}, {LINUX_ONLCR, ONLCR},   {LINUX_OCRNL, OCRNL},
    {LINUX_ONOCR, ONOCR}, {LINUX_ONLRET, ONLRET}, {LINUX_OFILL, OFILL},
    {LINUX_OFDEL, OFDEL},
};

/* Translate Linux c_oflag to macOS c_oflag. */
static tcflag_t linux_oflag_to_mac(uint32_t lf)
{
    return termios_flags_to_mac(lf, oflag_map, ARRAY_SIZE(oflag_map));
}

/* Translate macOS c_oflag to Linux c_oflag. */
static uint32_t mac_oflag_to_linux(tcflag_t mf)
{
    return termios_flags_to_linux(mf, oflag_map, ARRAY_SIZE(oflag_map));
}

/* Linux aarch64 c_cflag bits (asm-generic/termbits.h). All standard flags
 * differ from macOS: macOS shifts everything left by 4 bits (e.g., Linux
 * CS8=0x30, macOS CS8=0x300; Linux CSTOPB=0x40, macOS=0x400). The CBAUD field
 * (Linux 0x0000100f) encodes baud rate symbolically; macOS uses raw numeric
 * speeds via cfgetispeed/cfsetispeed, so termios translation drops CBAUD from
 * c_cflag and always uses the speed accessors.
 */
#define LINUX_CSIZE 0x0030
#define LINUX_CS5 0x0000
#define LINUX_CS6 0x0010
#define LINUX_CS7 0x0020
#define LINUX_CS8 0x0030
#define LINUX_CSTOPB 0x0040
#define LINUX_CREAD 0x0080
#define LINUX_PARENB 0x0100
#define LINUX_PARODD 0x0200
#define LINUX_HUPCL 0x0400
#define LINUX_CLOCAL 0x0800

/* LINUX_CBAUD 0x0000100f and LINUX_CBAUDEX 0x00001000 encode baud in c_cflag;
 * macOS uses dedicated speed fields, so the c_cflag translation tables skip
 * CBAUD and the TCGETS/TCSETS arms convert it with the helpers below.
 * TCGETS2/TCSETS2 use BOTHER to signal numeric c_ispeed/c_ospeed.
 */
#define LINUX_CBAUD 0x100f
#define LINUX_BOTHER 0x1000
/* CIBAUD is CBAUD shifted by IBSHIFT (asm-generic/termbits.h). */
#define LINUX_IBSHIFT 16

/* Decode a Linux CBAUD field value to a numeric baud rate.
 * Returns the numeric rate, or 0 for B0 / unknown. Standard rates B0-B38400 are
 * in the low nibble (0-15); extended rates B57600-B4000000 use CBAUDEX (0x1000)
 * + low nibble.
 */
static speed_t linux_cbaud_to_speed(uint32_t cbaud)
{
    static const speed_t std_rates[16] = {
        0,   50,   75,   110,  134,  150,  200,   300,
        600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
    };
    static const speed_t ext_rates[16] = {
        0,       57600,   115200,  230400,  460800,  500000,  576000,  921600,
        1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000,
    };
    uint32_t rate_idx = cbaud & 0xF;

    if (cbaud < 16)
        return std_rates[cbaud];
    if (cbaud & LINUX_BOTHER)
        return ext_rates[rate_idx];
    return 0;
}

/* Encode a numeric baud rate as a Linux CBAUD field value (the inverse of
 * linux_cbaud_to_speed).
 *
 * Returns the B* index for the standard rates, or BOTHER for a rate Linux has
 * no symbolic name for, so cfgetospeed() in the guest sees the same constant it
 * passed to cfsetospeed().
 */
static uint32_t speed_to_linux_cbaud(speed_t speed)
{
    for (uint32_t i = 0; i < 16; i++) {
        if (linux_cbaud_to_speed(i) == speed)
            return i;
        if (i && linux_cbaud_to_speed(LINUX_BOTHER | i) == speed)
            return LINUX_BOTHER | i;
    }
    return LINUX_BOTHER;
}

/* Encode the host line rates into the CBAUD and CIBAUD fields of a Linux
 * c_cflag, the way tty_termios_encode_baud_rate() does: CBAUD always carries
 * the output rate; CIBAUD is set only when the input rate differs, and is left
 * at B0 ("same as output") otherwise.
 */
static uint32_t linux_cflag_speed_bits(const struct termios *t)
{
    speed_t ospeed = cfgetospeed(t), ispeed = cfgetispeed(t);
    uint32_t bits = speed_to_linux_cbaud(ospeed);
    if (ispeed != ospeed)
        bits |= speed_to_linux_cbaud(ispeed) << LINUX_IBSHIFT;
    return bits;
}

/* Apply the CBAUD/CIBAUD fields of a plain (non-termios2) Linux c_cflag to a
 * host termios, following drivers/tty/tty_baudrate.c: the output rate is the
 * CBAUD table entry; the input rate is CIBAUD's, or the output rate when CIBAUD
 * is B0. Two values carry no rate and leave the host speed untouched: B0 in
 * CBAUD, which on Linux means "drop DTR/RTS" (not emulated), and a bare BOTHER,
 * which the kernel resolves from the tty's current c_ospeed/c_ispeed because
 * the plain struct has no speed fields -- so a tcgetattr/tcsetattr round trip
 * on a port set to 74880 through termios2 must not collapse the line to B0.
 */
static int apply_linux_cflag_speeds(struct termios *t, uint32_t c_cflag)
{
    uint32_t cbaud = c_cflag & LINUX_CBAUD;
    uint32_t cibaud = (c_cflag >> LINUX_IBSHIFT) & LINUX_CBAUD;
    speed_t orate = linux_cbaud_to_speed(cbaud);

    /* Both B0 and a bare BOTHER decode to 0, but they must part ways in the
     * CIBAUD-empty fallback: BOTHER resolves the input rate from the tty's
     * current output rate (tty_termios_baud_rate reads c_ospeed), while B0
     * carries no rate at all and must leave a split input rate alone.
     */
    speed_t irate = cibaud == 0
                        ? (cbaud == LINUX_BOTHER ? cfgetospeed(t) : orate)
                        : linux_cbaud_to_speed(cibaud);
    if (orate && cfsetospeed(t, orate) < 0)
        return -1;
    if (irate && cfsetispeed(t, irate) < 0)
        return -1;
    return 0;
}

/* CSIZE: Linux CS5=0x00, CS6=0x10, CS7=0x20, CS8=0x30
 *        macOS CS5=0x00, CS6=0x100, CS7=0x200, CS8=0x300
 */
static const termios_field_pair_t csize_map[] = {
    {LINUX_CS5, CS5},
    {LINUX_CS6, CS6},
    {LINUX_CS7, CS7},
    {LINUX_CS8, CS8},
};

/* CBAUD and CBAUDEX are absent on purpose: the baud rate travels in the
 * c_ispeed and c_ospeed fields, not in c_cflag. The TCGETS/TCSETS arms in
 * sys_ioctl encode and decode the CBAUD field separately, since plain termios
 * has no speed fields for a guest libc to consult.
 */
static const termios_flag_pair_t cflag_map[] = {
    {LINUX_CSTOPB, CSTOPB}, {LINUX_CREAD, CREAD}, {LINUX_PARENB, PARENB},
    {LINUX_PARODD, PARODD}, {LINUX_HUPCL, HUPCL}, {LINUX_CLOCAL, CLOCAL},
};

/* Translate Linux c_cflag to macOS c_cflag. */
static tcflag_t linux_cflag_to_mac(uint32_t lf)
{
    return termios_field_to_mac(lf, LINUX_CSIZE, csize_map,
                                ARRAY_SIZE(csize_map)) |
           termios_flags_to_mac(lf, cflag_map, ARRAY_SIZE(cflag_map));
}

/* Translate macOS c_cflag to Linux c_cflag. */
static uint32_t mac_cflag_to_linux(tcflag_t mf)
{
    return termios_field_to_linux(mf, CSIZE, csize_map, ARRAY_SIZE(csize_map)) |
           termios_flags_to_linux(mf, cflag_map, ARRAY_SIZE(cflag_map));
}

/* Linux aarch64 c_lflag bits (asm-generic/termbits.h). Virtually every flag has
 * a different value from macOS. Only ECHO (0x0008) is the same on both
 * platforms. XCASE (Linux 0x004, rarely used, no macOS equivalent) is dropped;
 * macOS 0x004 has different semantics and is not translated here.
 */
#define LINUX_ISIG 0x00001
#define LINUX_ICANON 0x00002
#define LINUX_ECHO 0x00008 /* same on macOS */
#define LINUX_ECHOE 0x00010
#define LINUX_ECHOK 0x00020
#define LINUX_ECHONL 0x00040
#define LINUX_NOFLSH 0x00080
#define LINUX_TOSTOP 0x00100
#define LINUX_ECHOCTL 0x00200
#define LINUX_ECHOPRT 0x00400
#define LINUX_ECHOKE 0x00800
#define LINUX_FLUSHO 0x01000
#define LINUX_PENDIN 0x04000
#define LINUX_IEXTEN 0x08000
#define LINUX_EXTPROC 0x10000

/* Translate Linux c_lflag to macOS c_lflag. XCASE (Linux 0x004) has no macOS
 * equivalent and is absent on purpose.
 */
static const termios_flag_pair_t lflag_map[] = {
    {LINUX_ISIG, ISIG},       {LINUX_ICANON, ICANON}, {LINUX_ECHO, ECHO},
    {LINUX_ECHOE, ECHOE},     {LINUX_ECHOK, ECHOK},   {LINUX_ECHONL, ECHONL},
    {LINUX_NOFLSH, NOFLSH},   {LINUX_TOSTOP, TOSTOP}, {LINUX_ECHOCTL, ECHOCTL},
    {LINUX_ECHOPRT, ECHOPRT}, {LINUX_ECHOKE, ECHOKE}, {LINUX_FLUSHO, FLUSHO},
    {LINUX_PENDIN, PENDIN},   {LINUX_IEXTEN, IEXTEN}, {LINUX_EXTPROC, EXTPROC},
};

static tcflag_t linux_lflag_to_mac(uint32_t lf)
{
    return termios_flags_to_mac(lf, lflag_map, ARRAY_SIZE(lflag_map));
}

/* Translate macOS c_lflag to Linux c_lflag. */
static uint32_t mac_lflag_to_linux(tcflag_t mf)
{
    return termios_flags_to_linux(mf, lflag_map, ARRAY_SIZE(lflag_map));
}

/* read/write and positional variants. */

/* Open a host fd reference for regular I/O, checking type and seals under
 * fd_lock for thread safety.
 *
 * Returns -LINUX_EBADF for path-only or closed fds, -LINUX_EPERM for
 * write-sealed fds (when check_write_seal is set), or 0 on success.
 */
static int64_t host_fd_ref_open_checked(int guest_fd,
                                        host_fd_ref_t *ref,
                                        bool check_write_seal)
{
    if (check_write_seal) {
        fd_entry_t snap;
        if (!fd_snapshot(guest_fd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_PATH)
            return -LINUX_EBADF;
        if (snap.seals & LINUX_F_SEAL_WRITE)
            return -LINUX_EPERM;
        return host_fd_ref_open(guest_fd, ref) < 0 ? -LINUX_EBADF : 0;
    }
    return host_fd_ref_open_io(guest_fd, ref);
}

/* True when a read on this pty master must fail with EIO.
 *
 * Linux fails every read variant once the master has hung up, not just read(2).
 * Only after the queue drains: a shell that printed on its way out leaves that
 * output behind, and Linux hands it over before reporting the hangup, so
 * deciding on the hangup first would swallow it.
 *
 * Without this the host read simply blocks -- elfuse's keepalive slave keeps
 * the pty alive from its point of view -- so a terminal that drains its master
 * with readv() gets the POLLHUP, calls readv, and wedges there forever with its
 * window still open.
 */
static bool pty_read_hangs_up(int guest_fd, uint64_t gen, int host_fd)
{
    if (!proc_pty_master_hung_up(guest_fd, gen))
        return false;
    struct pollfd drain = {.fd = host_fd, .events = POLLIN};
    return poll(&drain, 1, 0) <= 0 || !(drain.revents & POLLIN);
}

static int64_t host_fd_ref_open_regular_io(int guest_fd, host_fd_ref_t *ref)
{
    return host_fd_ref_open_io(guest_fd, ref);
}

/* host_fd_ref_open_regular_io() that also pins the generation the reference was
 * resolved against, in the same fd_lock window. See host_fd_ref_open_io_gen().
 */
static int64_t host_fd_ref_open_regular_io_gen(int guest_fd,
                                               host_fd_ref_t *ref,
                                               uint64_t *out_gen)
{
    return host_fd_ref_open_io_gen(guest_fd, ref, out_gen);
}

static int64_t proc_try_read_intercept(int fd,
                                       int host_fd,
                                       void *buf,
                                       size_t count,
                                       int64_t offset,
                                       int use_pread)
{
    ssize_t intercepted = 0;
    int handled = proc_intercept_read(fd, buf, count, offset, &intercepted);
    if (handled < 0)
        return linux_errno();
    if (handled > 0) {
        if (!use_pread &&
            lseek(host_fd, offset + (int64_t) intercepted, SEEK_SET) < 0)
            return linux_errno();
        return intercepted;
    }
    return INT64_MIN;
}

static int64_t proc_try_readv_intercept(int fd,
                                        int host_fd,
                                        const struct iovec *iov,
                                        int iovcnt,
                                        int64_t offset,
                                        int use_pread)
{
    ssize_t intercepted = 0;
    int handled = proc_intercept_readv(fd, iov, iovcnt, offset, &intercepted);
    if (handled < 0)
        return linux_errno();
    if (handled > 0) {
        if (!use_pread &&
            lseek(host_fd, offset + (int64_t) intercepted, SEEK_SET) < 0)
            return linux_errno();
        return intercepted;
    }
    return INT64_MIN;
}

/* Sendfile/copy_file_range chunk read: route the chunk through proc_intercept
 * when the source fd is a synthetic /proc node, otherwise fall through
 * (INT64_MIN). For the streaming (use_pread=0) variant the input offset is
 * irrelevant; the helper queries the live host fd cursor.
 */
static int64_t proc_try_chunk_read_intercept(int fd,
                                             int host_fd,
                                             void *buf,
                                             size_t count,
                                             int64_t offset,
                                             int use_pread)
{
    if (!use_pread) {
        offset = lseek(host_fd, 0, SEEK_CUR);
        if (offset < 0)
            return INT64_MIN;
    }
    return proc_try_read_intercept(fd, host_fd, buf, count, offset, use_pread);
}

static int64_t proc_try_writev_intercept(int fd,
                                         int host_fd,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         int64_t offset,
                                         int use_pwrite)
{
    uint64_t total = 0;
    char stack_buf[256];
    char *buf = stack_buf;
    char *heap = NULL;
    ssize_t written = 0;
    int handled;

    /* The sum feeds malloc() and then a memcpy loop that writes exactly that
     * many bytes, so a wrapped total here is a short allocation followed by a
     * long copy. host_iov_prepare clamps every entry to the guest mapping it
     * points into, which made the wrap unreachable by provenance rather than by
     * construction; iov_total_add makes it unreachable by construction.
     */
    for (int i = 0; i < iovcnt; i++) {
        /* INT64_MIN is this helper's "not handled", and that is the right
         * answer: the fd may well not be a /proc node, so the size verdict
         * belongs to the real writev below, not to the interceptor.
         */
        if (!iov_total_add(total, iov[i].iov_len, &total))
            return INT64_MIN;
    }
    if (total > sizeof(stack_buf)) {
        heap = malloc(total);
        if (!heap)
            return -LINUX_ENOMEM;
        buf = heap;
    }

    size_t off = 0;
    for (int i = 0; i < iovcnt; i++) {
        memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    handled = proc_intercept_write(fd, host_fd, buf, total, offset, use_pwrite,
                                   &written);
    free(heap);
    if (handled < 0)
        return linux_errno();
    if (handled > 0)
        return written;
    return INT64_MIN;
}

static int64_t io_write_result(ssize_t ret)
{
    if (ret >= 0)
        return ret;

    int saved_errno = errno;
    if (saved_errno == EPIPE)
        signal_queue(LINUX_SIGPIPE);
    errno = saved_errno;
    return linux_errno();
}

int64_t sys_write(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    int type = fd_get_type(fd);
    if (type == FD_FUSE_DEV)
        return fuse_dev_write(g, fd, buf_gva, count);
    if (type == FD_EVENTFD)
        return eventfd_write(fd, g, buf_gva, count);

    /* Linux accepts write() on a netlink socket as sendto() with no explicit
     * destination, and iproute2-style senders use it in place of sendto. The
     * host fd behind a netlink guest fd is the read end of the readiness pipe,
     * so falling through would write to a read-only pipe end and report EBADF
     * for a request the emulation can answer.
     */
    if (type == FD_NETLINK)
        return netlink_send(fd, g, buf_gva, count);

    /* usbdevfs has no write op; vfs_write answers -EINVAL for such files.
     * Falling through would scribble on the readiness pipe's read end.
     */
    if (type == FD_USBDEV)
        return -LINUX_EINVAL;

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    /* Linux: write(fd, NULL, 0) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    /* Resolve buffer and cap count to available contiguous guest bytes.
     * guest_ptr_avail returns the host pointer and remaining bytes in the
     * current region. This prevents host write() from reading past the guest
     * buffer boundary.
     */
    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_R, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        ssize_t intercepted = 0;
        int handled = proc_intercept_write(fd, host_ref.fd, buf, count, offset,
                                           0, &intercepted);
        if (handled < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        if (handled > 0) {
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    /* A blocking write on a full pipe/socket buffer would park this vCPU thread
     * in an uninterruptible host write() where the preempt thread's
     * hv_vcpus_exit cannot reach it. Wait for POLLOUT (or a guest signal)
     * first. Unlike the socket send paths there is no per-call nonblocking flag
     * for write(), so the tiny window where the buffer refills between the wait
     * and write() can still block; that matches sys_read and the receive paths.
     */
    int64_t wwait = io_block_wait(fd, host_ref.fd, POLLOUT);
    if (wwait < 0) {
        host_fd_ref_close(&host_ref);
        return wwait;
    }

    ssize_t ret = write(host_ref.fd, buf, count);
    host_fd_ref_close(&host_ref);
    return io_write_result(ret);
}

int64_t sys_read(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    /* Read the type once under fd_lock so a concurrent close/reopen cannot make
     * different dispatch checks disagree. Each handler still re-validates
     * internally and returns EBADF if its slot changed.
     */
    int type = fd_get_type(fd);
    switch (type) {
    case FD_FUSE_DEV:
        return fuse_dev_read(fd, g, buf_gva, count);
    case FD_FUSE_FILE:
        return fuse_read_fd(g, fd, buf_gva, count);
    case FD_EVENTFD:
        return eventfd_read(fd, g, buf_gva, count);
    case FD_SIGNALFD:
        return signalfd_read(fd, g, buf_gva, count);
    case FD_TIMERFD:
        return timerfd_read(fd, g, buf_gva, count);
    case FD_INOTIFY:
        return inotify_read(fd, g, buf_gva, count);
    case FD_NETLINK:
        return netlink_read(fd, g, buf_gva, count);
    case FD_URANDOM:
        return urandom_read(g, fd, buf_gva, count);
    case FD_USBDEV:
        return usbdev_read(fd, g, buf_gva, count);
    }

    /* Pin the generation in the same fd_lock window as the host fd. The pty
     * hangup check below re-resolves the guest fd, and this is the witness that
     * the slot still holds the very file this read resolved.
     */
    host_fd_ref_t host_ref;
    uint64_t read_gen;
    int64_t err = host_fd_ref_open_regular_io_gen(fd, &host_ref, &read_gen);
    if (err < 0)
        return err;

    /* Linux: read(fd, NULL, 0) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    /* Resolve buffer and cap count to available contiguous guest bytes.
     * Prevents host read() from writing past the guest buffer boundary.
     */
    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    /* A pty master whose guest-side slaves have all closed is hung up. Linux
     * answers EIO there; the host would block forever instead, because elfuse's
     * keepalive slave keeps the pty alive from its point of view.
     *
     * Only once nothing is left to read: a shell that printed on its way out
     * leaves that output queued, and Linux hands it over before reporting the
     * hangup. Deciding on the hangup first would swallow it.
     */
    if (pty_read_hangs_up(fd, read_gen, host_ref.fd)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EIO;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted =
            proc_try_read_intercept(fd, host_ref.fd, buf, count, offset, 0);
        if (intercepted != INT64_MIN) {
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    /* Wait interruptibly when the fd can block on a read (pipe, socket, fifo,
     * char/tty). Regular files never block and skip this.
     */
    int64_t rwait = io_block_wait(fd, host_ref.fd, POLLIN);
    if (rwait < 0) {
        host_fd_ref_close(&host_ref);
        return rwait;
    }

    ssize_t ret = read(host_ref.fd, buf, count);
    int64_t result = ret < 0 ? recv_eof_or_errno(host_ref.fd, fd) : ret;
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_pread64(guest_t *g,
                    int fd,
                    uint64_t buf_gva,
                    uint64_t count,
                    int64_t offset)
{
    if (fuse_is_file_fd(fd))
        return fuse_pread_fd(g, fd, buf_gva, count, offset);

    /* usbdevfs serves its descriptors blob positionally too: every read path on
     * the fd must agree, and the host fd behind it is a readiness pipe.
     */
    if (fd_get_type(fd) == FD_USBDEV)
        return usbdev_pread(fd, g, buf_gva, count, offset);

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux: pread(fd, NULL, 0, off) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    int64_t intercepted =
        proc_try_read_intercept(fd, host_ref.fd, buf, count, offset, 1);
    if (intercepted != INT64_MIN) {
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pread(host_ref.fd, buf, count, offset);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : ret;
}

int64_t sys_pwrite64(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t count,
                     int64_t offset)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    /* Linux: pwrite(fd, NULL, 0, off) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_R, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    ssize_t intercepted = 0;
    int handled = proc_intercept_write(fd, host_ref.fd, buf, count, offset, 1,
                                       &intercepted);
    if (handled < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    if (handled > 0) {
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pwrite(host_ref.fd, buf, count, offset);
    host_fd_ref_close(&host_ref);
    return io_write_result(ret);
}

/* Helper: build host iovec array from guest iovec array. Uses guest_read for
 * the iovec array (may cross 2MiB block boundary) and guest_ptr_avail for each
 * buffer (caps to contiguous bytes). required_perms: MEM_PERM_W for readv (host
 * writes to guest buffers),
 *                 MEM_PERM_R for writev (host reads from guest buffers).
 * Returns 0 on success, -LINUX_EFAULT on bad guest pointer.
 */
static int64_t build_host_iov(guest_t *g,
                              uint64_t iov_gva,
                              int iovcnt,
                              struct iovec *host_iov,
                              int required_perms)
{
    linux_iovec_t stack_giov[SYSCALL_IOV_STACK_MAX];
    linux_iovec_t *guest_iov = stack_giov;
    linux_iovec_t *heap = NULL;
    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        heap = malloc((size_t) iovcnt * sizeof(*guest_iov));
        if (!heap)
            return -LINUX_ENOMEM;
        guest_iov = heap;
    }
    if (guest_read(g, iov_gva, guest_iov,
                   (size_t) iovcnt * sizeof(*guest_iov)) < 0) {
        free(heap);
        return -LINUX_EFAULT;
    }
    for (int i = 0; i < iovcnt; i++) {
        if (guest_iov[i].iov_len == 0) {
            host_iov[i].iov_base = NULL;
            host_iov[i].iov_len = 0;
            continue;
        }
        uint64_t avail = 0;
        void *base = guest_ptr_bound(g, guest_iov[i].iov_base, &avail,
                                     required_perms, guest_iov[i].iov_len);
        if (!base) {
            free(heap);
            return -LINUX_EFAULT;
        }

        /* Cap to contiguous permitted bytes. When the guest iov entry spans a
         * non-contiguous boundary (different mapping or permission), zero every
         * subsequent host iov length so the host readv/writev returns a
         * POSIX-compliant short I/O rather than silently packing the truncated
         * tail of buffer i into buffer i+1 -- which corrupts the guest's data
         * layout.
         */
        uint64_t len = guest_iov[i].iov_len;
        host_iov[i].iov_base = base;
        if (len > avail) {
            host_iov[i].iov_len = avail;
            for (int j = i + 1; j < iovcnt; j++) {
                host_iov[j].iov_base = NULL;
                host_iov[j].iov_len = 0;
            }
            break;
        }
        host_iov[i].iov_len = len;
    }
    free(heap);
    return 0;
}

int64_t host_iov_prepare(guest_t *g,
                         uint64_t iov_gva,
                         int iovcnt,
                         int required_perms,
                         host_iov_buf_t *buf)
{
    buf->iov = buf->stack;
    buf->heap = NULL;

    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        buf->heap = malloc((size_t) iovcnt * sizeof(*buf->iov));
        if (!buf->heap)
            return -LINUX_ENOMEM;
        buf->iov = buf->heap;
    }

    int64_t err = build_host_iov(g, iov_gva, iovcnt, buf->iov, required_perms);
    if (err < 0) {
        free(buf->heap);
        buf->heap = NULL;
        buf->iov = NULL;
        return err;
    }

    return 0;
}

int64_t host_iov_prepare_msg(guest_t *g,
                             uint64_t iov_gva,
                             int iovcnt,
                             int required_perms,
                             host_iov_buf_t *buf)
{
    if (iovcnt == 0) {
        buf->iov = buf->stack;
        buf->heap = NULL;
        return 0;
    }
    return host_iov_prepare(g, iov_gva, iovcnt, required_perms, buf);
}

void host_iov_free(host_iov_buf_t *buf)
{
    free(buf->heap);
    buf->heap = NULL;
    buf->iov = NULL;
}

static int64_t single_guest_iov(guest_t *g,
                                uint64_t iov_gva,
                                linux_iovec_t *iov)
{
    if (guest_read_small(g, iov_gva, iov, sizeof(*iov)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Linux returns 0 for zero-iovcnt vector I/O once the fd validates:
 * import_iovec() yields an empty iterator and do_iter_read/do_iter_write return
 * before the file offset is touched, so even pwritev2(RWF_APPEND) leaves the
 * position alone. macOS readv/writev instead reject iovcnt == 0 with EINVAL, so
 * short-circuit before any host call -- the append path's SEEK_END would
 * otherwise move the shared offset. The iov pointer is not dereferenced (Linux
 * ignores it for an empty vector), and negative counts keep flowing into
 * host_iov_prepare's EINVAL.
 *
 * The checks Linux runs before its empty-vector return still apply, in this
 * order: the positional variants fail non-seekable files with ESPIPE
 * (FMODE_PREAD/FMODE_PWRITE in do_preadv/do_pwritev), and all variants fail
 * wrong-direction fds with EBADF (FMODE_READ/FMODE_WRITE in
 * do_iter_read/do_iter_write). Both are probed on the host fd, whose open mode
 * mirrors the guest's for host-backed types; fd_table linux_flags cannot be
 * used because pipe/socket entries only track CLOEXEC there. Virtual
 * multiplexed fds (eventfd/timerfd/signalfd/...) sit on host pipes or kqueues
 * whose mode says nothing about the guest-visible fd (the Linux anon-inode
 * equivalents are O_RDWR), so they validate existence only. No F_SEAL_WRITE
 * check: Linux never reaches the write path for an empty vector, so a
 * write-sealed memfd returns 0 here too.
 */
static int64_t vec_zero_iovcnt(int fd, bool op_is_write, bool positional)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type == FD_PATH)
        return -LINUX_EBADF;

    bool host_mode_mirrors_guest =
        snap.type == FD_REGULAR || snap.type == FD_DIR ||
        snap.type == FD_PIPE || snap.type == FD_SOCKET ||
        snap.type == FD_STDIO || snap.type == FD_URANDOM;
    if (!host_mode_mirrors_guest)
        return 0;

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    int64_t ret = 0;
    if (positional && lseek(host_ref.fd, 0, SEEK_CUR) < 0 && errno == ESPIPE)
        ret = -LINUX_ESPIPE;
    if (ret == 0) {
        int fl = fcntl(host_ref.fd, F_GETFL);
        int accmode = fl >= 0 ? (fl & O_ACCMODE) : O_RDWR;
        if (op_is_write ? accmode == O_RDONLY : accmode == O_WRONLY)
            ret = -LINUX_EBADF;
    }
    host_fd_ref_close(&host_ref);
    return ret;
}


/* readv()/preadv() on an FD_USBDEV fd. Linux's usbdev file has only a plain
 * read op, so vectored reads take do_loop_readv_writev: one read per iovec
 * entry, stopping at the first short transfer. positional keeps the fd position
 * untouched and reads at offset plus the bytes already copied; otherwise each
 * usbdev_read advances the fd position like read(2).
 */
static int64_t usbdev_vec_read(guest_t *g,
                               int fd,
                               uint64_t iov_gva,
                               int iovcnt,
                               int64_t offset,
                               bool positional)
{
    if (positional && offset < 0)
        return -LINUX_EINVAL; /* do_preadv: before the fd lookup */
    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    linux_iovec_t stack_giov[SYSCALL_IOV_STACK_MAX];
    linux_iovec_t *giov = stack_giov;
    linux_iovec_t *heap_giov = NULL;
    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        heap_giov = malloc((size_t) iovcnt * sizeof(*giov));
        if (!heap_giov)
            return -LINUX_ENOMEM;
        giov = heap_giov;
    }
    int64_t ret = validate_iov_total(g, iov_gva, iovcnt, giov);
    if (ret == 0) {
        for (int i = 0; i < iovcnt; i++) {
            if (giov[i].iov_len == 0)
                continue;
            int64_t got =
                positional
                    ? usbdev_pread(fd, g, giov[i].iov_base, giov[i].iov_len,
                                   offset + ret)
                    : usbdev_read(fd, g, giov[i].iov_base, giov[i].iov_len);
            if (got < 0) {
                ret = ret > 0 ? ret : got;
                break;
            }
            ret += got;

            /* A short entry ends the transfer; POSIX forbids packing the tail
             * of entry i into entry i+1.
             */
            if ((uint64_t) got < giov[i].iov_len)
                break;
        }
    }
    free(heap_giov);
    return ret;
}

int64_t sys_readv(guest_t *g, int fd, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt == 0)
        return vec_zero_iovcnt(fd, false, false);
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_readv(fd, g, iov_gva, iovcnt);
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        if (fd_get_type(fd) == FD_URANDOM &&
            giov.iov_len > (uint64_t) SSIZE_MAX) {
            err = urandom_check_readable(fd);
            if (err < 0)
                return err;
            return -LINUX_EINVAL;
        }
        return sys_read(g, fd, giov.iov_base, giov.iov_len);
    }

    /* Special FD types need their custom read handlers because glibc may use
     * readv() instead of read() for the same logical operation. Delegate scalar
     * special fds to the first iov entry's buffer. Use the first iov's length
     * (not the sum of all iovs) because the data goes into giov[0].iov_base
     * which is only giov[0].iov_len bytes long.
     */
    int type = fd_get_type(fd);
    if (type == FD_URANDOM) {
        int64_t err = urandom_check_readable(fd);
        if (err < 0)
            return err;
        if (!iov_count_ok(iovcnt))
            return -LINUX_EINVAL;

        linux_iovec_t stack_giov[SYSCALL_IOV_STACK_MAX];
        linux_iovec_t *giov = stack_giov;
        linux_iovec_t *heap_giov = NULL;
        if (iovcnt > SYSCALL_IOV_STACK_MAX) {
            heap_giov = malloc((size_t) iovcnt * sizeof(*giov));
            if (!heap_giov)
                return -LINUX_ENOMEM;
            giov = heap_giov;
        }
        err = validate_iov_total(g, iov_gva, iovcnt, giov);
        if (err < 0) {
            free(heap_giov);
            return err;
        }

        /* Stage every entry through a host buffer for the reason spelled out on
         * urandom_fill_guest: a resolved guest pointer would be written under
         * the per-fd cache lock, where a vanished MAP_SHARED page kills the
         * host instead of reporting EFAULT.
         */
        int64_t ret = 0;
        for (int i = 0; i < iovcnt; i++) {
            if (giov[i].iov_len == 0)
                continue;
            int64_t got =
                urandom_fill_guest(g, fd, giov[i].iov_base, giov[i].iov_len);
            if (got < 0) {
                ret = ret > 0 ? ret : got;
                break;
            }
            ret += got;

            /* A short entry means the guest buffer ran out mid-way; POSIX
             * requires the transfer to stop there rather than pack the tail of
             * entry i into entry i+1.
             */
            if ((uint64_t) got < giov[i].iov_len)
                break;
        }
        free(heap_giov);

        /* Mirror sys_read's slow-path refill so a readv consumer that drains
         * the shim ring leaves it ready for the next call, instead of forcing
         * every subsequent EL1 fast-path attempt back through HVC until some
         * other path triggers a refill.
         */
        shim_globals_refill_urandom_ring(g);
        return ret;
    }
    if (type == FD_EVENTFD || type == FD_SIGNALFD || type == FD_TIMERFD ||
        type == FD_INOTIFY) {
        if (iovcnt <= 0)
            return -LINUX_EINVAL;

        /* Use guest_read for the iov array since guest_ptr alone is unsafe if
         * the array spans a 2MiB block boundary.
         */
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva, &giov, sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        return sys_read(g, fd, giov.iov_base, giov.iov_len);
    }
    if (type == FD_USBDEV)
        return usbdev_vec_read(g, fd, iov_gva, iovcnt, 0, false);

    host_fd_ref_t host_ref;
    uint64_t readv_gen;
    int64_t err = host_fd_ref_open_regular_io_gen(fd, &host_ref, &readv_gen);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }
    if (!host_iov_has_payload(&host_iov, iovcnt)) {
        err = io_check_access(host_ref.fd, POLLIN);
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return err < 0 ? err : 0;
    }

    /* Same hangup rule as sys_read: a terminal draining its master with readv
     * must be told the shell is gone, or it blocks here forever.
     *
     * After the zero-payload branch on purpose: a vector that can consume
     * nothing reads zero bytes on Linux whatever the pty's state, so deciding
     * the hangup first would turn that into a spurious EIO.
     */
    if (pty_read_hangs_up(fd, readv_gen, host_ref.fd)) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return -LINUX_EIO;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_readv_intercept(
            fd, host_ref.fd, host_iov.iov, iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    int64_t rwait = io_block_wait(fd, host_ref.fd, POLLIN);
    if (rwait < 0) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return rwait;
    }

    ssize_t ret = readv(host_ref.fd, host_iov.iov, iovcnt);
    int64_t result = ret < 0 ? recv_eof_or_errno(host_ref.fd, fd) : ret;
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_writev(guest_t *g, int fd, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt == 0)
        return vec_zero_iovcnt(fd, true, false);

    /* Ahead of the single-entry shortcut: a one-entry writev of nothing reports
     * 0, while the write(2) the shortcut would reach reports ENODATA.
     */
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_writev(fd, g, iov_gva, iovcnt);
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_write(g, fd, giov.iov_base, giov.iov_len);
    }

    /* Special FD types: glibc may use writev() for eventfd wakeup writes.
     * Delegate using the first iov entry. Use giov.iov_len (not the sum of all
     * iovs) because the data is at giov.iov_base which is only giov.iov_len
     * bytes. eventfd expects exactly 8 bytes.
     */
    int wtype = fd_get_type(fd);
    if (wtype == FD_EVENTFD) {
        if (iovcnt <= 0)
            return -LINUX_EINVAL;
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva, &giov, sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        return eventfd_write(fd, g, giov.iov_base, giov.iov_len);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }
    if (!host_iov_has_payload(&host_iov, iovcnt)) {
        err = io_check_access(host_ref.fd, POLLOUT);
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return err < 0 ? err : 0;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_writev_intercept(
            fd, host_ref.fd, host_iov.iov, iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    int64_t wwait = io_block_wait(fd, host_ref.fd, POLLOUT);
    if (wwait < 0) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return wwait;
    }

    ssize_t ret = writev(host_ref.fd, host_iov.iov, iovcnt);
    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_preadv(guest_t *g,
                   int fd,
                   uint64_t iov_gva,
                   int iovcnt,
                   int64_t offset)
{
    if (iovcnt == 0) {
        /* do_preadv rejects a negative offset before looking up the fd, so
         * EINVAL outranks EBADF here; nonzero counts keep getting EINVAL from
         * the host preadv instead.
         */
        if (offset < 0)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, false, true);
    }
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_pread64(g, fd, giov.iov_base, giov.iov_len, offset);
    }
    if (fd_get_type(fd) == FD_USBDEV)
        return usbdev_vec_read(g, fd, iov_gva, iovcnt, offset, true);

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_readv_intercept(
        fd, host_ref.fd, host_iov.iov, iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = preadv(host_ref.fd, host_iov.iov, iovcnt, offset);
    int64_t result = ret < 0 ? linux_errno() : ret;
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_pwritev(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset)
{
    if (iovcnt == 0) {
        /* Same ordering as sys_preadv: negative offset EINVAL first. */
        if (offset < 0)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, true, true);
    }
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_pwrite64(g, fd, giov.iov_base, giov.iov_len, offset);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_writev_intercept(
        fd, host_ref.fd, host_iov.iov, iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pwritev(host_ref.fd, host_iov.iov, iovcnt, offset);
    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

static int64_t sys_pwritev_append(guest_t *g,
                                  int fd,
                                  uint64_t iov_gva,
                                  int iovcnt,
                                  bool update_file_offset)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    ssize_t ret;
    if (update_file_offset) {
        if (lseek(host_ref.fd, 0, SEEK_END) < 0) {
            ret = -1;
        } else {
            ret = writev(host_ref.fd, host_iov.iov, iovcnt);
        }
    } else {
        struct stat st;
        if (fstat(host_ref.fd, &st) < 0) {
            ret = -1;
        } else {
            ret = pwritev(host_ref.fd, host_iov.iov, iovcnt, st.st_size);
        }
    }

    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

/* Linux RWF_* flags for preadv2/pwritev2 (include/uapi/linux/fs.h) */
#define RWF_HIPRI 0x00000001  /* High priority hint (best-effort) */
#define RWF_DSYNC 0x00000002  /* Per-I/O data integrity sync */
#define RWF_SYNC 0x00000004   /* Per-I/O file integrity sync */
#define RWF_NOWAIT 0x00000008 /* Nonblocking hint (best-effort) */
#define RWF_APPEND 0x00000010 /* Append mode (pwritev2 only) */
#define RWF_SUPPORTED \
    (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND)

int64_t sys_preadv2(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset,
                    int flags)
{
    /* Linux validates RWF flags only once the write/read actually proceeds
     * (kiocb_set_rw_flags sits behind the empty-vector return in
     * do_iter_read/do_iter_write), so an empty vector short-circuits before the
     * flag checks. Offset -1 selects do_readv (no seekability check); any other
     * negative offset fails EINVAL before the fd lookup.
     */
    if (iovcnt == 0) {
        if (offset < -1)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, false, offset != -1);
    }
    if (flags & ~RWF_SUPPORTED)
        return -LINUX_EOPNOTSUPP;
    if (flags & RWF_APPEND)
        return -LINUX_EINVAL; /* RWF_APPEND is write-only */
    /* RWF_HIPRI, RWF_NOWAIT: best-effort hints, safe to ignore. RWF_DSYNC,
     * RWF_SYNC: no effect on reads.
     */
    if (offset == -1)
        return sys_readv(g, fd, iov_gva, iovcnt);
    return sys_preadv(g, fd, iov_gva, iovcnt, offset);
}

int64_t sys_pwritev2(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     int iovcnt,
                     int64_t offset,
                     int flags)
{
    /* Same ordering as sys_preadv2: empty vectors return before RWF flag
     * validation, which also keeps RWF_APPEND from moving the offset.
     */
    if (iovcnt == 0) {
        if (offset < -1)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, true, offset != -1);
    }
    if (flags & ~RWF_SUPPORTED)
        return -LINUX_EOPNOTSUPP;
    int64_t r;
    if (flags & RWF_APPEND)
        r = sys_pwritev_append(g, fd, iov_gva, iovcnt, offset == -1);
    else if (offset == -1)
        r = sys_writev(g, fd, iov_gva, iovcnt);
    else
        r = sys_pwritev(g, fd, iov_gva, iovcnt, offset);
    /* RWF_SYNC/RWF_DSYNC: sync after successful write */
    if (r > 0 && (flags & (RWF_SYNC | RWF_DSYNC))) {
        host_fd_ref_t host_ref;
        if (host_fd_ref_open_regular_io(fd, &host_ref) == 0) {
            fsync(host_ref.fd);
            host_fd_ref_close(&host_ref);
        }
    }
    return r;
}

static int64_t process_vm_import_iov(guest_t *g,
                                     uint64_t iov_gva,
                                     uint64_t iovcnt,
                                     linux_iovec_t **iov_out)
{
    *iov_out = NULL;

    if (iovcnt > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;
    if (iovcnt == 0)
        return 0;
    if (iovcnt > SIZE_MAX / sizeof(linux_iovec_t))
        return -LINUX_EINVAL;

    size_t bytes = (size_t) iovcnt * sizeof(linux_iovec_t);
    linux_iovec_t *iov = malloc(bytes);
    if (!iov)
        return -LINUX_ENOMEM;
    if (guest_read(g, iov_gva, iov, bytes) < 0) {
        free(iov);
        return -LINUX_EFAULT;
    }

    uint64_t total = 0;
    for (uint64_t i = 0; i < iovcnt; i++) {
        if (!iov_total_add(total, iov[i].iov_len, &total)) {
            free(iov);
            return -LINUX_EINVAL;
        }
    }

    *iov_out = iov;
    return 0;
}

static void process_vm_advance_iov(linux_iovec_t *iov,
                                   uint64_t iovcnt,
                                   uint64_t *idx,
                                   uint64_t *off)
{
    while (*idx < iovcnt && *off >= iov[*idx].iov_len) {
        *off = 0;
        (*idx)++;
    }
}

static int64_t process_vm_copy(guest_t *g,
                               linux_iovec_t *local_iov,
                               uint64_t local_iovcnt,
                               linux_iovec_t *remote_iov,
                               uint64_t remote_iovcnt,
                               bool write_remote)
{
    uint64_t li = 0, ri = 0, lo = 0, ro = 0;
    uint64_t copied = 0;

    for (;;) {
        process_vm_advance_iov(local_iov, local_iovcnt, &li, &lo);
        process_vm_advance_iov(remote_iov, remote_iovcnt, &ri, &ro);
        if (li >= local_iovcnt || ri >= remote_iovcnt)
            return (int64_t) copied;

        uint64_t local_left = local_iov[li].iov_len - lo;
        uint64_t remote_left = remote_iov[ri].iov_len - ro;
        uint64_t len = local_left < remote_left ? local_left : remote_left;
        if (len == 0)
            continue;

        if (local_iov[li].iov_base > UINT64_MAX - lo ||
            remote_iov[ri].iov_base > UINT64_MAX - ro)
            return copied > 0 ? (int64_t) copied : -LINUX_EFAULT;

        uint64_t src_gva = write_remote ? local_iov[li].iov_base + lo
                                        : remote_iov[ri].iov_base + ro;
        uint64_t dst_gva = write_remote ? remote_iov[ri].iov_base + ro
                                        : local_iov[li].iov_base + lo;

        uint64_t src_avail = 0, dst_avail = 0;
        void *src = guest_ptr_bound(g, src_gva, &src_avail, MEM_PERM_R, len);
        void *dst = guest_ptr_bound(g, dst_gva, &dst_avail, MEM_PERM_W, len);
        if (!src || !dst)
            return copied > 0 ? (int64_t) copied : -LINUX_EFAULT;

        uint64_t chunk = len;
        if (chunk > src_avail)
            chunk = src_avail;
        if (chunk > dst_avail)
            chunk = dst_avail;
        if (chunk == 0)
            return copied > 0 ? (int64_t) copied : -LINUX_EFAULT;

        /* Both ends are guest memory touched from host user mode, so either
         * side can be a vanished MAP_SHARED overlay page. Linux reports a
         * partial transfer here, or EFAULT when nothing moved.
         *
         * The copy reports its own progress rather than being wrapped in a bare
         * guard: chunk runs to the end of the contiguous region and can be
         * megabytes, so treating a fault as "this whole chunk moved nothing"
         * would drop everything the copy had already written.
         */
        size_t moved = guest_host_copy_partial(dst, src, (size_t) chunk);
        copied += moved;
        lo += moved;
        ro += moved;
        if (moved < (size_t) chunk)
            return copied > 0 ? (int64_t) copied : -LINUX_EFAULT;
    }
}

static int64_t sys_process_vm(guest_t *g,
                              int64_t pid,
                              uint64_t local_iov_gva,
                              uint64_t local_iovcnt,
                              uint64_t remote_iov_gva,
                              uint64_t remote_iovcnt,
                              uint64_t flags,
                              bool write_remote)
{
    if (flags != 0)
        return -LINUX_EINVAL;
    int32_t target_pid = (int32_t) pid;
    if (target_pid <= 0)
        return -LINUX_ESRCH;
    if (target_pid != (int32_t) proc_get_pid() && !thread_find(target_pid))
        return -LINUX_ESRCH;
    if (local_iovcnt == 0 || remote_iovcnt == 0)
        return 0;

    linux_iovec_t *local_iov = NULL;
    linux_iovec_t *remote_iov = NULL;
    int64_t err =
        process_vm_import_iov(g, local_iov_gva, local_iovcnt, &local_iov);
    if (err < 0)
        return err;
    err = process_vm_import_iov(g, remote_iov_gva, remote_iovcnt, &remote_iov);
    if (err < 0) {
        free(local_iov);
        return err;
    }

    int64_t ret = process_vm_copy(g, local_iov, local_iovcnt, remote_iov,
                                  remote_iovcnt, write_remote);
    free(remote_iov);
    free(local_iov);
    return ret;
}

int64_t sys_process_vm_readv(guest_t *g,
                             int64_t pid,
                             uint64_t local_iov_gva,
                             uint64_t local_iovcnt,
                             uint64_t remote_iov_gva,
                             uint64_t remote_iovcnt,
                             uint64_t flags)
{
    return sys_process_vm(g, pid, local_iov_gva, local_iovcnt, remote_iov_gva,
                          remote_iovcnt, flags, false);
}

int64_t sys_process_vm_writev(guest_t *g,
                              int64_t pid,
                              uint64_t local_iov_gva,
                              uint64_t local_iovcnt,
                              uint64_t remote_iov_gva,
                              uint64_t remote_iovcnt,
                              uint64_t flags)
{
    return sys_process_vm(g, pid, local_iov_gva, local_iovcnt, remote_iov_gva,
                          remote_iovcnt, flags, true);
}

/* terminal I/O. */

/* NOLINTNEXTLINE(readability-function-size) */
int64_t sys_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg)
{
    /* FIOCLEX/FIONCLEX are the ioctl form of fcntl(F_SETFD): they set/clear the
     * guest close-on-exec flag, which lives in fd_table linux_flags (not the
     * host fd's FD_CLOEXEC, which is per-descriptor and would be lost on the
     * dup that host_fd_ref hands multi-threaded callers, so mirror the F_SETFD
     * path in sys_fcntl). They need no host fd, so dispatch them before
     * host_fd_ref_open_regular_io(): that helper rejects O_PATH (FD_PATH) fds
     * with EBADF, but Linux allows these ioctls -- like fcntl(F_SETFD) -- on
     * O_PATH descriptors. Validate the slot and mutate the flag in a single
     * fd_lock section so there is no validate-then-mutate window in which a
     * concurrent close/reuse could flip CLOEXEC on a different file that took
     * the slot. The arg is ignored.
     */
    if (request == LINUX_FIOCLEX || request == LINUX_FIONCLEX) {
        if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
            return -LINUX_EBADF;
        pthread_mutex_lock(&fd_lock);
        if (fd_table[fd].type == FD_CLOSED) {
            pthread_mutex_unlock(&fd_lock);
            return -LINUX_EBADF;
        }
        if (request == LINUX_FIOCLEX)
            fd_table[fd].linux_flags |= LINUX_O_CLOEXEC;
        else
            fd_table[fd].linux_flags &= ~LINUX_O_CLOEXEC;
        pthread_mutex_unlock(&fd_lock);
        return 0;
    }

    /* usbdevfs fds answer their own ioctl set; the host fd behind them is a
     * readiness pipe, so nothing below applies. usbdev_ioctl re-snapshots the
     * fd and pins the side-table entry by generation itself.
     */
    if (fd_get_type(fd) == FD_USBDEV)
        return usbdev_ioctl(g, fd, request, arg);

    if (request == LINUX_SIOCGIFHWADDR) {
        fd_entry_t snap;
        if (!fd_snapshot(fd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_PATH)
            return -LINUX_EBADF;
        if (snap.type != FD_SOCKET)
            return -LINUX_ENOTTY;
        return linux_siocgifhwaddr(g, arg);
    }

    host_fd_ref_t host_ref;
    uint64_t ioctl_gen;
    int64_t err = host_fd_ref_open_regular_io_gen(fd, &host_ref, &ioctl_gen);
    if (err < 0)
        return err;
    int host_fd = host_ref.fd;

    /* Rosetta's Virtualization.framework probe ioctls are issued on the
     * /proc/self/exe launcher fd very early at startup. Gate on that actual
     * host file rather than on every fd in a Rosetta guest, but do not key on
     * ROSETTA_PATH itself: the probe is against the launcher, not the
     * translator image.
     */
    if (rosetta_vz_request(request) && rosetta_ioctl_target_fd(g, host_fd)) {
        int64_t r = rosetta_vz_ioctl(g, request, arg);
        host_fd_ref_close(&host_ref);
        return r;
    }

    switch (request) {
    case LINUX_TIOCSPGRP: {
        /* Set foreground process group for controlling terminal. */
        int32_t pgrp = 0;
        host_fd_ref_close(&host_ref);
        if (guest_read_small(g, arg, &pgrp, sizeof(pgrp)) < 0)
            return -LINUX_EFAULT;
        proc_set_fg_pgrp((int64_t) pgrp);
        return 0;
    }
    case LINUX_TIOCSCTTY:
        /* Set controlling terminal.  arg is a flag (usually 0). */
        host_fd_ref_close(&host_ref);
        proc_set_ctty(1);
        return 0;
    case LINUX_TIOCNOTTY:
        /* Detach from controlling terminal. */
        host_fd_ref_close(&host_ref);
        proc_set_ctty(0);
        return 0;
    case LINUX_TIOCGSID: {
        /* Get session ID of the controlling terminal. */
        int32_t val = (int32_t) proc_get_sid();
        host_fd_ref_close(&host_ref);
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    case LINUX_TIOCGWINSZ: {
        /* Get terminal window size */
        (void) proc_pty_master_adopt(fd);
        struct winsize ws;
        if (ioctl(host_fd, TIOCGWINSZ, &ws) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_winsize_t lws = {
            .ws_row = ws.ws_row,
            .ws_col = ws.ws_col,
            .ws_xpixel = ws.ws_xpixel,
            .ws_ypixel = ws.ws_ypixel,
        };
        if (guest_write_small(g, arg, &lws, sizeof(lws)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }
    case LINUX_TIOCSWINSZ: {
        /* Set terminal window size. Same struct as TIOCGWINSZ; foot, sshd,
         * tmux, and any libvte-derived emulator call this on the PTY master
         * after spawning the slave child. Without it, terminal startup fails
         * with -ENOTTY from the default arm below.
         *
         * A master received through SCM_RIGHTS bypasses /dev/ptmx open
         * interception, so lazily create its keepalive before the host ioctl.
         * The helper is a no-op for non-pty fds; the real ioctl below still
         * supplies the final errno.
         */
        linux_winsize_t lws;
        if (guest_read_small(g, arg, &lws, sizeof(lws)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct winsize ws = {
            .ws_row = lws.ws_row,
            .ws_col = lws.ws_col,
            .ws_xpixel = lws.ws_xpixel,
            .ws_ypixel = lws.ws_ypixel,
        };
        (void) proc_pty_master_adopt(fd);
        int rc = ioctl(host_fd, TIOCSWINSZ, &ws);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TIOCPKT: {
        /* Packet mode on a pty master: each master read is then prefixed with a
         * status byte carrying flush/stop/start events. libvte switches it on
         * immediately after posix_openpt and treats any failure as fatal, so
         * without this every VTE terminal -- gnome-terminal, xfce4-terminal,
         * tilix -- dies at startup with "Failed to open PTY: Inappropriate
         * ioctl for device" from the default arm below.
         *
         * macOS numbers the request differently but takes the same int flag
         * through a pointer, and its TIOCPKT_* status bits match Linux value
         * for value, so the packet stream itself needs no translation.
         *
         * A master received through SCM_RIGHTS bypasses the /dev/ptmx open
         * intercept, so adopt it first the way TIOCSWINSZ does; the helper is a
         * no-op for non-pty fds and the host ioctl still supplies the errno.
         */
        int pktmode = 0;
        if (guest_read_small(g, arg, &pktmode, sizeof(pktmode)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        (void) proc_pty_master_adopt(fd);
        int rc = ioctl(host_fd, TIOCPKT, &pktmode);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TCGETS: {
        /* Get terminal attributes. c_cc index mapping is in file-scope
         * linux_mac_cc[].
         */
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_termios_t lt = {0};
        lt.c_iflag = mac_iflag_to_linux(t.c_iflag);
        lt.c_oflag = mac_oflag_to_linux(t.c_oflag);

        /* Plain termios has no speed fields: cfgetospeed()/cfgetispeed() in the
         * guest decode CBAUD/CIBAUD out of c_cflag, so encode the host rates
         * back into it.
         */
        lt.c_cflag = mac_cflag_to_linux(t.c_cflag) | linux_cflag_speed_bits(&t);
        lt.c_lflag = mac_lflag_to_linux(t.c_lflag);
        termios_copy_cc_to_linux(lt.c_cc, t.c_cc);
        if (guest_write_small(g, arg, &lt, sizeof(lt)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSETS:
    case LINUX_TCSETSW:
    case LINUX_TCSETSF: {
        linux_termios_t lt;
        if (guest_read_small(g, arg, &lt, sizeof(lt)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY; /* Not a terminal */
        }
        t.c_iflag = linux_iflag_to_mac(lt.c_iflag);
        t.c_oflag = linux_oflag_to_mac(lt.c_oflag);
        t.c_cflag = linux_cflag_to_mac(lt.c_cflag);
        t.c_lflag = linux_lflag_to_mac(lt.c_lflag);
        termios_copy_cc_to_mac(t.c_cc, lt.c_cc);

        /* musl and glibc <= 2.41 store the rate in CBAUD (and CIBAUD for a
         * split input rate) and issue plain TCSETS; glibc 2.42+ always uses
         * TCSETS2. Dropping the field here would leave a USB-serial port at
         * whatever speed the host last had.
         */
        if (apply_linux_cflag_speeds(&t, lt.c_cflag) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int action = termios_action_for(request);
        if (tcsetattr(host_fd, action, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCGETS2: {
        /* termios2 variant: same as TCGETS plus numeric c_ispeed/c_ospeed. The
         * kernel hands back the same c_cflag for both requests (the B* index
         * when the rate has one, BOTHER otherwise), so encode it the same way
         * rather than forcing BOTHER; the numeric fields are always filled, as
         * the kernel does.
         */
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_termios2_t lt2 = {0};
        lt2.c_iflag = mac_iflag_to_linux(t.c_iflag);
        lt2.c_oflag = mac_oflag_to_linux(t.c_oflag);
        lt2.c_cflag =
            mac_cflag_to_linux(t.c_cflag) | linux_cflag_speed_bits(&t);
        lt2.c_lflag = mac_lflag_to_linux(t.c_lflag);
        termios_copy_cc_to_linux(lt2.c_cc, t.c_cc);
        lt2.c_ispeed = (uint32_t) cfgetispeed(&t);
        lt2.c_ospeed = (uint32_t) cfgetospeed(&t);
        if (guest_write_small(g, arg, &lt2, sizeof(lt2)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSETS2:
    case LINUX_TCSETSW2:
    case LINUX_TCSETSF2: {
        /* termios2 set: decode CBAUD for standard rates, use c_ispeed/ c_ospeed
         * when BOTHER is set.
         */
        linux_termios2_t lt2;
        if (guest_read_small(g, arg, &lt2, sizeof(lt2)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        t.c_iflag = linux_iflag_to_mac(lt2.c_iflag);
        t.c_oflag = linux_oflag_to_mac(lt2.c_oflag);
        t.c_cflag = linux_cflag_to_mac(lt2.c_cflag);
        t.c_lflag = linux_lflag_to_mac(lt2.c_lflag);
        termios_copy_cc_to_mac(t.c_cc, lt2.c_cc);

        /* Resolve the rates the way tty_termios_baud_rate() and
         * tty_termios_input_baud_rate() do: the output rate is CBAUD's table
         * entry, or the numeric c_ospeed for BOTHER; the input rate is CIBAUD's
         * -- B0 meaning "same as output", BOTHER meaning the numeric c_ispeed.
         * The TCGETS2 arm above reports a split host rate as CBAUD+CIBAUD
         * indexes, so an unchanged tcgetattr/tcsetattr pair from a termios2
         * libc must decode CIBAUD or it would collapse the input rate to the
         * output rate. B0 output (drop DTR/RTS on Linux, not emulated) leaves
         * the host speed untouched, as in the plain TCSETS arm.
         */
        uint32_t cbaud = lt2.c_cflag & LINUX_CBAUD;
        uint32_t cibaud = (lt2.c_cflag >> LINUX_IBSHIFT) & LINUX_CBAUD;
        speed_t ospeed = cbaud == LINUX_BOTHER ? (speed_t) lt2.c_ospeed
                                               : linux_cbaud_to_speed(cbaud);
        if (ospeed != 0) {
            speed_t ispeed = cibaud == 0 ? ospeed
                             : cibaud == LINUX_BOTHER
                                 ? (speed_t) lt2.c_ispeed
                                 : linux_cbaud_to_speed(cibaud);
            if (ispeed == 0)
                ispeed = ospeed;
            if (cfsetispeed(&t, ispeed) < 0 || cfsetospeed(&t, ospeed) < 0) {
                host_fd_ref_close(&host_ref);
                return linux_errno();
            }
        }
        int action = termios_action_for(request);
        if (tcsetattr(host_fd, action, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSBRK: {
        /* Linux overloads TCSBRK: its kernel always waits for pending output
         * first, then sends a break only for arg 0; a nonzero arg is how glibc
         * and musl implement tcdrain(3) (they issue TCSBRK with 1). macOS has
         * no ioctl form of either, so route to the POSIX wrappers in that
         * order.
         */
        int64_t rc = tty_drain_interruptible(host_fd);
        if (rc == 0 && arg == 0 && tcsendbreak(host_fd, 0) < 0)
            rc = linux_errno();
        host_fd_ref_close(&host_ref);
        return rc;
    }

    case LINUX_TCSBRKP: {
        /* POSIX form of tcsendbreak: arg is the duration in deciseconds (0
         * means 250 ms). The Linux kernel drains pending output before both
         * TCSBRK and TCSBRKP; macOS tcsendbreak() does not, and ignores the
         * duration (fixed ~0.4 s), which is close enough for a break.
         */
        int64_t rc = tty_drain_interruptible(host_fd);
        if (rc == 0 && tcsendbreak(host_fd, (int) arg) < 0)
            rc = linux_errno();
        host_fd_ref_close(&host_ref);
        return rc;
    }

    case LINUX_TIOCSBRK:
    case LINUX_TIOCCBRK: {
        /* BSD-style break on/off (pyserial's break_condition). Same request
         * semantics on macOS; a pty answers ENOTTY on both systems. The Linux
         * kernel drains pending output before TIOCSBRK (but not TIOCCBRK), same
         * as TCSBRK.
         */
        int64_t rc = 0;
        if (request == LINUX_TIOCSBRK)
            rc = tty_drain_interruptible(host_fd);
        if (rc == 0 &&
            ioctl(host_fd, request == LINUX_TIOCSBRK ? TIOCSBRK : TIOCCBRK) < 0)
            rc = linux_errno();
        host_fd_ref_close(&host_ref);
        return rc;
    }

    case LINUX_TCFLSH: {
        /* tcflush(3): arg is the queue selector. Linux numbers TCIFLUSH,
         * TCOFLUSH, TCIOFLUSH 0..2 (asm-generic/termbits-common.h); macOS
         * numbers them 1..3 (sys/termios.h), hence the explicit map.
         */
        int queue;
        switch (arg) {
        case 0:
            queue = TCIFLUSH;
            break;
        case 1:
            queue = TCOFLUSH;
            break;
        case 2:
            queue = TCIOFLUSH;
            break;
        default:
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        int rc = tcflush(host_fd, queue);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TCXONC: {
        /* tcflow(3): arg is the action. Linux numbers TCOOFF, TCOON, TCIOFF,
         * TCION 0..3 (asm-generic/termbits-common.h); macOS numbers them 1..4
         * (sys/termios.h), hence the explicit map.
         */
        int action;
        switch (arg) {
        case 0:
            action = TCOOFF;
            break;
        case 1:
            action = TCOON;
            break;
        case 2:
            action = TCIOFF;
            break;
        case 3:
            action = TCION;
            break;
        default:
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        int rc = tcflow(host_fd, action);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TIOCOUTQ: {
        /* Bytes still queued for output; pyserial's out_waiting and the esptool
         * reset sequence poll this.
         */
        int pending = 0;
        if (ioctl(host_fd, TIOCOUTQ, &pending) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int32_t val = (int32_t) pending;
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCEXCL:
    case LINUX_TIOCNXCL: {
        /* Exclusive-use flag on the tty; no argument. */
        int rc =
            ioctl(host_fd, request == LINUX_TIOCEXCL ? TIOCEXCL : TIOCNXCL);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TIOCMGET: {
        /* Modem control lines. TIOCM_* bit values are identical on Linux and
         * macOS (see linux-wire.h), so the int needs no translation. Only real
         * serial drivers implement these on Darwin; a pty answers ENOTTY.
         */
        int bits = 0;
        if (ioctl(host_fd, TIOCMGET, &bits) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int32_t val = (int32_t) bits;
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCMSET:
    case LINUX_TIOCMBIS:
    case LINUX_TIOCMBIC: {
        /* The Linux kernel masks the set/clear words to the output lines
         * (DTR|RTS|OUT1|OUT2|LOOP, tty_io.c tty_tiocmset) before they reach
         * the driver, so read-only status bits (CTS/DSR/CAR/RNG) in the guest's
         * word are silently dropped. Darwin has no OUT1/OUT2/LOOP, so the
         * settable intersection is DTR|RTS. TIOCMSET on Linux means "set = val
         * & mask, clear = ~val & mask" -- bits outside the mask are left alone
         * -- whereas Darwin's TIOCMSET overwrites the whole word, so emulate
         * the Linux semantics with a TIOCMBIS/TIOCMBIC pair. The first host
         * call is issued even when its masked word is empty so a fd whose
         * driver lacks modem control still reports ENOTTY, as Linux does before
         * looking at the value.
         */
        int32_t val = 0;
        if (guest_read_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        const int settable = TIOCM_DTR | TIOCM_RTS;
        int rc;
        if (request == LINUX_TIOCMSET) {
            int bis = (int) val & settable;
            int bic = ~(int) val & settable;
            rc = ioctl(host_fd, TIOCMBIS, &bis);
            if (rc == 0 && bic != 0)
                rc = ioctl(host_fd, TIOCMBIC, &bic);
        } else {
            int bits = (int) val & settable;
            rc = ioctl(host_fd, request == LINUX_TIOCMBIS ? TIOCMBIS : TIOCMBIC,
                       &bits);
        }
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TIOCGPGRP: {
        /* Get foreground process group from guest state. */
        host_fd_ref_close(&host_ref);
        int32_t val = (int32_t) proc_get_fg_pgrp();
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_FIONREAD: {
        /* Get bytes available for reading */
        int avail = 0;
        if (ioctl(host_fd, FIONREAD, &avail) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int32_t val = (int32_t) avail;
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCGPTN: {
        /* Get the slave pty number associated with a /dev/ptmx master fd. Pass
         * the guest fd: proc_pty_master_adopt snapshots the canonical (host_fd,
         * generation) under fd_lock, performs the slave open on a private dup,
         * then re-validates the slot before publishing the keepalive. Passing
         * the per-syscall host_fd_ref dup or a raw host fd would race with
         * sibling close+reuse.
         */
        uint32_t val = proc_pty_master_adopt(fd);
        if (val == UINT32_MAX) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_FIOASYNC: {
        /* Set/clear O_ASYNC (SIGIO-driven I/O). This is the ioctl form of
         * fcntl(F_SETFL, O_ASYNC): unify both onto the same armed bit and
         * kqueue watcher (asyncio.c) so the two entry points cannot drift.
         * Snapshot only for the slot generation; asyncio_apply rescans under
         * fd_lock for each alias's backing fd and class.
         */
        int32_t on = 0;
        if (guest_read_small(g, arg, &on, sizeof(on)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        fd_entry_t snap;
        if (!fd_snapshot(fd, &snap)) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EBADF;
        }
        asyncio_apply(fd, snap.generation, on != 0);
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCSPTLCK: {
        /* Lock/unlock the slave side of a pty. glibc unlockpt() always passes 0
         * (unlock); util-linux's setlock(1) passes 1 to lock. macOS exposes
         * unlockpt(3) but no re-lock primitive, so the lock branch is accepted
         * as a best-effort no-op for real ptmx masters rather than surfacing as
         * -EINVAL: an application probing the result would otherwise misread
         * the failure as "this kernel has no devpts".
         */
        int32_t lock = 0;
        if (guest_read_small(g, arg, &lock, sizeof(lock)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int rc = 0;
        if (lock == 0) {
            rc = unlockpt(host_fd);
        } else {
            char slave[64];
            if (ptsname_r(host_fd, slave, sizeof(slave)) != 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_ENOTTY;
            }
        }
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }
    case LINUX_TIOCGPTPEER: {
        /* Return a fresh fd referring to the slave side of a /dev/ptmx master.
         * Linux added this in 4.13 so callers can avoid the ptsname(3) round
         * trip and any /dev/pts visibility races. The arg holds open(2)-style
         * flags. Restrict to the bits Linux's pty driver actually honors
         * (accmode + O_NOCTTY + O_NONBLOCK + O_CLOEXEC); any other bit, in
         * particular O_CREAT / O_TRUNC / O_EXCL / O_PATH, would be silently
         * ignored on Linux and is rejected with EINVAL here so misuse does not
         * leak nonsense flags into the guest fd table.
         */
        int linux_flags = (int) arg;
        const int allowed = LINUX_O_ACCMODE | LINUX_O_NOCTTY |
                            LINUX_O_NONBLOCK | LINUX_O_CLOEXEC;
        if (linux_flags & ~allowed) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }

        /* Resolve the Linux pts number before opening, the same way TIOCGPTN
         * does: the slave handed out here counts toward the master's hangup
         * accounting, and that table is keyed by pts number. Pass the guest fd
         * so the adopt validates against the canonical (host_fd, generation)
         * rather than this call's host_fd_ref dup.
         */
        uint32_t pts_num = proc_pty_master_adopt(fd);
        char slave[64];
        if (ptsname_r(host_fd, slave, sizeof(slave)) != 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        int oflags = translate_open_flags(linux_flags);
        int host_slave_fd = open(slave, oflags);
        if (host_slave_fd < 0) {
            int saved_errno = errno;
            host_fd_ref_close(&host_ref);
            errno = saved_errno;
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        int guest_fd = fd_alloc(FD_REGULAR, host_slave_fd, NULL);
        if (guest_fd < 0) {
            close(host_slave_fd);
            return -LINUX_EMFILE;
        }

        /* Record the slave against its master. Without this the master's
         * guest_slave_seen stays false and a master whose only slave arrived
         * this way never reports a hangup -- and TIOCGPTPEER has been the
         * recommended way to reach the peer since Linux 4.13. Registered after
         * fd_alloc so a failed alloc leaves nothing behind to retire.
         *
         * Only when the slot still holds the generation this ioctl resolved.
         * proc_pty_master_adopt re-resolves the guest fd, so its pts_num
         * describes the master the slot held at that moment, while ptsname_r
         * and the open above used the host fd pinned on entry. Generations only
         * ever increase, so an unchanged one here proves the slot never moved
         * across either window and the two agree on one master. If it did move,
         * pts_num belongs to a different pty and charging the slave to it would
         * corrupt that master's accounting; dropping the record instead only
         * forgoes a hangup report on a master the guest concurrently closed.
         */
        if (pts_num != UINT32_MAX && fd_current_generation(fd) == ioctl_gen)
            proc_pty_note_guest_slave(host_slave_fd, pts_num);

        /* Track CLOEXEC + accmode in the guest table so exec honors them; the
         * host fd's own FD_CLOEXEC is per-descriptor and would be lost on the
         * dup that host_fd_ref hands multi-threaded callers.
         */
        fd_publish_linux_flags(guest_fd, linux_flags);
        return guest_fd;
    }

    case LINUX_FIONBIO: {
        /* Set/clear O_NONBLOCK on the fd. Linux FIONBIO takes an int* arg:
         * nonzero enables non-blocking, zero disables it. libuv's
         * uv__nonblock_ioctl() (its default on Linux) issues this on pipe and
         * socket fds at setup; without it the guest's uv_pipe_open() fails with
         * ENOTTY and Node's stdio stream construction throws.
         */
        int32_t on = 0;
        if (guest_read_small(g, arg, &on, sizeof(on)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int r = fd_update_status_flag(host_fd, O_NONBLOCK, on != 0);
        host_fd_ref_close(&host_ref);
        return r < 0 ? linux_errno() : 0;
    }

    default:
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOTTY;
    }
}

/* file space/copy. */

int64_t sys_fallocate(int fd, int mode, int64_t offset, int64_t len)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux validates offset >= 0 and len > 0 */
    if (offset < 0 || len <= 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }

    /* FALLOC_FL_PUNCH_HOLE always requires FALLOC_FL_KEEP_SIZE on Linux; map
     * both to macOS F_PUNCHHOLE on the host fd, with a pwrite-zeros fallback
     * for misalignment.
     *
     * The Linux semantic is "reads in [offset, offset+len) return zero; file
     * size unchanged". macOS F_PUNCHHOLE enforces filesystem block alignment on
     * both ends and rejects sub-block requests with EINVAL -- that one-byte
     * probe (offset=0 len=1) foot's wl_shm pool issues surfaces as
     * "fallocate(FALLOC_FL_PUNCH_HOLE) not supported (Invalid argument)"
     * otherwise, and foot disables punch-hole for the whole session.
     *
     * Writing zeros over the region produces the same observable result: reads
     * return zero, file size unchanged. The disk-space deallocation
     * optimisation is lost on the pwrite path, but the probe succeeds, so foot
     * keeps punch-hole enabled and the later, properly aligned calls
     * (page-sized buffers) still take the F_PUNCHHOLE fast path.
     */
    const int kPunchHole =
        LINUX_FALLOC_FL_PUNCH_HOLE | LINUX_FALLOC_FL_KEEP_SIZE;
    if (mode == kPunchHole) {
        struct fpunchhole hole = {
            .fp_flags = 0,
            .reserved = 0,
            .fp_offset = (off_t) offset,
            .fp_length = (off_t) len,
        };
        if (fcntl(host_ref.fd, F_PUNCHHOLE, &hole) == 0) {
            host_fd_ref_close(&host_ref);
            return 0;
        }

        /* EINVAL: misaligned, sub-block, or non-regular file. pwrite zeros only
         * through the current EOF so KEEP_SIZE remains guest-visible. Any other
         * host errno propagates verbatim.
         */
        if (errno != EINVAL) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        struct stat st;
        if (fstat(host_ref.fd, &st) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }

        /* Zero only through the current EOF, so KEEP_SIZE stays guest-visible.
         * st_size is signed and offset is already proved non-negative above.
         */
        uint64_t window;
        if (!slice_clamp((uint64_t) st.st_size, (uint64_t) offset,
                         (uint64_t) len, &window)) {
            host_fd_ref_close(&host_ref);
            return 0;
        }
        int64_t remaining = (int64_t) window;

        static const char zeros[4096];
        off_t cur = (off_t) offset;
        while (remaining > 0) {
            size_t chunk = remaining > (int64_t) sizeof(zeros)
                               ? sizeof(zeros)
                               : (size_t) remaining;
            ssize_t nw = pwrite(host_ref.fd, zeros, chunk, cur);
            if (nw < 0) {
                if (errno == EINTR)
                    continue;
                host_fd_ref_close(&host_ref);
                return linux_errno();
            }
            if (nw == 0)
                break; /* defensive; pwrite on a regular file should not 0 */
            cur += nw;
            remaining -= nw;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    /* mode 0 = basic allocation -> ftruncate fallback. Anything else (collapse
     * range, zero range, insert range, unshare range) stays unsupported and
     * surfaces as -EOPNOTSUPP for the guest to handle.
     */
    if (mode != 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EOPNOTSUPP;
    }

    struct stat st;
    if (fstat(host_ref.fd, &st) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    /* Extend file if needed (ftruncate only extends, does not shrink) */
    int64_t new_size = offset + len;
    if (new_size < offset) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFBIG; /* Overflow check */
    }
    if (new_size > st.st_size) {
        if (ftruncate(host_ref.fd, new_size) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

/* Scratch buffer size for the file-copy syscall emulations. Heap-allocated per
 * call rather than placed on the stack: guest threads run on host pthreads
 * whose stacks are far smaller than a 64KiB frame would tolerate.
 */
#define IO_COPY_BUF_SIZE (64 * 1024)

/* Chunked read/write copy shared by sendfile and copy_file_range. Reads from
 * in_hfd (honoring proc_try_chunk_read_intercept for /proc-backed guest fd
 * in_gfd) and writes to out_hfd. A non-negative *off_in / *off_out selects
 * pread/pwrite at that offset and is advanced by the bytes moved; -1 selects
 * read/write against the fd's own position. Queues SIGPIPE on EPIPE. Stops on
 * EOF or short write.
 *
 * Returns the byte count moved, or a negative Linux errno only when the very
 * first read or write failed (partial transfers report the count so the caller
 * can still write offsets back).
 */
static int64_t copy_fd_range(int in_gfd,
                             int in_hfd,
                             int out_hfd,
                             int64_t *off_in,
                             int64_t *off_out,
                             uint64_t len)
{
    char *buf = malloc(IO_COPY_BUF_SIZE);
    if (!buf)
        return -LINUX_ENOMEM;

    size_t total = 0, remaining = len;
    int64_t ret;
    while (remaining > 0) {
        size_t chunk =
            remaining > IO_COPY_BUF_SIZE ? IO_COPY_BUF_SIZE : remaining;
        ssize_t nr;
        if (*off_in >= 0) {
            int64_t intercepted = proc_try_chunk_read_intercept(
                in_gfd, in_hfd, buf, chunk, *off_in, 1);
            nr = (intercepted != INT64_MIN)
                     ? intercepted
                     : pread(in_hfd, buf, chunk, *off_in);
        } else {
            int64_t intercepted =
                proc_try_chunk_read_intercept(in_gfd, in_hfd, buf, chunk, 0, 0);
            nr = (intercepted != INT64_MIN) ? intercepted
                                            : read(in_hfd, buf, chunk);
        }
        if (nr < 0) {
            ret = total > 0 ? (int64_t) total : linux_errno();
            goto done;
        }
        if (nr == 0)
            break; /* EOF */

        ssize_t nw = (*off_out >= 0) ? pwrite(out_hfd, buf, nr, *off_out)
                                     : write(out_hfd, buf, nr);
        if (nw < 0) {
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            ret = total > 0 ? (int64_t) total : linux_errno();
            goto done;
        }

        total += nw;
        remaining -= nw;
        if (*off_in >= 0)
            *off_in += nw;
        if (*off_out >= 0)
            *off_out += nw;
        if (nw < nr) {
            /* Short write. For position-based input, read() already consumed
             * all nr bytes but only nw were sent, so rewind the input fd by the
             * unsent nr - nw so a later call re-reads them. Linux advances the
             * input only by bytes actually transferred. For offset-based input,
             * pread left the position untouched and off_in advanced by nw only,
             * so there is nothing to undo. Best-effort: a non-seekable input
             * (which sendfile/copy_file_range do not accept) simply keeps the
             * prior behavior.
             */
            if (*off_in < 0)
                (void) lseek(in_hfd, (off_t) (nw - nr), SEEK_CUR);
            break;
        }
    }
    ret = (int64_t) total;

done:
    free(buf);
    return ret;
}

int64_t sys_sendfile(guest_t *g,
                     int out_fd,
                     int in_fd,
                     uint64_t offset_gva,
                     uint64_t count)
{
    host_fd_ref_t out_ref, in_ref;
    int64_t err = host_fd_ref_open_regular_io(out_fd, &out_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(in_fd, &in_ref);
    if (err < 0) {
        host_fd_ref_close(&out_ref);
        return err;
    }

    /* macOS sendfile() requires a socket destination, so sendfile emulation
     * uses a pread/write loop for general file-to-file copies.
     */
    int64_t offset = -1;
    if (offset_gva != 0) {
        if (guest_read_small(g, offset_gva, &offset, sizeof(offset)) < 0) {
            err = -LINUX_EFAULT;
            goto out_sendfile;
        }
        if (offset < 0) {
            err = -LINUX_EINVAL;
            goto out_sendfile;
        }
    }

    /* sendfile has no output offset, so out always uses write(). */
    int64_t off_out = -1;
    int64_t moved =
        copy_fd_range(in_fd, in_ref.fd, out_ref.fd, &offset, &off_out, count);
    if (moved < 0) {
        err = moved;
        goto out_sendfile;
    }
    size_t total = (size_t) moved;

    /* Write back updated offset (even on partial transfer). Preserve partial
     * success: if bytes were transferred but offset writeback fails, return the
     * count rather than -EFAULT.
     */
    if (offset_gva != 0) {
        if (guest_write_small(g, offset_gva, &offset, sizeof(offset)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }

out_sendfile:
    host_fd_ref_close(&in_ref);
    host_fd_ref_close(&out_ref);
    if (err != 0)
        return err;
    return (int64_t) total;
}

int64_t sys_copy_file_range(guest_t *g,
                            int fd_in,
                            uint64_t off_in_gva,
                            int fd_out,
                            uint64_t off_out_gva,
                            uint64_t len,
                            unsigned int flags)
{
    /* Linux reserves flags for future use and rejects any nonzero value. */
    if (flags != 0)
        return -LINUX_EINVAL;

    host_fd_ref_t in_ref, out_ref;
    int64_t err = host_fd_ref_open_regular_io(fd_in, &in_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(fd_out, &out_ref);
    if (err < 0) {
        host_fd_ref_close(&in_ref);
        return err;
    }

    /* Read optional offsets from guest memory */
    int64_t off_in = -1, off_out = -1;
    if (off_in_gva != 0) {
        if (guest_read_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
            err = -LINUX_EFAULT;
            goto out_copy_file_range;
        }
    }
    if (off_out_gva != 0) {
        if (guest_read_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
            err = -LINUX_EFAULT;
            goto out_copy_file_range;
        }
    }

    /* Emulate with a pread/pwrite loop. */
    int64_t moved =
        copy_fd_range(fd_in, in_ref.fd, out_ref.fd, &off_in, &off_out, len);
    if (moved < 0) {
        err = moved;
        goto out_copy_file_range;
    }
    size_t total = (size_t) moved;

    /* Write back updated offsets (even on partial transfer). Preserve partial
     * success on writeback failure.
     */
    if (off_in_gva != 0) {
        if (guest_write_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }
    if (off_out_gva != 0) {
        if (guest_write_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }

out_copy_file_range:
    host_fd_ref_close(&out_ref);
    host_fd_ref_close(&in_ref);
    if (err != 0)
        return err;
    return (int64_t) total;
}

/* splice/tee. */

/* splice: emulate by reading from in_fd and writing to out_fd */
int64_t sys_splice(guest_t *g,
                   int fd_in,
                   uint64_t off_in_gva,
                   int fd_out,
                   uint64_t off_out_gva,
                   size_t len,
                   unsigned int flags)
{
    (void) flags;
    host_fd_ref_t in_ref, out_ref;
    int64_t err = host_fd_ref_open_regular_io(fd_in, &in_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(fd_out, &out_ref);
    if (err < 0) {
        host_fd_ref_close(&in_ref);
        return err;
    }

    /* Handle offsets */
    int64_t off_in = -1, off_out = -1;
    if (off_in_gva) {
        if (guest_read_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
            host_fd_ref_close(&out_ref);
            host_fd_ref_close(&in_ref);
            return -LINUX_EFAULT;
        }
    }
    if (off_out_gva) {
        if (guest_read_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
            host_fd_ref_close(&out_ref);
            host_fd_ref_close(&in_ref);
            return -LINUX_EFAULT;
        }
    }

    /* Emulate with a read/write loop over a heap buffer. splice fully drains
     * each read chunk (inner write loop) rather than stopping on a short write,
     * so it does not share copy_fd_range.
     */
    uint8_t *buf = malloc(IO_COPY_BUF_SIZE);
    if (!buf) {
        host_fd_ref_close(&out_ref);
        host_fd_ref_close(&in_ref);
        return -LINUX_ENOMEM;
    }
    size_t chunk = len > IO_COPY_BUF_SIZE ? IO_COPY_BUF_SIZE : len;

    size_t total = 0;
    int saved_errno = 0;   /* Preserve errno across guest_write */
    bool rw_error = false; /* Track whether read or write failed */
    int64_t ret;
    while (total < len) {
        size_t n = (len - total) > chunk ? chunk : (len - total);
        ssize_t r = (off_in >= 0) ? pread(in_ref.fd, buf, n, off_in)
                                  : read(in_ref.fd, buf, n);
        if (r < 0) {
            rw_error = true;
            saved_errno = errno;
            break;
        }
        if (r == 0)
            break; /* EOF */
        if (off_in >= 0)
            off_in += r;

        size_t written = 0;
        while (written < (size_t) r) {
            ssize_t w =
                (off_out >= 0)
                    ? pwrite(out_ref.fd, buf + written, r - written, off_out)
                    : write(out_ref.fd, buf + written, r - written);
            if (w <= 0) {
                if (w < 0) {
                    rw_error = true;
                    saved_errno = errno;
                }
                if (w < 0 && saved_errno == EPIPE)
                    signal_queue(LINUX_SIGPIPE);
                total += written; /* Account for partial bytes written */
                /* Position-based input: read() consumed all r bytes but only
                 * written were moved, so rewind the input fd by r - written to
                 * match Linux advancing only by bytes transferred. Best-effort;
                 * a pipe input (common for splice) cannot seek and keeps the
                 * prior behavior. saved_errno is restored at done.
                 */
                if (off_in < 0 && written < (size_t) r)
                    (void) lseek(in_ref.fd, (off_t) ((ssize_t) written - r),
                                 SEEK_CUR);
                goto done;
            }
            written += w;
            if (off_out >= 0)
                off_out += w;
        }
        total += r;
    }

done:
    /* Write back updated offsets, then pick the return value. Preserve partial
     * transfer success: if bytes were already moved, return that count even
     * when an offset writeback faults (consistent with
     * sendfile/copy_file_range). A failed off_in writeback skips the off_out
     * writeback, matching the kernel.
     */
    if (off_in_gva && off_in >= 0 &&
        guest_write_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
        ret = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    } else if (off_out_gva && off_out >= 0 &&
               guest_write_small(g, off_out_gva, &off_out, sizeof(off_out)) <
                   0) {
        ret = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    } else if (total > 0) {
        ret = (int64_t) total;
    } else if (rw_error) {
        /* Restore saved_errno; the guest writes above may have clobbered it. */
        errno = saved_errno;
        ret = linux_errno();
    } else {
        ret = 0;
    }

    free(buf);
    host_fd_ref_close(&out_ref);
    host_fd_ref_close(&in_ref);
    return ret;
}

/* vmsplice: emulate as writev to the pipe fd */
int64_t sys_vmsplice(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     unsigned long nr_segs,
                     unsigned int flags)
{
    (void) flags;
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;
    if (nr_segs > 1024) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL; /* UIO_MAXIOV */
    }

    size_t total = 0;
    for (unsigned long i = 0; i < nr_segs; i++) {
        linux_iovec_t liov;
        if (guest_read_small(g, iov_gva + i * sizeof(linux_iovec_t), &liov,
                             sizeof(liov)) < 0) {
            host_fd_ref_close(&host_ref);
            return total > 0 ? (int64_t) total : -LINUX_EFAULT;
        }

        if (liov.iov_len == 0)
            continue;
        uint64_t avail = 0;
        void *src =
            guest_ptr_bound(g, liov.iov_base, &avail, MEM_PERM_R, liov.iov_len);
        if (!src)
            return host_fd_ref_close(&host_ref),
                   (total > 0 ? (int64_t) total : -LINUX_EFAULT);
        uint64_t len = liov.iov_len;
        if (len > avail)
            len = avail;

        ssize_t w = write(host_ref.fd, src, len);
        if (w < 0) {
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            err = total > 0 ? (int64_t) total : linux_errno();
            host_fd_ref_close(&host_ref);
            return err;
        }
        total += w;
        if ((uint64_t) w < len)
            break;
    }

    host_fd_ref_close(&host_ref);
    return (int64_t) total;
}

/* tee: copy data between two pipes without consuming it. Full emulation would
 * need pipe peeking semantics that macOS does not expose; report EINVAL rather
 * than consuming data incorrectly.
 */
int64_t sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags)
{
    (void) fd_in;
    (void) fd_out;
    (void) len;
    (void) flags;
    return -LINUX_EINVAL;
}
