/*
 * Poll/select/epoll syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * ppoll, pselect6, and epoll (emulated via macOS kqueue). All functions are
 * called from syscall_dispatch() in syscall/syscall.c.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <poll.h>

#include "utils.h"

#include "proved/fdset.h"
#include "proved/timespec.h"

#include "debug/log.h"

#include "runtime/futex.h"
#include "runtime/thread.h" /* thread_stop_requested */

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "runtime/procemu.h"
#include "syscall/poll.h"
#include "syscall/proc.h" /* proc_exit_group_requested */
#include "syscall/signal.h"
#include "syscall/time.h" /* linux_timespec_valid */
#include "syscall/wakeup-pipe.h"

/* The proof in proved/fdset.h bounds nfds by FDSET_MAX_FDS and sizes the
 * bitmask buffers below from FDSET_MAX_WORDS. That is only the right bound if
 * it is also the fd table's: pselect6 used to reject on the host's FD_SETSIZE
 * instead, two constants that are both 1024 on macOS but are not the same
 * constant, so a host with a larger FD_SETSIZE would have read guest bytes past
 * three stack arrays.
 */
_Static_assert(FDSET_MAX_FDS == FD_TABLE_SIZE,
               "the accepted nfds bound must be the fd table's size");

/* polling/select. */

typedef struct {
    int host_fd;
    uint16_t word;
    uint8_t bit_index;
    short events;
    short revents;
    host_fd_ref_t ref;
} pselect_req_t;

/* Longest a host wait may run before its caller re-checks the interrupt
 * conditions. A wait armed with the guest's whole timeout does not watch the
 * wakeup pipe and cannot be woken by thread_wake_all_blocked, so a teardown or
 * an execve handoff would wait out the guest's timeout instead of the slice.
 */
#define POLL_WAKE_SLICE_MS 200

static int64_t poll_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Milliseconds left of a finite wait, never negative. deadline_ms is -1 for a
 * wait with no deadline, which reports the full slice every time.
 */
static int poll_slice_ms(int64_t deadline_ms)
{
    if (deadline_ms < 0)
        return POLL_WAKE_SLICE_MS;

    int64_t remaining = deadline_ms - poll_now_ms();
    if (remaining <= 0)
        return 0;
    return remaining < POLL_WAKE_SLICE_MS ? (int) remaining
                                          : POLL_WAKE_SLICE_MS;
}


static inline void host_fd_refs_close(host_fd_ref_t *refs, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++)
        host_fd_ref_close(&refs[i]);
}

/* A guest's events reach the host untranslated, and the two spellings of a
 * writable descriptor do not share a value: Linux POLLWRNORM is 0x100, which
 * macOS spells POLLWRBAND, while macOS POLLWRNORM is POLLOUT itself. Testing
 * the pair answers a guest that asks with either. Linux's default mask stops
 * there, so Linux POLLWRBAND (0x200) is deliberately absent.
 */
#define POLL_WRITE_EVENTS (POLLOUT | POLLWRBAND)

/* One entry for poll_eval_unpollable(): the host descriptor the caller
 * resolved, the events the guest asked about, and the answer written back. A
 * negative fd marks an entry that is not part of the refused set, so the two
 * callers can keep one array parallel to their own request list.
 */
typedef struct {
    int fd;
    short events;
    short revents;
} poll_unpollable_t;

/* Evaluate the entries host poll() refused. macOS poll() answers POLLNVAL for
 * any descriptor it will not put on a kqueue: /dev/null, /dev/zero,
 * /dev/random, /dev/urandom, directories, and kqueue descriptors themselves.
 * Linux polls all of them, the character devices and directories through the
 * default always-ready mask and an epoll descriptor through its own readiness.
 * macOS select() accepts every one of them, so the caller drops them from the
 * poll() set and routes them here.
 *
 * A host descriptor at or above FD_SETSIZE has no bit in an fd_set and reports
 * the requested events ready, which matches Linux for everything except an
 * epoll descriptor with nothing pending.
 *
 * Returns how many entries are ready.
 */
static uint32_t poll_eval_unpollable(poll_unpollable_t *entries, uint32_t n)
{
    fd_set read_set, write_set, except_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);

    int max_fd = -1;
    for (uint32_t i = 0; i < n; i++) {
        entries[i].revents = 0;
        int fd = entries[i].fd;
        if (fd < 0 || !RANGE_CHECK(fd, 0, FD_SETSIZE))
            continue;
        short events = entries[i].events;
        if (events & (POLLIN | POLLRDNORM))
            FD_SET(fd, &read_set);
        if (events & POLL_WRITE_EVENTS)
            FD_SET(fd, &write_set);
        if (events & POLLPRI)
            FD_SET(fd, &except_set);
        if (fd > max_fd)
            max_fd = fd;
    }

    struct timeval zero = {0, 0};
    bool selected = max_fd < 0 || select(max_fd + 1, &read_set, &write_set,
                                         &except_set, &zero) >= 0;

    uint32_t ready = 0;
    for (uint32_t i = 0; i < n; i++) {
        int fd = entries[i].fd;
        if (fd < 0)
            continue;
        short events = entries[i].events;
        short got = 0;
        if (!RANGE_CHECK(fd, 0, FD_SETSIZE)) {
            got = (short) (events & (POLLIN | POLLRDNORM | POLL_WRITE_EVENTS));
        } else if (selected) {
            int mask = 0;
            if (FD_ISSET(fd, &read_set))
                mask |= events & (POLLIN | POLLRDNORM);
            if (FD_ISSET(fd, &write_set))
                mask |= events & POLL_WRITE_EVENTS;
            if (FD_ISSET(fd, &except_set))
                mask |= POLLPRI;
            got = (short) mask;
        }
        entries[i].revents = got;
        if (got)
            ready++;
    }
    return ready;
}

int64_t sys_ppoll(guest_t *g,
                  uint64_t fds_gva,
                  uint32_t nfds,
                  uint64_t timeout_gva,
                  uint64_t sigmask_gva)
{
    if (nfds > 256)
        return -LINUX_EINVAL;

    /* Read pollfd array from guest (layout is identical to macOS) */
    linux_pollfd_t guest_fds[256];
    if (nfds > 0) {
        if (guest_read_small(g, fds_gva, guest_fds,
                             nfds * sizeof(linux_pollfd_t)) < 0)
            return -LINUX_EFAULT;
    }

    /* Translate guest FDs to host FDs */
    struct pollfd host_fds[256];
    host_fd_ref_t host_refs[256];
    bool need_pollnval[256] = {false};

    /* Generation pinned per entry in the same fd_lock window as its host fd.
     * The pty hangup checks below re-resolve the guest fd, so each needs a
     * witness that the slot still holds the very file this poll resolved; 0
     * marks entries with nothing pinned and never matches a live generation.
     */
    uint64_t guest_gen[256] = {0};
    uint32_t invalid_count = 0;

    /* Entries host poll() refuses with POLLNVAL even though their reference
     * resolved. See poll_eval_unpollable().
     */
    poll_unpollable_t unpollable[256];
    uint32_t unpollable_count = 0;
    bool unpollable_checked = false;
    for (uint32_t i = 0; i < nfds; i++) {
        host_refs[i] = HOST_FD_REF_INIT;
        unpollable[i] = (poll_unpollable_t) {.fd = -1};
        int guest_fd = guest_fds[i].fd;
        int host_fd = -1;
        if (guest_fd >= 0) {
            int64_t rc =
                host_fd_ref_open_io_gen(guest_fd, &host_refs[i], &guest_gen[i]);
            if (rc == -LINUX_ENOMEM) {
                /* The pin could not be allocated. POLLNVAL here would name a
                 * descriptor that is still open, and the usual reaction to
                 * POLLNVAL is to close it, so a guest under memory pressure
                 * would tear down its own working fds. Fail the whole wait with
                 * the errno Linux uses when it cannot build the tables for one.
                 */
                host_fd_refs_close(host_refs, i);
                return -LINUX_ENOMEM;
            }
            if (rc < 0) {
                need_pollnval[i] = true;
                invalid_count++;
            } else {
                host_fd = host_refs[i].fd;
            }
        }
        host_fds[i].fd = host_fd;
        host_fds[i].events = guest_fds[i].events;
        host_fds[i].revents = 0;
    }

    /* Log fd types for shutdown diagnostics (verbose only) */
    if (timeout_gva == 0) {
        char fdbuf[256];
        int pos = 0;
        for (uint32_t i = 0; i < nfds && i < 8; i++) {
            int gfd = guest_fds[i].fd;
            const char *type = "?";
            if (RANGE_CHECK(gfd, 0, FD_TABLE_SIZE)) {
                switch (fd_table[gfd].type) {
                case FD_EVENTFD:
                    type = "efd";
                    break;
                case FD_TIMERFD:
                    type = "tfd";
                    break;
                case FD_EPOLL:
                    type = "epoll";
                    break;
                case FD_SIGNALFD:
                    type = "sfd";
                    break;
                default:
                    type = "fd";
                    break;
                }
            }
            pos += snprintf(fdbuf + pos, sizeof(fdbuf) - (size_t) pos,
                            "%s%d(%s->%d)", i ? "," : "", gfd, type,
                            host_fds[i].fd);
        }
        log_debug("ppoll: nfds=%u infinite timeout, fds=[%s]", nfds, fdbuf);
    }

    /* Convert timeout (compute in int64_t to avoid overflow, clamp to INT_MAX)
     */
    int timeout_ms = -1; /* Infinite by default */
    if (timeout_gva != 0) {
        linux_timespec_t lts;
        if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0) {
            host_fd_refs_close(host_refs, nfds);
            return -LINUX_EFAULT;
        }
        /* Linux returns EINVAL for negative timeout values */
        if (!linux_timespec_valid(&lts)) {
            host_fd_refs_close(host_refs, nfds);
            return -LINUX_EINVAL;
        }

        /* Rounds the sub-millisecond remainder up: truncating turned a 500 us
         * ppoll into poll(0), which returns immediately, so a guest waiting in
         * sub-millisecond ppoll spun instead of sleeping.
         */
        timeout_ms = timespec_to_poll_ms(lts.tv_sec, lts.tv_nsec);
    }

    /* Atomically install signal mask for the duration of the poll */
    uint64_t saved_mask = 0;
    bool mask_installed = false;
    if (sigmask_gva != 0) {
        uint64_t new_mask;
        if (guest_read_small(g, sigmask_gva, &new_mask, sizeof(new_mask)) < 0) {
            host_fd_refs_close(host_refs, nfds);
            return -LINUX_EFAULT;
        }
        saved_mask = signal_save_blocked();
        signal_set_blocked(new_mask);
        mask_installed = true;
    }

    /* Add the wakeup pipe so exit_group/futex/signal requests can interrupt a
     * thread blocked in host poll(). Without this, host-blocked threads cannot
     * be interrupted by hv_vcpus_exit() because they're not in hv_vcpu_run().
     *
     * Every wait gets it, not just an indefinite one: a finite wait that only
     * watched the guest's own fds would sit out its whole timeout before
     * noticing a teardown, and an execve de_thread waiting on that thread
     * counts it as one that would not leave.
     */
    bool added_wakeup = false;
    int wake_fd = wakeup_pipe_read_fd();
    if (wake_fd >= 0 && nfds < 256) {
        host_fds[nfds].fd = wake_fd;
        host_fds[nfds].events = POLLIN;
        host_fds[nfds].revents = 0;
        added_wakeup = true;
    }

    /* When any guest fd is invalid, Linux still polls the rest and returns
     * POLLNVAL on the bad ones alongside revents on the good ones. Force a
     * non-blocking poll() so valid fds with pending events still get reported
     * in the same call.
     */
    int poll_timeout_ms = timeout_ms;
    if (invalid_count > 0)
        poll_timeout_ms = 0;

    /* A finite wait runs to this deadline in slices; an unbounded one has none
     * and re-arms forever. A zero timeout is a poll, not a wait, and keeps its
     * single non-blocking call.
     */
    int64_t deadline_ms =
        poll_timeout_ms > 0 ? poll_now_ms() + poll_timeout_ms : -1;

    int ret;
    uint32_t unpollable_ready = 0;
ppoll_retry:
    do {
        if (unpollable_count > 0)
            unpollable_ready = poll_eval_unpollable(unpollable, nfds);

        int slice = (poll_timeout_ms == 0 || unpollable_ready > 0)
                        ? 0
                        : poll_slice_ms(deadline_ms);
        ret = poll(host_fds, nfds + added_wakeup, slice);

        /* Take the descriptors macOS refuses out of the set once and evaluate
         * them through select() from here on. A refused entry makes poll()
         * return at once, so this costs no wait.
         */
        if (ret > 0 && !unpollable_checked) {
            unpollable_checked = true;
            for (uint32_t i = 0; i < nfds; i++) {
                if (need_pollnval[i] || !(host_fds[i].revents & POLLNVAL))
                    continue;
                unpollable[i].fd = host_refs[i].fd;
                unpollable[i].events = host_fds[i].events;
                host_fds[i].fd = -1;
                unpollable_count++;
            }
            if (unpollable_count > 0)
                goto ppoll_retry;
        }

        /* Check for process/thread interrupts after waking. */
        if (thread_stop_requested() || futex_interrupt_consume() ||
            signal_pending_interruption(NULL)) {
            /* Finite wait: part of the guest's timeout is already spent. */
            if (deadline_ms >= 0)
                syscall_restart_forbid();
            ret = -1;
            errno = EINTR;
            break;
        }

        /* Nothing happened within the slice, so re-arm: an indefinite wait
         * forever, a finite one until its deadline. Only a zero timeout, which
         * is a poll rather than a wait, gets a single call. Break out when a
         * master has hung up, since the host will never make that fd ready.
         */
        if (ret == 0) {
            bool hup_pending = false;
            for (uint32_t i = 0; i < nfds && !hup_pending; i++)
                hup_pending =
                    !need_pollnval[i] && guest_fds[i].fd >= 0 &&
                    proc_pty_master_hung_up(guest_fds[i].fd, guest_gen[i]);
            if (hup_pending)
                break;
        }
    } while (ret == 0 && unpollable_ready == 0 && poll_timeout_ms != 0 &&
             (deadline_ms < 0 || poll_slice_ms(deadline_ms) > 0));

    /* POSIX poll() ignores entries with fd < 0 and resets revents to 0, so
     * re-stamp POLLNVAL on the invalid slots and credit them to the return
     * count.
     */
    if (ret >= 0 && invalid_count > 0) {
        for (uint32_t i = 0; i < nfds; i++)
            if (need_pollnval[i])
                host_fds[i].revents = POLLNVAL;
        ret += (int) invalid_count;
    }

    if (ret >= 0 && unpollable_count > 0) {
        for (uint32_t i = 0; i < nfds; i++)
            if (unpollable[i].fd >= 0)
                host_fds[i].revents = unpollable[i].revents;
        ret += (int) unpollable_ready;
    }

    /* A pty master whose guest-side slaves have all closed is hung up, but the
     * host still sees elfuse's keepalive slave and reports nothing. Stamp
     * POLLHUP here so a terminal waiting for its shell to exit -- foot polls
     * for exactly this -- is not left waiting forever.
     */
    if (ret >= 0) {
        for (uint32_t i = 0; i < nfds; i++) {
            if (need_pollnval[i] || guest_fds[i].fd < 0)
                continue;
            if (!proc_pty_master_hung_up(guest_fds[i].fd, guest_gen[i]))
                continue;
            if (host_fds[i].revents == 0)
                ret++;
            host_fds[i].revents |= POLLHUP;
        }
    }

    int saved_errno = errno;

    /* Drain the wakeup pipe if it fired, and subtract from count since the
     * wakeup pipe is not visible to the guest.
     */
    if (added_wakeup && (host_fds[nfds].revents & POLLIN)) {
        wakeup_pipe_drain();
        if (ret > 0)
            ret--;
        if (ret == 0 && poll_timeout_ms != 0 &&
            (deadline_ms < 0 || poll_slice_ms(deadline_ms) > 0))
            goto ppoll_retry;
    }

    /* Restore original signal mask */
    if (mask_installed)
        signal_restore_blocked(saved_mask);

    host_fd_refs_close(host_refs, nfds);

    if (ret < 0) {
        errno = saved_errno;
        return linux_errno();
    }

    /* Write back revents to guest only when the guest-visible array changes.
     * Tight ppoll(..., timeout=0) loops often come back with all-zero revents,
     * in which case rewriting the whole pollfd array is wasted work.
     */
    bool changed = false;
    for (uint32_t i = 0; i < nfds; i++) {
        if (guest_fds[i].revents != host_fds[i].revents)
            changed = true;
        guest_fds[i].revents = host_fds[i].revents;
    }
    if (changed && nfds > 0) {
        if (guest_write_small(g, fds_gva, guest_fds,
                              nfds * sizeof(linux_pollfd_t)) < 0)
            return -LINUX_EFAULT;
    }

    return ret;
}

/* State the pselect6 poll fallback carries across its passes. pselect6 falls
 * back to poll() when a host descriptor is out of fd_set range, and poll() then
 * refuses the descriptors kqueue will not take. Those leave the poll set and
 * are answered through poll_eval_unpollable(), the way sys_ppoll answers them.
 */
typedef struct {
    pselect_req_t *reqs;
    /* Parallel to reqs; a non-negative fd marks an entry poll() refused. */
    poll_unpollable_t *unp;
    int req_count;
    int wake_fd;      /* -1 when the wakeup pipe is not in this set */
    uint32_t refused; /* entries taken out of the poll set */
    uint32_t ready;   /* of those, the ones select() reports ready */
    bool checked;     /* the refused set is found once, on the first pass */
    bool wakeup_fired;
} pselect_fallback_t;

/* One pass of the fallback: answer the refused entries, poll the rest, and
 * leave both results in reqs[].revents.
 *
 * Returns what poll() returned, or -1 with errno set. *restart asks for another
 * pass, which happens once, on the pass that exposes the refused entries -- a
 * refused entry makes poll() return at once, so that restart waits for nothing.
 */
static int pselect_fallback_pass(pselect_fallback_t *fb,
                                 const struct timespec *wait_ts,
                                 bool *restart)
{
    *restart = false;
    if (fb->refused > 0)
        fb->ready = poll_eval_unpollable(fb->unp, (uint32_t) fb->req_count);

    struct pollfd poll_stack[64];
    struct pollfd *poll_fds = poll_stack;
    struct pollfd *poll_heap = NULL;
    int poll_count = fb->req_count + (fb->wake_fd >= 0 ? 1 : 0);
    if (poll_count > (int) ARRAY_SIZE(poll_stack)) {
        poll_heap = malloc((size_t) poll_count * sizeof(*poll_heap));
        if (!poll_heap) {
            errno = ENOMEM;
            return -1;
        }
        poll_fds = poll_heap;
    }
    for (int i = 0; i < fb->req_count; i++) {
        poll_fds[i].fd = fb->unp[i].fd >= 0 ? -1 : fb->reqs[i].host_fd;
        poll_fds[i].events = fb->reqs[i].events;
        poll_fds[i].revents = 0;
    }
    if (fb->wake_fd >= 0) {
        poll_fds[fb->req_count].fd = fb->wake_fd;
        poll_fds[fb->req_count].events = POLLIN;
        poll_fds[fb->req_count].revents = 0;
    }

    int timeout_ms =
        fb->ready > 0 ? 0
                      : timespec_to_poll_ms(wait_ts->tv_sec, wait_ts->tv_nsec);
    int ret = poll(poll_fds, (nfds_t) poll_count, timeout_ms);
    if (ret >= 0) {
        for (int i = 0; i < fb->req_count; i++)
            fb->reqs[i].revents = poll_fds[i].revents;
        fb->wakeup_fired =
            fb->wake_fd >= 0 && (poll_fds[fb->req_count].revents & POLLIN);
    }
    free(poll_heap);

    /* Every guest fd resolved before the wait, so a POLLNVAL here is the host
     * refusing the descriptor, not a closed one.
     */
    if (ret > 0 && !fb->checked) {
        fb->checked = true;
        for (int i = 0; i < fb->req_count; i++) {
            if (!(fb->reqs[i].revents & POLLNVAL))
                continue;
            fb->unp[i].fd = fb->reqs[i].host_fd;
            fb->unp[i].events = fb->reqs[i].events;
            fb->refused++;
        }
        *restart = fb->refused > 0;
    }
    return ret;
}

/* The three fd_set bitmasks of one pselect6 call, in guest word form.
 *
 * A NULL pointer is a set the caller did not pass, so the words behind it are
 * never read or written back. The buffers are sized by the proved
 * FDSET_MAX_WORDS bound, which is why a caller may index them with any word
 * fdset_words admitted.
 */
typedef struct {
    uint64_t rbuf[FDSET_MAX_WORDS];
    uint64_t wbuf[FDSET_MAX_WORDS];
    uint64_t ebuf[FDSET_MAX_WORDS];
    uint64_t *r;
    uint64_t *w;
    uint64_t *e;
} pselect_bits_t;

static void pselect_bits_init(pselect_bits_t *b,
                              uint64_t readfds_gva,
                              uint64_t writefds_gva,
                              uint64_t exceptfds_gva)
{
    b->r = b->w = b->e = NULL;
    if (readfds_gva) {
        memset(b->rbuf, 0, sizeof(b->rbuf));
        b->r = b->rbuf;
    }
    if (writefds_gva) {
        memset(b->wbuf, 0, sizeof(b->wbuf));
        b->w = b->wbuf;
    }
    if (exceptfds_gva) {
        memset(b->ebuf, 0, sizeof(b->ebuf));
        b->e = b->ebuf;
    }
}

int64_t sys_pselect6(guest_t *g,
                     int nfds,
                     uint64_t readfds_gva,
                     uint64_t writefds_gva,
                     uint64_t exceptfds_gva,
                     uint64_t timeout_gva,
                     uint64_t sigmask_gva)
{
    /* pselect6 atomically sets the signal mask during the wait, then restores
     * it. The sixth argument is a pointer to a struct:
     *   { const sigset_t *ss; size_t ss_len; }
     */
    uint64_t nfds_words_u;
    if (!fdset_words(nfds, &nfds_words_u))
        return -LINUX_EINVAL;

    if (nfds == 0 && readfds_gva == 0 && writefds_gva == 0 &&
        exceptfds_gva == 0 && sigmask_gva == 0 && timeout_gva != 0) {
        linux_timespec_t lts;
        if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0)
            return -LINUX_EFAULT;
        if (!linux_timespec_valid(&lts))
            return -LINUX_EINVAL;
        if (lts.tv_sec == 0 && lts.tv_nsec == 0)
            return 0;
    }

    fd_set read_set, write_set, except_set;
    fd_set *read_setp = NULL;
    fd_set *write_setp = NULL;
    fd_set *except_setp = NULL;
    FD_ZERO(&read_set);
    if (writefds_gva)
        FD_ZERO(&write_set);
    if (exceptfds_gva)
        FD_ZERO(&except_set);

    if (readfds_gva)
        read_setp = &read_set;
    if (writefds_gva)
        write_setp = &write_set;
    if (exceptfds_gva)
        except_setp = &except_set;

    int max_host_fd = -1, nfds_words = (int) nfds_words_u;
    pselect_req_t reqs_stack[64];
    pselect_req_t *reqs = reqs_stack;
    pselect_req_t *reqs_heap = NULL;
    int req_count = 0;

    /* One entry per request, filled in for the ones host poll() refuses. The
     * heap copy rides in the reqs allocation so there is still one buffer to
     * free.
     */
    poll_unpollable_t unp_stack[64];
    poll_unpollable_t *unp = unp_stack;

    /* Translate fd_sets from guest. Linux fd_set uses unsigned long bitmask.
     * fdset_words proved nfds_words <= FDSET_MAX_WORDS, so bitmask_bytes below
     * cannot exceed what these three buffers hold.
     */
    if (readfds_gva || writefds_gva || exceptfds_gva) {
        pselect_bits_t bits;
        pselect_bits_init(&bits, readfds_gva, writefds_gva, exceptfds_gva);
        int req_cap = 0;
        size_t bitmask_bytes = (size_t) nfds_words * 8;
        if (readfds_gva &&
            guest_read_small(g, readfds_gva, bits.r, bitmask_bytes) < 0)
            return -LINUX_EFAULT;
        if (writefds_gva &&
            guest_read_small(g, writefds_gva, bits.w, bitmask_bytes) < 0)
            return -LINUX_EFAULT;
        if (exceptfds_gva &&
            guest_read_small(g, exceptfds_gva, bits.e, bitmask_bytes) < 0)
            return -LINUX_EFAULT;

        for (int word = 0; word < nfds_words; word++) {
            uint64_t requested = (bits.r ? bits.r[word] : 0) |
                                 (bits.w ? bits.w[word] : 0) |
                                 (bits.e ? bits.e[word] : 0);
            req_cap += bit_popcount64(requested);
        }
        if (req_cap > (int) (ARRAY_SIZE(reqs_stack))) {
            reqs_heap =
                malloc((size_t) req_cap * (sizeof(*reqs_heap) + sizeof(*unp)));
            if (!reqs_heap)
                return -LINUX_ENOMEM;
            reqs = reqs_heap;
            unp = (poll_unpollable_t *) (reqs_heap + req_cap);
        }

        for (int word = 0; word < nfds_words; word++) {
            uint64_t requested = (bits.r ? bits.r[word] : 0) |
                                 (bits.w ? bits.w[word] : 0) |
                                 (bits.e ? bits.e[word] : 0);
            while (requested) {
                int bit_index = bit_ctz64(requested);
                uint64_t fd_index;
                uint64_t bit = BIT64(bit_index);

                /* Bits above nfds in the last word are the guest's to set and
                 * Linux ignores them (fs/select.c bounds its per-word loop by
                 * n). Honoring them polled an fd the caller never asked about,
                 * and returned EBADF when it was not open.
                 */
                if (!fdset_fd_index(nfds, (uint64_t) word, (uint64_t) bit_index,
                                    &fd_index)) {
                    requested &= requested - 1;
                    continue;
                }
                int i = (int) fd_index;
                host_fd_ref_t ref = HOST_FD_REF_INIT;
                int64_t rc = host_fd_ref_open_io(i, &ref);
                if (rc == -LINUX_ENOMEM)
                    goto pselect_nomem;
                if (rc < 0)
                    goto pselect_badf;
                int host_fd = ref.fd;
                reqs[req_count].host_fd = host_fd;
                reqs[req_count].word = (uint16_t) word;
                reqs[req_count].bit_index = (uint8_t) bit_index;
                reqs[req_count].events = 0;
                reqs[req_count].revents = 0;
                if (bits.r && (bits.r[word] & bit))
                    reqs[req_count].events |= POLLIN;
                if (bits.w && (bits.w[word] & bit))
                    reqs[req_count].events |= POLLOUT;
                if (bits.e && (bits.e[word] & bit))
                    reqs[req_count].events |= POLLPRI;
                reqs[req_count].ref = ref;
                unp[req_count] = (poll_unpollable_t) {.fd = -1};
                req_count++;
                if (RANGE_CHECK(host_fd, 0, FD_SETSIZE)) {
                    if (host_fd > max_host_fd)
                        max_host_fd = host_fd;
                    if (bits.r && (bits.r[word] & bit))
                        FD_SET(host_fd, read_setp);
                    if (bits.w && (bits.w[word] & bit))
                        FD_SET(host_fd, write_setp);
                    if (bits.e && (bits.e[word] & bit))
                        FD_SET(host_fd, except_setp);
                }
                requested &= requested - 1;
            }
        }
    }

    bool has_timeout = (timeout_gva != 0);
    struct timespec ts;
    if (has_timeout) {
        linux_timespec_t lts;
        if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0)
            goto pselect_fault;
        /* Linux returns EINVAL for negative or out-of-range timeout values */
        if (!linux_timespec_valid(&lts))
            goto pselect_inval;
        ts.tv_sec = lts.tv_sec;
        ts.tv_nsec = lts.tv_nsec;
    }

    /* Apply signal mask atomically around the select. Linux pselect6 arg6
     * points to { sigset_t *ss; size_t ss_len }. Save the current blocked mask,
     * apply the new one, do the select, then restore the original mask.
     */
    uint64_t saved_blocked = 0;
    bool mask_applied = false;
    if (sigmask_gva) {
        struct {
            uint64_t ss, ss_len;
        } ssarg;
        if (guest_read_small(g, sigmask_gva, &ssarg, sizeof(ssarg)) < 0)
            goto pselect_fault;
        if (ssarg.ss != 0) {
            /* Linux requires ss_len == sizeof(sigset_t). */
            if (ssarg.ss_len != 8)
                goto pselect_inval;
            uint64_t new_mask;
            if (guest_read_small(g, ssarg.ss, &new_mask, sizeof(new_mask)) < 0)
                goto pselect_fault;
            saved_blocked = signal_save_blocked();
            signal_set_blocked(new_mask);
            mask_applied = true;
        }
    }

    /* For indefinite selects, add the wakeup pipe so exit_group/futex/signal
     * requests can interrupt.
     */
    bool added_wakeup = false;

    /* One read of the pipe fd for the whole call: the FD_SET here and the
     * FD_ISSET/FD_CLR after the wait must name the same descriptor.
     */
    int wake_fd = wakeup_pipe_read_fd();
    if (!has_timeout && wake_fd >= 0) {
        if (RANGE_CHECK(wake_fd, 0, FD_SETSIZE)) {
            FD_SET(wake_fd, &read_set);
            if (wake_fd > max_host_fd)
                max_host_fd = wake_fd;
        }
        added_wakeup = true;
        read_setp = &read_set;
    }

    struct timespec poll_ts = {.tv_sec = 0, .tv_nsec = 200000000L}; /* 200ms */

    /* Save fd_sets because pselect modifies them in-place to indicate ready
     * fds. Without saving/restoring, the indefinite retry loop would operate on
     * corrupted (zeroed) fd_sets after a 200ms timeout iteration.
     */
    fd_set saved_read, saved_write, saved_except;
    if (!has_timeout) {
        if (read_setp)
            saved_read = read_set;
        if (write_setp)
            saved_write = write_set;
        if (except_setp)
            saved_except = except_set;
    }

    bool use_poll_fallback = false;
    for (int i = 0; i < req_count; i++) {
        if (!RANGE_CHECK(reqs[i].host_fd, 0, FD_SETSIZE)) {
            use_poll_fallback = true;
            break;
        }
    }
    if (added_wakeup && !RANGE_CHECK(wake_fd, 0, FD_SETSIZE))
        use_poll_fallback = true;

    pselect_fallback_t fb = {
        .reqs = reqs,
        .unp = unp,
        .req_count = req_count,
        .wake_fd = added_wakeup ? wake_fd : -1,
    };

    int ret;
pselect_retry:
    fb.wakeup_fired = false;
    for (int i = 0; i < req_count; i++)
        reqs[i].revents = 0;
    do {
        if (!has_timeout) {
            if (read_setp)
                read_set = saved_read;
            if (write_setp)
                write_set = saved_write;
            if (except_setp)
                except_set = saved_except;
        }

        if (use_poll_fallback) {
            bool restart;
            ret = pselect_fallback_pass(&fb, has_timeout ? &ts : &poll_ts,
                                        &restart);

            /* The interrupt predicates below call into the runtime and can
             * overwrite errno, so an allocation failure leaves the loop here.
             */
            if (ret < 0 && errno == ENOMEM)
                break;
            if (restart)
                goto pselect_retry;
        } else {
            ret = pselect(max_host_fd + 1, read_setp, write_setp, except_setp,
                          has_timeout ? &ts : &poll_ts, NULL);
        }

        if (thread_stop_requested() || futex_interrupt_consume() ||
            signal_pending_interruption(NULL)) {
            /* Finite wait: part of the guest's timeout is already spent. */
            if (has_timeout)
                syscall_restart_forbid();
            ret = -1;
            errno = EINTR;
            break;
        }
    } while (ret == 0 && fb.ready == 0 && !has_timeout);

    int save_errno = errno;

    /* Drain wakeup pipe if it fired, and subtract from count since the wakeup
     * pipe is not visible to the guest.
     */
    bool wakeup_fired =
        added_wakeup &&
        (use_poll_fallback ? fb.wakeup_fired : FD_ISSET(wake_fd, &read_set));
    if (wakeup_fired) {
        wakeup_pipe_drain();
        if (!use_poll_fallback)
            FD_CLR(wake_fd, &read_set);
        if (ret > 0)
            ret--;
        if (ret == 0 && !has_timeout)
            goto pselect_retry;
    }

    /* Restore original signal mask */
    if (mask_applied)
        signal_restore_blocked(saved_blocked);

    for (int i = 0; i < req_count; i++)
        host_fd_ref_close(&reqs[i].ref);

    if (ret < 0) {
        errno = save_errno;
        free(reqs_heap);
        return linux_errno();
    }

    /* Write back result fd_sets (zero then set bits for matching fds) */
    if (readfds_gva || writefds_gva || exceptfds_gva) {
        pselect_bits_t bits;
        pselect_bits_init(&bits, readfds_gva, writefds_gva, exceptfds_gva);
        int ready_bits = 0;
        for (int i = 0; i < req_count; i++) {
            int host_fd = reqs[i].host_fd, word = reqs[i].word;
            uint64_t bit = BIT64(reqs[i].bit_index);
            if (use_poll_fallback) {
                /* An entry poll() refused holds its select() answer in unp, the
                 * poll set having left reqs[i].revents at zero.
                 */
                short revents =
                    unp[i].fd >= 0 ? unp[i].revents : reqs[i].revents;
                if (bits.r && (revents & (POLLIN | POLLHUP | POLLERR))) {
                    bits.r[word] |= bit;
                    ready_bits++;
                }
                if (bits.w && (revents & (POLLOUT | POLLHUP | POLLERR))) {
                    bits.w[word] |= bit;
                    ready_bits++;
                }
                if (bits.e && (revents & POLLPRI)) {
                    bits.e[word] |= bit;
                    ready_bits++;
                }
            } else if (RANGE_CHECK(host_fd, 0, FD_SETSIZE)) {
                if (bits.r && FD_ISSET(host_fd, &read_set))
                    bits.r[word] |= bit;
                if (bits.w && FD_ISSET(host_fd, write_setp))
                    bits.w[word] |= bit;
                if (bits.e && FD_ISSET(host_fd, except_setp))
                    bits.e[word] |= bit;
            }
        }

        /* poll() counts a descriptor once however many events it reports;
         * select() counts it once per set it is reported in, so a descriptor
         * ready to read and to write counts twice. The bits just written are
         * that count for the descriptors the fallback answered.
         */
        if (use_poll_fallback)
            ret = ready_bits;

        int bytes = nfds_words * 8;
        if (bits.r && guest_write_small(g, readfds_gva, bits.r, bytes) < 0)
            goto pselect_fault;
        if (bits.w && guest_write_small(g, writefds_gva, bits.w, bytes) < 0)
            goto pselect_fault;
        if (bits.e && guest_write_small(g, exceptfds_gva, bits.e, bytes) < 0)
            goto pselect_fault;
    }

    free(reqs_heap);
    return ret;

    int64_t err;
pselect_fault:
    err = -LINUX_EFAULT;
    goto pselect_cleanup;
pselect_inval:
    err = -LINUX_EINVAL;
    goto pselect_cleanup;
pselect_badf:
    err = -LINUX_EBADF;
    goto pselect_cleanup;
pselect_nomem:
    err = -LINUX_ENOMEM;
pselect_cleanup:
    for (int i = 0; i < req_count; i++)
        host_fd_ref_close(&reqs[i].ref);
    free(reqs_heap);
    return err;
}

/* epoll emulation via kqueue
 *
 * Linux epoll is emulated using macOS kqueue. Each epoll_create1() creates a
 * kqueue fd. epoll_ctl translates to kevent() calls. epoll_pwait translates to
 * kevent() with timeout.
 *
 * Limitations:
 *   - EPOLLEXCLUSIVE not supported (rare, for load balancing)
 *   - epoll_data is stored per epoll instance (fd_table[epfd].dir), indexed by
 *     guest fd; each instance keeps its own table
 */

/* Linux EPOLL constants */
#define LINUX_EPOLLIN 0x001
#define LINUX_EPOLLOUT 0x004
#define LINUX_EPOLLERR 0x008
#define LINUX_EPOLLHUP 0x010
#define LINUX_EPOLLRDHUP 0x2000
#define LINUX_EPOLLET (1U << 31)
#define LINUX_EPOLLONESHOT (1U << 30)

/* Linux epoll_ctl operations */
#define LINUX_EPOLL_CTL_ADD 1
#define LINUX_EPOLL_CTL_DEL 2
#define LINUX_EPOLL_CTL_MOD 3

/* Linux EPOLL_CLOEXEC = O_CLOEXEC = 0x80000 on aarch64 */
#define LINUX_EPOLL_CLOEXEC 0x80000

/* Linux epoll_event on aarch64 (NOT packed; 16 bytes with padding) */
typedef struct {
    uint32_t events, _pad;
    uint64_t data;
} linux_epoll_event_t;

/* Per-fd registration entry within an epoll instance. */
typedef struct {
    uint32_t events;     /* Registered EPOLL* events mask */
    uint64_t data;       /* User data to return in epoll_wait */
    uint64_t generation; /* fd_entry_t.generation captured at ADD/MOD. Detects a
                          * close+reopen ABA: if the guest fd's current
                          * generation no longer matches, the registered open
                          * file is gone and this stale entry must not drive
                          * kevent against the reused host fd.
                          */
    uint64_t ofd_id; /* Open file description identity captured at ADD/MOD. */
    bool active;     /* Registered in this instance */
    bool oneshot_armed; /* EPOLLONESHOT and event already fired,
                         * waiting for EPOLL_CTL_MOD re-arm.
                         * kqueue removed the event, so poll emulation prevents
                         * reporting but allow MOD.
                         */
    bool pty_master;    /* Registration is for a tracked pty master. */

    /* The target is pollable on Linux but takes no knote here, so read
     * readiness can never arrive through kqueue. /dev/random is the only such
     * target today. Linux reports it readable as soon as the pool is seeded and
     * from then on always, which is what the wait synthesizes.
     */
    bool always_readable;
} epoll_reg_t;

/* Per-epoll-instance data, stored in fd_table[epfd].dir. Each instance has its
 * own registration table so multiple epoll instances watching the same FD do
 * not overwrite each other's user data.
 */
typedef struct {
    /* Reference count guarded by fd_lock. Starts at 1 (the fd-table's
     * reference, held while the epfd is open) and gains one per in-flight
     * epoll_ctl / epoll_pwait that pinned the instance via
     * epoll_instance_acquire(). The allocation is freed only when the count
     * reaches zero, so a concurrent close() of the epoll fd from a sibling
     * thread cannot free it out from under a call still walking regs[]
     * (including across a blocking kevent()).
     */
    int refcount;

    /* Serializes all regs[] reads and writes: epoll_ctl / epoll_pwait take it
     * for their short reg bookkeeping (never across the blocking kevent()
     * wait), and epoll_note_fd_closed takes it while holding fd_lock. Mirrors
     * the Linux eventpoll->mtx that serializes interest-list mutation against
     * ready-list scans. Lock order: fd_lock -> lock (see internal.h).
     */
    pthread_mutex_t lock;
    int active_count;
    int pty_master_count;
    int always_readable_count;
    epoll_reg_t regs[FD_TABLE_SIZE];
} epoll_instance_t;

static void epoll_reg_deactivate_locked(epoll_instance_t *inst,
                                        epoll_reg_t *reg)
{
    if (reg->active && inst->active_count > 0)
        inst->active_count--;
    if (reg->pty_master && inst->pty_master_count > 0)
        inst->pty_master_count--;
    if (reg->always_readable && inst->always_readable_count > 0)
        inst->always_readable_count--;
    reg->active = false;
    reg->oneshot_armed = false;
    reg->pty_master = false;
    reg->always_readable = false;
    reg->generation = 0;
    reg->ofd_id = 0;
}

/* Count of live epoll instances. When zero, epoll_note_fd_closed() skips its
 * scan entirely -- the overwhelmingly common case (a process with no epoll fd
 * pays nothing on every close). Guarded by fd_lock, matching the fd_table scan.
 */
static int epoll_live_count;

/* Drop one reference; free when the last one goes. Caller holds fd_lock. Safe
 * to destroy inst->lock here: the last reference is dropped only after every
 * epoll_ctl / epoll_pwait that held one has released both its reg lock and its
 * reference, so nothing is parked on the mutex.
 */
static void epoll_instance_unref_locked(epoll_instance_t *inst)
{
    if (--inst->refcount == 0) {
        pthread_mutex_destroy(&inst->lock);
        free(inst);
    }
}

/* Pin the epoll instance behind epfd for the duration of a call, so a
 * concurrent close(epfd) cannot free it mid-use.
 *
 * Returns the instance with an extra reference, or NULL if epfd is not a live
 * epoll fd. Balance every non-NULL return with epoll_instance_release().
 */
static epoll_instance_t *epoll_instance_acquire(int epfd)
{
    if (!RANGE_CHECK(epfd, 0, FD_TABLE_SIZE))
        return NULL;
    pthread_mutex_lock(&fd_lock);
    epoll_instance_t *inst = NULL;
    if (fd_table[epfd].type == FD_EPOLL) {
        inst = (epoll_instance_t *) fd_table[epfd].dir;
        if (inst)
            inst->refcount++;
    }
    pthread_mutex_unlock(&fd_lock);
    return inst;
}

/* Release a reference taken by epoll_instance_acquire(). */
static void epoll_instance_release(epoll_instance_t *inst)
{
    pthread_mutex_lock(&fd_lock);
    epoll_instance_unref_locked(inst);
    pthread_mutex_unlock(&fd_lock);
}

/* Duplicate an epoll fd. Linux dup(2)/dup3(2)/F_DUPFD of an epoll fd yield a
 * second descriptor onto the SAME eventpoll instance -- shared interest list
 * and all. The generic dup path in duplicate_guest_fd() cannot express that: it
 * clones DIR streams but leaves fd_table[dst].dir NULL for every other type, so
 * a duped epoll fd would have no interest table and every epoll_ctl/epoll_pwait
 * on it would fail. Handle it here by pointing the new slot's dir at the shared
 * instance and taking a reference, mirroring eventfd_dup_fd's counter sharing.
 */
int epoll_dup_fd(int src_fd,
                 int src_host_fd,
                 uint64_t src_generation,
                 int min_guest_fd,
                 int fixed_guest_fd,
                 bool fixed_slot,
                 int linux_flags)
{
    /* Pin the source instance and dup its host kqueue under fd_lock so a
     * concurrent close(src_fd) can neither free the shared instance nor
     * invalidate the host fd between validation and dup. The reference and the
     * live-count bump both cover the new slot; on any failure below,
     * epoll_instance_free() undoes exactly one of each.
     */
    pthread_mutex_lock(&fd_lock);
    epoll_instance_t *inst = NULL;
    if (fd_table[src_fd].type == FD_EPOLL &&
        fd_table[src_fd].host_fd == src_host_fd &&
        fd_table[src_fd].generation == src_generation)
        inst = (epoll_instance_t *) fd_table[src_fd].dir;
    if (!inst) {
        pthread_mutex_unlock(&fd_lock);
        errno = EBADF;
        return -1;
    }
    inst->refcount++;

    /* The alias names the same open file description, so it carries the
     * source's status flags and its ofd_id rather than a freshly built set;
     * every alias sweep (O_NONBLOCK shadow, O_ASYNC, the SIGIO owner) matches
     * on ofd_id, and a rebuilt one hides the alias from all of them.
     */
    int src_flags = fd_table[src_fd].linux_flags & FD_DESCRIPTION_FLAGS;
    uint64_t src_ofd_id = fd_table[src_fd].ofd_id;
    int new_host_fd = dup(src_host_fd);
    if (new_host_fd < 0) {
        epoll_instance_unref_locked(inst);
        pthread_mutex_unlock(&fd_lock);
        return -1;
    }
    epoll_live_count++;
    pthread_mutex_unlock(&fd_lock);

    /* Publish type, host_fd, the shared dir, and flags in one fd_lock critical
     * section (fd_alloc_dir_*), so the slot is never observable as FD_EPOLL
     * with a NULL dir -- matching sys_epoll_create1. The access mode comes from
     * fd_type_accmode on publish, the same as it does there.
     */
    int lflags = src_flags | (linux_flags & LINUX_O_CLOEXEC);

    /* The new slot aliases the source's description: the allocator installs its
     * ofd_id, foreign_description and nonblock_owned inside the window that
     * publishes the slot, rather than this path patching them on afterwards.
     */
    fd_alias_spec_t spec = fd_alias_identity(src_ofd_id, 0);
    int new_guest_fd = fd_alloc_alias_dir(
        &spec, fixed_slot ? fixed_guest_fd : -1, min_guest_fd, FD_EPOLL,
        new_host_fd, NULL, inst, lflags, NULL);
    if (new_guest_fd < 0) {
        /* fd_alloc_dir_at fails only when fixed_guest_fd is out of range or
         * over RLIMIT_NOFILE; dup2/dup3 report that as EBADF, not the EMFILE
         * that the lowest-free path returns. Capture the intended errno before
         * cleanup so the close()/epoll_instance_free() below (either may touch
         * errno) cannot clobber it; restore it last. Matches eventfd_dup_fd's
         * override.
         */
        int saved_errno = fixed_slot ? EBADF : errno;
        close(new_host_fd);
        epoll_instance_free(inst); /* drops the ref and the live-count bump */
        errno = saved_errno;
        return -1;
    }

    return new_guest_fd;
}

/* Eagerly drop a closed guest fd from every epoll instance's interest table.
 *
 * Linux auto-removes a fd from all epoll interest lists when its last
 * descriptor closes; elfuse keys epoll state on the guest fd number, so a close
 * must clear that number from every instance or regs[fd].active keeps claiming
 * the fd is still watched. Without this, correctness leans on the cross-call
 * generation guard in sys_epoll_ctl() to lazily notice the stale entry, and
 * sys_epoll_pwait() (which does not re-check generation) would surface a stale
 * registration the moment a host fd or udata value gets reused.
 *
 * Called from fd_mark_closed_unlocked() -- the single chokepoint every close
 * path funnels through -- so it covers sys_close, close_range, dup2 over an
 * open slot, and the execve CLOEXEC sweep alike. The caller holds fd_lock (or
 * runs single-threaded on the relaxed fast path), so the fd_table scan and the
 * cleared slot's own instance (already FD_CLOSED, hence skipped) are stable.
 * The kqueue knote itself needs no EV_DELETE: the host fd close that follows
 * drops it automatically, and clearing the software state is what makes the
 * pwait active-check honest.
 */
void epoll_note_fd_closed(int closed_fd, uint64_t closed_ofd_id)
{
    if (epoll_live_count == 0)
        return;
    if (closed_ofd_id != 0) {
        for (int fd = 0; fd < FD_TABLE_SIZE; fd++) {
            if (fd == closed_fd)
                continue;
            if (fd_table[fd].type != FD_CLOSED &&
                fd_table[fd].ofd_id == closed_ofd_id)
                return;
        }
    }
    for (int epfd = 0; epfd < FD_TABLE_SIZE; epfd++) {
        if (fd_table[epfd].type != FD_EPOLL)
            continue;
        epoll_instance_t *inst = (epoll_instance_t *) fd_table[epfd].dir;
        if (!inst)
            continue;

        /* fd_lock -> inst->lock ordering; the instance is in the table so its
         * refcount is at least the table's reference and cannot be freed here.
         */
        pthread_mutex_lock(&inst->lock);
        epoll_reg_deactivate_locked(inst, &inst->regs[closed_fd]);
        pthread_mutex_unlock(&inst->lock);
    }
}

/* Drop the fd-table's reference to an epoll instance and remove it from the
 * live count. Called by fd_cleanup_entry() when an FD_EPOLL slot closes. The
 * memory is freed here only if no in-flight epoll_ctl / epoll_pwait still holds
 * a reference; the last releaser frees it otherwise.
 */
void epoll_instance_free(void *inst)
{
    if (!inst)
        return;
    pthread_mutex_lock(&fd_lock);
    if (epoll_live_count > 0)
        epoll_live_count--;
    epoll_instance_unref_locked(inst);
    pthread_mutex_unlock(&fd_lock);
}

static inline void epoll_merge_event(linux_epoll_event_t *out,
                                     const struct kevent *kev,
                                     const epoll_reg_t *reg)
{
    if (kev->filter == EVFILT_READ)
        out->events |= LINUX_EPOLLIN;
    if (kev->filter == EVFILT_WRITE)
        out->events |= LINUX_EPOLLOUT;
    if (kev->flags & EV_EOF) {
        out->events |= LINUX_EPOLLHUP;
        if (kev->filter == EVFILT_READ && (reg->events & LINUX_EPOLLRDHUP))
            out->events |= LINUX_EPOLLRDHUP;
    }
    if (kev->flags & EV_ERROR)
        out->events |= LINUX_EPOLLERR;
}

int64_t sys_epoll_create1(int flags)
{
    int kq = kqueue();
    if (kq < 0)
        return linux_errno();

    if ((flags & LINUX_EPOLL_CLOEXEC) && fd_set_cloexec(kq) < 0) {
        close(kq);
        return linux_errno();
    }

    /* Allocate per-instance registration table */
    epoll_instance_t *inst = calloc(1, sizeof(*inst));
    if (!inst) {
        close(kq);
        return -LINUX_ENOMEM;
    }
    if (pthread_mutex_init(&inst->lock, NULL) != 0) {
        free(inst);
        close(kq);
        return -LINUX_ENOMEM;
    }

    /* No access mode here: FD_EPOLL is in fd_type_accmode, and every publish
     * forces the mode that table names back in (fd_flags_with_accmode), so a
     * creator naming it again is a second place for one fact to live.
     */
    int lflags = 0;
    if (flags & LINUX_EPOLL_CLOEXEC)
        lflags |= LINUX_O_CLOEXEC;

    /* Publish type, host_fd, dir, and flags in one fd_lock critical section
     * (fd_alloc_dir) so the slot is never visible to a concurrent close/scan as
     * FD_EPOLL with a NULL dir. refcount is set on the still-private instance
     * beforehand, so the close hook sees a fully formed instance the instant
     * the slot reads FD_EPOLL.
     */
    inst->refcount = 1; /* the fd-table's reference */
    int gfd = fd_alloc_dir(FD_EPOLL, kq, NULL, inst, lflags);
    if (gfd < 0) {
        pthread_mutex_destroy(&inst->lock);
        free(inst);
        close(kq);
        return -LINUX_EMFILE;
    }

    /* Count this instance for epoll_note_fd_closed()'s fast-path skip. A
     * pathological close_range() racing this create can close gfd between the
     * publish above and here; the close hook then frees the instance and this
     * increment leaves the counter one too high. Each such race can add one, so
     * the counter may stay positive with no live instance -- that only forces
     * the scan to run when it need not (perf only, and the guarded decrement
     * still never underflows), never a correctness or memory-safety issue.
     */
    pthread_mutex_lock(&fd_lock);
    epoll_live_count++;
    pthread_mutex_unlock(&fd_lock);

    return gfd;
}

/* Whether the kqueue accepts any knote on this fd, which tells a refused write
 * filter apart from a target kqueue rejects outright. The probe knote is added
 * disabled on purpose: sys_epoll_pwait blocks on this same kqueue without
 * inst->lock, and an enabled probe on a ready target would hand that wait an
 * event whose NULL udata reads back as guest fd 0. The target carries no other
 * registration here, so the paired delete takes nothing else with it.
 */
static bool epoll_target_pollable(int kq, int host_fd)
{
    struct kevent probe;
    EV_SET(&probe, host_fd, EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0, NULL);
    if (kevent(kq, &probe, 1, NULL, 0, NULL) < 0)
        return false;
    EV_SET(&probe, host_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(kq, &probe, 1, NULL, 0, NULL);
    return true;
}

/* Whether Linux would take this target at all. A plain file has no poll method
 * and kqueue does not mind, so that refusal originates here; fstat answers it
 * rather than the fd type, since FD_REGULAR also covers a fifo or a tty opened
 * by path. An open that resolved a path through an intercept answers from
 * path_poll_capable instead, because fstat would be describing elfuse's staging
 * file: /proc/self/mountinfo and /sys/devices/system/cpu/online are ordinary
 * host files here and pollable on Linux, while /proc/self/stat and /etc/passwd
 * are the same kind of host file and are not.
 */
static bool epoll_target_supported(int kq, const fd_entry_t *snap)
{
    /* A settled path answers for itself. The kqueue probe would veto
     * /dev/random, which Linux polls and macOS refuses a knote on.
     */
    if (snap->path_poll_capable)
        return true;
    struct stat st;
    if (fstat(snap->host_fd, &st) == 0 && S_ISREG(st.st_mode))
        return false;
    return epoll_target_pollable(kq, snap->host_fd);
}

/* Remove the filters an aborted registration pass already armed. Each carries
 * the udata of a registration the caller is about to abandon, and a knote left
 * on a live target wakes the next sys_epoll_pwait with an event that wait can
 * only drop, returning 0 ahead of its timeout. Deleting a filter this pass
 * dropped rather than armed fails with ENOENT and is ignored, the way every
 * other delete here is.
 */
static void epoll_undo_changes(int kq, const struct kevent *changes, int n)
{
    for (int i = 0; i < n; i++) {
        struct kevent del;
        EV_SET(&del, changes[i].ident, changes[i].filter, EV_DELETE, 0, 0,
               NULL);
        kevent(kq, &del, 1, NULL, 0, NULL);
    }
}

/* epoll_target_supported for the paths that have no instance to probe on,
 * because the epoll descriptor is not one or the op never named a registration.
 * The probe needs any kqueue rather than this instance's, so a call that is
 * already failing borrows one; the paths that succeed never reach here and
 * still pay nothing.
 */
static bool epoll_target_supported_standalone(const fd_entry_t *snap)
{
    if (snap->path_poll_capable)
        return true;
    struct stat st;
    if (fstat(snap->host_fd, &st) == 0 && S_ISREG(st.st_mode))
        return false;
    int kq = kqueue();
    if (kq < 0)
        return true;
    bool ok = epoll_target_pollable(kq, snap->host_fd);
    close(kq);
    return ok;
}

/* EINVAL unless the target has no poll method, which the kernel decides first.
 */
static int64_t epoll_einval_unless_unsupported(const fd_entry_t *snap)
{
    return epoll_target_supported_standalone(snap) ? -LINUX_EINVAL
                                                   : -LINUX_EPERM;
}

int64_t sys_epoll_ctl(guest_t *g, int epfd, int op, int fd, uint64_t event_gva)
{
    /* The event is copied before anything else, because that is where the
     * kernel copies it. SYSCALL_DEFINE4(epoll_ctl) runs the copy_from_user in
     * the syscall wrapper and returns EFAULT there, before do_epoll_ctl reaches
     * either fdget, so an unreadable event outranks a bad descriptor for every
     * op that reads one. Measured against Linux 6.18: epoll_ctl(-1, ADD, fd,
     * (void *) 1) is EFAULT, not EBADF.
     *
     * ep_op_has_event(op) is op != EPOLL_CTL_DEL, so an unknown op copies too,
     * and DEL reads nothing: epoll_ctl(-1, DEL, -1, (void *) 1) is the one call
     * in that family that answers EBADF.
     */
    linux_epoll_event_t ev_in;
    if (op != LINUX_EPOLL_CTL_DEL &&
        guest_read_small(g, event_gva, &ev_in, sizeof(ev_in)) < 0)
        return -LINUX_EFAULT;

    host_fd_ref_t epoll_ref;
    int64_t ref_err = host_fd_ref_open(epfd, &epoll_ref);
    if (ref_err < 0)
        return ref_err;

    /* Validate the target fd and read its persistent host fd in a single
     * fd_lock snapshot, so the kqueue knote ident is taken from the same entry
     * that was validated. A kqueue knote is keyed by the fd number and the
     * kernel drops it the moment that fd is closed, so the ident has to be the
     * fd table's own host fd. Snapshotting, rather than host_fd_ref_open() plus
     * a separate fd_to_host(), keeps the validate and the ident read atomic
     * under one fd_lock. The snapshot's generation then guards the cross-call
     * ABA below. Result mapping uses udata (the guest fd), so the ident only
     * needs to stay open and refer to the same open file description.
     *
     * Ahead of the instance lookup because do_epoll_ctl reaches both fdgets
     * first, and because the target decides EPERM ahead of every EINVAL below.
     */
    fd_entry_t target_snap;
    if (!fd_snapshot(fd, &target_snap)) {
        host_fd_ref_close(&epoll_ref);
        return -LINUX_EBADF;
    }

    /* Pin the instance so a concurrent close(epfd) cannot free it under us.
     *
     * A target with no poll method outranks this EINVAL: do_epoll_ctl tests
     * file_can_poll before is_file_epoll. Measured on Linux 6.12,
     * epoll_ctl(plain_file, ADD, plain_file, &ev) is EPERM while the same call
     * on a pipe is EINVAL.
     */
    epoll_instance_t *inst = epoll_instance_acquire(epfd);
    if (!inst) {
        int64_t err = epoll_einval_unless_unsupported(&target_snap);
        host_fd_ref_close(&epoll_ref);
        return err;
    }

    int64_t ret;

    /* The op and the pairing, in that order and here rather than at the top,
     * because the kernel decides both inside do_epoll_ctl after both fdgets:
     * epoll_ctl(-1, 99, fd, &ev) is EBADF, not EINVAL.
     *
     * Without the op check the arms below test DEL, then ADD, then MOD, and any
     * other value fell past all three into the registration path and armed a
     * knote. The pairing check used to open this function, ahead of both
     * lookups, which made epoll_ctl(-1, ADD, -1, &ev) answer EINVAL where the
     * kernel answers EBADF.
     */
    if (op != LINUX_EPOLL_CTL_ADD && op != LINUX_EPOLL_CTL_DEL &&
        op != LINUX_EPOLL_CTL_MOD) {
        ret = epoll_einval_unless_unsupported(&target_snap);
        goto out;
    }
    if (fd == epfd) {
        ret = -LINUX_EINVAL;
        goto out;
    }
    int target_host_fd = target_snap.host_fd;
    bool target_pty_master =
        proc_pty_master_pts_num(target_host_fd) != UINT32_MAX;

    /* Serialize all regs[] access and the paired kqueue mutation against a
     * concurrent close hook or a sibling epoll_ctl on the same instance. The
     * kevent() calls below are change-only (non-blocking), so holding the lock
     * across them is bounded. From here every exit goes through out_locked.
     */
    pthread_mutex_lock(&inst->lock);
    epoll_reg_t *reg = &inst->regs[fd];

    /* Cross-call ABA guard. If the guest closed this fd and reopened it (or the
     * slot was reused) since the registration was stamped, the kernel already
     * dropped the original knote when the old host fd closed, yet the guest fd
     * number -- and thus reg->active -- still looks live. Acting on it would
     * EV_DELETE/EV_MOD the wrong knote on the reused host fd. A mismatched
     * generation means the registration is gone: drop it so DEL/MOD report
     * ENOENT (matching Linux's auto-removal on close) and ADD starts fresh.
     */
    if ((reg->active || reg->oneshot_armed) &&
        reg->generation != target_snap.generation) {
        epoll_reg_deactivate_locked(inst, reg);
    }

    if (op == LINUX_EPOLL_CTL_DEL) {
        /* Linux returns ENOENT when removing an unregistered fd, but it tests
         * the target's poll support before it looks at the operation, so a
         * target it would never have accepted answers EPERM here too. Only the
         * unregistered path pays for the check.
         */
        if (!reg->active) {
            ret = epoll_target_supported(epoll_ref.fd, &target_snap)
                      ? -LINUX_ENOENT
                      : -LINUX_EPERM;
            goto out_locked;
        }

        /* Remove all filters for this fd. EPOLLRDHUP alone registers
         * EVFILT_READ (see ADD path), so check both EPOLLIN and EPOLLRDHUP.
         * Each delete goes in its own kevent call for the reason the MOD path
         * below already states: a batched call with a NULL eventlist stops at
         * the first failed change and leaks the survivor, and events names a
         * filter that may not be registered -- a dropped write filter, or the
         * one EPOLLONESHOT already removed. Errors are ignored either way,
         * since the fd may already be closed.
         */
        {
            struct kevent del;
            if (reg->events & (LINUX_EPOLLIN | LINUX_EPOLLRDHUP)) {
                EV_SET(&del, target_host_fd, EVFILT_READ, EV_DELETE, 0, 0,
                       NULL);
                kevent(epoll_ref.fd, &del, 1, NULL, 0, NULL);
            }
            if (reg->events & LINUX_EPOLLOUT) {
                EV_SET(&del, target_host_fd, EVFILT_WRITE, EV_DELETE, 0, 0,
                       NULL);
                kevent(epoll_ref.fd, &del, 1, NULL, 0, NULL);
            }
            epoll_reg_deactivate_locked(inst, reg);
        }
        ret = 0;
        goto out_locked;
    }

    /* The plain-file half of epoll_target_supported, inline so an ADD does not
     * pay for the kqueue probe: the registration below already asks kqueue the
     * rest of the question.
     *
     * do_epoll_ctl decides poll support earlier than this position alone
     * suggests: file_can_poll runs ahead of is_file_epoll and ahead of the op
     * switch, not merely ahead of the registration lookup. Everything it
     * outranks that this function answers sooner is answered by
     * epoll_einval_unless_unsupported at those two sites, so by the time a call
     * reaches here the only checks left below are the EEXIST and ENOENT this
     * position covers.
     */
    if (!target_snap.path_poll_capable) {
        struct stat target_st;
        if (fstat(target_host_fd, &target_st) == 0 &&
            S_ISREG(target_st.st_mode)) {
            ret = -LINUX_EPERM;
            goto out_locked;
        }
    }

    /* Linux semantics: ADD fails with EEXIST if already registered; MOD fails
     * with ENOENT if not registered. oneshot_armed registrations (EPOLLONESHOT
     * fired, waiting for re-arm) are still valid for MOD.
     */
    if (op == LINUX_EPOLL_CTL_ADD && reg->active) {
        ret = -LINUX_EEXIST;
        goto out_locked;
    }
    if (op == LINUX_EPOLL_CTL_MOD && !reg->active && !reg->oneshot_armed) {
        ret = epoll_target_supported(epoll_ref.fd, &target_snap) ? -LINUX_ENOENT
                                                                 : -LINUX_EPERM;
        goto out_locked;
    }

    /* Copied above, in the order Linux copies it. Reading it a second time here
     * would let a sibling change the value between the fault check and the
     * registration, and would report EFAULT after the EEXIST and ENOENT checks
     * that Linux answers it before.
     */
    linux_epoll_event_t ev = ev_in;

    /* For MOD, remove old registrations first if they exist in kqueue.
     * EPOLLRDHUP alone registers EVFILT_READ (see ADD path), so check both
     * EPOLLIN and EPOLLRDHUP (same logic as CTL_DEL). Always attempt the
     * deletes even when oneshot_armed: with multi-filter EPOLLONESHOT, only the
     * filter that fired was removed by EV_ONESHOT; the other filter is still
     * registered and must be cleaned. Issue each delete in its own kevent call
     * so an ENOENT on one filter does not abort the other -- with a single
     * batched call and NULL eventlist, kevent stops at the first failed change
     * and leaks the survivor.
     */
    if (op == LINUX_EPOLL_CTL_MOD && reg->active) {
        struct kevent del;
        if (reg->events & (LINUX_EPOLLIN | LINUX_EPOLLRDHUP)) {
            EV_SET(&del, target_host_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
            kevent(epoll_ref.fd, &del, 1, NULL, 0, NULL);
        }
        if (reg->events & LINUX_EPOLLOUT) {
            EV_SET(&del, target_host_fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
            kevent(epoll_ref.fd, &del, 1, NULL, 0, NULL);
        }
    }

    /* Build kevent changes */
    struct kevent changes[2];
    int nchanges = 0;

    /* EPOLLET maps to EV_CLEAR. Idle re-poll, full drain, and post-drain
     * new-data edges all match Linux EPOLLET. Narrow divergence: a partial read
     * (without draining to EAGAIN) is a data-count state change that re-arms
     * kqueue, so the next kevent fires while Linux EPOLLET stays silent.
     * Distinguishing "partial-read remainder" from "drained-then-refilled"
     * would require a unified drain signal across every data-consuming path
     * (read / recv* / splice / ...) feeding back into this layer, which the
     * epoll/kqueue bridge does not maintain. Apps that follow the documented
     * EPOLLET contract (drain to EAGAIN) are unaffected; tests/test-epoll-
     * edge.c locks in that contract.
     */
    uint16_t kflags = EV_ADD;
    if (ev.events & LINUX_EPOLLET)
        kflags |= EV_CLEAR;
    if (ev.events & LINUX_EPOLLONESHOT)
        kflags |= EV_ONESHOT;

    /* Use (void*)(uintptr_t)fd as udata to identify the guest fd */
    void *udata = (void *) (uintptr_t) fd;

    if (ev.events & (LINUX_EPOLLIN | LINUX_EPOLLRDHUP)) {
        EV_SET(&changes[nchanges], target_host_fd, EVFILT_READ, kflags, 0, 0,
               udata);
        nchanges++;
    }
    if (ev.events & LINUX_EPOLLOUT) {
        EV_SET(&changes[nchanges], target_host_fd, EVFILT_WRITE, kflags, 0, 0,
               udata);
        nchanges++;
    }

    /* A mask naming no readiness filter registers nothing, so the loop below
     * never asks kqueue whether the target takes a knote at all. Linux tests
     * poll support before it reads the event, and answers EPERM for a directory
     * or a character device whatever the mask says, so ask here.
     */
    if (nchanges == 0 && !epoll_target_pollable(epoll_ref.fd, target_host_fd)) {
        ret = -LINUX_EPERM;
        goto out_locked;
    }

    /* Linux decides EPERM from the target alone, never from the requested
     * events: epoll_ctl(2) accepts EPOLLOUT on a timerfd or on a nested epoll
     * fd, neither of which ever reports itself writable. Both are kqueues here,
     * and kqueue refuses EVFILT_WRITE on a kqueue with EINVAL, so register one
     * filter per call and drop a refused write filter instead of failing the
     * whole ADD. A batched call would also stop at the first failed change and
     * leave the survivor registered. EINVAL on the read filter, or on a write
     * filter whose target takes no knote at all, is the EPERM case.
     *
     * A target the path already settled is never that case: /dev/random is
     * pollable on Linux and takes no knote here, so its refusal drops the
     * filter the way a kqueue's write filter does. Read readiness then has no
     * knote to arrive on, which always_readable carries to the wait.
     *
     * An error that is not EINVAL abandons a registration this loop may have
     * already armed filters for, each carrying the udata of an entry the bail
     * never activates. Undo them: sys_epoll_pwait does reap such a knote, but
     * only after it has woken the wait and counted the event, so the call
     * returns 0 ahead of its timeout. MOD arrives here with its old filters
     * already deleted, so this is also what keeps a half-failed re-registration
     * from leaving one behind. The EPERM arm below needs no undo: it is
     * reachable only while nothing is armed, since a refused read filter is the
     * first change and a refused write filter without a registered read one
     * means the mask named no read filter at all.
     */
    bool read_registered = false;
    bool read_refused = false;
    for (int i = 0; i < nchanges; i++) {
        if (kevent(epoll_ref.fd, &changes[i], 1, NULL, 0, NULL) == 0) {
            if (changes[i].filter == EVFILT_READ)
                read_registered = true;
            continue;
        }
        if (errno != EINVAL) {
            ret = linux_errno();
            epoll_undo_changes(epoll_ref.fd, changes, i);
            goto out_locked;
        }
        if (target_snap.path_poll_capable) {
            if (changes[i].filter == EVFILT_READ)
                read_refused = true;
            continue;
        }
        if (changes[i].filter == EVFILT_READ ||
            !(read_registered ||
              epoll_target_pollable(epoll_ref.fd, target_host_fd))) {
            ret = -LINUX_EPERM;
            goto out_locked;
        }
    }

    /* Store registration data in per-instance table. Clear oneshot_armed when
     * MOD successfully re-arms. Stamp the snapshot's generation so a later
     * close+reopen of this guest fd is detected as a stale registration by the
     * ABA guard above.
     */
    reg->events = ev.events;
    reg->data = ev.data;
    reg->generation = target_snap.generation;
    reg->ofd_id = target_snap.ofd_id;
    if (!reg->active)
        inst->active_count++;
    if (target_pty_master && !reg->pty_master)
        inst->pty_master_count++;
    else if (!target_pty_master && reg->pty_master &&
             inst->pty_master_count > 0)
        inst->pty_master_count--;
    if (read_refused && !reg->always_readable)
        inst->always_readable_count++;
    else if (!read_refused && reg->always_readable &&
             inst->always_readable_count > 0)
        inst->always_readable_count--;
    reg->active = true;
    reg->oneshot_armed = false;
    reg->pty_master = target_pty_master;
    reg->always_readable = read_refused;

    ret = 0;

out_locked:
    pthread_mutex_unlock(&inst->lock);
out:
    host_fd_ref_close(&epoll_ref);
    epoll_instance_release(inst);
    return ret;
}

/* Whether this instance holds a registration whose read readiness kqueue can
 * never deliver. Same shape as a pending hangup: the wait must not block to its
 * deadline waiting for an event that cannot arrive.
 */
static bool epoll_has_always_readable(epoll_instance_t *inst)
{
    pthread_mutex_lock(&inst->lock);
    bool any = inst->always_readable_count > 0;
    pthread_mutex_unlock(&inst->lock);
    return any;
}

/* Collect guest fds registered in this instance whose pty master has hung up.
 *
 * kqueue never reports this: elfuse holds a keepalive slave open for the
 * master's whole life, so macOS still considers the pty live and stays silent.
 * Without this an epoll-based terminal waits forever for a hangup that cannot
 * arrive -- foot leaves its window open after the shell exits.
 *
 * Two-phase on purpose. regs[] needs inst->lock, but proc_pty_master_hung_up
 * takes fd_lock, which sorts *before* inst->lock (see internal.h). Testing
 * under the reg lock would invert that order against epoll_note_fd_closed,
 * which holds fd_lock and then takes inst->lock. So candidates are snapshotted
 * under the reg lock in bounded batches and tested once it is dropped.
 *
 * Returns the number of guest fds written to out_gfds, capped at max. out_gens
 * receives the registration generation each hit was tested against, so the
 * caller can re-verify it under inst->lock before acting: a sibling can
 * EPOLL_CTL_DEL and re-ADD the same fd number while the lock is dropped, and
 * stamping the hangup then would attach it to the new registration's data.
 */
static int epoll_collect_hung_up(epoll_instance_t *inst,
                                 int *out_gfds,
                                 uint64_t *out_gens,
                                 int max)
{
    if (max <= 0)
        return 0;

    enum { HUP_SCAN_BATCH = 64 };
    int cand_gfds[HUP_SCAN_BATCH];
    uint64_t cand_gens[HUP_SCAN_BATCH];
    int n = 0;
    int seen = 0;

    for (int gfd = 0; gfd < FD_TABLE_SIZE && n < max;) {
        int ncand = 0;
        int active_count;
        pthread_mutex_lock(&inst->lock);
        if (inst->pty_master_count <= 0) {
            pthread_mutex_unlock(&inst->lock);
            break;
        }
        active_count = inst->active_count;
        for (; gfd < FD_TABLE_SIZE && ncand < HUP_SCAN_BATCH &&
               seen < active_count;
             gfd++) {
            if (!inst->regs[gfd].active)
                continue;
            seen++;
            if (inst->regs[gfd].oneshot_armed || !inst->regs[gfd].pty_master)
                continue;
            cand_gfds[ncand] = gfd;

            /* Carry the generation the registration pinned at ADD/MOD, so a
             * close+reopen into the same fd number cannot be mistaken for the
             * registered master.
             */
            cand_gens[ncand] = inst->regs[gfd].generation;
            ncand++;
        }
        pthread_mutex_unlock(&inst->lock);
        if (ncand == 0 && seen >= active_count)
            break;

        for (int i = 0; i < ncand && n < max; i++) {
            if (!proc_pty_master_hung_up(cand_gfds[i], cand_gens[i]))
                continue;
            out_gfds[n] = cand_gfds[i];
            out_gens[n] = cand_gens[i];
            n++;
        }
    }
    return n;
}

int64_t sys_epoll_pwait(guest_t *g,
                        int epfd,
                        uint64_t events_gva,
                        int maxevents,
                        int timeout_ms,
                        uint64_t sigmask_gva)
{
    host_fd_ref_t epoll_ref;
    int64_t ref_err = host_fd_ref_open(epfd, &epoll_ref);
    if (ref_err < 0)
        return ref_err;

    if (maxevents <= 0) {
        host_fd_ref_close(&epoll_ref);
        return -LINUX_EINVAL;
    }

    /* Pin the instance so a concurrent close(epfd) cannot free it under us --
     * including across the blocking kevent() below.
     */
    epoll_instance_t *inst = epoll_instance_acquire(epfd);
    if (!inst) {
        host_fd_ref_close(&epoll_ref);
        return -LINUX_EINVAL;
    }

    int64_t ret;

    /* Atomically install signal mask for the duration of the wait */
    uint64_t saved_mask = 0;
    bool mask_installed = false;
    if (sigmask_gva != 0) {
        uint64_t new_mask;
        if (guest_read_small(g, sigmask_gva, &new_mask, sizeof(new_mask)) ==
            0) {
            saved_mask = signal_save_blocked();
            signal_set_blocked(new_mask);
            mask_installed = true;
        }
    }

    /* Convert timeout */
    bool has_timeout = (timeout_ms >= 0);
    struct timespec ts;
    if (has_timeout) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
    }

    /* A hangup that is already pending must not wait out the caller's timeout.
     * kqueue will never report it, so a finite epoll_wait would otherwise block
     * to its deadline before the stamping below runs, and an indefinite one
     * would burn a needless 200ms slice. Collect whatever else is ready without
     * blocking and fall straight through to the stamp.
     */
    int hup_probe;
    uint64_t hup_probe_gen;
    bool hup_ready =
        epoll_collect_hung_up(inst, &hup_probe, &hup_probe_gen, 1) > 0 ||
        epoll_has_always_readable(inst);
    struct timespec zero_ts = {.tv_sec = 0, .tv_nsec = 0};

    /* Collect kqueue events. For indefinite waits, use a short timeout and loop
     * so exit_group can interrupt. Cap maxevents before multiply to avoid
     * signed integer overflow when maxevents is very large.
     */
    if (maxevents > 128)
        maxevents = 128;
    int cap = maxevents * 2; /* Each epoll fd can produce 2 kevents */
    if (cap > 256)
        cap = 256;
    struct kevent kevents[256];

    struct timespec poll_ts = {.tv_sec = 0, .tv_nsec = 200000000L}; /* 200ms */
    int nready;
    do {
        nready = kevent(epoll_ref.fd, NULL, 0, kevents, cap,
                        hup_ready ? &zero_ts : (has_timeout ? &ts : &poll_ts));
        if (nready > 0) {
        }

        /* Evaluated stepwise only to name the one that fired; the guards
         * preserve the short-circuit order, so futex_interrupt_consume() still
         * runs exactly when it did as a single ||-chain.
         */
        /* Ready events outrank an interruption. Linux ep_poll() tests
         * ep_events_available() and jumps to send_events before it ever looks
         * at signal_pending(), so EINTR is the answer only for a wait that
         * produced nothing.
         *
         * Returning EINTR while holding a ready fd loses it for good in
         * practice: kqueue re-reports it on the next call, but the same pending
         * signal is still there, so the guest is handed EINTR forever and never
         * drains the fd. foot hit exactly that -- a SIGCHLD it had a handler
         * for but had not yet run left its Wayland socket readable and
         * undelivered, and it spun at 100% CPU without ever drawing a window.
         *
         * exit_group still wins outright: the process is going away and there
         * is nothing to deliver events to. An execve handed to this leader does
         * not: the thread keeps running, and dropping what kqueue already
         * dequeued would be worse here than for a signal, because EV_CLEAR and
         * EV_ONESHOT registrations consume the edge and nothing re-reports it.
         * The handoff runs at the top of the run loop whether this returns
         * events or EINTR, so letting the events win costs it nothing.
         */
        bool interrupted = thread_stop_requested() &&
                           !(nready > 0 && thread_stop_is_leader_work_only());
        if (!interrupted && nready <= 0)
            interrupted =
                futex_interrupt_consume() || signal_pending_interruption(NULL);
        if (interrupted) {
            /* Finite wait: part of the guest's timeout is already spent. */
            if (has_timeout)
                syscall_restart_forbid();
            nready = -1;
            errno = EINTR;
            break;
        }

        /* An indefinite wait re-arms on a 200ms slice; break out when a master
         * hung up during one, since kqueue will never make that fd ready.
         */
        if (nready == 0 && !has_timeout) {
            hup_ready =
                epoll_collect_hung_up(inst, &hup_probe, &hup_probe_gen, 1) > 0;
            if (hup_ready)
                break;
        }
    } while (nready == 0 && !has_timeout);

    int saved_errno = errno;

    /* Restore original signal mask after the blocking wait */
    if (mask_installed)
        signal_restore_blocked(saved_mask);

    if (nready < 0) {
        errno = saved_errno;
        ret = linux_errno();
        host_fd_ref_close(&epoll_ref);
        epoll_instance_release(inst);
        return ret;
    }

    /* Merge kevent results into epoll_event results. Multiple kevents for the
     * same fd (READ + WRITE) merge into one epoll_event. Use guest FD (not user
     * data) as the merge key, since two different FDs could legitimately share
     * the same epoll_data value.
     */
    linux_epoll_event_t out[256];
    /* Parallel array tracking which guest FD each output entry represents. */
    uint16_t out_gfds[256];
    int16_t out_index[FD_TABLE_SIZE];
    int nout = 0;

    memset(out_index, 0xff, sizeof(out_index));

    /* Gather hung-up masters before taking inst->lock: the collector takes that
     * lock itself, and it is not recursive.
     */
    int hup_gfds[256];
    uint64_t hup_gens[256];
    int nhup = epoll_collect_hung_up(inst, hup_gfds, hup_gens, maxevents);

    /* Serialize the regs[] reads and the oneshot re-arm against a concurrent
     * epoll_ctl or the close hook. Held only for this bookkeeping, never across
     * the blocking kevent() above; out[] is a local snapshot, so the guest
     * write happens after the unlock. Mirrors Linux dropping ep->mtx before
     * copyout.
     */
    pthread_mutex_lock(&inst->lock);

    for (int i = 0; i < nready && nout < maxevents; i++) {
        int gfd = (int) (uintptr_t) kevents[i].udata;
        if (!RANGE_CHECK(gfd, 0, FD_TABLE_SIZE) || !inst->regs[gfd].active) {
            struct kevent del;
            EV_SET(&del, kevents[i].ident, kevents[i].filter, EV_DELETE, 0, 0,
                   NULL);
            kevent(epoll_ref.fd, &del, 1, NULL, 0, NULL);
            continue;
        }

        /* EPOLLONESHOT semantics: once any event fired and was reported, the fd
         * stays disarmed until EPOLL_CTL_MOD re-arms it. With multi-filter
         * registrations (e.g. EPOLLIN | EPOLLOUT), EV_ONESHOT only removed the
         * filter that fired; surviving filters can still fire later and would
         * be reported here without this guard.
         */
        if (inst->regs[gfd].oneshot_armed)
            continue;

        epoll_reg_t *reg = &inst->regs[gfd];

        int idx = out_index[gfd];
        if (idx >= 0) {
            epoll_merge_event(&out[idx], &kevents[i], reg);
            continue;
        }

        idx = nout++;
        out_index[gfd] = idx;
        out_gfds[idx] = gfd;
        out[idx].events = 0;
        out[idx]._pad = 0;
        out[idx].data = reg->data;
        epoll_merge_event(&out[idx], &kevents[i], reg);
    }

    /* Stamp EPOLLIN for the registrations whose read readiness kqueue cannot
     * deliver. /dev/random is the only such target: Linux reports it readable
     * once the pool is seeded and from then on always, so the answer is a
     * property of the registration rather than something to sample. Unlike the
     * hangup scan below this reads regs[] under the lock it already holds, so
     * there is no unlocked snapshot to re-verify against a generation.
     */
    if (inst->always_readable_count > 0) {
        for (int gfd = 0; gfd < FD_TABLE_SIZE && nout < maxevents; gfd++) {
            epoll_reg_t *areg = &inst->regs[gfd];
            if (!areg->always_readable || !areg->active || areg->oneshot_armed)
                continue;
            if (!(areg->events & LINUX_EPOLLIN))
                continue;
            int idx = out_index[gfd];
            if (idx < 0) {
                idx = nout++;
                out_index[gfd] = (int16_t) idx;
                out_gfds[idx] = gfd;
                out[idx].events = 0;
                out[idx]._pad = 0;
                out[idx].data = areg->data;
            }
            out[idx].events |= LINUX_EPOLLIN;
        }
    }

    /* Stamp EPOLLHUP for the masters the host cannot report on. Linux delivers
     * EPOLLHUP whether or not the caller asked for it, so this ignores
     * reg->events. Merging into an existing entry keeps a hangup that lands
     * alongside queued output reported as EPOLLIN | EPOLLHUP, the way Linux
     * does it -- the reader drains the shell's parting output before acting on
     * the hangup. Runs before the oneshot marking below so an fd that fired
     * this round still carries the hangup into that same report.
     */
    for (int i = 0; i < nhup; i++) {
        int gfd = hup_gfds[i];

        /* Re-check under the lock: the collector tested unlocked, so a
         * concurrent epoll_ctl or close hook may have retired the entry since.
         * The generation match is what rejects a DEL + re-ADD of the same fd
         * number in that window, which would otherwise report this hangup
         * against the new registration's epoll_data.
         */
        if (!inst->regs[gfd].active || inst->regs[gfd].oneshot_armed ||
            inst->regs[gfd].generation != hup_gens[i])
            continue;
        int idx = out_index[gfd];
        if (idx < 0) {
            if (nout >= maxevents)
                break;
            idx = nout++;
            out_index[gfd] = idx;
            out_gfds[idx] = gfd;
            out[idx].events = 0;
            out[idx]._pad = 0;
            out[idx].data = inst->regs[gfd].data;
        }
        out[idx].events |= LINUX_EPOLLHUP;
    }

    /* Mark EPOLLONESHOT FDs as armed (fired but waiting for MOD re-arm). kqueue
     * already removed the event (EV_ONESHOT), so poll emulation marks the
     * registration as oneshot_armed to allow MOD but prevent further event
     * reporting until re-armed.
     */
    for (int i = 0; i < nout; i++) {
        int gfd = out_gfds[i];
        if (RANGE_CHECK(gfd, 0, FD_TABLE_SIZE) && inst->regs[gfd].active) {
            if (inst->regs[gfd].events & LINUX_EPOLLONESHOT)
                inst->regs[gfd].oneshot_armed = true;
        }
    }

    pthread_mutex_unlock(&inst->lock);

    /* Write results to guest */
    if (nout > 0) {
        for (int i = 0; i < nout; i++)
            if (guest_write_small(g, events_gva, out,
                                  nout * sizeof(linux_epoll_event_t)) < 0) {
                host_fd_ref_close(&epoll_ref);
                epoll_instance_release(inst);
                return -LINUX_EFAULT;
            }
    }

    host_fd_ref_close(&epoll_ref);
    epoll_instance_release(inst);
    return nout;
}
