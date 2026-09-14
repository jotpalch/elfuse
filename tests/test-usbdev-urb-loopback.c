/*
 * The async URB engine against a loopback device (ELFUSE_USB_FIXTURE=loopback)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: the async half of src/syscall/usbdev.c and the usbdevfs arms
 * of src/syscall/poll.c. The other usbdevfs lane runs against fixture devices
 * with no IOKit service behind them, so it stops at SUBMITURB's argument gate;
 * this one runs against a device whose IOKit answers come from
 * src/syscall/usbdev-fixture.c, so a URB can actually complete. Everything
 * between the ioctl and the wire is the production path: the bounce buffers,
 * the memory budget, the per-endpoint FIFO, the completion callback on the
 * event thread, the readiness and disconnect maps, REAPURB and the drain.
 *
 * The fixture is told what to do by a script (see usbdev-fixture.c) that this
 * binary rewrites through a vendor control request before each scenario, and it
 * keeps a log of what actually crossed the seam, which is how the trailing
 * zero-length packet is observed rather than inferred.
 *
 * The device is /dev/bus/usb/003/001, interface 2, bulk OUT 0x02, bulk IN 0x81,
 * interrupt IN 0x83, matching the out-of-tree board driver's endpoints.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* The guest headers may or may not spell it; poll.c must answer for it either
 * way, which is the whole of what the epoll half below asserts.
 */
#ifndef EPOLLWRNORM
#define EPOLLWRNORM 0x100
#endif

#define NODE "/dev/bus/usb/003/001"

/* A usbdevfs node that is not the fixture's, for the one scenario that is about
 * a guest fd number outliving the device it was opened on.
 */
#define OTHER_NODE "/dev/bus/usb/001/001"
#define IFNUM 2
#define EP_OUT 0x02
#define EP_IN 0x81
#define EP_INT 0x83
#define MPS 64

#define USBDEVFS_CONTROL 0xc0185500u
#define USBDEVFS_SUBMITURB 0x8038550au
#define USBDEVFS_DISCARDURB 0x0000550bu
#define USBDEVFS_REAPURB 0x4008550cu
#define USBDEVFS_REAPURBNDELAY 0x4008550du
#define USBDEVFS_SETINTERFACE 0x80085504u
#define USBDEVFS_SETCONFIGURATION 0x80045505u
#define USBDEVFS_CLAIMINTERFACE 0x8004550fu
#define USBDEVFS_RELEASEINTERFACE 0x80045510u
#define USBDEVFS_GET_CAPABILITIES 0x8004551au
#define USBDEVFS_CLEAR_HALT 0x80045515u
#define USBDEVFS_RESETEP 0x80045503u
#define USBDEVFS_RESET 0x00005514u
#define USBDEVFS_GETDRIVER 0x41045508u
#define USBDEVFS_IOCTL 0xc0105512u
#define USBDEVFS_DISCONNECT_CLAIM 0x8108551bu
#define USBDEVFS_IOCTL_DISCONNECT 0x5516u
#define USBDEVFS_IOCTL_CONNECT 0x5517u

struct getdriver {
    unsigned int interface;
    char driver[256];
};

struct usbdevfs_ioctl {
    int ifno, ioctl_code;
    void *data;
};

struct disconnect_claim {
    unsigned int interface, flags;
    char driver[256];
};

#define URB_TYPE_INTERRUPT 1
#define URB_TYPE_CONTROL 2
#define URB_TYPE_BULK 3
#define URB_SHORT_NOT_OK 0x01u
#define URB_ZERO_PACKET 0x40u

struct ctrltransfer {
    uint8_t bRequestType, bRequest;
    uint16_t wValue, wIndex, wLength;
    uint32_t timeout;
    void *data;
};

struct setinterface {
    unsigned int interface, altsetting;
};

struct urb {
    unsigned char type, endpoint;
    int status;
    unsigned int flags;
    void *buffer;
    int buffer_length, actual_length, start_frame;
    union {
        int number_of_packets;
        unsigned int stream_id;
    } u;
    int error_count;
    unsigned int signr;
    void *usercontext;
};

static int fd = -1;

/* A broken engine does not fail a blocking REAPURB, it never answers it, and a
 * lane that hangs is worse in CI than one that fails. Every scenario re-arms
 * this, and the handler names the scenario that ran out of time.
 */
static const char *stage = "startup";

static void on_alarm(int sig)
{
    (void) sig;
    static char pre[] = "\nTIMEOUT in stage: ";
    (void) !write(1, pre, sizeof(pre) - 1);
    (void) !write(1, stage, strlen(stage));
    (void) !write(1, "\n", 1);
    _exit(1);
}

static void enter(const char *name)
{
    stage = name;
    alarm(30);
}

static char msgbuf[256];
#define FAILF(...)                                     \
    do {                                               \
        snprintf(msgbuf, sizeof(msgbuf), __VA_ARGS__); \
        FAIL(msgbuf);                                  \
    } while (0)
#define CHECK(cond, ...)        \
    do {                        \
        if (cond)               \
            PASS();             \
        else                    \
            FAILF(__VA_ARGS__); \
    } while (0)

static long io(unsigned long req, void *arg)
{
    int r = ioctl(fd, req, arg);
    return r < 0 ? -errno : r;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* the fixture's control plane */

#define FX_LOG 0xf0
#define FX_SCRIPT 0xf1
#define FX_TERMINATE 0xf2
#define FX_RESET 0xf3
#define FX_STATS 0xf4
#define FX_REC 32

static long fx_script(const char *s)
{
    struct ctrltransfer ct = {.bRequestType = 0x40,
                              .bRequest = FX_SCRIPT,
                              .wValue = 0,
                              .wIndex = 0,
                              .wLength = (uint16_t) strlen(s),
                              .timeout = 1000,
                              .data = (void *) (uintptr_t) s};
    return io(USBDEVFS_CONTROL, &ct);
}

static long fx_reset(void)
{
    struct ctrltransfer ct = {.bRequestType = 0x40,
                              .bRequest = FX_RESET,
                              .timeout = 1000,
                              .data = NULL};
    return io(USBDEVFS_CONTROL, &ct);
}

static long fx_terminate(unsigned ms)
{
    struct ctrltransfer ct = {.bRequestType = 0x40,
                              .bRequest = FX_TERMINATE,
                              .wValue = (uint16_t) ms,
                              .timeout = 1000,
                              .data = NULL};
    return io(USBDEVFS_CONTROL, &ct);
}

/* Make every AbortPipe and USBDeviceAbortPipeZero answer kIOReturnNoDevice and
 * cancel nothing, without terminating the device: the one state an abort can
 * report that no other op reports for it.
 */
static long fx_aborts_gone(void)
{
    struct ctrltransfer ct = {.bRequestType = 0x40,
                              .bRequest = FX_TERMINATE,
                              .wValue = 0,
                              .wIndex = 4,
                              .timeout = 1000,
                              .data = NULL};
    return io(USBDEVFS_CONTROL, &ct);
}

/* Device handles the layer released while the fixture still owned a transfer on
 * the default control pipe. Readable after the fd that leaked one is gone,
 * which is the point: the release happens at close.
 */
static uint32_t fx_dev_releases_in_flight(void)
{
    uint8_t buf[4] = {0};
    struct ctrltransfer ct = {.bRequestType = 0xc0,
                              .bRequest = FX_STATS,
                              .wValue = 0,
                              .wIndex = 0,
                              .wLength = sizeof(buf),
                              .timeout = 1000,
                              .data = buf};
    if (io(USBDEVFS_CONTROL, &ct) != (long) sizeof(buf))
        return 0xffffffffu;
    return (uint32_t) buf[0] | ((uint32_t) buf[1] << 8) |
           ((uint32_t) buf[2] << 16) | ((uint32_t) buf[3] << 24);
}

/* Tear the claimed interface's pipes down without touching anything else, so
 * GetPipeProperties alone answers NoDevice.
 */
static long fx_pipes_gone(void)
{
    struct ctrltransfer ct = {.bRequestType = 0x40,
                              .bRequest = FX_TERMINATE,
                              .wValue = 0,
                              .wIndex = 2,
                              .timeout = 1000,
                              .data = NULL};
    return io(USBDEVFS_CONTROL, &ct);
}

static uint8_t logbuf[4096];
static int nlog;

static int fx_readlog(void)
{
    struct ctrltransfer ct = {.bRequestType = 0xc0,
                              .bRequest = FX_LOG,
                              .wValue = 0,
                              .wIndex = 0,
                              .wLength = sizeof(logbuf),
                              .timeout = 1000,
                              .data = logbuf};
    long r = io(USBDEVFS_CONTROL, &ct);
    nlog = r > 0 ? (int) (r / FX_REC) : 0;
    return nlog;
}

static unsigned rec_u32(int i, int off)
{
    const uint8_t *p = logbuf + (size_t) i * FX_REC + off;
    return (unsigned) p[0] | ((unsigned) p[1] << 8) | ((unsigned) p[2] << 16) |
           ((unsigned) p[3] << 24);
}
static unsigned rec_kind(int i)
{
    return logbuf[(size_t) i * FX_REC];
}
static unsigned rec_ep(int i)
{
    return logbuf[(size_t) i * FX_REC + 1];
}
static unsigned rec_conc(int i)
{
    return logbuf[(size_t) i * FX_REC + 3];
}
static unsigned rec_req(int i)
{
    return rec_u32(i, 4);
}
static unsigned rec_actual(int i)
{
    return rec_u32(i, 8);
}
static unsigned rec_start(int i)
{
    return rec_u32(i, 20);
}
static unsigned rec_data(int i, int byte)
{
    return logbuf[(size_t) i * FX_REC + 24 + byte];
}

/* Wait out something that has to happen on the event thread before the next
 * scenario starts -- a late abort completing an orphaned record, say.
 */
static void settle(int ms)
{
    struct timespec ts = {ms / 1000, (long) (ms % 1000) * 1000 * 1000};
    nanosleep(&ts, NULL);
}

/* urb helpers */

static void mk_bulk(struct urb *u, unsigned char ep, void *buf, int len)
{
    memset(u, 0, sizeof(*u));
    u->type = URB_TYPE_BULK;
    u->endpoint = ep;
    u->buffer = buf;
    u->buffer_length = len;
}

static long submit(struct urb *u)
{
    return io(USBDEVFS_SUBMITURB, u);
}

static struct urb *reap(bool block)
{
    struct urb *out = NULL;
    long r = io(block ? USBDEVFS_REAPURB : USBDEVFS_REAPURBNDELAY, &out);
    return r == 0 ? out : NULL;
}

/* A blocking REAPURB is the right thing to assert against an engine that still
 * queues, and the wrong thing to assert against one that has lost the URB: it
 * turns a failed assertion into a hung lane. Where a scenario's own break can
 * swallow a URB, poll for it instead and let the absence be the failure.
 */
static struct urb *reap_within(int ms)
{
    for (int waited = 0; waited <= ms; waited += 5) {
        struct urb *d = reap(false);
        if (d)
            return d;
        struct timespec ts = {0, 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* Hand back everything outstanding so one scenario cannot leak into the next.
 */
static void quiesce(void)
{
    for (int i = 0; i < 32; i++) {
        struct urb *d = reap(false);
        if (!d)
            break;
    }
}

static int poll_fd_once(int f, short events, int timeout_ms)
{
    struct pollfd p = {.fd = f, .events = events, .revents = 0};
    int r = poll(&p, 1, timeout_ms);
    return r <= 0 ? 0 : p.revents;
}

static int poll_once(short events, int timeout_ms)
{
    return poll_fd_once(fd, events, timeout_ms);
}

/* Close the fd every scenario runs on and open a fresh one.
 *
 * A disconnect is a fact about the device, not about the fd that noticed it, so
 * a scenario that provokes one on any fd leaves every other fd on the node
 * stamped too -- the main one included. The fixture's device is still there
 * (nothing was terminated), so a new open gets an undisconnected fd back.
 */
static void reopen_main(int *prev)
{
    unsigned ifn = IFNUM;
    close(*prev);
    fd = open(NODE, O_RDWR);
    *prev = fd;
    if (fd >= 0)
        io(USBDEVFS_CLAIMINTERFACE, &ifn);
}

/* scenarios */

static void t_complete_with_data(void)
{
    enter("t_complete_with_data");
    uint8_t out[16], in[64];
    struct urb uo, ui;
    for (int i = 0; i < 16; i++)
        out[i] = (uint8_t) (0x50 + i);
    memset(in, 0, sizeof(in));
    fx_reset();
    fx_script("ep02:ok;ep81:ok");

    mk_bulk(&uo, EP_OUT, out, sizeof(out));
    TEST("OUT submit accepted");
    CHECK(submit(&uo) == 0, "SUBMITURB OUT rc=%d", errno);
    struct urb *d = reap(true);
    TEST("OUT reaps itself");
    CHECK(d == &uo, "reaped %p want %p", (void *) d, (void *) &uo);
    TEST("OUT status 0 actual 16");
    CHECK(uo.status == 0 && uo.actual_length == 16, "status=%d actual=%d",
          uo.status, uo.actual_length);

    mk_bulk(&ui, EP_IN, in, sizeof(in));
    TEST("IN submit accepted");
    CHECK(submit(&ui) == 0, "SUBMITURB IN rc=%d", errno);
    d = reap(true);
    TEST("IN reaps the bytes the OUT wrote");
    CHECK(d == &ui && ui.status == 0 && ui.actual_length == 16 &&
              memcmp(in, out, 16) == 0,
          "status=%d actual=%d first=%02x", ui.status, ui.actual_length, in[0]);
    TEST("IN wrote nothing past actual_length");
    CHECK(in[16] == 0 && in[63] == 0, "in[16]=%02x in[63]=%02x", in[16],
          in[63]);
    quiesce();
}

static void t_short(void)
{
    enter("t_short");
    uint8_t in[64];
    struct urb u;
    fx_reset();
    fx_script("ep81:short(8)*2");
    memset(in, 0xee, sizeof(in));
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    reap(true);
    TEST("short IN is success with the short count");
    CHECK(u.status == 0 && u.actual_length == 8, "status=%d actual=%d",
          u.status, u.actual_length);
    TEST("short IN left the tail of the buffer alone");
    CHECK(in[8] == 0xee && in[63] == 0xee, "in[8]=%02x in[63]=%02x", in[8],
          in[63]);

    memset(in, 0xee, sizeof(in));
    mk_bulk(&u, EP_IN, in, sizeof(in));
    u.flags = URB_SHORT_NOT_OK;
    submit(&u);
    reap(true);
    TEST("SHORT_NOT_OK turns a short IN into -EREMOTEIO");
    CHECK(u.status == -EREMOTEIO && u.actual_length == 8, "status=%d actual=%d",
          u.status, u.actual_length);

    /* A device-supplied count larger than the buffer: every Linux HCD bounds
     * urb->actual_length by transfer_buffer_length, so a guest that copies
     * actual_length bytes out stays inside its own allocation.
     */
    fx_reset();
    fx_script("ep81:ok(999)");
    mk_bulk(&u, EP_IN, in, 32);
    submit(&u);
    reap(true);
    TEST("an over-reported transferred count is clamped to the buffer");
    CHECK(u.status == 0 && u.actual_length == 32, "status=%d actual=%d",
          u.status, u.actual_length);
    quiesce();
}

static void t_error_status(void)
{
    enter("t_error_status");
    uint8_t in[32];
    struct urb u;
    struct {
        const char *script;
        int want;
        const char *name;
    } rows[] = {
        {"ep81:stall", -EPIPE, "kIOUSBPipeStalled reaps -EPIPE"},
        {"ep81:timeout", -ETIMEDOUT,
         "kIOUSBTransactionTimeout reaps -ETIMEDOUT"},
        {"ep81:err", -EPROTO, "an unmapped IOReturn reaps -EPROTO"},
    };
    for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        fx_reset();
        fx_script(rows[i].script);
        mk_bulk(&u, EP_IN, in, sizeof(in));
        submit(&u);
        reap(true);
        TEST(rows[i].name);
        CHECK(u.status == rows[i].want, "status=%d want=%d", u.status,
              rows[i].want);
    }

    /* refuse: IOKit turns the start itself down, and the URB has to come back
     * through the URB-status map rather than the syscall map, whose Aborted row
     * would write -EINTR into urb->status.
     */
    fx_reset();
    fx_script("ep81:refuse(0xe00002cd)");
    mk_bulk(&u, EP_IN, in, sizeof(in));
    long rc = submit(&u);
    TEST("a start IOKit refuses is a SUBMITURB error");
    CHECK(rc == -ENODEV, "submit rc=%ld", rc);
    quiesce();

    /* The refusal above cannot tell the two maps apart: kIOReturnNotOpen is
     * -ENODEV in both. kIOReturnAborted is the row where they differ, and only
     * a queued follower can reach it, because the leader's refusal is a syscall
     * return value and the follower's is a urb->status. The syscall map answers
     * -EINTR there, which is a value the kernel never writes into a URB.
     */
    uint8_t lead[16], follow[16];
    struct urb ul, uf;
    fx_reset();
    fx_script("ep02:delay(60),ok,refuse(0xe00002eb)");
    memset(lead, 0x11, sizeof(lead));
    memset(follow, 0x22, sizeof(follow));
    mk_bulk(&ul, EP_OUT, lead, sizeof(lead));
    mk_bulk(&uf, EP_OUT, follow, sizeof(follow));
    submit(&ul);
    submit(&uf);
    struct urb *r1 = reap_within(2000);
    struct urb *r2 = reap_within(2000);
    TEST("a refused follower comes back through the URB-status map");
    CHECK(r1 == &ul && r2 == &uf && ul.status == 0 && uf.status == -ECONNRESET,
          "lead=%d follow=%d r1=%p r2=%p", ul.status, uf.status, (void *) r1,
          (void *) r2);
    quiesce();
}

static void t_queue_order(void)
{
    enter("t_queue_order");
    uint8_t a[16], b[16];
    struct urb ua, ub;
    fx_reset();
    fx_script("ep02:delay(80),ok,ok");
    memset(a, 0xa1, sizeof(a));
    memset(b, 0xb2, sizeof(b));
    mk_bulk(&ua, EP_OUT, a, sizeof(a));
    mk_bulk(&ub, EP_OUT, b, sizeof(b));
    submit(&ua);
    submit(&ub);
    struct urb *d1 = reap(true);
    struct urb *d2 = reap(true);
    TEST("both queued URBs come back, oldest first");
    CHECK(d1 == &ua && d2 == &ub, "d1=%p d2=%p", (void *) d1, (void *) d2);

    fx_readlog();
    int first = -1, second = -1;
    for (int i = 0; i < nlog; i++) {
        if (rec_kind(i) != 1 || rec_ep(i) != EP_OUT)
            continue;
        if (first < 0)
            first = i;
        else if (second < 0)
            second = i;
    }
    TEST("the wire saw exactly two transfers on the endpoint");
    CHECK(first >= 0 && second >= 0, "first=%d second=%d nlog=%d", first,
          second, nlog);
    TEST("never more than one in flight per endpoint");
    CHECK(first >= 0 && second >= 0 && rec_conc(first) == 1 &&
              rec_conc(second) == 1,
          "conc=%u,%u", first >= 0 ? rec_conc(first) : 0,
          second >= 0 ? rec_conc(second) : 0);
    TEST("the follower started only after the leader completed");
    CHECK(second >= 0 && rec_start(second) >= 70, "follower started at %u ms",
          second >= 0 ? rec_start(second) : 0);
    quiesce();
}

static void t_discard_inflight(void)
{
    enter("t_discard_inflight");
    uint8_t in[32], intr[8];
    struct urb ui, ux;
    fx_reset();
    fx_script("ep81:never;ep83:delay(30),ok");
    mk_bulk(&ui, EP_IN, in, sizeof(in));
    memset(&ux, 0, sizeof(ux));
    ux.type = URB_TYPE_INTERRUPT;
    ux.endpoint = EP_INT;
    ux.buffer = intr;
    ux.buffer_length = sizeof(intr);
    submit(&ui);
    submit(&ux);
    TEST("DISCARDURB on an in-flight URB returns 0");
    CHECK(io(USBDEVFS_DISCARDURB, &ui) == 0, "discard rc=%d", errno);
    struct urb *d = reap(false);
    TEST("the discarded URB is reapable immediately, as -ENOENT");
    CHECK(d == &ui && ui.status == -ENOENT, "d=%p status=%d", (void *) d,
          ui.status);
    d = reap(true);
    TEST("the sibling on another endpoint survives and completes");
    CHECK(d == &ux && ux.status == 0 && ux.actual_length == 8,
          "d=%p status=%d actual=%d", (void *) d, ux.status, ux.actual_length);
    quiesce();
}

static void t_discard_queued(void)
{
    enter("t_discard_queued");
    uint8_t a[16], b[16];
    struct urb ua, ub;
    fx_reset();
    fx_script("ep81:never*2");
    mk_bulk(&ua, EP_IN, a, sizeof(a));
    mk_bulk(&ub, EP_IN, b, sizeof(b));
    submit(&ua);
    submit(&ub);
    TEST("DISCARDURB on the queued follower returns 0");
    CHECK(io(USBDEVFS_DISCARDURB, &ub) == 0, "discard rc=%d", errno);
    struct urb *d = reap(false);
    TEST("the queued follower reaps -ENOENT and the leader stays in flight");
    CHECK(d == &ub && ub.status == -ENOENT && reap(false) == NULL,
          "d=%p status=%d", (void *) d, ub.status);
    io(USBDEVFS_DISCARDURB, &ua);
    d = reap(false);
    TEST("the leader then reaps -ENOENT too");
    CHECK(d == &ua && ua.status == -ENOENT, "d=%p status=%d", (void *) d,
          ua.status);
    quiesce();
}

static void t_poll(void)
{
    enter("t_poll");
    uint8_t in[32];
    struct urb u;
    fx_reset();
    fx_script("ep81:delay(150),ok");
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);

    /* Asking for both bits, because do_pollfd masks the answer by the events
     * the caller demanded: a poll for POLLOUT alone is answered POLLOUT alone,
     * on Linux as here.
     */
    short want = POLLOUT | POLLWRNORM;
    int rev = poll_once(want, 40);
    TEST("poll reports nothing while the URB is in flight");
    CHECK(rev == 0, "revents=0x%x", rev);
    rev = poll_once(want, 2000);
    TEST("poll reports POLLOUT|POLLWRNORM when the completion lands");
    CHECK(rev == (POLLOUT | POLLWRNORM), "revents=0x%x", rev);
    reap(false);
    rev = poll_once(want, 40);
    TEST("poll goes quiet again once the completion is reaped");
    CHECK(rev == 0, "revents=0x%x", rev);

    /* Same question through epoll, which reaches the fd by a different path in
     * poll.c (EVFILT_READ plus a per-registration EPOLLOUT flag).
     */
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLOUT, .data.fd = fd};
    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    fx_reset();
    fx_script("ep81:delay(150),ok");
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    struct epoll_event got;
    int n = epoll_wait(ep, &got, 1, 40);
    TEST("epoll reports nothing while the URB is in flight");
    CHECK(n == 0, "epoll_wait n=%d events=0x%x", n, n > 0 ? got.events : 0u);
    n = epoll_wait(ep, &got, 1, 2000);
    TEST("epoll reports EPOLLOUT when the completion lands");
    CHECK(n == 1 && (got.events & EPOLLOUT), "n=%d events=0x%x", n,
          n > 0 ? got.events : 0u);
    reap(false);

    /* usbdev_poll answers EPOLLOUT|EPOLLWRNORM and eventpoll has no mask of its
     * own: ep_item_poll masks the file's revents by epi->event.events, so a
     * registration naming only EPOLLWRNORM is asking for exactly one of the two
     * bits the file raises and has to be woken by it. poll() and select() next
     * door already answered the pair; epoll tested EPOLLOUT alone, so the same
     * fd with the same completion pending was silent -- measured, poll with
     * POLLWRNORM alone rc=1 revents=0x100 against epoll_wait with EPOLLWRNORM
     * alone rc=0 after its full 500 ms timeout.
     */
    struct pollfd pw = {.fd = fd, .events = POLLWRNORM};
    fx_reset();
    fx_script("ep81:delay(150),ok");
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    int pr = poll(&pw, 1, 2000);
    TEST("poll woken by POLLWRNORM alone reports POLLWRNORM");
    CHECK(pr == 1 && pw.revents == POLLWRNORM, "rc=%d revents=0x%x", pr,
          pr > 0 ? pw.revents : 0);

    ev.events = EPOLLWRNORM;
    epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
    double t0 = now_ms();
    n = epoll_wait(ep, &got, 1, 2000);
    double dt = now_ms() - t0;
    TEST("and epoll registered for EPOLLWRNORM alone is woken by it too");
    CHECK(n == 1 && got.events == (uint32_t) EPOLLWRNORM,
          "n=%d events=0x%x after %.0f ms", n, n > 0 ? got.events : 0u, dt);

    /* Both bits when both were asked for, which is what the mask being the
     * registration's rather than a constant is for.
     */
    ev.events = EPOLLOUT | EPOLLWRNORM;
    epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
    n = epoll_wait(ep, &got, 1, 2000);
    TEST("a registration naming both is given both");
    CHECK(n == 1 && got.events == (uint32_t) (EPOLLOUT | EPOLLWRNORM),
          "n=%d events=0x%x", n, n > 0 ? got.events : 0u);
    close(ep);
    reap(false);
    quiesce();
}

static void t_reap_modes(void)
{
    enter("t_reap_modes");
    uint8_t in[32];
    struct urb u;
    fx_reset();
    struct urb *out = NULL;
    TEST("REAPURBNDELAY with nothing pending is -EAGAIN");
    CHECK(io(USBDEVFS_REAPURBNDELAY, &out) == -EAGAIN, "rc=%d", errno);

    fx_script("ep81:delay(150),ok");
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    double t0 = now_ms();
    struct urb *d = reap(true);
    double dt = now_ms() - t0;
    TEST("a blocking REAPURB waits for the completion and returns it");
    CHECK(d == &u && dt >= 100.0, "d=%p waited %.0f ms", (void *) d, dt);
    quiesce();
}

static void t_zero_packet(void)
{
    enter("t_zero_packet");
    uint8_t out[MPS];
    struct urb u;
    memset(out, 0x5a, sizeof(out));

    fx_reset();
    fx_script("ep02:ok");
    mk_bulk(&u, EP_OUT, out, MPS);
    u.flags = URB_ZERO_PACKET;
    submit(&u);
    reap(true);
    TEST("a maxpacket-multiple ZERO_PACKET OUT still succeeds");
    CHECK(u.status == 0 && u.actual_length == MPS, "status=%d actual=%d",
          u.status, u.actual_length);
    fx_readlog();
    int data = -1, zlp = -1;
    for (int i = 0; i < nlog; i++) {
        if (rec_ep(i) != EP_OUT)
            continue;
        if (rec_kind(i) == 1 && rec_req(i) == MPS && data < 0)
            data = i;
        else if (rec_kind(i) == 3 && data >= 0 && zlp < 0)
            zlp = i;
    }
    TEST("the trailing zero-length packet reached the wire");
    CHECK(zlp > data && data >= 0 && rec_req(zlp) == 0 && rec_actual(zlp) == 0,
          "data=%d zlp=%d nlog=%d", data, zlp, nlog);

    /* Not a maxpacket multiple: no terminating packet, which is the other half
     * of the predicate.
     */
    fx_reset();
    fx_script("ep02:ok");
    mk_bulk(&u, EP_OUT, out, MPS - 1);
    u.flags = URB_ZERO_PACKET;
    submit(&u);
    reap(true);
    fx_readlog();
    int any_zlp = 0;
    for (int i = 0; i < nlog; i++)
        if (rec_kind(i) == 3)
            any_zlp = 1;
    TEST("a short OUT gets no terminating packet");
    CHECK(!any_zlp, "found a zero-length write among %d records", nlog);

    /* A terminating packet the device rejects is the URB's failure, because on
     * Linux that packet is part of the URB.
     */
    fx_reset();
    fx_script("ep02:zlpfail");
    mk_bulk(&u, EP_OUT, out, MPS);
    u.flags = URB_ZERO_PACKET;
    submit(&u);
    reap(true);
    TEST("a failed terminating packet lands in urb->status");
    CHECK(u.status == -EPIPE, "status=%d", u.status);
    quiesce();
}

/* The fixture's own contract, driven through its control plane rather than
 * through the engine: a scenario that cannot trust what the fixture reports
 * about itself cannot assert anything about the engine either.
 */
static void t_fixture_contract(void)
{
    enter("t_fixture_contract");
    uint8_t in[4];
    struct urb u;

    /* A script the control request cannot carry whole. The prefix parses, so
     * installing it silently swapped this scenario's rules for different ones
     * and answered that the whole request was transferred.
     */
    char big[600];
    memset(big, 0, sizeof(big));
    memcpy(big, "ep81:ok", 7);
    for (size_t k = 7; k + 9 < sizeof(big) - 1; k += 9)
        memcpy(big + k, ",delay(0)", 9);
    size_t used = strlen(big);
    memcpy(big + used, ",ok", 3);

    fx_reset();
    fx_script("ep81:stall");
    long r = fx_script(big);
    TEST(
        "a script too long for the fixture's buffer is refused, not truncated");
    CHECK(r == -EINVAL, "rc=%ld len=%zu", r, strlen(big));
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    reap(true);
    TEST("the refused script left the loaded one in place");
    CHECK(u.status == -EPIPE, "status=%d (the prefix would have said 0)",
          u.status);
    quiesce();

    /* An IN script may report more bytes than the URB asked for. The log keeps
     * the first eight bytes of the buffer, and read them to the reported count.
     */
    fx_reset();
    fx_script("ep81:ok(16)");
    memset(in, 0, sizeof(in));
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    reap(true);
    fx_readlog();
    int rec = -1;
    for (int i = 0; i < nlog; i++)
        if (rec_kind(i) == 1 && rec_ep(i) == EP_IN)
            rec = i;
    TEST("the wire log kept the over-reported IN transfer");
    CHECK(rec >= 0 && rec_req(rec) == 4 && rec_actual(rec) == 16,
          "rec=%d requested=%u actual=%u", rec, rec >= 0 ? rec_req(rec) : 0,
          rec >= 0 ? rec_actual(rec) : 0);
    int past = 0;
    for (int b = 4; b < 8; b++)
        if (rec >= 0 && rec_data(rec, b) != 0)
            past++;
    TEST("its payload peek stopped at the four bytes the URB submitted");
    CHECK(past == 0, "%d of 4 bytes past the buffer were recorded", past);
    quiesce();
}

/* A drain that misses its 2 s deadline is one answer, and the two ioctls that
 * retire the handles the survivors hold have to give it the same weight.
 */
static void t_drain_deadline(void)
{
    enter("t_drain_deadline");
    uint8_t in[32];
    struct urb u;
    unsigned ifn = IFNUM;

    /* SETINTERFACE renumbers this interface's pipeRefs. */
    fx_reset();
    fx_script("ep81:wedge");
    mk_bulk(&u, EP_IN, in, sizeof(in));
    submit(&u);
    struct setinterface si = {IFNUM, 0};
    double t0 = now_ms();
    long r = io(USBDEVFS_SETINTERFACE, &si);
    double dt = now_ms() - t0;
    TEST("SETINTERFACE is refused when the URB drain misses its deadline");
    CHECK(r == -EBUSY && dt >= 1900.0, "rc=%ld after %.0f ms", r, dt);
    settle(800); /* the late abort frees the orphaned record */
    quiesce();

    /* SETCONFIGURATION tears the whole pipe table down, so it is the same
     * question. Linux refuses it outright while any interface is claimed, so
     * the transfer that will not drain has to be ep0's -- which is also the
     * queue no interface claim covers, and the reason the kill is issued here
     * at all.
     */
    io(USBDEVFS_RELEASEINTERFACE, &ifn);
    fx_reset();
    fx_script("ep0:wedge");
    uint8_t setup[8] = {0x40, 0x01, 0, 0, 0, 0, 0, 0};
    memset(&u, 0, sizeof(u));
    u.type = URB_TYPE_CONTROL;
    u.endpoint = 0;
    u.buffer = setup;
    u.buffer_length = sizeof(setup);
    long sub = submit(&u);
    TEST("a control URB on ep0 is accepted with no interface claimed");
    CHECK(sub == 0, "SUBMITURB rc=%ld", sub);
    unsigned cfg = 1;
    t0 = now_ms();
    r = io(USBDEVFS_SETCONFIGURATION, &cfg);
    dt = now_ms() - t0;
    TEST("SETCONFIGURATION refuses on that same answer instead of ignoring it");
    CHECK(r == -EBUSY && dt >= 1900.0, "rc=%ld after %.0f ms", r, dt);
    settle(800);
    quiesce();
    io(USBDEVFS_CLAIMINTERFACE, &ifn);
}

/* A queued follower that starts after the device has gone. It reaches the same
 * IOKit answer SUBMITURB does, by a path that only the completion callback can
 * take, and it used to be the one site that did not stamp the fd.
 */
static void t_follower_device_gone(void)
{
    enter("t_follower_device_gone");
    uint8_t a[16], b[16];
    struct urb ua, ub;
    int prev = fd;
    unsigned ifn = IFNUM;

    /* Its own fd, because the stamp is permanent -- but not private to it: the
     * assertions at the end are that the main fd, which has submitted nothing
     * on this scenario's behalf, is told as well.
     */
    int fd2 = open(NODE, O_RDWR);
    if (fd2 < 0) {
        TEST("a second fd on the loopback node");
        FAILF("open rc=%d", errno);
        return;
    }
    fd = fd2;
    io(USBDEVFS_CLAIMINTERFACE, &ifn);
    fx_reset();
    fx_script("ep81:never,refuse(0xe00002c0)");
    mk_bulk(&ua, EP_IN, a, sizeof(a));
    mk_bulk(&ub, EP_IN, b, sizeof(b));
    submit(&ua);
    submit(&ub); /* queued behind the leader: no IOKit call yet */
    io(USBDEVFS_DISCARDURB, &ua);

    struct urb *d = reap_within(2000);
    TEST("the discarded leader reaps -ENOENT");
    CHECK(d == &ua && ua.status == -ENOENT, "d=%p status=%d", (void *) d,
          ua.status);
    d = reap_within(2000);
    TEST("the follower IOKit refuses with NoDevice reaps -ENODEV");
    CHECK(d == &ub && ub.status == -ENODEV, "d=%p status=%d", (void *) d,
          ub.status);

    int rev = poll_once(POLLIN, 200);
    TEST("that refusal marks the fd disconnected for pollers");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);
    uint32_t caps = 0;
    long ic = io(USBDEVFS_GET_CAPABILITIES, &caps);
    TEST("and a later ioctl no longer passes the disconnected gate");
    CHECK(ic == -ENODEV, "GET_CAPABILITIES rc=%ld", ic);

    /* The other fd on the same node. It submitted no URB for this scenario, so
     * nothing it did could have learned the device was gone: the stamp has to
     * reach it because usbdev_remove marks every open file on the device, not
     * because it went looking. Measured before that walk existed: this fd's
     * poll stayed 0x0000 and its GET_CAPABILITIES stayed 0 while fd2 above
     * already had 0x0018 and -ENODEV.
     */
    int prev_rev = poll_fd_once(prev, POLLIN, 500);
    TEST("the disconnect reaches the other fd open on the same device");
    CHECK((prev_rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP),
          "peer revents=0x%x", prev_rev);
    uint32_t pcaps = 0;
    int pic = ioctl(prev, USBDEVFS_GET_CAPABILITIES, &pcaps);
    TEST("and its ioctls answer ENODEV without having touched the device");
    CHECK(pic < 0 && errno == ENODEV, "peer GET_CAPABILITIES rc=%d errno=%d",
          pic, errno);

    close(fd2);
    fd = prev;
    reopen_main(&prev);
    TEST("a fresh fd on the still-present device is not disconnected");
    CHECK(fd >= 0 && io(USBDEVFS_GET_CAPABILITIES, &caps) == 0, "reopen rc=%d",
          errno);
}

/* The readiness pipe carries a level, not one byte per completion.
 *
 * There is no per-fd URB count cap, only the process-wide byte budget, and a
 * zero-length URB costs just its record against that -- so a backlog of
 * completions can be far larger than the 64 KiB the pipe holds. One byte per
 * completion loses the surplus: those records stay reapable with nothing
 * readable behind them, and once the guest has spent the bytes that did land,
 * poll, select and epoll all answer 0 for an fd whose very next reap returns
 * immediately.
 *
 * The backlog has to exist before the first reap -- a guest that reaps as the
 * completions arrive never lets one build -- so it is built without the event
 * thread at all: a leader that never completes, a queue of followers behind it,
 * and one DISCARDURB. The abort completes the leader, and the FIFO restart runs
 * straight down the queue completing every follower IOKit refuses, so all of
 * them are on the completed list by the time the ioctl returns.
 */
static void t_ready_level(void)
{
    enter("t_ready_level");
    alarm(180); /* the flood is the slowest thing in this lane */
    quiesce();
    fx_reset();
    fx_script("ep02:never,refuse(0xe0005000)");

    /* FLOOD is above any capacity a macOS pipe has (64 KiB) and inside the 16
     * MiB budget: the charge is the guest data plus the record, 160 bytes on
     * this target, so the 8-byte leader books 168 and each zero-length follower
     * 160, for 10560168 bytes over 66001 records.
     */
    enum { FLOOD = 66000, TOKENS = 65536 };
    struct urb *fl = calloc(FLOOD, sizeof *fl);
    if (!fl) {
        TEST("room for the flood's URB structs");
        FAILF("calloc of %d urbs failed", FLOOD);
        return;
    }

    uint8_t lead_buf[8] = {0};
    struct urb lead;
    mk_bulk(&lead, EP_OUT, lead_buf, sizeof lead_buf);
    long lr = submit(&lead);
    int n = 0;
    for (; n < FLOOD; n++) {
        fl[n].type = URB_TYPE_BULK;
        fl[n].endpoint = EP_OUT;
        fl[n].buffer = NULL;
        fl[n].buffer_length = 0;
        if (submit(&fl[n]) != 0)
            break;
    }
    TEST("the byte budget takes more zero-length URBs than the pipe has bytes");
    CHECK(lr == 0 && n == FLOOD, "leader rc=%ld, %d of %d queued", lr, n,
          FLOOD);

    /* One ioctl turns the whole queue into completions, with no window in which
     * a reap could keep pace with them.
     */
    long dr = io(USBDEVFS_DISCARDURB, &lead);
    TEST("discarding the leader completes the whole queue behind it");
    CHECK(dr == 0, "DISCARDURB rc=%ld", dr);

    /* Spend every byte the pipe could have held. */
    int reaped = 0;
    while (reaped < TOKENS && reap(false))
        reaped++;
    TEST("the pipe's worth of reaps hand URBs back");
    CHECK(reaped == TOKENS, "reaped %d of %d", reaped, TOKENS);

    double t0 = now_ms();
    int rev = poll_once(POLLOUT | POLLWRNORM, 1000);
    double poll_dt = now_ms() - t0;

    int epfd = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLOUT, .data.fd = fd}, got;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    t0 = now_ms();
    int en = epoll_wait(epfd, &got, 1, 1000);
    double ep_dt = now_ms() - t0;
    close(epfd);

    fd_set ws;
    FD_ZERO(&ws);
    FD_SET(fd, &ws);
    struct timeval tv = {1, 0};
    t0 = now_ms();
    int sn = select(fd + 1, NULL, &ws, NULL, &tv);
    double sel_dt = now_ms() - t0;

    /* Asked last, so all three waits above were answered while this completion
     * was sitting there for them.
     */
    struct urb *d = reap(false);
    TEST("a completion the pipe had no byte for is reapable all along");
    CHECK(d != NULL, "REAPURBNDELAY found nothing");
    TEST("poll reports it once the pipe's bytes are spent");
    CHECK(rev == (POLLOUT | POLLWRNORM), "revents=0x%x after %.0f ms", rev,
          poll_dt);
    TEST("epoll reports it too");
    CHECK(en == 1 && (got.events & EPOLLOUT), "n=%d events=0x%x after %.0f ms",
          en, en > 0 ? got.events : 0u, ep_dt);
    TEST("and select");
    CHECK(sn == 1 && FD_ISSET(fd, &ws), "ret=%d after %.0f ms", sn, sel_dt);

    int rest = d ? 1 : 0;
    while (reap(false))
        rest++;
    int quiet = poll_once(POLLOUT | POLLWRNORM, 0);
    TEST("the whole surplus reaps back and the fd goes quiet again");
    CHECK(rest == n + 1 - reaped && quiet == 0, "%d of %d left, revents=0x%x",
          rest, n + 1 - reaped, quiet);
    free(fl);
}

/* An orphaned record's charge follows its buffer, not the deadline.
 *
 * The drain's timeout arm settles the slot's own counters early so a reused
 * slot never sees a late callback move them. The process-wide budget is not one
 * of those: it accounts live memory, and the record's buffer is still allocated
 * and still owned by an in-flight IOKit transfer when the deadline passes. Hand
 * it back there and the accounting under-counts until the late callback runs,
 * and for good if it never does.
 */
static bool budget_takes_9mb(uint8_t *buf)
{
    struct urb p;
    mk_bulk(&p, EP_IN, buf, 9 * 1024 * 1024);
    if (submit(&p) != 0)
        return false;
    io(USBDEVFS_DISCARDURB, &p);
    (void) reap_within(2000);
    return true;
}

static void t_orphan_refund(void)
{
    enter("t_orphan_refund");
    quiesce();
    fx_reset();

    /* The wedge's abort lands well past the 2 s deadline, so there is a wide
     * window in which the record is orphaned and its buffer still IOKit's.
     */
    fx_script("ep02:wedge(5000);ep81:never");
    uint8_t *nine = malloc(9 * 1024 * 1024);
    uint8_t *eight = calloc(1, 8 * 1024 * 1024);
    if (!nine || !eight) {
        TEST("room for the budget probes");
        FAILF("malloc failed");
        free(nine);
        free(eight);
        return;
    }

    /* 9 MiB fits in the 16 MiB allowance alone and does not fit beside 8 MiB,
     * which is the whole question this scenario asks the budget.
     */
    TEST("9 MiB fits while nothing else is charged");
    CHECK(budget_takes_9mb(nine), "SUBMITURB rc=%d", errno);

    struct urb w;
    mk_bulk(&w, EP_OUT, eight, 8 * 1024 * 1024);
    long sub = submit(&w);
    TEST("an 8 MiB transfer that will not drain is accepted");
    CHECK(sub == 0, "SUBMITURB rc=%ld", sub);
    TEST("and 9 MiB no longer fits beside it");
    CHECK(!budget_takes_9mb(nine), "accepted with 8 MiB charged");

    struct setinterface si = {IFNUM, 0};
    double t0 = now_ms();
    long r = io(USBDEVFS_SETINTERFACE, &si);
    double dt = now_ms() - t0;
    TEST("SETINTERFACE is refused and the 8 MiB record is orphaned");
    CHECK(r == -EBUSY && dt >= 1900.0, "rc=%ld after %.0f ms", r, dt);

    TEST("the orphan keeps its charge: the buffer is still IOKit's");
    CHECK(!budget_takes_9mb(nine), "the budget came back before the memory");

    /* usb_kill_urb hands every URB back, so an orphan is reapable with the
     * status it leaves. It used to be unlinked, marked and dropped: the guest
     * never got the pointer and CAP_REAP_AFTER_DISCONNECT, which
     * GET_CAPABILITIES raises, did not hold on this path.
     */
    struct urb *orph = reap_within(500);
    TEST("the orphaned URB is handed back with usb_kill_urb's status");
    CHECK(orph == &w && w.status == -ENOENT, "d=%p status=%d", (void *) orph,
          orph ? orph->status : 0);

    /* Handed back is not freed. The record carries an IN copy-out the reap
     * reads and a buffer IOKit still owns, so the charge can only come back
     * when the last of the two owners is done with it.
     */
    TEST("and its charge is still held, the buffer being still IOKit's");
    CHECK(!budget_takes_9mb(nine), "the budget came back before the memory");

    settle(3500); /* the late abort lands and frees the buffer */
    TEST("the charge comes back with the buffer, not before it");
    CHECK(budget_takes_9mb(nine), "SUBMITURB rc=%d", errno);

    free(nine);
    free(eight);
    quiesce();
}

/* A drain that misses its deadline still has to restart the FIFOs it shut.
 *
 * draining stops every endpoint, the ones the kill does not match included. A
 * leader on such an endpoint can complete inside the drain window, and its
 * callback starts nothing while the flag is up; the orphaned records' own late
 * callbacks take the orphaned early return, so nothing else comes along to
 * restart it. Without a kick on the timeout path that endpoint is left with a
 * queued URB, none in flight, and a REAPURB that never returns.
 */
static void t_drain_timeout_restarts_fifos(void)
{
    enter("t_drain_timeout_restarts_fifos");
    quiesce();
    fx_reset();

    /* ep0 belongs to no interface, so SETINTERFACE's per-interface kill does
     * not match it and only draining stops it -- which is what leaves its
     * follower with nothing to restart it.
     */
    fx_script("ep0:delay(400),ok;ep02:wedge(4000)");
    uint8_t setup_l[8] = {0x40, 0x01, 0, 0, 0, 0, 0, 0};
    uint8_t setup_f[8] = {0x40, 0x02, 0, 0, 0, 0, 0, 0};
    uint8_t wbuf[8] = {0};
    struct urb ul, uf, uw;
    memset(&ul, 0, sizeof ul);
    ul.type = URB_TYPE_CONTROL;
    ul.endpoint = 0;
    ul.buffer = setup_l;
    ul.buffer_length = sizeof setup_l;
    memset(&uf, 0, sizeof uf);
    uf.type = URB_TYPE_CONTROL;
    uf.endpoint = 0;
    uf.buffer = setup_f;
    uf.buffer_length = sizeof setup_f;
    mk_bulk(&uw, EP_OUT, wbuf, sizeof wbuf);
    submit(&ul);
    submit(&uf); /* queued behind the leader on ep0's FIFO */
    submit(&uw);

    struct setinterface si = {IFNUM, 0};
    double t0 = now_ms();
    long r = io(USBDEVFS_SETINTERFACE, &si);
    double dt = now_ms() - t0;
    TEST("SETINTERFACE is refused when the wedged URB misses the deadline");
    CHECK(r == -EBUSY && dt >= 1900.0, "rc=%ld after %.0f ms", r, dt);

    struct urb *d = reap_within(1500);
    TEST("the ep0 leader that completed inside the drain is handed back");
    CHECK(d == &ul && ul.status == 0, "d=%p status=%d", (void *) d,
          d ? d->status : 0);
    d = reap_within(1500);
    TEST("the wedged record the deadline gave up on is handed back too");
    CHECK(d == &uw && uw.status == -ENOENT, "d=%p status=%d", (void *) d,
          d ? d->status : 0);
    d = reap_within(2500);
    TEST("and the follower it left queued is started, not stranded");
    CHECK(d == &uf && uf.status == 0, "d=%p status=%d", (void *) d,
          d ? d->status : 0);

    settle(2500); /* the wedge's late abort frees the orphan */
    quiesce();
}

/* disc_drained is per slot, and usbdev_init zeroes the table once at startup:
 * nothing else clears it, so a slot whose previous open drained after a
 * disconnect must have the flag reset with the rest of the per-open async
 * state. Two opens in a row land on the same slot -- the allocator takes the
 * lowest free one -- which is what puts the second open behind the first's
 * flag.
 *
 * The disconnect here is a follower IOKit refuses with NoDevice, not a
 * terminate: it stamps this fd and leaves the device every later scenario still
 * needs.
 */
static void t_disc_drained_reset(void)
{
    enter("t_disc_drained_reset");
    int prev = fd;
    unsigned ifn = IFNUM;
    for (int pass = 0; pass < 2; pass++) {
        int f = open(NODE, O_RDWR);
        if (f < 0) {
            TEST("an fd on the loopback node");
            FAILF("open rc=%d", errno);
            fd = prev;
            return;
        }
        fd = f;
        io(USBDEVFS_CLAIMINTERFACE, &ifn);
        fx_reset();
        fx_script("ep81:never,refuse(0xe00002c0);ep83:never");

        uint8_t a[16], b[16], c[16];
        struct urb ua, ub, uc;
        mk_bulk(&ua, EP_IN, a, sizeof a);
        mk_bulk(&ub, EP_IN, b, sizeof b);
        memset(&uc, 0, sizeof uc);
        uc.type = URB_TYPE_INTERRUPT;
        uc.endpoint = EP_INT;
        uc.buffer = c;
        uc.buffer_length = sizeof c;
        submit(&ua);
        submit(&ub); /* queued behind the leader */
        submit(&uc); /* the one only the drain can hand back */

        /* The leader reaps -ENOENT and its callback starts the follower, which
         * IOKit refuses with NoDevice: that is what stamps the fd.
         */
        io(USBDEVFS_DISCARDURB, &ua);

        int back = 0;
        bool got_int = false;
        for (int i = 0; i < 4; i++) {
            struct urb *d = reap_within(2000);
            if (!d)
                break;
            back++;
            if (d == &uc)
                got_int = true;
        }
        if (pass == 0) {
            TEST("a fresh slot drains its disconnect and returns every URB");
            CHECK(back == 3 && got_int, "%d back, ep83's %s", back,
                  got_int ? "among them" : "lost");
        } else {
            TEST("and so does the next open that lands on the same slot");
            CHECK(back == 3 && got_int, "%d back, ep83's %s", back,
                  got_int ? "among them" : "lost");
        }
        close(f);
        settle(50); /* the slot is free again before the next open */
    }
    fd = prev;

    /* Each pass above stamped the whole device, this fd included, so the
     * scenarios after this one need one that is not stamped.
     */
    reopen_main(&prev);
}

/* One vendor IN control transfer of a named length, straight through the
 * synchronous CONTROL path. The fixture answers this one itself, so what the
 * assertions below are about is the ioctl's own bookkeeping, not the wire.
 */
static long ctrl_of(int len)
{
    struct ctrltransfer ct = {.bRequestType = 0xc0,
                              .bRequest = FX_LOG,
                              .wValue = 0,
                              .wIndex = 0,
                              .wLength = (uint16_t) len,
                              .timeout = 1000,
                              .data = logbuf};
    return io(USBDEVFS_CONTROL, &ct);
}

/* A synchronous CONTROL is charged against the in-flight allowance.
 *
 * do_proc_control books PAGE_SIZE + sizeof(struct urb) + sizeof(struct
 * usb_ctrlrequest) before it touches its buffer and gives the same amount back
 * afterwards (devio.c:1187 and :1269): a fixed charge, not the request's
 * length. This path took none at all, so it was the one synchronous transfer
 * outside a budget the async engine and the synchronous BULK both respect --
 * measured with 16771328 bytes in flight, a sync BULK answered ENOMEM and a
 * sync CONTROL of wLength 4096 went through and reported 4096.
 *
 * The allowance is filled with URBs rather than with a transfer of its own,
 * because a synchronous transfer's charge is gone again by the time its ioctl
 * returns. Only the leader of an endpoint's FIFO reaches IOKit; the rest queue
 * inside elfuse, and every one of them is charged at submit, so one never-
 * completing leader is enough to park the whole budget.
 */
#define CHARGE_POOL 64

static void t_control_charge(void)
{
    enter("t_control_charge");
    fx_reset();
    fx_script("ep81:never");

    uint8_t *big = malloc(4u << 20);
    static struct urb pool[CHARGE_POOL];
    if (!big) {
        TEST("a buffer to fill the allowance with");
        FAILF("malloc");
        return;
    }
    memset(big, 0, 4u << 20);

    /* Descending steps, so the last accepted URB leaves less headroom than any
     * charge a CONTROL can take. The guest cannot name the record overhead the
     * engine adds, and does not have to: what it needs is a full allowance.
     */
    static const unsigned step[] = {4u << 20, 1u << 20, 64u << 10,
                                    4096,     256,      8};
    int n = 0;
    for (unsigned si = 0; si < sizeof(step) / sizeof(step[0]); si++) {
        while (n < CHARGE_POOL) {
            mk_bulk(&pool[n], EP_IN, big, (int) step[si]);
            if (submit(&pool[n]) != 0)
                break;
            n++;
        }
    }
    TEST("the allowance filled with URBs that will not complete");
    CHECK(n > 0 && n < CHARGE_POOL, "%d URBs accepted", n);

    mk_bulk(&pool[n], EP_IN, big, 4096);
    TEST("a further 4 KiB URB no longer fits");
    CHECK(submit(&pool[n]) == -ENOMEM, "submit rc=%d", errno);

    long cr = ctrl_of(4096);
    TEST("and neither does a synchronous CONTROL of the same length");
    CHECK(cr == -ENOMEM, "CONTROL rc=%ld", cr);

    for (int i = 0; i < n; i++)
        io(USBDEVFS_DISCARDURB, &pool[i]);
    int back = 0;
    for (int i = 0; i < n; i++)
        if (reap_within(2000))
            back++;
    TEST("every filler URB comes back");
    CHECK(back == n, "%d of %d", back, n);

    cr = ctrl_of(4096);
    TEST("and the CONTROL goes through once the allowance is given back");
    CHECK(cr >= 0, "CONTROL rc=%ld", cr);
    printf("  allowance held by %d URBs; CONTROL refused, then %ld\n", n, cr);
    free(big);
    quiesce();
}

/* A non-blocking reap never waits -- not even on the pass that owes the
 * post-disconnect kill.
 *
 * Linux's proc_reapurbnonblock pops async_getcompleted and answers EAGAIN or
 * ENODEV: it neither kills nor waits, because usbdev_remove ran
 * destroy_all_async before any reap could see the disconnect. This engine owes
 * that kill at the first reap that finds the completion list empty, and running
 * the whole of it inline made REAPURBNDELAY sit out the drain's 2 s deadline
 * holding async_lock against every SUBMITURB and DISCARDURB on the fd. Measured
 * before the split: rc=-1 errno=19 after 2006 ms, and 0 ms on the pass after
 * it.
 *
 * ep81 carries the URB the kill cannot recover promptly -- wedge answers its
 * abort 2500 ms later, past the deadline -- and ep83 is only how the fd gets
 * stamped without terminating the fixture's device, so this scenario can run
 * before the one that does.
 */
static void t_reap_ndelay_never_waits(void)
{
    enter("t_reap_ndelay_never_waits");
    int prev = fd;
    uint8_t a[16], b[16], c[16];
    struct urb ua, ub, uc;
    fx_reset();

    /* The wedge lands inside the drain deadline on purpose. Past it the
     * deadline is what answers -- a non-blocking reap orphans the survivor and
     * reports the device gone, which is the other half of this invariant and
     * t_ndelay_reaches_enodev's subject. Here the question is only whether the
     * pass that owes the kill waits, so the URB has to be one that genuinely
     * comes back.
     */
    fx_script("ep81:wedge(1200);ep83:never,refuse(0xe00002c0)");

    mk_bulk(&ua, EP_IN, a, sizeof(a));
    submit(&ua);

    memset(&ub, 0, sizeof(ub));
    ub.type = URB_TYPE_INTERRUPT;
    ub.endpoint = EP_INT;
    ub.buffer = b;
    ub.buffer_length = sizeof(b);
    uc = ub;
    uc.buffer = c;
    submit(&ub);
    submit(&uc); /* queued behind the leader */

    /* The leader's abort completes it and starts the follower, which IOKit
     * refuses with NoDevice: that refusal is the disconnect stamp.
     */
    io(USBDEVFS_DISCARDURB, &ub);

    int back = 0;
    for (int i = 0; i < 2; i++)
        if (reap_within(2000))
            back++;
    TEST("the stamped fd hands back the two ep83 URBs first");
    CHECK(back == 2, "%d of 2 back", back);

    /* Now the completion list is empty, the fd is disconnected and ep81's URB
     * is still outstanding: this is the pass that owes the kill.
     */
    double t0 = now_ms();
    struct urb *out = NULL;
    long r = io(USBDEVFS_REAPURBNDELAY, &out);
    double dt = now_ms() - t0;

    /* EAGAIN, not ENODEV: the aborts have gone out but ep81's URB has not come
     * back, and ENODEV is the end of the conversation. proc_reapurbnonblock's
     * own two answers are EAGAIN and ENODEV, and the one it would give if it
     * could reach this state -- disconnected, URBs still out -- is EAGAIN,
     * because on Linux destroy_all_async has already emptied the pending list
     * before any reap sees the disconnect.
     */
    TEST("the reap that owes the kill answers EAGAIN, not ENODEV");
    CHECK(r == -EAGAIN, "rc=%ld", r);
    TEST("and answers it without waiting out the 2 s drain deadline");
    CHECK(dt < 500.0, "elapsed %.0f ms", dt);
    printf("  REAPURBNDELAY on the pass that owed the kill: %.0f ms\n", dt);

    /* The aborts were issued, only not waited for, so the wedged URB comes back
     * on its own timetable -- and it comes back before any ENODEV does.
     */
    settle(1400);
    struct urb *late = NULL;
    long lr = io(USBDEVFS_REAPURBNDELAY, &late);
    TEST("the URB the aborts recovered is handed back once it lands");
    CHECK(lr == 0 && late == &ua, "rc=%ld urb=%p", lr, (void *) late);
    TEST("and only then is the fd out of URBs to answer for");
    CHECK(io(USBDEVFS_REAPURBNDELAY, &out) == -ENODEV, "rc=%d", errno);
    quiesce();
    reopen_main(&prev);
}

/* CAP_REAP_AFTER_DISCONNECT as one invariant, against all three reap orderings:
 * after a disconnect every in-flight URB is handed back BEFORE any reap answers
 * ENODEV, whichever flavor asked first.
 *
 * The regression this pins was a single flag doing two jobs. disc_drained is a
 * one-shot for issuing the post-disconnect aborts; it was also read as
 * permission to report the device drained, so a REAPURBNDELAY -- which issues
 * the aborts and by contract cannot wait for them -- latched it and every later
 * reap, blocking included, answered ENODEV with the URBs still in flight. An
 * ordinary libusb event loop polls non-blocking before it blocks, so pass 2
 * below is the common path and not a corner: measured before the fix as
 * REAPURBNDELAY rc=-19 urb=(nil) and then REAPURB rc=-19 in 0 ms, with the URB
 * arriving 400 ms after both.
 *
 * ep81 carries the two URBs whose refusal stamps the fd without terminating the
 * fixture's device, so this can run before the scenario that does. ep83 carries
 * the one only the drain can recover: wedge(300) answers its abort late enough
 * that the window is real, and early enough to stay inside the 2 s deadline, so
 * the URB genuinely comes back rather than being orphaned.
 */
static void t_enodev_never_precedes_the_urbs(void)
{
    enter("t_enodev_never_precedes_the_urbs");
    int prev = fd;
    static const char *const what[3] = {
        "every reap non-blocking",
        "every reap blocking",
        "a non-blocking poll first, then a blocking reap",
    };
    for (int pass = 0; pass < 3; pass++) {
        /* Pass 2 lets its one non-blocking probe answer what it likes -- pass 0
         * is what holds that answer to EAGAIN -- and asks the narrower question
         * the regression was measured on: whether the BLOCKING reap behind the
         * probe still waits for the URB, or takes the probe's latch as
         * permission to answer ENODEV in no time at all.
         */
        bool tolerate_probe = pass == 2;
        uint8_t a[16], b[16], c[16];
        struct urb ua, ub, uc;
        fx_reset();
        fx_script("ep81:never,refuse(0xe00002c0);ep83:wedge(300)");

        mk_bulk(&ua, EP_IN, a, sizeof(a));
        mk_bulk(&ub, EP_IN, b, sizeof(b));
        submit(&ua);
        submit(&ub); /* queued behind the leader */
        memset(&uc, 0, sizeof(uc));
        uc.type = URB_TYPE_INTERRUPT;
        uc.endpoint = EP_INT;
        uc.buffer = c;
        uc.buffer_length = sizeof(c);
        submit(&uc); /* the one only the drain can hand back */

        /* The leader's abort completes it and starts the follower, which IOKit
         * refuses with NoDevice: that refusal is the disconnect stamp.
         */
        io(USBDEVFS_DISCARDURB, &ua);

        /* probes counts the non-blocking reaps taken once the two completions
         * have run out. Pass 2 takes exactly one -- the pass that owes the
         * kill, which issues the aborts and latches disc_drained -- and blocks
         * from then on, which is the ordering a libusb event loop produces and
         * the one the regression turned into an instant ENODEV.
         */
        int back = 0, probes = 0;
        long early = 0;
        double blocked_ms = -1.0;
        for (int i = 0; i < 400 && back < 3 && !early; i++) {
            struct urb *out = NULL;
            bool blocking = pass == 1 || (pass == 2 && probes >= 1);
            double t0 = now_ms();
            long r =
                io(blocking ? USBDEVFS_REAPURB : USBDEVFS_REAPURBNDELAY, &out);
            if (r == 0) {
                back++;
                continue;
            }
            if (r == -ENODEV && !(tolerate_probe && !blocking)) {
                early = 1; /* the regression: ENODEV before the URBs */
                if (blocking)
                    blocked_ms = now_ms() - t0;
                continue;
            }
            if (back >= 2)
                probes++;
            settle(5);
        }
        TEST(what[pass]);
        if (early && blocked_ms >= 0)
            FAILF("the blocking reap answered ENODEV in %.0f ms, %d of 3 back",
                  blocked_ms, back);
        else
            CHECK(!early && back == 3, "%s after %d of 3 URBs",
                  early ? "ENODEV" : "gave up", back);

        /* Having answered for all three, the fd may end the conversation. */
        struct urb *out = NULL;
        TEST("and ENODEV once every URB has been answered for");
        CHECK(io(USBDEVFS_REAPURB, &out) == -ENODEV, "rc=%d", errno);
        reopen_main(&prev);
    }
    fd = prev;
}

/* The other half of CAP_REAP_AFTER_DISCONNECT: after a disconnect every reap
 * flavor reaches the end of the conversation, and reaches it inside one drain
 * deadline of the aborts.
 *
 * The regression this pins is the fix above growing a hole underneath it.
 * Splitting -ENODEV off the disc_drained latch made "nothing left out" the
 * whole of the -ENODEV condition, and the only thing that emptied the pending
 * list on a wire that answers no abort was the BLOCKING arm's 2 s wait and its
 * orphaning. A REAPURBNDELAY loop -- which is what an ordinary libusb event
 * loop runs -- had no such ceiling: it issued the aborts on its first pass and
 * could only answer -EAGAIN from then on, for ever, while poll held
 * POLLERR|POLLHUP. Measured before the fix with ep81:wedge(600000): 4000 ms of
 * REAPURBNDELAY gave 1958386 -EAGAIN and no -ENODEV, with revents 0x18, where
 * Linux's proc_reapurbnonblock answers connected(ps) ? -EAGAIN : -ENODEV and
 * the guest tears down.
 *
 * ep81:wedge(4000) is a wire that answers its abort well past the deadline, so
 * what decides here is the deadline and not the wire; the ep83 refusal is the
 * disconnect stamp, and it leaves no record behind.
 */
static void t_ndelay_reaches_enodev(void)
{
    enter("t_ndelay_reaches_enodev");
    int prev = fd;
    uint8_t a[16], c[16];
    struct urb ua, uc;
    fx_reset();
    fx_script("ep81:wedge(4000);ep83:refuse(0xe00002c0)");

    mk_bulk(&ua, EP_IN, a, sizeof(a));
    submit(&ua);
    memset(&uc, 0, sizeof(uc));
    uc.type = URB_TYPE_INTERRUPT;
    uc.endpoint = EP_INT;
    uc.buffer = c;
    uc.buffer_length = sizeof(c);
    TEST("the refused submit stamps the fd");
    CHECK(submit(&uc) == -ENODEV, "SUBMITURB rc=%d", errno);

    /* Before the deadline the URB may still come back, so -EAGAIN is the only
     * honest answer and orphaning early would throw it away.
     */
    double t0 = now_ms();
    struct urb *out = NULL;
    long r = io(USBDEVFS_REAPURBNDELAY, &out);
    double owed_ms = now_ms() - t0;
    TEST("the pass that owes the kill answers EAGAIN");
    CHECK(r == -EAGAIN, "rc=%ld", r);
    TEST("and issues the aborts without waiting for them");
    CHECK(owed_ms < 100.0, "elapsed %.0f ms", owed_ms);
    settle(500);
    r = io(USBDEVFS_REAPURBNDELAY, &out);
    TEST("and still EAGAIN half a second in, with the deadline unspent");
    CHECK(r == -EAGAIN, "rc=%ld", r);

    /* Spin the way libusb_handle_events_timeout(0) does. Bounded well past the
     * deadline and well inside the wedge's own abort, so an -ENODEV here is the
     * deadline's answer and a timeout here is the unbounded spin.
     */
    long eagain = 0;
    int handed_back = 0;
    double elapsed = -1.0, call_ms = -1.0;
    while (now_ms() - t0 < 3500.0) {
        double c0 = now_ms();
        out = NULL;
        r = io(USBDEVFS_REAPURBNDELAY, &out);
        if (r == -ENODEV) {
            call_ms = now_ms() - c0;
            elapsed = now_ms() - t0;
            break;
        }
        if (r == 0 && out == &ua)
            handed_back++;
        if (r == -EAGAIN)
            eagain++;
    }

    /* The whole of CAP_REAP_AFTER_DISCONNECT, on the one path where it did not
     * hold: the deadline's give-up used to unlink the record, mark it and drop
     * it, so the pass that gave up answered -ENODEV with the URB pointer never
     * returned -- measured as -ENODEV after 2037 ms with 0 URBs handed back,
     * against a control script that does hand one back. Linux's
     * destroy_all_async completes every pending URB into async_completed first,
     * and usb_kill_urb leaves -ENOENT in each.
     */
    TEST("the wedged URB is handed back before the conversation ends");
    CHECK(handed_back == 1 && ua.status == -ENOENT, "%d back, status=%d",
          handed_back, ua.status);
    TEST("a REAPURBNDELAY loop reaches ENODEV rather than spinning for ever");
    CHECK(elapsed >= 0, "%ld EAGAIN and no ENODEV in %.0f ms", eagain,
          now_ms() - t0);
    if (elapsed >= 0) {
        /* The deadline is armed by the pass that issues the aborts, a hair
         * after t0, so this brackets 2000 ms from below rather than demanding
         * it: the point is that neither the wire's 4000 ms abort nor an
         * immediate give-up is what answered.
         */
        TEST("it is the drain deadline that decides, not the wire");
        CHECK(elapsed >= 1900.0 && elapsed < 2500.0, "ENODEV at %.0f ms",
              elapsed);

        /* An entry whose contract says it does not block has to measure the
         * deadline rather than wait it out: the deadline is spent by the
         * caller's own spinning, never inside one call.
         */
        TEST("and no single REAPURBNDELAY blocked to get there");
        CHECK(call_ms < 100.0, "the ENODEV call took %.0f ms", call_ms);
        printf(
            "  REAPURBNDELAY reached ENODEV at %.0f ms, longest call %.0f ms\n",
            elapsed, call_ms);
    }

    /* The blocking flavor behind it agrees and does not wait either: there is
     * nothing left out for it to wait for.
     */
    double b0 = now_ms();
    long br = io(USBDEVFS_REAPURB, &out);
    double bms = now_ms() - b0;
    TEST("a blocking REAPURB behind it answers ENODEV without waiting");
    CHECK(br == -ENODEV && bms < 100.0, "rc=%ld in %.0f ms", br, bms);

    TEST("nothing is left to reap, and ERR|HUP stays raised");
    CHECK(poll_once(POLLOUT | POLLWRNORM, 50) == (POLLERR | POLLHUP),
          "revents=0x%x", poll_once(POLLOUT | POLLWRNORM, 0));

    settle(2600); /* the wedge's late abort frees the orphaned record */
    quiesce();
    reopen_main(&prev);
}

/* DISCARDURB's own abort is an op on the device, and what it answers is news.
 *
 * Both aborts here used to be cast to void. An AbortPipe that comes back
 * kIOReturnNoDevice canceled nothing, so the record stayed URB_INFLIGHT in the
 * pending list and the wait below it sat out its whole two seconds before
 * returning 0; the fd was never stamped, although usbdev_arm_disconnect_watch
 * names kIOReturnNoDevice detection on ops as its fallback and this is such an
 * op; and the URB was never handed back, although proc_unlinkurb is
 * usb_kill_urb, which always leaves the URB reapable. Measured: rc=0 after 2006
 * ms, fd unstamped, the following REAPURB still unanswered when the probe was
 * killed at 20 s.
 *
 * Nothing in the fixture's vocabulary could produce that answer -- AbortPipe
 * landed unconditionally -- so the fixture learned one fact of its own for it,
 * beside the pipes_gone it already had. Tying aborts to the terminate instead
 * would have left every 'never' transfer outstanding for ever, which is the
 * reason the seam invariant lists AbortPipe as deliberately outside it.
 */
static void t_discard_when_the_abort_is_refused(void)
{
    enter("t_discard_when_the_abort_is_refused");
    int prev = fd;
    quiesce();
    fx_reset();
    fx_script("ep02:never");
    uint8_t out[8] = {0};
    struct urb u;
    mk_bulk(&u, EP_OUT, out, sizeof(out));
    long sub = submit(&u);
    TEST("a transfer the wire will not answer on its own is accepted");
    CHECK(sub == 0, "SUBMITURB rc=%ld", sub);

    TEST("the fixture can refuse an abort the way a departed user client does");
    CHECK(fx_aborts_gone() == 0, "rc=%d", errno);

    double t0 = now_ms();
    long r = io(USBDEVFS_DISCARDURB, &u);
    double dt = now_ms() - t0;
    TEST("DISCARDURB answers at once rather than waiting out its own deadline");
    CHECK(r == 0 && dt < 500.0, "rc=%ld after %.0f ms", r, dt);

    int rev = poll_once(POLLIN, 0);
    TEST("the refusal stamps the fd, as every other device-gone answer does");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);

    struct urb *d = reap_within(500);
    TEST("and the URB comes back: proc_unlinkurb is usb_kill_urb");
    CHECK(d == &u && u.status == -ENOENT, "d=%p status=%d", (void *) d,
          d ? d->status : 0);

    reopen_main(&prev);
    fx_reset(); /* the abort refusal is a fixture fact, not this fd's */
}

/* An orphaned ep0 record pins the device handle, which nothing used to.
 *
 * usbdev_orphan_stalled_locked pins the handle an orphan still references so
 * teardown will not release it, and the pin was guarded on the record naming an
 * interface -- so a record on the default control pipe, which names none,
 * pinned nothing. The whole-slot drain unlinks it from pending, so the rescan
 * inside usbdev_kill_urbs_locked comes back clean, teardown reads drained and
 * releases u->dev with a DeviceRequestAsyncTO still outstanding at IOKit.
 * Measured as close() printing no leaking-handle line where the same scenario
 * on an interface endpoint prints one.
 *
 * The use-after-free that costs on real IOKit is out of reach here -- the
 * fixture frees a COM wrapper nothing dereferences again -- so what the fixture
 * counts instead is the release itself, against a transfer it still owns. That
 * counter is read back on a later fd, because the release happens at close.
 *
 * SETCONFIGURATION is the way in: it kills every URB on the device, ep0
 * included, and Linux refuses it while any interface is claimed, so the claim
 * goes first and the queue left is exactly the one no claim covers.
 */
static void t_ep0_orphan_pins_the_device(void)
{
    enter("t_ep0_orphan_pins_the_device");
    unsigned ifn = IFNUM;
    quiesce();
    fx_reset();
    io(USBDEVFS_RELEASEINTERFACE, &ifn);
    fx_script("ep0:wedge(3000)");

    uint8_t setup[8] = {0x40, 0x01, 0, 0, 0, 0, 0, 0};
    struct urb u;
    memset(&u, 0, sizeof(u));
    u.type = URB_TYPE_CONTROL;
    u.endpoint = 0;
    u.buffer = setup;
    u.buffer_length = sizeof(setup);
    long sub = submit(&u);
    TEST("a control URB on ep0 is accepted with no interface claimed");
    CHECK(sub == 0, "SUBMITURB rc=%ld", sub);

    unsigned cfg = 1;
    long r = io(USBDEVFS_SETCONFIGURATION, &cfg);
    TEST("SETCONFIGURATION is refused and the ep0 record is orphaned");
    CHECK(r == -EBUSY, "rc=%ld", r);
    struct urb *d = reap_within(500);
    TEST("the orphaned ep0 URB is handed back like any other");
    CHECK(d == &u && u.status == -ENOENT, "d=%p status=%d", (void *) d,
          d ? d->status : 0);

    close(fd);
    fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("a fresh fd after the teardown that would have leaked");
        FAILF("open rc=%d", errno);
        return;
    }
    uint32_t leaked = fx_dev_releases_in_flight();
    TEST("teardown did not release the device handle under the ep0 transfer");
    CHECK(leaked == 0, "%u release(s) with a transfer still outstanding",
          leaked);

    settle(1500); /* the wedge's late abort lands and frees the orphan */
    fx_reset();
    io(USBDEVFS_CLAIMINTERFACE, &ifn);
}

/* A pipe map that cannot be read is a device-gone answer, not an interface with
 * fewer endpoints than it has.
 *
 * GetNumEndpoints sizes the map and GetPipeProperties fills it in, and the
 * device can go between the two. The failing call used to be a continue, so
 * CLAIMINTERFACE answered 0 with npipes short of the interface's real count and
 * left the fd unstamped: the guest got a claimed interface whose SUBMITURB then
 * answered -ENOENT, no such endpoint, where Linux answers -ENODEV. Only
 * GetPipeProperties goes gone here, which is exactly that window.
 */
static void t_pipe_map_device_gone(void)
{
    enter("t_pipe_map_device_gone");
    int prev = fd;
    unsigned ifn = IFNUM;
    fx_reset();
    io(USBDEVFS_RELEASEINTERFACE, &ifn);
    TEST("the pipes-gone command is accepted");
    CHECK(fx_pipes_gone() == 0, "rc=%d", errno);

    long r = io(USBDEVFS_CLAIMINTERFACE, &ifn);
    TEST("a claim whose pipe map cannot be read answers ENODEV");
    CHECK(r == -ENODEV, "claim rc=%ld", r);

    /* And the answer was originated, not just returned: the connected() gate in
     * usbdev_ioctl is what answers from here on.
     */
    uint8_t a[16];
    struct urb ua;
    mk_bulk(&ua, EP_IN, a, sizeof(a));
    TEST("and it stamped the fd, so the next ioctl agrees");
    CHECK(submit(&ua) == -ENODEV, "SUBMITURB rc=%d", errno);

    /* Put the pipes back for the scenarios after this one. The reset is a
     * control request, and this fd is stamped now, so its own connected() gate
     * would answer it -ENODEV: it has to go over an fd that is not.
     */
    int tmp = open(NODE, O_RDWR);
    if (tmp >= 0) {
        int save = fd;
        fd = tmp;
        TEST("the pipes come back over an fd the disconnect did not stamp");
        CHECK(fx_reset() == 0, "reset rc=%d", errno);
        fd = save;
        close(tmp);
    }
    reopen_main(&prev);
}

/* Last: the device never comes back. */
static void t_disconnect(void)
{
    enter("t_disconnect");
    uint8_t a[32], b[32], z[32];
    struct urb ua, ub, uz;
    fx_reset();
    fx_script("ep02:ok;ep81:never;ep83:never");

    /* One completion the guest has not collected yet, and two URBs still on the
     * wire. The unreaped one is the whole point: the drain is decided once per
     * fd, and a pass that has a completion to hand back returns before it can
     * issue the kill, so deciding it on such a pass claims the drain and never
     * performs it -- these two would then never come back.
     */
    mk_bulk(&uz, EP_OUT, z, sizeof(z));
    submit(&uz);
    for (int i = 0; i < 200 && poll_once(POLLOUT | POLLWRNORM, 10) == 0; i++)
        ;

    mk_bulk(&ua, EP_IN, a, sizeof(a));
    memset(&ub, 0, sizeof(ub));
    ub.type = URB_TYPE_INTERRUPT;
    ub.endpoint = EP_INT;
    ub.buffer = b;
    ub.buffer_length = sizeof(b);
    submit(&ua);
    submit(&ub);
    TEST("the terminate command is accepted");
    CHECK(fx_terminate(0) == 0, "terminate rc=%d", errno);

    /* Unmaskable: the guest asked for POLLIN, which this fd never raises. */
    int rev = 0;
    for (int i = 0; i < 100 && !rev; i++)
        rev = poll_once(POLLIN, 50);
    TEST("a disconnect reports POLLERR|POLLHUP through a POLLIN-only wait");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);

    int back = 0, enoent = 0;
    struct urb *first = NULL;
    for (int i = 0; i < 5; i++) {
        struct urb *d = reap_within(2000);
        if (!d)
            break;
        if (!back)
            first = d;
        back++;
        if (d->status == -ENOENT)
            enoent++;
    }
    TEST("the completion left unreaped at the disconnect comes back first");
    CHECK(first == &uz && uz.status == 0, "first=%p status=%d", (void *) first,
          first ? first->status : 0);
    TEST("CAP_REAP_AFTER_DISCONNECT hands back every in-flight URB");
    CHECK(back == 3, "reaped %d of 3", back);
    TEST("each in-flight one carries the errno usb_kill_urb leaves");
    CHECK(enoent == 2, "%d of %d were -ENOENT", enoent, back);
    struct urb *out = NULL;
    TEST("REAPURB is -ENODEV once the drain is done");
    CHECK(io(USBDEVFS_REAPURB, &out) == -ENODEV, "rc=%d", errno);

    /* The disconnect wake byte keeps the completion pipe readable for good, so
     * the reapable half of the answer has to come from the completed list and
     * not from the pipe: with nothing left to hand back, POLLOUT|POLLWRNORM
     * must be gone while the unmaskable pair stays.
     */
    int quiet = poll_once(POLLOUT | POLLWRNORM, 50);
    TEST("a disconnect with nothing left to reap reports ERR|HUP alone");
    CHECK(quiet == (POLLERR | POLLHUP), "revents=0x%x", quiet);

    /* select() counts a descriptor once per set it is reported in, not once per
     * descriptor: fs/select.c has EPOLLERR in both POLLIN_SET and POLLOUT_SET
     * and does retval++ for each. A disconnected usbfs fd asked about in both
     * sets is therefore 2, where the host saw only the completion pipe in its
     * own READ set and answered 1.
     */
    fd_set rs, ws;
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_SET(fd, &rs);
    FD_SET(fd, &ws);
    struct timeval tv = {0, 0};
    int sr = select(fd + 1, &rs, &ws, NULL, &tv);
    int rbit = FD_ISSET(fd, &rs) ? 1 : 0, wbit = FD_ISSET(fd, &ws) ? 1 : 0;
    TEST("select counts a disconnected fd once per set it was asked about");
    CHECK(sr == 2 && rbit && wbit, "ret=%d read=%d write=%d", sr, rbit, wbit);
}

/* A synchronous op has to ORIGINATE the disconnect, not merely report it.
 *
 * The peer walk publishes a disconnect to every other fd on the node, but
 * something has to raise one first, and every site that did was the async
 * engine's: usbdev_arm_disconnect_watch is reached only from
 * usbdev_ensure_dev_async and usbdev_ensure_iface_async, both on the SUBMITURB
 * path, and the kIOReturnNoDevice stamps were all in the completion callback
 * and the URB start. An fd whose only contact with a departed device is a
 * synchronous transfer therefore answered ENODEV from that one ioctl and went
 * on reporting itself healthy to everything else: measured as poll revents
 * 0x0000 and GET_CAPABILITIES 0 on a device whose own CONTROL, on that same fd,
 * had just answered -19. Routing every op's IOKit status through
 * usbdev_ioret_op is what makes the header's "any op" true.
 *
 * Runs after t_disconnect, so the fixture's device is already terminated and a
 * fresh fd on the node meets one that is gone. Neither fd here submits a URB,
 * so no terminate watch is armed on either and the walk has no other way to
 * reach them: the synchronous CONTROL is the only possible source of the news.
 */
static void t_sync_op_originates_disconnect(void)
{
    enter("t_sync_op_originates_disconnect");
    int prev = fd;
    int fa = open(NODE, O_RDWR);
    int fb = open(NODE, O_RDWR);
    if (fa < 0 || fb < 0) {
        TEST("two fresh fds on the terminated loopback node");
        FAILF("open rc=%d", errno);
        if (fa >= 0)
            close(fa);
        if (fb >= 0)
            close(fb);
        return;
    }
    int rev = poll_fd_once(fb, POLLIN | POLLOUT | POLLWRNORM, 0);
    TEST("a fresh fd on a departed device starts out undisconnected");
    CHECK(rev == 0, "revents=0x%x", rev);

    /* Not one of the fixture's command requests (0xf0-0xf3): those are answered
     * ahead of its terminated check, so they would never reach it.
     */
    uint8_t buf[8];
    struct ctrltransfer ct = {.bRequestType = 0xc0,
                              .bRequest = 0x10,
                              .wValue = 0,
                              .wIndex = 0,
                              .wLength = sizeof(buf),
                              .timeout = 1000,
                              .data = buf};
    fd = fb;
    long cr = io(USBDEVFS_CONTROL, &ct);
    TEST("its synchronous CONTROL answers ENODEV");
    CHECK(cr == -ENODEV, "rc=%ld", cr);

    rev = poll_fd_once(fb, POLLIN, 0);
    TEST("and that answer stamps the fd that asked");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);

    uint32_t caps = 0;
    TEST("so the fd's other ioctls answer ENODEV rather than succeeding");
    CHECK(io(USBDEVFS_GET_CAPABILITIES, &caps) == -ENODEV, "rc=%d", errno);

    rev = poll_fd_once(fa, POLLIN, 0);
    TEST("and the peer that never touched the device is stamped with it");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);

    close(fa);
    close(fb);
    fd = prev;
}

/* The ops that ask the device about its interfaces answer for the device, not
 * for the interface.
 *
 * All four reach it through one CreateInterfaceIterator, whose IOReturn used to
 * be discarded into IO_OBJECT_NULL -- indistinguishable from "the enumeration
 * ran and this interface is not in it". So on a departed device GETDRIVER
 * answered -ENODATA and the three claim/connect ops answered -EINVAL, each
 * naming a missing interface on a device that was missing entirely, and none of
 * them stamped the fd, so the ioctl after them answered wrongly too. Linux's
 * usbdev_do_ioctl runs its connected() gate before any of these and answers
 * -ENODEV.
 *
 * A fresh fd on the terminated device is what makes this reachable: nothing has
 * stamped it yet, so usbdev_ioctl's own gate lets the call through to the wire
 * -- the same window t_sync_op_originates_disconnect uses for CONTROL. One fd
 * per op, because the first answer stamps the whole device.
 */
static void t_iface_query_on_a_departed_device(void)
{
    enter("t_iface_query_on_a_departed_device");
    int prev = fd;

    /* Not IFNUM: the main fd holds that one, and usbfs is one driver
     * device-wide, so all four ops answer from the claim without asking the
     * device anything. An unclaimed interface number is what reaches the
     * enumeration.
     */
    const unsigned free_ifnum = 0;
    struct getdriver gd = {.interface = free_ifnum};
    struct disconnect_claim dc = {.interface = free_ifnum};
    struct usbdevfs_ioctl idis = {.ifno = (int) free_ifnum,
                                  .ioctl_code = USBDEVFS_IOCTL_DISCONNECT};
    struct usbdevfs_ioctl icon = {.ifno = (int) free_ifnum,
                                  .ioctl_code = USBDEVFS_IOCTL_CONNECT};
    static const char *const what[4] = {
        "GETDRIVER",
        "DISCONNECT_CLAIM",
        "USBDEVFS_IOCTL DISCONNECT",
        "USBDEVFS_IOCTL CONNECT",
    };
    const unsigned long req[4] = {USBDEVFS_GETDRIVER, USBDEVFS_DISCONNECT_CLAIM,
                                  USBDEVFS_IOCTL, USBDEVFS_IOCTL};
    void *const arg[4] = {&gd, &dc, &idis, &icon};

    for (int i = 0; i < 4; i++) {
        int f = open(NODE, O_RDWR);
        if (f < 0) {
            TEST("a fresh fd on the terminated loopback node");
            FAILF("open rc=%d", errno);
            fd = prev;
            return;
        }
        fd = f;
        long r = io(req[i], arg[i]);
        TEST(what[i]);
        if (r != -ENODEV)
            FAILF("%s on a departed device rc=%ld, want ENODEV", what[i], r);
        else
            PASS();

        /* Originated, not merely returned: the stamp is what the ops after it
         * answer from, and its absence was half of this defect.
         */
        int rev = poll_fd_once(f, POLLIN, 0);
        TEST("and the answer stamped the fd that asked");
        CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP),
              "%s: revents=0x%x", what[i], rev);
        close(f);
    }
    fd = prev;
}

/* The same four ops on an interface that IS claimed, which is the branch that
 * answers out of this layer's own bookkeeping.
 *
 * A claim is elfuse state, not device state: it stays true after the device
 * leaves, and the usbfs answer built from it puts no question to IOKit. So
 * GETDRIVER answered 0 with driver "usbfs", the two USBDEVFS_IOCTL codes
 * answered -EBUSY, and DISCONNECT_CLAIM answered 0 -- taking a fresh claim on
 * an interface of a device that was gone -- each of them leaving the fd
 * unstamped, so poll stayed silent and every ioctl after them answered from the
 * stale slot too. Linux answers -ENODEV for all four: usbdev_do_ioctl's
 * connected() gate runs before proc_getdriver, proc_disconnect_claim and
 * proc_ioctl look at an interface at all.
 *
 * IFNUM rather than a free number, the opposite of the test above: the main fd
 * holds it, so usbdev_iface_claimed_elsewhere is what answers and the
 * enumeration is never reached. One fresh fd per op, because the first answer
 * stamps the whole device.
 */
static void t_iface_query_answers_for_the_device_not_the_claim(void)
{
    enter("t_iface_query_answers_for_the_device_not_the_claim");
    int prev = fd;

    struct getdriver gd = {.interface = IFNUM};
    struct disconnect_claim dc = {.interface = IFNUM};
    struct usbdevfs_ioctl idis = {.ifno = IFNUM,
                                  .ioctl_code = USBDEVFS_IOCTL_DISCONNECT};
    struct usbdevfs_ioctl icon = {.ifno = IFNUM,
                                  .ioctl_code = USBDEVFS_IOCTL_CONNECT};
    static const char *const what[4] = {
        "GETDRIVER",
        "DISCONNECT_CLAIM",
        "USBDEVFS_IOCTL DISCONNECT",
        "USBDEVFS_IOCTL CONNECT",
    };
    const unsigned long req[4] = {USBDEVFS_GETDRIVER, USBDEVFS_DISCONNECT_CLAIM,
                                  USBDEVFS_IOCTL, USBDEVFS_IOCTL};
    void *const arg[4] = {&gd, &dc, &idis, &icon};

    for (int i = 0; i < 4; i++) {
        int f = open(NODE, O_RDWR);
        if (f < 0) {
            TEST("a fresh fd on the terminated loopback node");
            FAILF("open rc=%d", errno);
            fd = prev;
            return;
        }
        fd = f;
        long r = io(req[i], arg[i]);
        TEST(what[i]);
        if (r != -ENODEV)
            FAILF(
                "%s on a claimed interface of a departed device rc=%ld, "
                "want ENODEV",
                what[i], r);
        else
            PASS();

        int rev = poll_fd_once(f, POLLIN, 0);
        TEST("and the answer stamped the fd that asked");
        CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP),
              "%s: revents=0x%x", what[i], rev);
        close(f);
    }
    fd = prev;
}


/* The device question runs before the interface number is judged, not after.
 *
 * GETDRIVER put usbdev_ensure_dev_reachable ahead of its range check and the
 * other two put it behind theirs, so one departed device gave three different
 * answers to the same probe: measured, GETDRIVER ifnum 200 was -ENODEV with the
 * fd stamped 0x18, while DISCONNECT_CLAIM ifnum 200, USBDEVFS_IOCTL ifno 200
 * and ifno -1 were all -EINVAL with revents 0x0. Linux runs usbdev_do_ioctl's
 * connected() gate before proc_disconnect_claim and proc_ioctl are entered at
 * all, so the interface-number check inside them is behind it and every one of
 * the four is -ENODEV.
 *
 * The number is out of range on purpose: an in-range one reaches the
 * enumeration and is answered correctly either way, which is why the two
 * scenarios above this one pass on the unfixed engine and this one does not.
 *
 * libusb_detach_kernel_driver(h, n) passes the application's own n through, so
 * this is what an app that has not validated n against the config descriptor
 * sees on an unplug: LIBUSB_ERROR_INVALID_PARAM instead of NO_DEVICE, and a
 * poll on the fd that still reports nothing.
 */
static void t_out_of_range_ifnum_on_a_departed_device(void)
{
    enter("t_out_of_range_ifnum_on_a_departed_device");
    int prev = fd;

    const unsigned bad = 200;
    struct getdriver gd = {.interface = bad};
    struct disconnect_claim dc = {.interface = bad};
    struct usbdevfs_ioctl ibig = {.ifno = (int) bad,
                                  .ioctl_code = USBDEVFS_IOCTL_DISCONNECT};
    struct usbdevfs_ioctl ineg = {.ifno = -1,
                                  .ioctl_code = USBDEVFS_IOCTL_DISCONNECT};
    static const char *const what[4] = {
        "GETDRIVER ifnum 200",
        "DISCONNECT_CLAIM ifnum 200",
        "USBDEVFS_IOCTL ifno 200",
        "USBDEVFS_IOCTL ifno -1",
    };
    const unsigned long req[4] = {USBDEVFS_GETDRIVER, USBDEVFS_DISCONNECT_CLAIM,
                                  USBDEVFS_IOCTL, USBDEVFS_IOCTL};
    void *const arg[4] = {&gd, &dc, &ibig, &ineg};

    for (int i = 0; i < 4; i++) {
        int f = open(NODE, O_RDWR);
        if (f < 0) {
            TEST("a fresh fd on the terminated loopback node");
            FAILF("open rc=%d", errno);
            fd = prev;
            return;
        }
        fd = f;
        long r = io(req[i], arg[i]);
        TEST(what[i]);
        if (r != -ENODEV)
            FAILF("%s on a departed device rc=%ld, want ENODEV", what[i], r);
        else
            PASS();
        int rev = poll_fd_once(f, POLLIN, 0);
        TEST("and the answer stamped the fd that asked");
        CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP),
              "%s: revents=0x%x", what[i], rev);
        close(f);
    }
    fd = prev;
}

/* A claim is granted only against a device the call has just reached.
 *
 * The scenarios from here down predate tests/test-usbdev-ioctl-departed.c and
 * are kept for the shapes it does not build: an interface another fd holds, an
 * interface number past the table, and a claim taken through usbdev_pipe_for_ep
 * rather than by name. Which ops answer what on a departed device is that
 * lane's table, not a count in any of these comments.
 *
 * usbdev_claim_locked asked usbdev_ensure_dev_plugin, which hands back a cached
 * handle and puts no question to IOKit, so the claim went through on a device
 * that had gone: measured, CLAIMINTERFACE 2 returned 0 with revents 0x0, and
 * then RELEASEINTERFACE on the claim it had just invented returned 0 too. Linux
 * answers -ENODEV to both.
 *
 * The three ops after it are the same defect through usbdev_pipe_for_ep, which
 * claims the owning interface implicitly: CLEAR_HALT, RESETEP and SETINTERFACE
 * all reached the wire calls behind that invented claim and returned 0. RESET
 * is the fourth shape and needs no claim at all -- with none held its pipe loop
 * runs zero IOKit calls, so it ran to the end and returned 0 on a device that
 * was gone, which is libusb_reset_device, the canonical recovery call,
 * reporting success to an application whose NO_DEVICE branch is the one it
 * wanted.
 *
 * One fresh fd per op, because the first answer stamps the whole device.
 */
static void t_ops_that_reach_the_wire_ask_the_device_first(void)
{
    enter("t_ops_that_reach_the_wire_ask_the_device_first");
    int prev = fd;

    unsigned ifn = IFNUM;
    unsigned ep_in = EP_IN, ep_out = EP_OUT;
    struct setinterface si = {.interface = IFNUM, .altsetting = 0};
    static const char *const what[5] = {
        "CLAIMINTERFACE", "CLEAR_HALT", "RESETEP", "SETINTERFACE", "RESET",
    };
    const unsigned long req[5] = {USBDEVFS_CLAIMINTERFACE, USBDEVFS_CLEAR_HALT,
                                  USBDEVFS_RESETEP, USBDEVFS_SETINTERFACE,
                                  USBDEVFS_RESET};
    void *const arg[5] = {&ifn, &ep_in, &ep_out, &si, NULL};

    for (int i = 0; i < 5; i++) {
        int f = open(NODE, O_RDWR);
        if (f < 0) {
            TEST("a fresh fd on the terminated loopback node");
            FAILF("open rc=%d", errno);
            fd = prev;
            return;
        }
        fd = f;
        long r = io(req[i], arg[i]);
        TEST(what[i]);
        if (r != -ENODEV)
            FAILF("%s on a departed device rc=%ld, want ENODEV", what[i], r);
        else
            PASS();
        int rev = poll_fd_once(f, POLLIN, 0);
        TEST("and the answer stamped the fd that asked");
        CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP),
              "%s: revents=0x%x", what[i], rev);
        close(f);
    }
    fd = prev;
}

/* After t_disconnect, so the device is already gone: a watch armed now is armed
 * against a service that has already terminated.
 */
static void t_watch_after_terminate(void)
{
    enter("t_watch_after_terminate");
    int prev = fd;
    int fd3 = open(NODE, O_RDWR);
    if (fd3 < 0) {
        TEST("a fresh fd on the terminated loopback node");
        FAILF("open rc=%d", errno);
        return;
    }
    fd = fd3;

    /* SUBMITURB arms the disconnect watch and then fails on its own argument:
     * the setup packet is readable and the data it describes is not, so the URB
     * gets as far as the ep0 event source -- which is where the watch is armed
     * -- and copies no data in, reaching no IOKit entry point that could report
     * the device gone. Nothing else on this fd can have learned it either,
     * which leaves the watch as the only source of the wake, and a watch
     * registered after the terminate had already fired was recorded and never
     * called.
     *
     * A vendor request on the default control pipe is what gets there with
     * nothing claimed: it is the one URB shape that skips the endpoint lookup
     * (devio.c:1651) and, being vendor, skips check_ctrlrecip's implicit claim
     * as well. Both of those now answer -ENODEV on a departed device, which is
     * correct and is why the URB cannot be a bulk one on a claimed endpoint any
     * more.
     */
    long pgsz = sysconf(_SC_PAGESIZE);
    uint8_t *pg = mmap(NULL, (size_t) pgsz * 2, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pg == MAP_FAILED || munmap(pg + pgsz, (size_t) pgsz) != 0) {
        TEST("a mapped setup packet followed by an unmapped page");
        FAILF("mmap rc=%d", errno);
        close(fd3);
        fd = prev;
        return;
    }
    uint8_t *setup = pg + pgsz - 8;
    setup[0] = 0x40; /* vendor, host-to-device: no implicit claim */
    setup[1] = 0x01;
    setup[2] = setup[3] = setup[4] = setup[5] = 0;
    setup[6] = 16; /* wLength; the data begins at the unmapped page */
    setup[7] = 0;

    struct urb u;
    memset(&u, 0, sizeof(u));
    u.type = URB_TYPE_CONTROL;
    u.endpoint = 0;
    u.buffer = setup;
    u.buffer_length = 8 + 16;
    long r = submit(&u);
    TEST("SUBMITURB with an unmapped buffer is -EFAULT after arming the watch");
    CHECK(r == -EFAULT, "submit rc=%ld", r);

    /* -EFAULT rather than -ENODEV is what keeps the assertion below about the
     * watch: usbdev_ioctl's gate answers -ENODEV before the handler runs, so an
     * fd already carrying the mark could not have reached the copy-in at all.
     * The wake therefore has no other source than the registration this submit
     * made.
     */
    int rev = poll_once(POLLOUT | POLLWRNORM, 500);
    TEST("the already-fired terminate reaches a watch registered afterwards");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);

    munmap(pg, (size_t) pgsz);
    close(fd3);
    fd = prev;
}

/* SETCONFIGURATION asks the device about its interfaces too, and is the one
 * that did not go through usbdev_iface_service: it opened its own
 * CreateInterfaceIterator to look for a bound host driver and discarded the
 * IOReturn, so a departed device was read as "the enumeration ran and no driver
 * is bound" and the op carried on. What it carried on into is not an error at
 * all -- the config change reached the wire and was answered -- so
 * SETCONFIGURATION returned 0 on a device that was gone and stamped nothing,
 * leaving every later ioctl on the fd answering from an undisconnected fd where
 * Linux's connected() gate answers -ENODEV to all of it.
 *
 * proc_setconfig refuses outright while any interface of the device is claimed,
 * by this fd or another, so the enumeration is only reachable with the node's
 * claims dropped. The main fd is stamped by now and its RELEASEINTERFACE would
 * answer -ENODEV without releasing anything, so closing it is what drops its
 * claim. Runs last for that reason.
 */
static void t_setconfig_on_a_departed_device(void)
{
    enter("t_setconfig_on_a_departed_device");
    close(fd);
    fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("a fresh fd on the terminated loopback node");
        FAILF("open rc=%d", errno);
        return;
    }
    unsigned cfg = 1;
    long r = io(USBDEVFS_SETCONFIGURATION, &cfg);
    TEST("SETCONFIGURATION on a departed device answers ENODEV");
    CHECK(r == -ENODEV, "SETCONFIGURATION rc=%ld, want ENODEV", r);

    /* Originated, not merely returned: the stamp is what the ops after it
     * answer from, and its absence was half of this defect.
     */
    int rev = poll_fd_once(fd, POLLIN, 0);
    TEST("and the answer stamped the fd that asked");
    CHECK((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          rev);
}

/* A terminate delivered while the fd it names is closing, and the guest fd
 * number handed straight to somebody else.
 *
 * usbdev_interest_cb re-validates its packed token against used and the slot
 * generation, and the peer walk next door tests dead beside used; this one did
 * not. usbdev_fd_cleanup sets dead before it tears the slot down, and the
 * teardown drain is two seconds wide against a wedged transfer, so a terminate
 * arriving inside it stamped a slot whose fd had already closed -- on the guest
 * fd number, which a sibling can hold by then. The stamp outlives the slot,
 * since teardown clears disconnected afterwards and the cleanup's map clear is
 * skipped precisely because a live entry now answers to that number. Measured
 * 5/5: the sibling opened a DIFFERENT node, got the same guest fd, and was
 * permanently poll revents=0x18 with every ioctl -ENODEV; without the terminate
 * the same sibling is 0x0000.
 *
 * The same callback carries the peer walk, and only the stamp may be skipped. A
 * second fd open on the terminated node that never submits an async URB arms no
 * watch of its own, so the walk from the closing fd is the third of the three
 * stamp sources tests/usbdev-ioctl-departed.tbl's REAPURB row names -- "or by a
 * peer that learned first" -- and the only one such an fd has here. Guarding
 * the walk with dead as well left it polling 0x0000 for a device that was gone,
 * which is what the peer arms below measure.
 *
 * Its own process because it terminates the fixture device, which every
 * scenario in the main run still needs.
 */
static int race_sibling_fd = -1;

static void *race_open_sibling(void *arg)
{
    struct timespec ts = {0, (long) (intptr_t) arg * 1000 * 1000};
    nanosleep(&ts, NULL);
    race_sibling_fd = open(OTHER_NODE, O_RDWR);
    return NULL;
}

static int t_terminate_during_close(void)
{
    enter("t_terminate_during_close");
    printf("a terminate delivered while the fd it names is closing\n");
    fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("the loopback node");
        FAILF("open rc=%d", errno);
        return 1;
    }
    unsigned ifn = IFNUM;
    io(USBDEVFS_CLAIMINTERFACE, &ifn);

    /* The sync-only peer, opened before the terminate and left alone: no claim,
     * no submit, so no watch of its own. It takes a higher fd number than the
     * one the sibling below races for.
     */
    int peer = open(NODE, O_RDWR);
    if (peer < 0) {
        TEST("a second fd on the same loopback node");
        FAILF("open rc=%d", errno);
        return 1;
    }
    fx_reset();
    fx_script("ep02:wedge(2500)");
    uint8_t out[8] = {0};
    struct urb u;
    mk_bulk(&u, EP_OUT, out, sizeof(out));
    long sub = submit(&u);
    TEST("a transfer whose abort outlives the teardown drain");
    CHECK(sub == 0, "SUBMITURB rc=%ld", sub);

    /* Inside the close's two-second drain from both ends: the terminate at 60
     * ms, the sibling's open at 20 ms so that the fd number is taken before
     * usbdev_fd_cleanup decides whether to clear the map.
     */
    TEST("a terminate armed to land inside that drain");
    CHECK(fx_terminate(60) == 0, "rc=%d", errno);
    pthread_t th;
    if (pthread_create(&th, NULL, race_open_sibling, (void *) (intptr_t) 20)) {
        TEST("the sibling thread");
        FAILF("pthread_create failed");
        return 1;
    }
    double t0 = now_ms();
    close(fd);
    double dt = now_ms() - t0;
    pthread_join(th, NULL);
    printf("  close returned after %.0f ms\n", dt);

    if (race_sibling_fd < 0) {
        TEST("the sibling's open of another node");
        FAILF("open rc=%d", errno);
        return 1;
    }
    int rev = poll_fd_once(race_sibling_fd, POLLIN | POLLOUT | POLLWRNORM, 0);
    TEST("the sibling holding the closed fd number is not stamped");
    CHECK((rev & (POLLERR | POLLHUP)) == 0, "revents=0x%x", rev);
    uint32_t caps = 0;
    int ic = ioctl(race_sibling_fd, USBDEVFS_GET_CAPABILITIES, &caps);
    TEST("and its ioctls do not answer for a device that was never its own");
    CHECK(!(ic < 0 && errno == ENODEV), "GET_CAPABILITIES rc=%d errno=%d", ic,
          ic < 0 ? errno : 0);
    close(race_sibling_fd);

    /* The peer's only route to the news is the walk the closing fd ran. Both
     * arms answer from the same stamp: the revents remap, and the reap that
     * ends on it rather than on -EAGAIN.
     */
    int prev = poll_fd_once(peer, POLLIN | POLLOUT | POLLWRNORM, 0);
    TEST("a sync-only peer on the terminated node learns the device is gone");
    CHECK((prev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "revents=0x%x",
          prev);
    void *reaped = NULL;
    int pr = ioctl(peer, USBDEVFS_REAPURBNDELAY, &reaped);
    int pe = pr < 0 ? errno : 0;
    TEST("and its non-blocking reap answers ENODEV, not EAGAIN");
    CHECK(pr < 0 && pe == ENODEV, "rc=%d errno=%d", pr, pe);
    close(peer);

    settle(2600); /* the wedge's late abort, before the process exits */
    SUMMARY("test-usbdev-urb-loopback terminate-race");
    return fails ? 1 : 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, on_alarm);
    if (argc > 1 && !strcmp(argv[1], "terminate-race"))
        return t_terminate_during_close();
    enter("open");
    printf("usbdevfs async URB engine over the IOKit loopback fixture\n");
    fd = open(NODE, O_RDWR);
    if (fd < 0) {
        printf(
            "  cannot open %s (errno %d); this lane needs "
            "ELFUSE_USB_FIXTURE=loopback\n",
            NODE, errno);
        return 1;
    }
    unsigned ifn = IFNUM;
    TEST("CLAIMINTERFACE on the loopback interface");
    CHECK(io(USBDEVFS_CLAIMINTERFACE, &ifn) == 0, "claim rc=%d", errno);
    uint32_t caps = 0;
    TEST("GET_CAPABILITIES still names ZERO_PACKET and REAP_AFTER_DISCONNECT");
    CHECK(io(USBDEVFS_GET_CAPABILITIES, &caps) == 0 && caps == 0x11u,
          "caps=0x%x", caps);

    t_complete_with_data();
    t_short();
    t_error_status();
    t_queue_order();
    t_discard_inflight();
    t_discard_queued();
    t_poll();
    t_reap_modes();
    t_zero_packet();
    t_fixture_contract();
    t_ready_level();
    t_drain_deadline();
    t_orphan_refund();
    t_control_charge();
    t_drain_timeout_restarts_fifos();
    t_follower_device_gone();
    t_disc_drained_reset();
    t_reap_ndelay_never_waits();
    t_enodev_never_precedes_the_urbs();
    t_ndelay_reaches_enodev();
    t_pipe_map_device_gone();
    t_discard_when_the_abort_is_refused();
    t_ep0_orphan_pins_the_device();
    t_disconnect();
    t_sync_op_originates_disconnect();
    t_iface_query_on_a_departed_device();
    t_iface_query_answers_for_the_device_not_the_claim();
    t_out_of_range_ifnum_on_a_departed_device();
    t_ops_that_reach_the_wire_ask_the_device_first();
    t_watch_after_terminate();
    t_setconfig_on_a_departed_device();

    close(fd);
    SUMMARY("test-usbdev-urb-loopback");
    return fails ? 1 : 0;
}
