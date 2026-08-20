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
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define NODE "/dev/bus/usb/003/001"
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
#define USBDEVFS_CLAIMINTERFACE 0x8004550fu
#define USBDEVFS_GET_CAPABILITIES 0x8004551au

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

static int poll_once(short events, int timeout_ms)
{
    struct pollfd p = {.fd = fd, .events = events, .revents = 0};
    int r = poll(&p, 1, timeout_ms);
    return r <= 0 ? 0 : p.revents;
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
    TEST("a start IOKit refuses is a SUBMITURB error");
    CHECK(submit(&u) == -ENODEV, "submit rc=%ld", submit(&u));
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
    TEST("poll reports nothing while the URB is in flight");
    CHECK(poll_once(want, 40) == 0, "revents=0x%x", poll_once(want, 0));
    int rev = poll_once(want, 2000);
    TEST("poll reports POLLOUT|POLLWRNORM when the completion lands");
    CHECK(rev == (POLLOUT | POLLWRNORM), "revents=0x%x", rev);
    reap(false);
    TEST("poll goes quiet again once the completion is reaped");
    CHECK(poll_once(want, 40) == 0, "revents=0x%x", poll_once(want, 0));

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

/* Last: the device never comes back. */
static void t_disconnect(void)
{
    enter("t_disconnect");
    uint8_t a[32], b[32];
    struct urb ua, ub;
    fx_reset();
    fx_script("ep81:never*2;ep83:never");
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
    for (int i = 0; i < 4; i++) {
        struct urb *d = reap(true);
        if (!d)
            break;
        back++;
        if (d->status == -ENOENT)
            enoent++;
    }
    TEST("CAP_REAP_AFTER_DISCONNECT hands back every in-flight URB");
    CHECK(back == 2, "reaped %d of 2", back);
    TEST("each one carries the errno usb_kill_urb leaves");
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
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, on_alarm);
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
    t_disconnect();

    close(fd);
    SUMMARY("test-usbdev-urb-loopback");
    return fails ? 1 : 0;
}
