/*
 * Every usbdevfs ioctl on a device that has gone (ELFUSE_USB_FIXTURE=loopback)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: usbdev_ioctl's disconnect contract in src/syscall/usbdev.c
 * and the usbdevfs arms of src/syscall/poll.c, across the whole ioctl surface
 * rather than the handful of ops a reviewer thought to name.
 *
 * The surface is not listed here. scripts/gen-usbdev-ioctl-departed.py reads it
 * out of usbdev_ioctl's own dispatch, joins it against the Linux answers
 * recorded in tests/usbdev-ioctl-departed.tbl, and emits the rows below; an
 * ioctl the layer implements with no recorded answer fails that generator, so
 * this lane covers the surface by construction. Each row carries four columns
 * and this binary asserts all four: the ioctl return, the errno behind it, the
 * poll revents left on the fd that asked, and the revents on another fd open on
 * the same node, which is what says the disconnect was recorded against the
 * device rather than against one caller.
 *
 * A row whose recorded elfuse answer differs from Linux's is an XFAIL carrying
 * both values: it must answer what this layer answers, and it must not answer
 * what Linux does. So a gap cannot widen unnoticed and cannot close unnoticed
 * either.
 *
 * Three of the rows name requests the layer defines and dispatches nowhere, so
 * they drive usbdev_ioctl's default arm: the arm the join could not reach while
 * it was built from case labels alone, and the one answering -ENOTTY where
 * Linux answers -ENODEV.
 *
 * Every row asks on an fd that has not been told the device left. The fresh
 * phase ends by asking on one that has, which is where the universal in
 * docs/internals.md holds: the whole usbdevfs surface answers -ENODEV on a
 * marked fd. It ends by asking where that universal stops, too -- the requests
 * do_vfs_ioctl answers before f_op->unlocked_ioctl, which are not usbdevfs and
 * are not -ENODEV on any fd of a departed device.
 *
 * The device is the loopback fixture's, /dev/bus/usb/003/001 interface 2, and
 * it is terminated once at startup. Three things follow from that and shape the
 * run:
 *
 *   Every correct -ENODEV stamps every fd open on the node, so no two rows can
 *   share an fd. Each row opens its own subject and its own peer.
 *
 *   A synchronous-only fd is never told the device left: the terminate watch is
 *   armed by the async paths alone. That is what leaves an unstamped fd for
 *   each row to ask on, and it is why the phases below can hold a claim across
 *   the terminate.
 *
 *   The fixture's terminate is delivered by the event thread, which the same
 *   async paths start, so one throwaway fd submits one URB to bring the thread
 *   up and is closed again before the terminate lands.
 *
 * Phases, one process each (see mk/tests.mk): the rows that need a claim taken
 * before the device left cannot share a process with the rows that stamp every
 * fd on the node.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

#include "test-harness.h"

/* Generated into build/ from tests/usbdev-ioctl-departed.tbl; see the Makefile
 * rule that puts build/ on this binary's include path.
 */
#include "usbdev-ioctl-departed-vectors.h"

int passes = 0, fails = 0;

#define NODE "/dev/bus/usb/003/001"
#define IFNUM 2
#define EP_IN 0x81
#define EP_OUT 0x02

/* Past USBDEV_MAX_IFACES, so the layer's own interface-number bound is what
 * would answer if the device question did not run first.
 */
#define IFNUM_UNREPRESENTABLE 200

#define USBDEVFS_CONTROL 0xc0185500u
#define USBDEVFS_IOCTL_DISCONNECT 0x5516

/* The fixture's control plane (src/syscall/usbdev-fixture.c). */
#define FX_TERMINATE 0xf2

struct ctrltransfer {
    uint8_t bRequestType, bRequest;
    uint16_t wValue, wIndex, wLength;
    uint32_t timeout;
    void *data;
};

struct bulktransfer {
    unsigned int ep, len, timeout;
    void *data;
};

struct setinterface {
    unsigned int interface, altsetting;
};

struct getdriver {
    unsigned int interface;
    char driver[256];
};

struct disconnect_claim {
    unsigned int interface, flags;
    char driver[256];
};

struct usbdevfs_ioctl {
    int ifno, ioctl_code;
    void *data;
};

struct connectinfo {
    unsigned int devnum;
    unsigned char slow;
};

struct disconnectsignal {
    unsigned int signr;
    void *context;
};

/* Arguments of the three requests this layer defines and does not dispatch. */
struct hub_portinfo {
    char nports;
    char port[127];
};

struct streams {
    unsigned int num_streams, num_eps;
    unsigned char eps[4];
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

#define URB_TYPE_CONTROL 2
#define URB_TYPE_BULK 3

/* No type accepts this bit, so proc_do_submiturb's argument gate is what would
 * answer if the device question did not run first (devio.c:1644-1650).
 */
#define URB_FLAG_UNDEFINED 0x08u

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

static char msgbuf[512];
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

static void settle(int ms)
{
    (void) poll(NULL, 0, ms);
}

static int revents_of(int f)
{
    struct pollfd p = {.fd = f, .events = POLLIN | POLLOUT};
    return poll(&p, 1, 0) > 0 ? p.revents : 0;
}

/* the row drivers, one per generated row */

static long departed_drive_CONTROL(int f, unsigned long req)
{
    static uint8_t buf[8];
    struct ctrltransfer ct = {.bRequestType = 0xc0, /* vendor IN: no recipient
                                                       check ahead of the wire
                                                       */
                              .bRequest = 0x01,
                              .wLength = sizeof(buf),
                              .timeout = 1000,
                              .data = buf};
    return ioctl(f, req, &ct);
}

static long departed_drive_BULK(int f, unsigned long req)
{
    static uint8_t buf[8];
    struct bulktransfer bt = {
        .ep = EP_IN, .len = sizeof(buf), .timeout = 1000, .data = buf};
    return ioctl(f, req, &bt);
}

static long departed_drive_RESETEP(int f, unsigned long req)
{
    unsigned int ep = EP_IN;
    return ioctl(f, req, &ep);
}

static long departed_drive_CLEAR_HALT(int f, unsigned long req)
{
    unsigned int ep = EP_IN;
    return ioctl(f, req, &ep);
}

static long departed_drive_SETINTERFACE(int f, unsigned long req)
{
    struct setinterface si = {.interface = IFNUM, .altsetting = 0};
    return ioctl(f, req, &si);
}

static long departed_drive_SETCONFIGURATION(int f, unsigned long req)
{
    unsigned int cfg = 1;
    return ioctl(f, req, &cfg);
}

static long departed_drive_GETDRIVER(int f, unsigned long req)
{
    static struct getdriver gd;
    gd.interface = 0;
    return ioctl(f, req, &gd);
}

static long departed_drive_DISCONNECT_CLAIM(int f, unsigned long req)
{
    static struct disconnect_claim dc;
    dc.interface = 0;
    dc.flags = 0;
    return ioctl(f, req, &dc);
}

static long departed_drive_DRIVER_IOCTL(int f, unsigned long req)
{
    struct usbdevfs_ioctl ci = {.ifno = 0,
                                .ioctl_code = USBDEVFS_IOCTL_DISCONNECT};
    return ioctl(f, req, &ci);
}

static long departed_drive_RESET(int f, unsigned long req)
{
    return ioctl(f, req, NULL);
}

static long departed_drive_CLAIMINTERFACE(int f, unsigned long req)
{
    unsigned int ifn = 0;
    return ioctl(f, req, &ifn);
}

static long departed_drive_CLAIMINTERFACE_BOUND(int f, unsigned long req)
{
    unsigned int ifn = IFNUM_UNREPRESENTABLE;
    return ioctl(f, req, &ifn);
}

static long departed_drive_CLAIMINTERFACE_HELD(int f, unsigned long req)
{
    unsigned int ifn = IFNUM;
    return ioctl(f, req, &ifn);
}

static long departed_drive_RELEASEINTERFACE(int f, unsigned long req)
{
    unsigned int ifn = 0;
    return ioctl(f, req, &ifn);
}

static long departed_drive_RELEASEINTERFACE_BOUND(int f, unsigned long req)
{
    unsigned int ifn = IFNUM_UNREPRESENTABLE;
    return ioctl(f, req, &ifn);
}

static long departed_drive_RELEASEINTERFACE_HELD(int f, unsigned long req)
{
    unsigned int ifn = IFNUM;
    return ioctl(f, req, &ifn);
}

static long departed_drive_SUBMITURB(int f, unsigned long req)
{
    static uint8_t buf[8];
    static struct urb u;
    memset(&u, 0, sizeof(u));
    u.type = URB_TYPE_BULK;
    u.endpoint = EP_OUT;
    u.buffer = buf;
    u.buffer_length = sizeof(buf);
    return ioctl(f, req, &u);
}

static long departed_drive_SUBMITURB_BADFLAGS(int f, unsigned long req)
{
    static uint8_t buf[8];
    static struct urb u;
    memset(&u, 0, sizeof(u));
    u.type = URB_TYPE_BULK;
    u.endpoint = EP_OUT;
    u.flags = URB_FLAG_UNDEFINED;
    u.buffer = buf;
    u.buffer_length = sizeof(buf);
    return ioctl(f, req, &u);
}

static long departed_drive_DISCARDURB(int f, unsigned long req)
{
    static struct urb never_submitted;
    return ioctl(f, req, &never_submitted);
}

/* A blocking reap has no bound of its own once the wait is entered, so this
 * ends it with a signal rather than letting the lane hang: the interval timer
 * repeats so a wait this layer refuses to leave still ends the run, and the
 * lane's own watchdog handler is put back before the driver returns.
 */
static volatile sig_atomic_t reap_alarms;

static void on_reap_alarm(int sig)
{
    (void) sig;
    if (++reap_alarms < 5)
        return;
    static char msg[] = "\nREAPURB did not leave its wait on a signal\n";
    (void) !write(1, msg, sizeof(msg) - 1);
    _exit(1);
}

static long departed_drive_REAPURB(int f, unsigned long req)
{
    void *urbp = NULL;
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_reap_alarm; /* no SA_RESTART: the wait must not resume */
    reap_alarms = 0;
    alarm(0);
    sigaction(SIGALRM, &sa, &old);
    struct itimerval it = {.it_interval = {.tv_sec = 2},
                           .it_value = {.tv_sec = 2}};
    setitimer(ITIMER_REAL, &it, NULL);
    long r = ioctl(f, req, &urbp);
    int e = errno;
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, NULL);
    sigaction(SIGALRM, &old, NULL);
    alarm(30);
    errno = e;
    return r;
}

static long departed_drive_REAPURBNDELAY(int f, unsigned long req)
{
    void *urbp = NULL;
    return ioctl(f, req, &urbp);
}

static long departed_drive_GET_CAPABILITIES(int f, unsigned long req)
{
    uint32_t caps = 0;
    return ioctl(f, req, &caps);
}

static long departed_drive_GET_SPEED(int f, unsigned long req)
{
    return ioctl(f, req, NULL);
}

static long departed_drive_CONNECTINFO(int f, unsigned long req)
{
    static struct connectinfo ci;
    return ioctl(f, req, &ci);
}

static long departed_drive_DISCSIGNAL(int f, unsigned long req)
{
    struct disconnectsignal ds = {.signr = 0, .context = NULL};
    return ioctl(f, req, &ds);
}

/* The three rows that reach usbdev_ioctl's default arm: usbdevfs requests the
 * layer defines and dispatches nowhere. Their arguments are the ones Linux
 * reads for them, so that nothing but the arm decides the answer.
 */
static long departed_drive_HUB_PORTINFO(int f, unsigned long req)
{
    static struct hub_portinfo hp;
    return ioctl(f, req, &hp);
}

static long departed_drive_ALLOC_STREAMS(int f, unsigned long req)
{
    struct streams st = {.num_streams = 2, .num_eps = 1};
    st.eps[0] = EP_IN;
    return ioctl(f, req, &st);
}

static long departed_drive_WAIT_FOR_RESUME(int f, unsigned long req)
{
    return ioctl(f, req, NULL);
}


/* setup */

/* The request code the generated table records for one usbdevfs ioctl, for the
 * two calls the setup makes on its own account rather than as a row.
 */
static unsigned long request_of(const char *req_name)
{
    for (int i = 0; i < USBDEV_DEPARTED_NROWS; i++)
        if (!strcmp(usbdev_departed_rows[i].req_name, req_name))
            return usbdev_departed_rows[i].request;
    return 0;
}

static long fx_terminate(int f, unsigned ms)
{
    struct ctrltransfer ct = {.bRequestType = 0x40,
                              .bRequest = FX_TERMINATE,
                              .wValue = (uint16_t) ms,
                              .timeout = 1000,
                              .data = NULL};
    return ioctl(f, USBDEVFS_CONTROL, &ct);
}

/* Bring the event thread up, which is what delivers the fixture's terminate,
 * and take the watch it arms away again by closing the fd that armed it.
 *
 * One SUBMITURB does both. It is a default-control-pipe URB whose data lands in
 * an unmapped page, which is the shape that reaches the ep0 event source -- and
 * so usbdev_loop_get and the watch -- and then fails on its own argument
 * without a claim, without a wire call and without anything to reap. Any fd
 * left holding a watch would be told the device left, and its peer walk would
 * stamp every other fd on the node, which is exactly what the rows below need
 * not to have happened yet.
 */
static bool start_event_thread(void)
{
    long pgsz = sysconf(_SC_PAGESIZE);
    uint8_t *pg = mmap(NULL, (size_t) pgsz * 2, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pg == MAP_FAILED || munmap(pg + pgsz, (size_t) pgsz) != 0)
        return false;
    uint8_t *setup = pg + pgsz - 8;
    setup[0] = 0x40; /* vendor, host-to-device: no implicit claim */
    setup[1] = 0x01;
    setup[2] = setup[3] = setup[4] = setup[5] = 0;
    setup[6] = 16; /* wLength; the data begins at the unmapped page */
    setup[7] = 0;

    int f = open(NODE, O_RDWR);
    if (f < 0) {
        munmap(pg, (size_t) pgsz);
        return false;
    }
    struct urb u;
    memset(&u, 0, sizeof(u));
    u.type = URB_TYPE_CONTROL;
    u.endpoint = 0;
    u.buffer = setup;
    u.buffer_length = 8 + 16;
    long r = ioctl(f, request_of("USBDEVFS_SUBMITURB"), &u);
    int e = errno;
    close(f);
    munmap(pg, (size_t) pgsz);
    return r < 0 && e == EFAULT;
}

/* reporting */

static const char *revents_name(int mask)
{
    if (mask == 0)
        return "NONE";
    if (mask == (POLLERR | POLLHUP))
        return "ERRHUP";
    static char other[32];
    snprintf(other, sizeof(other), "0x%x", (unsigned) mask);
    return other;
}

static const char *errno_name(int e)
{
    switch (e) {
    case 0:
        return "NONE";
    case EAGAIN:
        return "EAGAIN";
    case EBUSY:
        return "EBUSY";
    case EINTR:
        return "EINTR";
    case EINVAL:
        return "EINVAL";
    case ENODATA:
        return "ENODATA";
    case ENODEV:
        return "ENODEV";
    case ENOENT:
        return "ENOENT";
    case ENOTTY:
        return "ENOTTY";
    case EPERM:
        return "EPERM";
    case EPROTO:
        return "EPROTO";
    default: {
        static char other[16];
        snprintf(other, sizeof(other), "errno%d", e);
        return other;
    }
    }
}

static void print_tuple(char *out,
                        size_t n,
                        long rc,
                        int e,
                        int stamp,
                        int peer)
{
    snprintf(out, n, "%ld/%s/%s/%s", rc, errno_name(rc < 0 ? e : 0),
             revents_name(stamp), revents_name(peer));
}

/* the run */

static bool run_row(const usbdev_departed_row_t *row, int subject, int peer)
{
    errno = 0;
    long rc = usbdev_departed_drivers[row - usbdev_departed_rows](subject,
                                                                  row->request);
    int e = errno;
    int stamp = revents_of(subject);
    int pv = revents_of(peer);

    const usbdev_departed_tuple_t *want =
        row->diverges ? &row->here : &row->kernel;
    bool ok = rc == want->rc && (rc >= 0 || e == want->err) &&
              stamp == want->stamp && pv == want->peer;

    char got[96], expect[96];
    print_tuple(got, sizeof(got), rc, e, stamp, pv);
    print_tuple(expect, sizeof(expect), want->rc, want->err, want->stamp,
                want->peer);

    TEST(row->id);
    if (ok)
        PASS();
    else
        FAILF("%s: got %s, want %s", row->id, got, expect);

    if (row->diverges) {
        /* The gap must still be a gap: an XFAIL that has quietly started
         * answering what Linux answers is a row to retire, not to keep.
         */
        char kern[96];
        print_tuple(kern, sizeof(kern), row->kernel.rc, row->kernel.err,
                    row->kernel.stamp, row->kernel.peer);
        TEST("and still differs from Linux");
        CHECK(!(rc == row->kernel.rc && (rc >= 0 || e == row->kernel.err) &&
                stamp == row->kernel.stamp && pv == row->kernel.peer),
              "%s: now answers Linux's %s; retire the XFAIL row", row->id,
              kern);
    }

    printf("    %-24s %-8s %-22s %-22s devio.c:%d\n", row->id,
           row->diverges ? "XFAIL" : "match", got,
           row->diverges ? expect : "(Linux)", row->devio_line);
    return ok;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, on_alarm);
    enter("startup");

    if (argc != 2) {
        printf("usage: %s fresh|held-claim|held-release\n", argv[0]);
        return 2;
    }
    int phase;
    if (!strcmp(argv[1], "fresh"))
        phase = USBDEV_DEPARTED_FRESH;
    else if (!strcmp(argv[1], "held-claim"))
        phase = USBDEV_DEPARTED_HELD_CLAIM;
    else if (!strcmp(argv[1], "held-release"))
        phase = USBDEV_DEPARTED_HELD_RELEASE;
    else {
        printf("unknown phase '%s'\n", argv[1]);
        return 2;
    }

    printf("usbdevfs ioctl surface on a departed loopback device (%s)\n",
           argv[1]);

    TEST("the event thread is up and holds no watch");
    CHECK(start_event_thread(), "could not arm the loopback event thread");

    /* One fd per row, and the peer opened before the call so it is a peer of
     * it. In the held phases the subject is opened first instead, because its
     * claim has to be taken while the device is still there.
     */
    int held = -1;
    if (phase != USBDEV_DEPARTED_FRESH) {
        held = open(NODE, O_RDWR);
        unsigned int ifn = IFNUM;
        TEST("an fd claims the interface while the device is here");
        CHECK(held >= 0 &&
                  ioctl(held, request_of("USBDEVFS_CLAIMINTERFACE"), &ifn) == 0,
              "claim rc=%d errno=%d", held, errno);
    }

    int term = phase == USBDEV_DEPARTED_FRESH ? open(NODE, O_RDWR) : held;

    /* The other half of the DISCARDURB row, taken while the device is still
     * here: an unknown URB is -EINVAL, and only the departure turns that into
     * -ENODEV. A layer that answered -ENODEV to every discard would satisfy the
     * row and fail this.
     */
    struct urb unknown;
    memset(&unknown, 0, sizeof(unknown));
    errno = 0;
    long dr = term >= 0
                  ? ioctl(term, request_of("USBDEVFS_DISCARDURB"), &unknown)
                  : 0;
    TEST("an unknown URB is EINVAL while the device is here");
    CHECK(term >= 0 && dr < 0 && errno == EINVAL, "DISCARDURB rc=%ld errno=%d",
          dr, errno);

    /* The other half of the three default-arm rows, taken while the device is
     * still here. Those rows want -ENODEV from an arm that used to answer
     * -ENOTTY, and an arm rewritten to answer -ENODEV always would satisfy
     * every one of them. -ENOTTY is what the arm owes a device that is there.
     */
    int unimpl_ok = term >= 0;
    for (int i = 0; i < USBDEV_DEPARTED_NROWS && unimpl_ok; i++) {
        const usbdev_departed_row_t *row = &usbdev_departed_rows[i];
        if (strcmp(row->id, "HUB_PORTINFO") &&
            strcmp(row->id, "ALLOC_STREAMS") &&
            strcmp(row->id, "WAIT_FOR_RESUME"))
            continue;
        errno = 0;
        long r = usbdev_departed_drivers[i](term, row->request);
        if (r != -1 || errno != ENOTTY) {
            unimpl_ok = false;
            FAILF("%s while the device is here: rc=%ld errno=%s", row->id, r,
                  errno_name(errno));
        }
    }
    TEST("an unimplemented request is ENOTTY while the device is here");
    CHECK(unimpl_ok, "an unimplemented request did not answer ENOTTY");

    TEST("the device is terminated");
    CHECK(term >= 0 && fx_terminate(term, 30) >= 0, "terminate errno=%d",
          errno);
    if (phase == USBDEV_DEPARTED_FRESH)
        close(term);
    settle(300);

    if (held >= 0) {
        /* The premise of these rows: a synchronous-only fd armed no watch, so
         * it still holds a claim on a device it has not been told about. If
         * that stopped being true the rows below would pass against the gate at
         * the top of usbdev_ioctl and prove nothing.
         */
        TEST("the claiming fd was told nothing");
        CHECK(revents_of(held) == 0, "revents=0x%x", revents_of(held));
    }

    printf("    %-24s %-8s %-22s %-22s %s\n", "row", "answer", "measured",
           "Linux", "cite");
    int driven = 0, want = 0;
    for (int i = 0; i < USBDEV_DEPARTED_NROWS; i++) {
        const usbdev_departed_row_t *row = &usbdev_departed_rows[i];
        if (row->phase != phase)
            continue;
        want++;
        enter(row->id);
        int subject, peer;
        if (held >= 0) {
            subject = held;
            peer = open(NODE, O_RDWR);
        } else {
            peer = open(NODE, O_RDWR);
            subject = open(NODE, O_RDWR);
        }
        if (subject < 0 || peer < 0) {
            TEST(row->id);
            FAILF("%s: open errno=%d", row->id, errno);
            continue;
        }
        (void) run_row(row, subject, peer);
        driven++;
        close(peer);
        if (held < 0)
            close(subject);
    }
    if (held >= 0)
        close(held);

    /* The other half of the contract, and the half no row above can reach.
     * Every row asks on an fd that has NOT been told the device left, which is
     * what makes the per-request answers interesting; docs/internals.md's
     * universal is about the fd that HAS been told, and unpinned it was a
     * sentence rather than a measurement. On a marked fd the whole surface
     * answers -ENODEV -- the gate at the top of usbdev_ioctl is ahead of every
     * arm including the default one, and the two reaps let past it decide the
     * same way for themselves once nothing is left to hand back.
     */
    if (phase == USBDEV_DEPARTED_FRESH) {
        enter("stamped fd");
        int st = open(NODE, O_RDWR);
        errno = 0;
        long crc =
            st >= 0 ? departed_drive_CONTROL(st, request_of("USBDEVFS_CONTROL"))
                    : 0;
        int cerr = errno, cre = st >= 0 ? revents_of(st) : 0;
        TEST("an fd that reached the wire carries the mark");
        CHECK(
            st >= 0 && crc < 0 && cerr == ENODEV && cre == (POLLERR | POLLHUP),
            "CONTROL rc=%ld errno=%s revents=%s", crc, errno_name(cerr),
            revents_name(cre));

        char first[160];
        first[0] = '\0';
        int uniform = 0;
        for (int i = 0; i < USBDEV_DEPARTED_NROWS && st >= 0; i++) {
            const usbdev_departed_row_t *row = &usbdev_departed_rows[i];
            enter(row->id);
            errno = 0;
            long rc = usbdev_departed_drivers[i](st, row->request);
            int e = errno, re = revents_of(st);
            if (rc == -1 && e == ENODEV && re == (POLLERR | POLLHUP)) {
                uniform++;
            } else if (!first[0]) {
                snprintf(first, sizeof(first), "%s answered %ld/%s/%s", row->id,
                         rc, errno_name(rc < 0 ? e : 0), revents_name(re));
            }
        }
        enter("stamped fd");
        TEST("and then answers ENODEV to the whole usbdevfs surface");
        CHECK(st >= 0 && uniform == USBDEV_DEPARTED_NROWS,
              "%d of %d requests; %s", uniform, USBDEV_DEPARTED_NROWS,
              first[0] ? first : "no fd");

        /* Where that universal stops. do_vfs_ioctl answers these for every file
         * before it calls f_op->unlocked_ioctl, so on Linux they never reach
         * usbfs and never meet connected(); here they are answered ahead of the
         * gate and ahead of the default arm's device question. What this
         * asserts is that the answer does not move with what the fd has been
         * told -- not that -ENOTTY is Linux's answer, which for eight of the
         * ten it is not. Those eight, and what Linux gives instead, are
         * recorded and printed by check_vfs_ioctls in tests/test-usbdev-ioctl.c
         * rather than asserted here. Both fds are driven because the two used
         * to answer -ENODEV for different reasons: the marked one from the
         * gate, the fresh one from the ask.
         */
        static const struct {
            const char *name;
            unsigned long request;
        } vfs_first[] = {
            {"FIOQSIZE", 0x5460ul},
            {"FIGETBSZ", 0x00000002ul},
            {"FIFREEZE", 0xc0045877ul},
            {"FITHAW", 0xc0045878ul},
            {"FS_IOC_FIEMAP", 0xc020660bul},
            {"FICLONE", 0x40049409ul},
            {"FICLONERANGE", 0x4020940dul},
            {"FIDEDUPERANGE", 0xc0189436ul},
            {"FS_IOC_GETFSUUID", 0x80111500ul},
            {"FS_IOC_GETFSSYSFSPATH", 0x80811501ul},
        };
        const int nvfs = (int) (sizeof(vfs_first) / sizeof(vfs_first[0]));
        int vf = open(NODE, O_RDWR);
        for (int which = 0; which < 2; which++) {
            int subject = which == 0 ? st : vf;
            int want_revents = which == 0 ? (POLLERR | POLLHUP) : 0;
            char firstbad[160];
            firstbad[0] = '\0';
            int enotty = 0;
            for (int i = 0; i < nvfs && subject >= 0; i++) {
                enter(vfs_first[i].name);
                unsigned char scratch[64] = {0};
                errno = 0;
                long rc = ioctl(subject, vfs_first[i].request, scratch);
                int e = errno, re = revents_of(subject);
                if (rc == -1 && e == ENOTTY && re == want_revents)
                    enotty++;
                else if (!firstbad[0])
                    snprintf(firstbad, sizeof(firstbad),
                             "%s answered %ld/%s/%s", vfs_first[i].name, rc,
                             errno_name(rc < 0 ? e : 0), revents_name(re));
            }
            enter(which == 0 ? "stamped fd" : "fresh fd");
            TEST(which == 0
                     ? "the mark does not reach what do_vfs_ioctl answers first"
                     : "and neither does the default arm's device question");
            CHECK(subject >= 0 && enotty == nvfs, "%d of %d requests; %s",
                  enotty, nvfs, firstbad[0] ? firstbad : "no fd");
        }

        /* The other request docs/internals.md names for the marked fd. io.c
         * answers FIONBIO for these fds, so the mark cannot reach it either.
         */
        enter("stamped fd");
        int on = 1;
        errno = 0;
        long nbrc = st >= 0 ? ioctl(st, 0x5421ul, &on) : -1;
        int nbe = errno, nbre = st >= 0 ? revents_of(st) : 0;
        TEST("nor FIONBIO, which io.c answers ahead of this layer");
        CHECK(st >= 0 && nbrc == 0 && nbre == (POLLERR | POLLHUP),
              "FIONBIO rc=%ld errno=%s revents=%s", nbrc,
              errno_name(nbrc < 0 ? nbe : 0), revents_name(nbre));

        if (vf >= 0)
            close(vf);
        if (st >= 0)
            close(st);
    }

    enter("summary");
    TEST("every row of this phase was driven");
    CHECK(driven == want && want > 0, "drove %d of %d rows", driven, want);

    printf("\n");
    for (int i = 0; i < USBDEV_DEPARTED_NROWS; i++) {
        const usbdev_departed_row_t *row = &usbdev_departed_rows[i];
        if (row->phase == phase && row->diverges)
            printf("  XFAIL %s: %s\n", row->id, row->note);
    }

    SUMMARY("test-usbdev-ioctl-departed");
    return fails ? 1 : 0;
}
