/*
 * A loopback device behind the IOKit COM seam (ELFUSE_USB_FIXTURE=loopback)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Why this exists: the async URB engine in usbdev.c cannot be reached without
 * an IOKit service behind the node, and the other ELFUSE_USB_FIXTURE models
 * have none, so submit, complete, reap, the per-endpoint queue, the disconnect
 * drain and every readiness path in poll.c had no in-tree lane at all. IOKit
 * publishes no loopback device to borrow, so the seam is placed at the
 * narrowest point that still leaves all of that real: the two COM vtables.
 * Nothing above them changes, and the only calls replaced are the ones that
 * would have gone to the wire plus the callbacks that would have come back from
 * it.
 *
 * The script grammar (ELFUSE_USB_LOOPBACK, or the guest's 0xF1 command below):
 *
 *   script := rule (';' rule)*
 *   rule   := 'ep' <hex address> ':' step (',' step)*
 *   step   := name ['(' number ')'] ['*' repeat]
 *
 * Endpoint 00 is the default control pipe. A rule's steps are consumed one per
 * transfer on that endpoint and the last one repeats forever; an endpoint with
 * no rule behaves as 'ok'. A delay step is not an outcome: it sets the delay
 * that the next outcome in the same rule waits before completing.
 *
 *   ok / ok(n)   kIOReturnSuccess. arg0 is the transferred count: the whole
 *                buffer, or n verbatim, which is how an over-reporting device
 *                (n > the submitted length) reaches the actual_length clamp.
 *   short(n)     kIOReturnUnderrun with arg0 = n. usbfs treats a short read as
 *                success, so this is the URB_SHORT_NOT_OK input as well.
 *   stall        kIOUSBPipeStalled, the -EPIPE row.
 *   timeout      kIOUSBTransactionTimeout, the -ETIMEDOUT row.
 *   nodev        kIOReturnNoDevice: -ENODEV plus the disconnect mark the
 *                completion callback makes from that code alone.
 *   err(code)    any IOReturn verbatim; with no argument, kIOReturnIOError,
 *                which is the map's default -EPROTO row.
 *   refuse(code) the submit entry point itself returns code instead of
 *                scheduling anything, which is the start-gate path where the
 *                URB-status map has to be used rather than the syscall map.
 *                With no argument, kIOReturnNotOpen.
 *   never        accepted and never completed: DISCARDURB's abort, the drain
 *                deadline and orphaning all need a transfer that sits there.
 *   delay(ms)    the next outcome completes ms milliseconds later.
 *   terminate    the device terminates, with no completion for the transfer
 *                that triggered it and kIOReturnNoDevice for every later start.
 *                That is what the board actually does: three URBs outstanding
 *                at terminate produced zero callbacks, and CAP_REAP_AFTER_
 *                DISCONNECT's self-issued kill exists for exactly that.
 *   zlpfail      the transfer succeeds and the terminating zero-length write
 *                the completion callback then issues comes back stalled.
 *
 * Vendor control requests on the fixture device itself are the control plane,
 * so a guest can drive many scenarios in one process. They are answered inside
 * DeviceRequestTO, which is the synchronous ioctl path, so they never disturb
 * the async script:
 *
 *   0xC0 0xF0  read the wire log from record wValue, 32 bytes per record
 *   0x40 0xF1  replace the script with the request payload
 *   0x40 0xF2  terminate the device in wValue milliseconds
 *   0x40 0xF3  clear the wire log and the loopback data stash
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/usb/USB.h>

#include "debug/log.h"
#include "runtime/usb-fixture.h"
#include "syscall/linux-wire.h"
#include "syscall/usbdev-fixture.h"

/* mode */

bool usbdev_fixture_loopback(void)
{
    static _Atomic int cached = -1;
    int v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v < 0) {
        const char *env = getenv("ELFUSE_USB_FIXTURE");
        v = (env && !strcmp(env, "loopback")) ? 1 : 0;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    return v != 0;
}

/* script */

typedef enum {
    FX_DELAY = 0,
    FX_OK,
    FX_SHORT,
    FX_STALL,
    FX_TIMEOUT,
    FX_NODEV,
    FX_ERR,
    FX_REFUSE,
    FX_NEVER,
    FX_TERMINATE,
    FX_ZLPFAIL,
    FX_ABORTED, /* not spellable: what an abort turns a transfer into */
} fx_act_t;

typedef struct {
    uint8_t act;
    bool has_arg;
    uint32_t arg;
} fx_step_t;

#define FX_MAX_RULES 16
#define FX_MAX_STEPS 32

typedef struct {
    bool used;
    uint8_t ep;
    int nsteps;
    int cursor;
    fx_step_t steps[FX_MAX_STEPS];
} fx_rule_t;

/* One 32-byte wire-log record, serialized little-endian for the guest. The
 * count is written at submit and patched at completion, so a transfer that is
 * still in flight (or never completes) is in the log too.
 */
typedef struct {
    uint8_t kind; /* 1 async, 2 sync pipe, 3 zero-length write, 4 control */
    uint8_t ep;
    uint8_t flags; /* bit 0: IN */
    uint8_t
        concurrent; /* transfers in flight on this endpoint, this included */
    uint32_t requested;
    uint32_t actual;
    uint32_t ioreturn;
    uint32_t seq;
    uint32_t start_ms;
    uint8_t data[8];
} fx_rec_t;

#define FX_REC_BYTES 32
#define FX_LOG_MAX 128
#define FX_STASH_MAX 4096
#define FX_MAX_XFERS 64
#define FX_MAX_WATCH 32

typedef struct {
    uint32_t location_id;
    fx_rule_t rules[FX_MAX_RULES];
    bool terminated;
    uint8_t stash[FX_STASH_MAX];
    uint32_t stash_len;
    fx_rec_t log[FX_LOG_MAX];
    unsigned nlog;
    unsigned seq;
    unsigned inflight_ep[256];
    bool zlp_fail[256];
    uint64_t t0_ms;
    struct {
        bool used;
        IOServiceInterestCallback cb;
        void *refcon;
    } watch[FX_MAX_WATCH];
} fx_dev_t;

typedef struct {
    bool used;
    fx_dev_t *dev;
    uint8_t ep;
    bool is_in;
    bool abort;
    void *buf;
    uint32_t size;
    uint8_t act;
    bool has_arg;
    uint32_t arg;
    IOAsyncCallback1 cb;
    void *refcon;
    CFRunLoopTimerRef timer;
    int logidx;
} fx_xfer_t;

/* One device, one lock. A leaf: the timer callback takes it, drops it, and only
 * then calls into usbdev.c, so async_lock is never held beneath it and it is
 * never held beneath async_lock across a callback. See internal.h.
 */
static pthread_mutex_t usbdev_fixture_lock = PTHREAD_MUTEX_INITIALIZER;
static fx_dev_t fx_dev;
static bool fx_dev_ready;
static fx_xfer_t fx_xfers[FX_MAX_XFERS];
static CFRunLoopRef fx_loop;

static uint64_t fx_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) (ts.tv_nsec / 1000000);
}

static const char *fx_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n')
        p++;
    return p;
}

static bool fx_word(const char **pp, const char *word)
{
    size_t n = strlen(word);
    if (strncmp(*pp, word, n) != 0)
        return false;
    *pp += n;
    return true;
}

/* Parse one step.
 *
 * Returns false on anything unrecognized, which the caller reports rather than
 * silently running a different script than it was given.
 */
static bool fx_parse_step(const char **pp, fx_step_t *st, int *repeat)
{
    const char *p = fx_skip_ws(*pp);
    st->has_arg = false;
    st->arg = 0;
    *repeat = 1;
    if (fx_word(&p, "delay"))
        st->act = FX_DELAY;
    else if (fx_word(&p, "ok"))
        st->act = FX_OK;
    else if (fx_word(&p, "short"))
        st->act = FX_SHORT;
    else if (fx_word(&p, "stall"))
        st->act = FX_STALL;
    else if (fx_word(&p, "timeout"))
        st->act = FX_TIMEOUT;
    else if (fx_word(&p, "nodev"))
        st->act = FX_NODEV;
    else if (fx_word(&p, "err"))
        st->act = FX_ERR;
    else if (fx_word(&p, "refuse"))
        st->act = FX_REFUSE;
    else if (fx_word(&p, "never"))
        st->act = FX_NEVER;
    else if (fx_word(&p, "terminate"))
        st->act = FX_TERMINATE;
    else if (fx_word(&p, "zlpfail"))
        st->act = FX_ZLPFAIL;
    else
        return false;
    if (*p == '(') {
        char *end = NULL;
        unsigned long v = strtoul(p + 1, &end, 0);
        if (!end || *end != ')')
            return false;
        st->has_arg = true;
        st->arg = (uint32_t) v;
        p = end + 1;
    }
    if (*p == '*') {
        char *end = NULL;
        unsigned long v = strtoul(p + 1, &end, 10);
        if (!end || end == p + 1 || v == 0)
            return false;
        *repeat = (int) (v > FX_MAX_STEPS ? FX_MAX_STEPS : v);
        p = end;
    }
    *pp = fx_skip_ws(p);
    return true;
}

/* Replace the whole rule set. Called with the lock held. */
static void fx_script_load(fx_dev_t *d, const char *script)
{
    memset(d->rules, 0, sizeof(d->rules));
    if (!script || !*script)
        return;
    const char *p = script;
    int nrules = 0;
    while (*p && nrules < FX_MAX_RULES) {
        p = fx_skip_ws(p);
        if (!fx_word(&p, "ep")) {
            log_warn("usbdev fixture: script wants ep<hex>: at \"%s\"", p);
            return;
        }
        char *end = NULL;
        unsigned long ep = strtoul(p, &end, 16);
        if (!end || end == p || ep > 0xff || *end != ':') {
            log_warn("usbdev fixture: bad endpoint in script at \"%s\"", p);
            return;
        }
        p = end + 1;
        fx_rule_t *r = &d->rules[nrules++];
        r->used = true;
        r->ep = (uint8_t) ep;
        r->nsteps = 0;
        r->cursor = 0;
        for (;;) {
            fx_step_t st;
            int rep = 1;
            if (!fx_parse_step(&p, &st, &rep)) {
                log_warn("usbdev fixture: bad step in script at \"%s\"", p);
                r->used = false;
                return;
            }
            for (int i = 0; i < rep && r->nsteps < FX_MAX_STEPS; i++)
                r->steps[r->nsteps++] = st;
            if (*p != ',')
                break;
            p++;
        }
        if (*p == ';')
            p++;
        else if (*p)
            break;
    }
}

/* The next outcome for ep, plus the delay the steps ahead of it asked for. The
 * cursor stops on the last outcome, so it repeats.
 */
static void fx_next(fx_dev_t *d, uint8_t ep, fx_step_t *out, uint32_t *delay_ms)
{
    out->act = FX_OK;
    out->has_arg = false;
    out->arg = 0;
    *delay_ms = 0;
    fx_rule_t *r = NULL;
    for (int i = 0; i < FX_MAX_RULES; i++) {
        if (d->rules[i].used && d->rules[i].ep == ep) {
            r = &d->rules[i];
            break;
        }
    }
    if (!r || r->nsteps == 0)
        return;
    for (;;) {
        int i = r->cursor;
        if (i >= r->nsteps) {
            /* Past the end: repeat the last outcome, with the delay that came
             * with it.
             */
            for (int k = r->nsteps - 1; k >= 0; k--) {
                if (r->steps[k].act != FX_DELAY) {
                    *out = r->steps[k];
                    if (k > 0 && r->steps[k - 1].act == FX_DELAY)
                        *delay_ms = r->steps[k - 1].arg;
                    return;
                }
            }
            return;
        }
        if (r->steps[i].act == FX_DELAY) {
            *delay_ms += r->steps[i].arg;
            r->cursor++;
            continue;
        }
        *out = r->steps[i];
        r->cursor++;
        return;
    }
}

/* wire log */

static int fx_log_open(fx_dev_t *d,
                       uint8_t kind,
                       uint8_t ep,
                       bool is_in,
                       uint32_t requested,
                       const void *payload,
                       unsigned concurrent)
{
    if (d->nlog >= FX_LOG_MAX)
        return -1;
    if (d->t0_ms == 0)
        d->t0_ms = fx_now_ms();
    int idx = (int) d->nlog++;
    fx_rec_t *r = &d->log[idx];
    memset(r, 0, sizeof(*r));
    r->kind = kind;
    r->ep = ep;
    r->flags = is_in ? 1u : 0u;
    r->concurrent = (uint8_t) (concurrent > 255 ? 255 : concurrent);
    r->requested = requested;
    r->ioreturn = 0xffffffffu; /* still in flight */
    r->seq = ++d->seq;
    r->start_ms = (uint32_t) (fx_now_ms() - d->t0_ms);
    if (payload && requested)
        memcpy(r->data, payload, requested < 8 ? requested : 8);
    return idx;
}

static void fx_log_close(fx_dev_t *d,
                         int idx,
                         uint32_t actual,
                         IOReturn result,
                         const void *payload)
{
    if (idx < 0 || idx >= (int) d->nlog)
        return;
    fx_rec_t *r = &d->log[idx];
    r->actual = actual;
    r->ioreturn = (uint32_t) result;
    if (payload && (r->flags & 1u)) {
        uint32_t n = actual < 8 ? actual : 8;
        memcpy(r->data, payload, n);
    }
}

static void fx_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) v;
    p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16);
    p[3] = (uint8_t) (v >> 24);
}

static void fx_rec_serialize(const fx_rec_t *r, uint8_t *out)
{
    memset(out, 0, FX_REC_BYTES);
    out[0] = r->kind;
    out[1] = r->ep;
    out[2] = r->flags;
    out[3] = r->concurrent;
    fx_put32(out + 4, r->requested);
    fx_put32(out + 8, r->actual);
    fx_put32(out + 12, r->ioreturn);
    fx_put32(out + 16, r->seq);
    fx_put32(out + 20, r->start_ms);
    memcpy(out + 24, r->data, 8);
}

/* loopback data */

/* What an IN transfer hands back: the bytes the last OUT wrote, or a
 * deterministic ramp when nothing has been written yet.
 *
 * Returns the count.
 */
static uint32_t fx_fill_in(fx_dev_t *d, void *buf, uint32_t size)
{
    if (!buf || !size)
        return 0;
    uint8_t *b = buf;
    if (d->stash_len) {
        uint32_t n = size < d->stash_len ? size : d->stash_len;
        memcpy(b, d->stash, n);
        return n;
    }
    for (uint32_t i = 0; i < size; i++)
        b[i] = (uint8_t) (0xa0u + (i & 0x0fu));
    return size;
}

static void fx_store_out(fx_dev_t *d, const void *buf, uint32_t size)
{
    if (!buf || !size)
        return;
    uint32_t n = size > FX_STASH_MAX ? FX_STASH_MAX : size;
    memcpy(d->stash, buf, n);
    d->stash_len = n;
}

/* completions */

static void fx_timer_cb(CFRunLoopTimerRef timer, void *info);
static void fx_terminate_cb(CFRunLoopTimerRef timer, void *info);

/* Arm a one-shot timer on the event runloop (lock held). Timers are never
 * canceled: an abort moves the fire date forward and the outcome is decided
 * inside the callback, so a completion that was already dispatched cannot be
 * completed twice.
 */
static CFRunLoopTimerRef fx_arm(uint32_t delay_ms,
                                CFRunLoopTimerCallBack fn,
                                void *info)
{
    if (!fx_loop)
        return NULL;
    CFRunLoopTimerContext ctx = {0, info, NULL, NULL, NULL};
    CFRunLoopTimerRef t = CFRunLoopTimerCreate(
        kCFAllocatorDefault,
        CFAbsoluteTimeGetCurrent() + (double) delay_ms / 1000.0, 0, 0, 0, fn,
        &ctx);
    if (!t)
        return NULL;
    CFRunLoopAddTimer(fx_loop, t, kCFRunLoopDefaultMode);
    CFRunLoopWakeUp(fx_loop);
    return t;
}

static void fx_deliver_terminate(fx_dev_t *d)
{
    struct {
        IOServiceInterestCallback cb;
        void *refcon;
    } snap[FX_MAX_WATCH];
    int n = 0;
    pthread_mutex_lock(&usbdev_fixture_lock);
    d->terminated = true;
    for (int i = 0; i < FX_MAX_WATCH; i++) {
        if (d->watch[i].used && d->watch[i].cb) {
            snap[n].cb = d->watch[i].cb;
            snap[n].refcon = d->watch[i].refcon;
            n++;
        }
    }
    pthread_mutex_unlock(&usbdev_fixture_lock);

    /* Outside the lock, the way IOKit calls it: usbdev_interest_cb takes the
     * table lock and then the entry's async_lock underneath it.
     */
    for (int i = 0; i < n; i++)
        snap[i].cb(snap[i].refcon, IO_OBJECT_NULL,
                   kIOMessageServiceIsTerminated, NULL);
}

static void fx_terminate_cb(CFRunLoopTimerRef timer, void *info)
{
    CFRelease(timer);
    fx_deliver_terminate(info);
}

static void fx_timer_cb(CFRunLoopTimerRef timer, void *info)
{
    fx_xfer_t *x = info;
    pthread_mutex_lock(&usbdev_fixture_lock);
    if (!x->used || x->timer != timer) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return;
    }
    fx_dev_t *d = x->dev;
    IOReturn result = kIOReturnSuccess;
    uint32_t actual = 0;
    uint8_t act = x->abort ? (uint8_t) FX_ABORTED : x->act;
    switch (act) {
    case FX_ABORTED:
        result = kIOReturnAborted;
        break;
    case FX_STALL:
        result = kIOUSBPipeStalled;
        break;
    case FX_TIMEOUT:
        result = kIOUSBTransactionTimeout;
        break;
    case FX_NODEV:
        result = kIOReturnNoDevice;
        break;
    case FX_ERR:
        result = x->has_arg ? (IOReturn) x->arg : kIOReturnIOError;
        break;
    case FX_SHORT:
        result = kIOReturnUnderrun;
        actual = x->is_in ? fx_fill_in(d, x->buf, x->size) : x->size;
        if (x->has_arg)
            actual = x->arg;
        break;
    case FX_ZLPFAIL:
        d->zlp_fail[x->ep] = true;
        __attribute__((fallthrough));
    default:
        actual = x->is_in ? fx_fill_in(d, x->buf, x->size) : x->size;
        if (!x->is_in)
            fx_store_out(d, x->buf, x->size);
        if (x->has_arg)
            actual = x->arg;
        break;
    }
    fx_log_close(d, x->logidx, actual, result, x->is_in ? x->buf : NULL);
    if (d->inflight_ep[x->ep])
        d->inflight_ep[x->ep]--;
    IOAsyncCallback1 cb = x->cb;
    void *refcon = x->refcon;
    x->used = false;
    x->timer = NULL;
    pthread_mutex_unlock(&usbdev_fixture_lock);
    CFRelease(timer);

    /* On the event thread, with no fixture lock held: exactly where
     * IODispatchCalloutFromCFMessage would have run usbdev_async_cb.
     */
    if (cb)
        cb(refcon, result, (void *) (uintptr_t) actual);
}

/* Hand a transfer to the fixture.
 *
 * Returns what the IOKit entry point returns: the async entry points never call
 * back inline, because usbdev_urb_start calls them with async_lock held.
 */
static IOReturn fx_submit(fx_dev_t *d,
                          uint8_t ep,
                          bool is_in,
                          void *buf,
                          uint32_t size,
                          IOAsyncCallback1 cb,
                          void *refcon)
{
    pthread_mutex_lock(&usbdev_fixture_lock);
    if (d->terminated) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return kIOReturnNoDevice;
    }
    fx_step_t st;
    uint32_t delay_ms = 0;
    fx_next(d, ep, &st, &delay_ms);
    if (st.act == FX_REFUSE) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return st.has_arg ? (IOReturn) st.arg : kIOReturnNotOpen;
    }
    fx_xfer_t *x = NULL;
    for (int i = 0; i < FX_MAX_XFERS; i++) {
        if (!fx_xfers[i].used) {
            x = &fx_xfers[i];
            break;
        }
    }
    if (!x) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return kIOReturnNoResources;
    }
    memset(x, 0, sizeof(*x));
    x->used = true;
    x->dev = d;
    x->ep = ep;
    x->is_in = is_in;
    x->buf = buf;
    x->size = size;
    x->act = st.act;
    x->has_arg = st.has_arg;
    x->arg = st.arg;
    x->cb = cb;
    x->refcon = refcon;
    unsigned conc = ++d->inflight_ep[ep];
    x->logidx = fx_log_open(d, 1, ep, is_in, size, is_in ? NULL : buf, conc);
    if (st.act == FX_TERMINATE) {
        /* No completion for this one, the way the board answers a terminate. */
        CFRunLoopTimerRef t = fx_arm(delay_ms, fx_terminate_cb, d);
        if (!t) {
            d->inflight_ep[ep]--;
            x->used = false;
            pthread_mutex_unlock(&usbdev_fixture_lock);
            return kIOReturnNotOpen;
        }
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return kIOReturnSuccess;
    }
    if (st.act != FX_NEVER) {
        x->timer = fx_arm(delay_ms, fx_timer_cb, x);
        if (!x->timer) {
            d->inflight_ep[ep]--;
            x->used = false;
            pthread_mutex_unlock(&usbdev_fixture_lock);
            return kIOReturnNotOpen;
        }
    }
    pthread_mutex_unlock(&usbdev_fixture_lock);
    return kIOReturnSuccess;
}

/* AbortPipe / USBDeviceAbortPipeZero: asynchronous, the way IOKit's are. Every
 * transfer outstanding on the endpoint is turned into kIOReturnAborted and
 * completed from the event thread, which is the whole reason DISCARDURB shuts
 * the endpoint's FIFO around the call.
 */
static IOReturn fx_abort(fx_dev_t *d, uint8_t ep)
{
    pthread_mutex_lock(&usbdev_fixture_lock);
    for (int i = 0; i < FX_MAX_XFERS; i++) {
        fx_xfer_t *x = &fx_xfers[i];
        if (!x->used || x->dev != d || x->ep != ep)
            continue;
        x->abort = true;
        if (x->timer)
            CFRunLoopTimerSetNextFireDate(x->timer, CFAbsoluteTimeGetCurrent());
        else
            x->timer = fx_arm(0, fx_timer_cb, x);
    }
    if (fx_loop)
        CFRunLoopWakeUp(fx_loop);
    pthread_mutex_unlock(&usbdev_fixture_lock);
    return kIOReturnSuccess;
}

/* the control plane, answered inside DeviceRequestTO */

#define FX_CMD_LOG 0xf0
#define FX_CMD_SCRIPT 0xf1
#define FX_CMD_TERMINATE 0xf2
#define FX_CMD_RESET 0xf3

static bool fx_command(fx_dev_t *d, IOUSBDevRequestTO *req, IOReturn *out)
{
    if ((req->bmRequestType & 0x60) != 0x40 || req->bRequest < 0xf0)
        return false;
    *out = kIOReturnSuccess;
    req->wLenDone = 0;
    switch (req->bRequest) {
    case FX_CMD_LOG: {
        pthread_mutex_lock(&usbdev_fixture_lock);
        unsigned first = req->wValue;
        uint8_t *p = req->pData;
        uint32_t room = p ? req->wLength / FX_REC_BYTES : 0;
        uint32_t n = 0;
        for (; first + n < d->nlog && n < room; n++)
            fx_rec_serialize(&d->log[first + n], p + n * FX_REC_BYTES);
        req->wLenDone = n * FX_REC_BYTES;
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return true;
    }
    case FX_CMD_SCRIPT: {
        char buf[512];
        uint32_t n = req->wLength < sizeof(buf) - 1
                         ? req->wLength
                         : (uint32_t) sizeof(buf) - 1;
        if (n && req->pData)
            memcpy(buf, req->pData, n);
        else
            n = 0;
        buf[n] = '\0';
        pthread_mutex_lock(&usbdev_fixture_lock);
        fx_script_load(d, buf);
        pthread_mutex_unlock(&usbdev_fixture_lock);
        req->wLenDone = req->wLength;
        return true;
    }
    case FX_CMD_TERMINATE: {
        pthread_mutex_lock(&usbdev_fixture_lock);
        CFRunLoopTimerRef t = fx_arm(req->wValue, fx_terminate_cb, d);
        pthread_mutex_unlock(&usbdev_fixture_lock);
        if (!t)
            *out =
                kIOReturnNotOpen; /* no event thread yet: nothing to run on */
        return true;
    }
    case FX_CMD_RESET:
        pthread_mutex_lock(&usbdev_fixture_lock);
        d->nlog = 0;
        d->seq = 0;
        d->t0_ms = 0;
        d->stash_len = 0;
        memset(d->zlp_fail, 0, sizeof(d->zlp_fail));
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return true;
    default:
        *out = kIOReturnUnsupported;
        return true;
    }
}

/* the two objects */

typedef struct {
    IOUSBDeviceInterface650 *vtbl; /* first: the handle is &obj->vtbl */
    fx_dev_t *dev;
} fx_devobj_t;

typedef struct {
    IOUSBInterfaceInterface800 *vtbl;
    fx_dev_t *dev;
    unsigned ifnum;
} fx_ifobj_t;

static fx_dev_t *fx_of_dev(void *self)
{
    return ((fx_devobj_t *) self)->dev;
}

static fx_dev_t *fx_of_if(void *self)
{
    return ((fx_ifobj_t *) self)->dev;
}

static uint8_t fx_pipe_ep(UInt8 pipeRef)
{
    if (pipeRef == 0 || pipeRef > USB_FIXTURE_LOOPBACK_NEPS)
        return 0;
    return usb_fixture_loopback_eps[pipeRef - 1].addr;
}

static HRESULT fx_query(void *self, REFIID iid, LPVOID *ppv)
{
    (void) self;
    (void) iid;
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG fx_addref(void *self)
{
    (void) self;
    return 1;
}

static ULONG fx_release_dev(void *self)
{
    free(self);
    return 0;
}

static ULONG fx_release_if(void *self)
{
    free(self);
    return 0;
}

static IOReturn fx_ok0(void *self)
{
    (void) self;
    return kIOReturnSuccess;
}

static void fx_source_noop(void *info)
{
    (void) info;
}

/* A real CFRunLoopSource with nothing behind it: usbdev.c adds it to the event
 * runloop and removes and releases it at teardown, and both must be genuine
 * CoreFoundation calls on a genuine object.
 */
static IOReturn fx_create_source(void *self, CFRunLoopSourceRef *source)
{
    (void) self;
    CFRunLoopSourceContext ctx = {0};
    ctx.perform = fx_source_noop;
    CFRunLoopSourceRef s = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &ctx);
    if (!s)
        return kIOReturnNoMemory;
    *source = s;
    return kIOReturnSuccess;
}

static IOReturn fx_dev_request_to(void *self, IOUSBDevRequestTO *req)
{
    fx_dev_t *d = fx_of_dev(self);
    IOReturn cmd = kIOReturnSuccess;
    if (fx_command(d, req, &cmd))
        return cmd;
    pthread_mutex_lock(&usbdev_fixture_lock);
    if (d->terminated) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return kIOReturnNoDevice;
    }
    bool in = (req->bmRequestType & 0x80) != 0 && req->wLength != 0;
    uint32_t n = in ? fx_fill_in(d, req->pData, req->wLength) : req->wLength;
    if (!in)
        fx_store_out(d, req->pData, req->wLength);
    int idx = fx_log_open(d, 4, 0, in, req->wLength, in ? NULL : req->pData, 1);
    fx_log_close(d, idx, n, kIOReturnSuccess, in ? req->pData : NULL);
    req->wLenDone = n;
    pthread_mutex_unlock(&usbdev_fixture_lock);
    return kIOReturnSuccess;
}

static IOReturn fx_dev_request_async_to(void *self,
                                        IOUSBDevRequestTO *req,
                                        IOAsyncCallback1 cb,
                                        void *refcon)
{
    bool in = (req->bmRequestType & 0x80) != 0 && req->wLength != 0;
    return fx_submit(fx_of_dev(self), 0, in, req->pData, req->wLength, cb,
                     refcon);
}

static IOReturn fx_abort_pipe_zero(void *self)
{
    return fx_abort(fx_of_dev(self), 0);
}

static IOReturn fx_set_configuration(void *self, UInt8 cfg)
{
    (void) self;
    return cfg == 1 ? kIOReturnSuccess : kIOReturnBadArgument;
}

static IOReturn fx_create_iface_iterator(void *self,
                                         IOUSBFindInterfaceRequest *req,
                                         io_iterator_t *iter)
{
    (void) self;
    (void) req;
    *iter = IO_OBJECT_NULL;
    return kIOReturnSuccess;
}

static IOReturn fx_get_num_endpoints(void *self, UInt8 *ne)
{
    (void) self;
    *ne = USB_FIXTURE_LOOPBACK_NEPS;
    return kIOReturnSuccess;
}

static IOReturn fx_get_pipe_properties(void *self,
                                       UInt8 pipeRef,
                                       UInt8 *dir,
                                       UInt8 *num,
                                       UInt8 *type,
                                       UInt16 *mps,
                                       UInt8 *interval)
{
    (void) self;
    if (pipeRef == 0 || pipeRef > USB_FIXTURE_LOOPBACK_NEPS)
        return kIOReturnBadArgument;
    const usb_fixture_ep_t *e = &usb_fixture_loopback_eps[pipeRef - 1];
    *dir = (e->addr & 0x80) ? kUSBIn : kUSBOut;
    *num = e->addr & 0x0f;
    *type = (e->attr & 0x03) == 0x03 ? kUSBInterrupt : kUSBBulk;
    *mps = e->mps;
    *interval = e->interval;
    return kIOReturnSuccess;
}

static IOReturn fx_abort_pipe(void *self, UInt8 pipeRef)
{
    return fx_abort(fx_of_if(self), fx_pipe_ep(pipeRef));
}

static IOReturn fx_clear_stall(void *self, UInt8 pipeRef)
{
    (void) self;
    return pipeRef && pipeRef <= USB_FIXTURE_LOOPBACK_NEPS
               ? kIOReturnSuccess
               : kIOReturnBadArgument;
}

static IOReturn fx_set_alt(void *self, UInt8 alt)
{
    (void) self;
    return alt == 0 ? kIOReturnSuccess : kIOReturnBadArgument;
}

static IOReturn fx_read_pipe_to(void *self,
                                UInt8 pipeRef,
                                void *buf,
                                UInt32 *size,
                                UInt32 ndt,
                                UInt32 ct)
{
    (void) ndt;
    (void) ct;
    fx_dev_t *d = fx_of_if(self);
    uint8_t ep = fx_pipe_ep(pipeRef);
    pthread_mutex_lock(&usbdev_fixture_lock);
    if (d->terminated) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return kIOReturnNoDevice;
    }
    uint32_t n = fx_fill_in(d, buf, *size);
    int idx = fx_log_open(d, 2, ep, true, *size, NULL, 1);
    fx_log_close(d, idx, n, kIOReturnSuccess, buf);
    *size = n;
    pthread_mutex_unlock(&usbdev_fixture_lock);
    return kIOReturnSuccess;
}

/* Also the ZERO_PACKET path: usbdev_async_cb issues the terminating packet as a
 * size-0 WritePipeTO from the event thread with async_lock dropped, and this is
 * where that packet becomes observable.
 */
static IOReturn fx_write_pipe_to(void *self,
                                 UInt8 pipeRef,
                                 void *buf,
                                 UInt32 size,
                                 UInt32 ndt,
                                 UInt32 ct)
{
    (void) ndt;
    (void) ct;
    fx_dev_t *d = fx_of_if(self);
    uint8_t ep = fx_pipe_ep(pipeRef);
    pthread_mutex_lock(&usbdev_fixture_lock);
    if (d->terminated) {
        pthread_mutex_unlock(&usbdev_fixture_lock);
        return kIOReturnNoDevice;
    }
    IOReturn r = kIOReturnSuccess;
    if (size == 0 && d->zlp_fail[ep]) {
        d->zlp_fail[ep] = false;
        r = kIOUSBPipeStalled;
    }
    int idx = fx_log_open(d, size == 0 ? 3 : 2, ep, false, size, buf, 1);
    fx_log_close(d, idx, r == kIOReturnSuccess ? size : 0, r, NULL);
    if (r == kIOReturnSuccess && size)
        fx_store_out(d, buf, size);
    pthread_mutex_unlock(&usbdev_fixture_lock);
    return r;
}

static IOReturn fx_read_pipe_async(void *self,
                                   UInt8 pipeRef,
                                   void *buf,
                                   UInt32 size,
                                   IOAsyncCallback1 cb,
                                   void *refcon)
{
    return fx_submit(fx_of_if(self), fx_pipe_ep(pipeRef), true, buf, size, cb,
                     refcon);
}

static IOReturn fx_write_pipe_async(void *self,
                                    UInt8 pipeRef,
                                    void *buf,
                                    UInt32 size,
                                    IOAsyncCallback1 cb,
                                    void *refcon)
{
    return fx_submit(fx_of_if(self), fx_pipe_ep(pipeRef), false, buf, size, cb,
                     refcon);
}

static IOReturn fx_read_pipe_async_to(void *self,
                                      UInt8 pipeRef,
                                      void *buf,
                                      UInt32 size,
                                      UInt32 ndt,
                                      UInt32 ct,
                                      IOAsyncCallback1 cb,
                                      void *refcon)
{
    (void) ndt;
    (void) ct;
    return fx_read_pipe_async(self, pipeRef, buf, size, cb, refcon);
}

static IOReturn fx_write_pipe_async_to(void *self,
                                       UInt8 pipeRef,
                                       void *buf,
                                       UInt32 size,
                                       UInt32 ndt,
                                       UInt32 ct,
                                       IOAsyncCallback1 cb,
                                       void *refcon)
{
    (void) ndt;
    (void) ct;
    return fx_write_pipe_async(self, pipeRef, buf, size, cb, refcon);
}

static IOReturn fx_control_request_async_to(void *self,
                                            UInt8 pipeRef,
                                            IOUSBDevRequestTO *req,
                                            IOAsyncCallback1 cb,
                                            void *refcon)
{
    bool in = (req->bmRequestType & 0x80) != 0 && req->wLength != 0;
    return fx_submit(fx_of_if(self), fx_pipe_ep(pipeRef), in, req->pData,
                     req->wLength, cb, refcon);
}

static IOUSBDeviceInterface650 fx_dev_vtbl = {
    .QueryInterface = fx_query,
    .AddRef = fx_addref,
    .Release = fx_release_dev,
    .CreateDeviceAsyncEventSource = fx_create_source,
    .USBDeviceOpen = fx_ok0,
    .USBDeviceClose = fx_ok0,
    .SetConfiguration = fx_set_configuration,
    .DeviceRequestTO = fx_dev_request_to,
    .DeviceRequestAsyncTO = fx_dev_request_async_to,
    .USBDeviceAbortPipeZero = fx_abort_pipe_zero,
    .CreateInterfaceIterator = fx_create_iface_iterator,
};

static IOUSBInterfaceInterface800 fx_if_vtbl = {
    .QueryInterface = fx_query,
    .AddRef = fx_addref,
    .Release = fx_release_if,
    .CreateInterfaceAsyncEventSource = fx_create_source,
    .USBInterfaceOpen = fx_ok0,
    .USBInterfaceClose = fx_ok0,
    .GetNumEndpoints = fx_get_num_endpoints,
    .GetPipeProperties = fx_get_pipe_properties,
    .SetAlternateInterface = fx_set_alt,
    .AbortPipe = fx_abort_pipe,
    .ClearPipeStallBothEnds = fx_clear_stall,
    .ReadPipeTO = fx_read_pipe_to,
    .WritePipeTO = fx_write_pipe_to,
    .ReadPipeAsync = fx_read_pipe_async,
    .WritePipeAsync = fx_write_pipe_async,
    .ReadPipeAsyncTO = fx_read_pipe_async_to,
    .WritePipeAsyncTO = fx_write_pipe_async_to,
    .ControlRequestAsyncTO = fx_control_request_async_to,
};

/* Every entry usbdev.c reaches through one of the two handles. A vtable slot
 * left NULL is a null call at runtime rather than a compile error, so the list
 * is checked once instead of being discovered by a crash inside a lane.
 */
static void fx_vtable_check(void)
{
    const struct {
        const void *fn;
        const char *name;
    } required[] = {
        {(const void *) fx_dev_vtbl.Release, "Release"},
        {(const void *) fx_dev_vtbl.USBDeviceOpen, "USBDeviceOpen"},
        {(const void *) fx_dev_vtbl.USBDeviceClose, "USBDeviceClose"},
        {(const void *) fx_dev_vtbl.CreateDeviceAsyncEventSource,
         "CreateDeviceAsyncEventSource"},
        {(const void *) fx_dev_vtbl.SetConfiguration, "SetConfiguration"},
        {(const void *) fx_dev_vtbl.DeviceRequestTO, "DeviceRequestTO"},
        {(const void *) fx_dev_vtbl.DeviceRequestAsyncTO,
         "DeviceRequestAsyncTO"},
        {(const void *) fx_dev_vtbl.USBDeviceAbortPipeZero,
         "USBDeviceAbortPipeZero"},
        {(const void *) fx_dev_vtbl.CreateInterfaceIterator,
         "CreateInterfaceIterator"},
        {(const void *) fx_if_vtbl.Release, "Release"},
        {(const void *) fx_if_vtbl.USBInterfaceOpen, "USBInterfaceOpen"},
        {(const void *) fx_if_vtbl.USBInterfaceClose, "USBInterfaceClose"},
        {(const void *) fx_if_vtbl.CreateInterfaceAsyncEventSource,
         "CreateInterfaceAsyncEventSource"},
        {(const void *) fx_if_vtbl.GetNumEndpoints, "GetNumEndpoints"},
        {(const void *) fx_if_vtbl.GetPipeProperties, "GetPipeProperties"},
        {(const void *) fx_if_vtbl.SetAlternateInterface,
         "SetAlternateInterface"},
        {(const void *) fx_if_vtbl.AbortPipe, "AbortPipe"},
        {(const void *) fx_if_vtbl.ClearPipeStallBothEnds,
         "ClearPipeStallBothEnds"},
        {(const void *) fx_if_vtbl.ReadPipeTO, "ReadPipeTO"},
        {(const void *) fx_if_vtbl.WritePipeTO, "WritePipeTO"},
        {(const void *) fx_if_vtbl.ReadPipeAsync, "ReadPipeAsync"},
        {(const void *) fx_if_vtbl.WritePipeAsync, "WritePipeAsync"},
        {(const void *) fx_if_vtbl.ReadPipeAsyncTO, "ReadPipeAsyncTO"},
        {(const void *) fx_if_vtbl.WritePipeAsyncTO, "WritePipeAsyncTO"},
        {(const void *) fx_if_vtbl.ControlRequestAsyncTO,
         "ControlRequestAsyncTO"},
    };
    for (unsigned i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (!required[i].fn)
            log_warn("usbdev fixture: vtable entry %s is NULL",
                     required[i].name);
    }
}

/* seam */

void usbdev_fixture_bind_loop(CFRunLoopRef loop)
{
    if (!usbdev_fixture_loopback())
        return;
    pthread_mutex_lock(&usbdev_fixture_lock);
    fx_loop = loop;
    pthread_mutex_unlock(&usbdev_fixture_lock);
}

/* Resolve the one modeled device, standing it up on first use. */
static fx_dev_t *fx_device(uint32_t location_id)
{
    if (!usbdev_fixture_loopback() ||
        location_id != USB_FIXTURE_LOOPBACK_LOCATION)
        return NULL;
    pthread_mutex_lock(&usbdev_fixture_lock);
    if (!fx_dev_ready) {
        fx_dev.location_id = location_id;
        fx_script_load(&fx_dev, getenv("ELFUSE_USB_LOOPBACK"));
        fx_dev_ready = true;
        fx_vtable_check();
    }
    fx_dev_t *d = &fx_dev;
    pthread_mutex_unlock(&usbdev_fixture_lock);
    return d;
}

bool usbdev_fixture_has_device(uint32_t location_id, unsigned vid, unsigned pid)
{
    return fx_device(location_id) != NULL && vid == USB_FIXTURE_LOOPBACK_VID &&
           pid == USB_FIXTURE_LOOPBACK_PID;
}

int64_t usbdev_fixture_open_device(uint32_t location_id,
                                   unsigned vid,
                                   unsigned pid,
                                   IOUSBDeviceInterface650 ***out)
{
    fx_dev_t *d = fx_device(location_id);
    if (!d || vid != USB_FIXTURE_LOOPBACK_VID ||
        pid != USB_FIXTURE_LOOPBACK_PID)
        return -LINUX_ENODEV;
    fx_devobj_t *o = calloc(1, sizeof(*o));
    if (!o)
        return -LINUX_ENOMEM;
    o->vtbl = &fx_dev_vtbl;
    o->dev = d;
    *out = &o->vtbl;
    return 0;
}

int64_t usbdev_fixture_open_iface(uint32_t location_id,
                                  unsigned ifnum,
                                  IOUSBInterfaceInterface800 ***out)
{
    fx_dev_t *d = fx_device(location_id);
    if (!d)
        return -LINUX_ENODEV;
    if (ifnum != USB_FIXTURE_LOOPBACK_IFNUM)
        return -LINUX_ENOENT;
    fx_ifobj_t *o = calloc(1, sizeof(*o));
    if (!o)
        return -LINUX_ENOMEM;
    o->vtbl = &fx_if_vtbl;
    o->dev = d;
    o->ifnum = ifnum;
    *out = &o->vtbl;
    return 0;
}

void usbdev_fixture_watch(uint32_t location_id,
                          IOServiceInterestCallback cb,
                          void *refcon)
{
    fx_dev_t *d = fx_device(location_id);
    if (!d)
        return;
    pthread_mutex_lock(&usbdev_fixture_lock);
    int free_slot = -1;
    for (int i = 0; i < FX_MAX_WATCH; i++) {
        if (d->watch[i].used && d->watch[i].refcon == refcon) {
            free_slot = i;
            break;
        }
        if (free_slot < 0 && !d->watch[i].used)
            free_slot = i;
    }
    if (free_slot >= 0) {
        d->watch[free_slot].used = true;
        d->watch[free_slot].cb = cb;
        d->watch[free_slot].refcon = refcon;
    }
    pthread_mutex_unlock(&usbdev_fixture_lock);
}

void usbdev_fixture_unwatch(void *refcon)
{
    if (!usbdev_fixture_loopback())
        return;
    pthread_mutex_lock(&usbdev_fixture_lock);
    for (int i = 0; i < FX_MAX_WATCH; i++) {
        if (fx_dev.watch[i].used && fx_dev.watch[i].refcon == refcon)
            fx_dev.watch[i].used = false;
    }
    pthread_mutex_unlock(&usbdev_fixture_lock);
}
