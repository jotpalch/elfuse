/*
 * Native-host unit tests for the URB bookkeeping that needs no device
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The async engine's own lane (tests/test-usbdev-ioctl.c) runs against
 * ELFUSE_USB_FIXTURE, where there is no IOKit service to complete a transfer,
 * so everything past SUBMITURB's argument gate is unreachable from it. That is
 * how a 2190-line engine came to ship with two constant compares behind it, and
 * how five of the defects a first review found -- a refcon that lost half the
 * slot table, a transferred count copied straight through from the device, a
 * URB count cap Linux does not have, an argument order the synchronous path
 * next door already had right, and an endpoint queue that handed AbortPipe a
 * bystander -- all sat in code no test executed.
 *
 * What is testable without a device is the arithmetic, so src/syscall/
 * usbdev-urb.h holds it and this binary exercises it directly on any machine,
 * board attached or not. Each case below fails on the shape that shipped: the
 * refcon cases fail with a four-bit index field, the argument cases fail
 * without USBFS_XFER_MAX, the clamp cases fail when the device's count is
 * copied through, and the queue cases fail when an endpoint with an abort in
 * flight is allowed to start its successor.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "syscall/usbdev-urb.h"

static int passes, fails;

static void check(bool ok, const char *what)
{
    if (ok) {
        passes++;
    } else {
        fails++;
        printf("  FAIL %s\n", what);
    }
}

/* Every slot the table has must survive a round trip, at generations whose low
 * bits collide with the index field. A four-bit index decoded slot 16+k as slot
 * k with the generation one higher, which both lost that slot's disconnect and
 * could deliver it to a live fd sitting in slot k.
 */
static void check_watch_refcon(void)
{
    printf("test-usbdev-urb-host: disconnect-watch refcon\n");
    for (unsigned slot = 0; slot < USBDEV_MAX_FDS; slot++) {
        for (uint64_t gen = 0; gen < 8; gen++) {
            uintptr_t tok = usbdev_watch_pack(slot, gen);
            unsigned got_slot = ~0u;
            uint64_t got_gen = ~UINT64_C(0);
            bool ok = usbdev_watch_unpack(tok, &got_slot, &got_gen);
            check(ok && got_slot == slot && got_gen == gen,
                  "slot/generation round trip");
        }
    }

    /* No two live (slot, generation) pairs may share a token: that is the
     * aliasing that marked an attached device gone.
     */
    for (unsigned a = 0; a < USBDEV_MAX_FDS; a++) {
        for (unsigned b = a + 1; b < USBDEV_MAX_FDS; b++)
            check(usbdev_watch_pack(a, 7) != usbdev_watch_pack(b, 7),
                  "two slots never share one token");
    }

    /* The generation field must still be wide enough that a slot cannot be
     * reused often enough to alias itself.
     */
    check(USBDEV_WATCH_GEN_MASK >= (UINT64_C(1) << 50) - 1,
          "generation field stays wide");
}

/* proc_do_submiturb's first gate, in the kernel's order. */
static void check_arg_gate(void)
{
    printf("test-usbdev-urb-host: SUBMITURB argument gate\n");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0, 64, false) == 0,
          "a plain bulk URB is accepted");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0x100, 64, false) ==
              -LINUX_EINVAL,
          "an undefined flag bit is EINVAL");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, LINUX_URB_ISO_ASAP, 64,
                               false) == -LINUX_EINVAL,
          "ISO_ASAP on a bulk URB is EINVAL");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_ISO, LINUX_URB_ISO_ASAP, 64,
                               false) == 0,
          "ISO_ASAP on an ISO URB passes the mask");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0, -1, false) ==
              -LINUX_EINVAL,
          "a negative length is EINVAL through the unsigned compare");

    /* USBFS_XFER_MAX, the bound that was missing outright: without it these
     * lengths reached the memory budget and answered -ENOMEM, and on the
     * default control pipe the largest of them was accepted.
     */
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0, 0x7fffffff, false) ==
              -LINUX_EINVAL,
          "INT32_MAX is EINVAL, not ENOMEM");
    check(
        usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0, (int32_t) USBDEV_XFER_MAX,
                             false) == -LINUX_EINVAL,
        "exactly USBFS_XFER_MAX is EINVAL");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0,
                               (int32_t) USBDEV_XFER_MAX - 1, false) == 0,
          "one below USBFS_XFER_MAX passes the gate");
    check(
        usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0, 64, true) == -LINUX_EINVAL,
        "a null buffer with a positive length is EINVAL");
    check(usbdev_urb_arg_check(LINUX_URB_TYPE_BULK, 0, 0, true) == 0,
          "a null buffer with no length is fine");
}

/* urb->actual_length never exceeds the buffer the guest handed over. */
static void check_actual_clamp(void)
{
    printf("test-usbdev-urb-host: transferred-count clamp\n");
    check(usbdev_urb_clamp_actual(0, 64) == 0, "zero stays zero");
    check(usbdev_urb_clamp_actual(18, 64) == 18, "a short count passes");
    check(usbdev_urb_clamp_actual(64, 64) == 64, "an exact count passes");
    check(usbdev_urb_clamp_actual(65, 64) == 64, "one byte over is clamped");
    check(usbdev_urb_clamp_actual(UINT64_C(0xffffffff), 64) == 64,
          "a wild count is clamped, not reported");
    check(usbdev_urb_clamp_actual(4096, 0) == 0,
          "a zero-length URB reports nothing transferred");
}

static void check_zlp_predicate(void)
{
    printf("test-usbdev-urb-host: ZERO_PACKET predicate\n");
    check(usbdev_urb_needs_zlp(0, true, 1, 64, 64), "a maxpacket multiple");
    check(!usbdev_urb_needs_zlp(0, false, 1, 64, 64), "flag clear");
    check(!usbdev_urb_needs_zlp(-32, true, 1, 64, 64), "failed URB");
    check(!usbdev_urb_needs_zlp(0, true, 0, 64, 64), "ep0 is excluded");
    check(!usbdev_urb_needs_zlp(0, true, 1, 0, 64), "no data");
    check(!usbdev_urb_needs_zlp(0, true, 1, 100, 64), "not a multiple");
    check(!usbdev_urb_needs_zlp(0, true, 1, 64, 0), "unknown maxpacket");
}

/* AbortPipe's granularity is the whole pipe, so the FIFO stays shut until the
 * abort that is running has returned.
 */
static void check_ep_gate(void)
{
    printf("test-usbdev-urb-host: endpoint start gate\n");
    check(usbdev_ep_may_start(false, 0, false), "idle endpoint starts");
    check(!usbdev_ep_may_start(false, 0, true), "busy endpoint waits");
    check(!usbdev_ep_may_start(false, 1, false),
          "an abort in flight holds the successor back");
    check(!usbdev_ep_may_start(true, 0, false), "a slot being drained is shut");
    check(!usbdev_ep_may_start(true, 2, true), "all three at once");
}

int main(void)
{
    check_watch_refcon();
    check_arg_gate();
    check_actual_clamp();
    check_zlp_predicate();
    check_ep_gate();
    printf("test-usbdev-urb-host: %d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
