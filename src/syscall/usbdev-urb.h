/*
 * usbdevfs URB bookkeeping that needs no device
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The async engine in usbdev.c cannot be reached without an IOKit service
 * behind the node, so the parts of it that are pure arithmetic live here
 * instead: the disconnect-watch refcon, proc_do_submiturb's argument gate, the
 * transferred-byte clamp, the zero-length-packet predicate and the rule that
 * decides when an endpoint's queue may start its next URB. Each one is a place
 * this series has already shipped a defect, and each is decided before any
 * transfer, so tests/test-usbdev-urb-host.c exercises all of them on a machine
 * with no board attached.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "linux-wire.h"

/* No usbfs limit corresponds to this: Linux allocates a usb_dev_state per open.
 * The fixed table is a stage-2 simplification, so exhaustion is spelled -ENOMEM
 * -- a kernel-side resource shortfall -- rather than -EMFILE, which would tell
 * the guest its own descriptor limit is exhausted when it is not.
 */
#define USBDEV_MAX_FDS 32

/* The interest refcon packs the slot index with the open's fd-table generation
 * so a callback that outlives IOObjectRelease(u->notif) -- IOKit can have one
 * already dispatched on the event thread -- cannot mark a reused slot: the
 * generation of a later open never matches.
 *
 * The index field is sized from USBDEV_MAX_FDS rather than written out, because
 * writing it out is what went wrong: a 32-slot table with a four-bit index
 * decoded slot 16+k as slot k, so half the table never saw a disconnect and the
 * other half could be marked gone while still attached. The static assertion
 * below is the part that keeps the two from drifting again.
 */
#define USBDEV_WATCH_IDX_BITS 5
#define USBDEV_WATCH_IDX_MASK ((UINT64_C(1) << USBDEV_WATCH_IDX_BITS) - 1)
#define USBDEV_WATCH_GEN_MASK \
    ((UINT64_C(1) << (60 - USBDEV_WATCH_IDX_BITS)) - 1)

_Static_assert(USBDEV_MAX_FDS <= (1u << USBDEV_WATCH_IDX_BITS),
               "watch refcon index field is narrower than the slot table");

static inline uintptr_t usbdev_watch_pack(unsigned idx, uint64_t generation)
{
    return (uintptr_t) (((generation & USBDEV_WATCH_GEN_MASK)
                         << USBDEV_WATCH_IDX_BITS) |
                        (idx & USBDEV_WATCH_IDX_MASK));
}

/* Decode a refcon. False means the token cannot name a slot, which is what the
 * caller must treat as "drop this notification".
 */
static inline bool usbdev_watch_unpack(uintptr_t token,
                                       unsigned *idx,
                                       uint64_t *generation)
{
    unsigned i = (unsigned) (token & USBDEV_WATCH_IDX_MASK);
    if (i >= USBDEV_MAX_FDS)
        return false;
    *idx = i;
    *generation = (uint64_t) (token >> USBDEV_WATCH_IDX_BITS);
    return true;
}

/* USBFS_XFER_MAX (devio.c:140): UINT_MAX / 2 - 1000000, rejected with -EINVAL
 * before any allocation is attempted, so an oversize length never reaches the
 * memory budget and answers -ENOMEM.
 */
#define USBDEV_XFER_MAX (0xffffffffu / 2u - 1000000u)

#define LINUX_URB_TYPE_ISO 0
#define LINUX_URB_TYPE_INTERRUPT 1
#define LINUX_URB_TYPE_CONTROL 2
#define LINUX_URB_TYPE_BULK 3

#define LINUX_URB_SHORT_NOT_OK 0x01u
#define LINUX_URB_ISO_ASAP 0x02u
#define LINUX_URB_BULK_CONTINUATION 0x04u
#define LINUX_URB_NO_FSBR 0x20u
#define LINUX_URB_ZERO_PACKET 0x40u
#define LINUX_URB_NO_INTERRUPT 0x80u

/* proc_do_submiturb's first gate (devio.c:1631-1647), in the kernel's order:
 * the flags mask (ISO_ASAP is legal only on an ISO URB), then the length bound,
 * then the null buffer. Everything after it in the kernel needs the endpoint,
 * which is why this stops here -- resolving the endpoint before the per-type
 * checks is the ordering the caller must keep, and the ordering the async path
 * first got wrong while the synchronous path next door had it right.
 */
static inline int64_t usbdev_urb_arg_check(uint8_t type,
                                           uint32_t flags,
                                           int32_t buffer_length,
                                           bool buffer_null)
{
    uint32_t mask = LINUX_URB_SHORT_NOT_OK | LINUX_URB_BULK_CONTINUATION |
                    LINUX_URB_NO_FSBR | LINUX_URB_ZERO_PACKET |
                    LINUX_URB_NO_INTERRUPT;
    if (type == LINUX_URB_TYPE_ISO)
        mask |= LINUX_URB_ISO_ASAP;
    if (flags & ~mask)
        return -LINUX_EINVAL;
    if ((uint32_t) buffer_length >= USBDEV_XFER_MAX)
        return -LINUX_EINVAL;
    if (buffer_length > 0 && buffer_null)
        return -LINUX_EINVAL;
    return 0;
}

/* urb->actual_length is bounded by transfer_buffer_length in every Linux HCD,
 * so a guest that memcpy()s actual_length bytes out of its own buffer is
 * writing within its allocation. IOKit's transferred count is a device-supplied
 * number and gets the same bound here rather than being copied through.
 */
static inline uint32_t usbdev_urb_clamp_actual(uint64_t reported,
                                               uint32_t data_len)
{
    return reported > data_len ? data_len : (uint32_t) reported;
}

/* ZERO_PACKET: a maxpacket-multiple OUT with data gets a terminating
 * zero-length packet (darwin_usb.c:3193-3204). ep0 is excluded because the
 * control transfer carries its own status stage.
 */
static inline bool usbdev_urb_needs_zlp(int32_t status,
                                        bool zero_packet,
                                        uint8_t pipe,
                                        uint32_t data_len,
                                        uint16_t mps)
{
    return status == 0 && zero_packet && pipe > 0 && data_len > 0 && mps != 0 &&
           data_len % mps == 0;
}

/* Whether an endpoint's FIFO may hand its next URB to IOKit. AbortPipe cancels
 * every transfer outstanding on a pipe, so a queue that starts the follower
 * while an abort for the URB ahead of it is still in progress hands that abort
 * a bystander to cancel -- measured as the discarded URB reaping success and
 * its innocent successor reaping -ECONNRESET. An endpoint with an abort in
 * flight, and a slot being drained wholesale, both stay shut until the abort
 * that is running has returned.
 */
static inline bool usbdev_ep_may_start(bool draining,
                                       unsigned aborting,
                                       bool inflight)
{
    return !draining && aborting == 0 && !inflight;
}
