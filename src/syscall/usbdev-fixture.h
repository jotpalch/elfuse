/*
 * The IOKit COM seam behind ELFUSE_USB_FIXTURE=loopback
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Every wire call usbdev.c makes goes through one of two opaque handles,
 * IOUSBDeviceInterface650 ** and IOUSBInterfaceInterface800 **, always as
 * (*h)->Method(h, ...). Handing back a fixture object whose first member is a
 * vtable of the same shape substitutes for the device and changes nothing above
 * it: the URB records, the per-endpoint FIFO, the completion callback, the
 * readiness and disconnect maps, REAPURB and all of poll.c stay exactly the
 * code that runs against hardware. The only things replaced are the calls that
 * would have gone to the wire and the callbacks that would have come back from
 * it.
 *
 * Completions are delivered from a one-shot CFRunLoopTimer on the event thread
 * usbdev_loop_main runs, so usbdev_async_cb runs where
 * IODispatchCalloutFromCFMessage would have run it, under no lock the fixture
 * holds. The async entry points below only schedule; they never call back
 * inline, because usbdev_urb_start calls them with async_lock held.
 *
 * What the fixture is told to do is data, not a flag: ELFUSE_USB_LOOPBACK
 * carries a script of per-endpoint outcomes (see usbdev-fixture.c for the
 * grammar), and the guest can replace it, read the wire log back and terminate
 * the device through vendor control requests on the fixture device itself.
 *
 * All six entry points answer for the fixture only. usbdev_fixture_loopback()
 * is false in every normal run, usbdev_fixture_open_device refuses a location
 * the fixture does not model, and nothing else in this file is reachable then.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

/* Whether ELFUSE_USB_FIXTURE names the loopback model. Resolved once per
 * process, the shape usbdev_open_fault and fd_identity_window_delay use.
 */
bool usbdev_fixture_loopback(void);

/* Whether the fixture models the device at this location and identity. The
 * question is asked before any handle is created, because a fixture device has
 * no io_service_t: usbdev.c records a flag instead of a synthetic mach port,
 * and a port that is not one would eventually reach IOObjectRelease.
 */
bool usbdev_fixture_has_device(uint32_t location_id,
                               unsigned vid,
                               unsigned pid);

/* Tell the fixture which runloop carries completions. Called once by the event
 * thread as it starts; a no-op when the fixture is off.
 */
void usbdev_fixture_bind_loop(CFRunLoopRef loop);

/* A device handle for the fixture device at location_id, or -LINUX_ENODEV when
 * the fixture models no such device (which is every device but its own, so the
 * other ELFUSE_USB_FIXTURE modes keep answering exactly as before). The handle
 * is owned by the caller and released through its own Release entry.
 */
int64_t usbdev_fixture_open_device(uint32_t location_id,
                                   unsigned vid,
                                   unsigned pid,
                                   IOUSBDeviceInterface650 ***out);

/* An interface handle, already open: this stands in for the interface service
 * lookup, the plugin creation and USBInterfaceOpen at once, because all three
 * are IOKit and none of them has a per-step answer worth modeling.
 * -LINUX_ENOENT for an interface number the fixture device does not carry.
 */
int64_t usbdev_fixture_open_iface(uint32_t location_id,
                                  unsigned ifnum,
                                  IOUSBInterfaceInterface800 ***out);

/* Register / drop a terminate-interest callback, the
 * IOServiceAddInterestNotification half of the seam. refcon is usbdev.c's
 * packed slot token and identifies the registration.
 */
void usbdev_fixture_watch(uint32_t location_id,
                          IOServiceInterestCallback cb,
                          void *refcon);
void usbdev_fixture_unwatch(void *refcon);
