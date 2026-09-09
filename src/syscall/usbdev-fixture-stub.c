/*
 * The USB fixture seam, answered by a build that carries no fixture
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * usbdev.c asks the seam in syscall/usbdev-fixture.h whether a fixture models
 * the device it is about to open, and takes the IOKit registry path when the
 * answer is no. That question is worth asking unconditionally, because the
 * answer is what keeps the fixture out of the paths it must not touch; the
 * model behind a yes is not, because only an assertion wants a device that
 * echoes back what was written to it. So the question is compiled into every
 * binary and the model is not: this file says no to all of it, and
 * syscall/usbdev-fixture.c is linked in place of it when USB_LOOPBACK_FIXTURE
 * asks for the model (mk/config.mk).
 *
 * Answering at the link rather than at the call sites is what leaves usbdev.c
 * one program in both builds. Not one of its branches is conditionally
 * compiled, so the fixture cannot drift into code the default build never
 * compiles, and the whole cost of the seam in a shipped binary is these seven
 * bodies plus the calls that reach them: one per device open, one per interface
 * claim, one per disconnect watch, and one as the event thread starts.
 */

#include <stdbool.h>
#include <stdint.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include "syscall/linux-wire.h"
#include "syscall/usbdev-fixture.h"

bool usbdev_fixture_loopback(void)
{
    return false;
}

bool usbdev_fixture_has_device(uint32_t location_id, unsigned vid, unsigned pid)
{
    return false;
}

void usbdev_fixture_bind_loop(CFRunLoopRef loop) {}

/* -ENODEV, not -ENOSYS or a crash: the caller asked for a device this build
 * does not have, which is the same answer the model gives for every location
 * but its own, and the answer Linux reports for a device that is gone.
 */
int64_t usbdev_fixture_open_device(uint32_t location_id,
                                   unsigned vid,
                                   unsigned pid,
                                   IOUSBDeviceInterface650 ***out)
{
    return -LINUX_ENODEV;
}

int64_t usbdev_fixture_open_iface(uint32_t location_id,
                                  unsigned ifnum,
                                  IOUSBInterfaceInterface800 ***out)
{
    return -LINUX_ENODEV;
}

void usbdev_fixture_watch(uint32_t location_id,
                          IOServiceInterestCallback cb,
                          void *refcon)
{
}

void usbdev_fixture_unwatch(void *refcon) {}
