/*
 * The loopback fixture device's model, shared by the two halves that must agree
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * ELFUSE_USB_FIXTURE=loopback stands up one extra device whose descriptors come
 * from usb-sysfs.c and whose IOKit answers come from syscall/usbdev-fixture.c.
 * The endpoint table below is the single place both read: a descriptor blob
 * that advertises an endpoint GetPipeProperties does not report (or the other
 * way round) is a fixture that tests the wrong device, and the two halves live
 * in different directories, so the table is a header rather than a duplicated
 * literal.
 *
 * The addresses are the ones the out-of-tree board driver uses against the
 * ESP32-S3 at 303a:1001 (interface 2, bulk OUT 0x02, bulk IN 0x81, interrupt IN
 * 0x83), so a scenario can be written once and run in both places.
 */

#pragma once

#include <stdint.h>

typedef struct {
    uint8_t addr;     /* bEndpointAddress */
    uint8_t attr;     /* bmAttributes: 0x02 bulk, 0x03 interrupt */
    uint16_t mps;     /* wMaxPacketSize */
    uint8_t interval; /* bInterval */
} usb_fixture_ep_t;

#define USB_FIXTURE_LOOPBACK_BUS 3
#define USB_FIXTURE_LOOPBACK_PORT 1
#define USB_FIXTURE_LOOPBACK_DEVNUM 1
#define USB_FIXTURE_LOOPBACK_IFNUM 2
#define USB_FIXTURE_LOOPBACK_VID 0x303au
#define USB_FIXTURE_LOOPBACK_PID 0x1001u

/* model_build's own arithmetic, spelled once so the IOKit half can match a
 * device without re-deriving it: bus 1 is locationID 0x00xxxxxx.
 */
#define USB_FIXTURE_LOOPBACK_LOCATION                     \
    ((((uint32_t) USB_FIXTURE_LOOPBACK_BUS - 1u) << 24) | \
     ((uint32_t) USB_FIXTURE_LOOPBACK_PORT << 4))

#define USB_FIXTURE_LOOPBACK_NEPS 3

static const usb_fixture_ep_t
    usb_fixture_loopback_eps[USB_FIXTURE_LOOPBACK_NEPS] = {
        {0x02, 0x02, 64, 0}, /* bulk OUT */
        {0x81, 0x02, 64, 0}, /* bulk IN */
        {0x83, 0x03, 8, 1},  /* interrupt IN */
};
