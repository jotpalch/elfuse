/*
 * Bounded walks over raw USB descriptor blobs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A configuration blob is device-supplied: bLength and wTotalLength are bytes
 * the peripheral chose, not lengths the host derived, so a walk over them is a
 * walk over untrusted input. Every step here is expressed as an offset into the
 * buffer and advances only by what the buffer still holds; the cursor is never
 * moved past the end, which keeps both the loads and the pointer arithmetic
 * itself inside the object.
 *
 * Pure byte bookkeeping with no I/O and no IOKit, so the malformed-blob cases
 * are unit-testable without hardware (tests/test-usb-desc-host.c).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Standard descriptor type codes this layer names. */
#define USB_DT_DEVICE 1
#define USB_DT_CONFIG 2
#define USB_DT_INTERFACE 4
#define USB_DT_ENDPOINT 5

/* Shortest descriptor that can carry a type: bLength + bDescriptorType. */
#define USB_DESC_MIN_LEN 2

/* Fixed sizes of the descriptors this layer reads fields out of. */
#define USB_DEVICE_DESC_LEN 18
#define USB_CONFIG_DESC_LEN 9
#define USB_INTERFACE_DESC_LEN 9
#define USB_ENDPOINT_DESC_LEN 7

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t off;     /* cursor; the invariant is off <= len, always */
    bool truncated; /* a descriptor claimed more bytes than remained */
} usb_desc_iter_t;

void usb_desc_iter_init(usb_desc_iter_t *it, const uint8_t *buf, size_t len);

/* Next descriptor, or NULL once the blob is exhausted or malformed.
 *
 * Stops (and sets it->truncated) on a bLength below USB_DESC_MIN_LEN or a
 * bLength larger than the bytes that remain, because either means the rest of
 * the blob can no longer be located -- descriptors are self-delimiting, so a
 * bad length is the end of what can be read, not a record to skip. On stop the
 * cursor stays where the bad record began, so it->off still satisfies off <=
 * len and names how much of the blob was understood.
 *
 * *len_out receives the descriptor's bLength when non-NULL.
 */
const uint8_t *usb_desc_iter_next(usb_desc_iter_t *it, uint8_t *len_out);

/* Locate the configuration descriptor whose bConfigurationValue is cfg_value,
 * else the first well-formed one, inside a blob laid out as a device descriptor
 * followed by raw configuration descriptors (the usbfs read() view).
 *
 * A configuration spans wTotalLength bytes, so the search steps by that rather
 * than by bLength, and clamps it to the bytes that remain.
 *
 * Every candidate is checked to be a configuration header -- bLength exactly
 * USB_CONFIG_DESC_LEN and bDescriptorType USB_DT_CONFIG -- before any later
 * field is read from it, and the walk stops at the first record that is not
 * one. wTotalLength alone cannot be trusted to land the cursor on the next
 * configuration: a device that under-reports it would otherwise have an
 * interface descriptor matched on byte 5 and returned as its active config.
 *
 * Returns the descriptor with *len_out set to its usable span, or NULL when the
 * blob carries no configuration.
 */
const uint8_t *usb_desc_active_config(const uint8_t *blob,
                                      size_t blob_len,
                                      unsigned cfg_value,
                                      size_t *len_out);

/* Every distinct interface of a configuration, at alternate setting 0.
 *
 * `out` receives one pointer per bInterfaceNumber, in the order the numbers
 * first appear, pointing at that number's alternate-setting-0 descriptor inside
 * cfg. Later alternate settings and repeats of a number already seen are
 * skipped, which is the set sysfs turns into <dev>:<cfg>.<if> directories.
 *
 * USB_DESC_INTERFACES_MAX is the whole domain, not a policy: bInterfaceNumber
 * is a __u8 (linux/usb/ch9.h), so a configuration cannot name more distinct
 * interfaces than there are byte values, and a caller sized that way can never
 * lose one. A smaller table would not bound the walk -- cfg_len already does --
 * it would silently drop every interface numbered above it.
 *
 * *truncated_out, when non-NULL, reports whether the walk stopped on a
 * malformed record rather than at the end of the configuration, so the caller
 * can say so about a blob it only partly understood.
 *
 * Returns the count written, which is at most USB_DESC_INTERFACES_MAX.
 */
#define USB_DESC_INTERFACES_MAX 256

size_t usb_desc_interfaces(const uint8_t *cfg,
                           size_t cfg_len,
                           const uint8_t **out,
                           size_t outcap,
                           bool *truncated_out,
                           size_t *stop_off_out);

/* Longest configuration string this layer will render, matching the kernel's
 * MAX_USB_STRING_SIZE (message.c:1067): 127 UTF-16 code units at up to three
 * UTF-8 bytes each, plus the terminator. A string the device reports longer
 * than that is truncated by usb_string() on Linux too.
 */
#define USB_MAX_STRING_SIZE (127 * 3 + 1)

/* The four sysfs attributes Linux derives from the active configuration.
 *
 * Each member holds the file's exact contents including the trailing newline,
 * or an empty string when the value behind it is unavailable. Empty means an
 * empty file, never an absent one -- see usb_desc_actconfig_attrs.
 */
typedef struct {
    char num_interfaces[8]; /* bNumInterfaces */
    char bm_attributes[8];  /* bmAttributes   */
    char max_power[16];     /* bMaxPower      */
    char configuration[USB_MAX_STRING_SIZE + 1];
} usb_actconfig_attrs_t;

/* Render bNumInterfaces, bmAttributes, bMaxPower and configuration for the
 * active configuration descriptor cfg (cfg_len bytes usable, NULL when the blob
 * carried none), exactly as drivers/usb/core/sysfs.c renders them.
 *
 * All four live in the kernel's dev_attr_grp (sysfs.c:782-786), an attribute
 * group with no .is_visible hook (sysfs.c:815-817), so every USB device
 * directory carries all four files unconditionally. What varies is their
 * contents, not their presence: usb_actconfig_show (sysfs.c:29-43) leaves its
 * return value at the 0 that usb_lock_device_interruptible gave it when
 * udev->actconfig is NULL, which is a zero-length read rather than an error.
 * Emitting a file only when its value is known is therefore not the cautious
 * choice -- it turns a zero-length read into ENOENT, which is a different
 * answer to a reader that checks for the attribute's existence. That is why
 * this fills all four members on every call and the caller writes all four.
 *
 * configuration follows configuration_show (sysfs.c:71-87), which emits
 * "<string>\n" only when actconfig->string is non-NULL and nothing at all
 * otherwise. That string is usb_cache_string's result (message.c:1077-1100),
 * documented to be "NULL if the index is 0 or the string could not be read" --
 * so an empty configuration on Linux means "no cached string", which is a
 * strictly weaker statement than "iConfiguration is 0". Pass cfg_string NULL or
 * empty for the could-not-be-read case; it is ignored when iConfiguration is 0,
 * because index 0 makes usb_cache_string return NULL before it reads anything.
 *
 * max_power_unit is the mA per bMaxPower count that usb_get_max_power applies:
 * 8 at SuperSpeed and above, 2 below it. The caller owns the speed mapping.
 */
void usb_desc_actconfig_attrs(const uint8_t *cfg,
                              size_t cfg_len,
                              unsigned max_power_unit,
                              const char *cfg_string,
                              usb_actconfig_attrs_t *out);
