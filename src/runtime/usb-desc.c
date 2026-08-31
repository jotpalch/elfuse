/*
 * Bounded walks over raw USB descriptor blobs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See runtime/usb-desc.h for why these walks treat their input as untrusted.
 */

#include <stdio.h>

#include "runtime/usb-desc.h"

static uint16_t desc_le16(const uint8_t *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

void usb_desc_iter_init(usb_desc_iter_t *it, const uint8_t *buf, size_t len)
{
    it->buf = buf;
    it->len = buf ? len : 0;
    it->off = 0;
    it->truncated = false;
}

const uint8_t *usb_desc_iter_next(usb_desc_iter_t *it, uint8_t *len_out)
{
    size_t left = it->len - it->off; /* off <= len holds on entry and exit */
    if (left < USB_DESC_MIN_LEN) {
        it->truncated = left != 0;
        return NULL;
    }
    const uint8_t *d = it->buf + it->off;
    uint8_t blen = d[0];

    /* The comparison is done in the remaining-bytes domain, never by forming
     * it->buf + it->off + blen first: a bLength longer than the blob would make
     * that pointer itself out of bounds.
     */
    if (blen < USB_DESC_MIN_LEN || blen > left) {
        it->truncated = true;
        return NULL;
    }
    it->off += blen;
    if (len_out)
        *len_out = blen;
    return d;
}

size_t usb_desc_interfaces(const uint8_t *cfg,
                           size_t cfg_len,
                           const uint8_t **out,
                           size_t outcap,
                           bool *truncated_out,
                           size_t *stop_off_out)
{
    if (truncated_out)
        *truncated_out = false;
    if (stop_off_out)
        *stop_off_out = 0;
    if (!cfg || !out || outcap == 0)
        return 0;

    /* One bit per bInterfaceNumber value: the field is a byte, so 256 bits
     * cover every number a descriptor can carry and the dedup can never be the
     * reason an interface goes missing.
     */
    uint8_t seen[USB_DESC_INTERFACES_MAX / 8] = {0};
    size_t n = 0;

    usb_desc_iter_t it;
    usb_desc_iter_init(&it, cfg, cfg_len);
    const uint8_t *d;
    uint8_t dlen;
    while ((d = usb_desc_iter_next(&it, &dlen)) && n < outcap) {
        if (d[1] != USB_DT_INTERFACE || dlen < USB_INTERFACE_DESC_LEN)
            continue;
        if (d[3] != 0) /* bAlternateSetting */
            continue;
        unsigned ifnum = d[2];
        if (seen[ifnum >> 3] & (uint8_t) (1u << (ifnum & 7)))
            continue;
        seen[ifnum >> 3] |= (uint8_t) (1u << (ifnum & 7));
        out[n++] = d;
    }
    if (truncated_out)
        *truncated_out = it.truncated;
    if (stop_off_out)
        *stop_off_out = it.off;
    return n;
}

const uint8_t *usb_desc_active_config(const uint8_t *blob,
                                      size_t blob_len,
                                      unsigned cfg_value,
                                      size_t *len_out)
{
    if (!blob || blob_len < USB_DEVICE_DESC_LEN + USB_CONFIG_DESC_LEN)
        return NULL;

    size_t off = USB_DEVICE_DESC_LEN;
    const uint8_t *first = NULL;
    size_t first_len = 0;
    while (blob_len - off >= USB_CONFIG_DESC_LEN) {
        const uint8_t *p = blob + off;
        size_t left = blob_len - off;

        /* bLength and bDescriptorType are what identify this record as a
         * configuration header, and they are checked before any field past them
         * is read. Without this a device that under-reports wTotalLength walks
         * the cursor into the middle of its own configuration, and the next
         * record -- an interface descriptor, whose byte 5 is bInterfaceProtocol
         * rather than bConfigurationValue -- gets matched and returned as the
         * active configuration.
         */
        if (p[0] != USB_CONFIG_DESC_LEN || p[1] != USB_DT_CONFIG)
            break; /* not a configuration header; the walk ends here */

        size_t total = desc_le16(p + 2); /* wTotalLength */
        if (total < USB_CONFIG_DESC_LEN)
            break; /* not a locatable configuration; the walk ends here */
        /* A device that under-reports the trailing configuration still has a
         * usable header, so clamp rather than discard -- but clamping is also
         * what keeps the step below inside the blob.
         */
        if (total > left)
            total = left;
        if (!first) {
            first = p;
            first_len = total;
        }
        if (p[5] == (uint8_t) cfg_value) { /* bConfigurationValue */
            *len_out = total;
            return p;
        }
        off += total;
    }
    if (first) {
        *len_out = first_len;
        return first;
    }
    return NULL;
}

void usb_desc_actconfig_attrs(const uint8_t *cfg,
                              size_t cfg_len,
                              unsigned max_power_unit,
                              const char *cfg_string,
                              usb_actconfig_attrs_t *out)
{
    /* Empty first, so every early return still leaves four defined -- and
     * therefore four emitted -- attributes behind.
     */
    out->num_interfaces[0] = '\0';
    out->bm_attributes[0] = '\0';
    out->max_power[0] = '\0';
    out->configuration[0] = '\0';

    /* No active configuration is the kernel's actconfig == NULL: four files
     * that read empty, not four files that are missing.
     */
    if (!cfg || cfg_len < USB_CONFIG_DESC_LEN)
        return;

    /* Widths are the kernel's own format strings (sysfs.c:49-50, 65). */
    snprintf(out->num_interfaces, sizeof(out->num_interfaces), "%2d\n", cfg[4]);
    snprintf(out->bm_attributes, sizeof(out->bm_attributes), "%2x\n", cfg[7]);

    /* cfg[8] * max_power_unit cannot overflow: 255 * 8 == 2040. */
    snprintf(out->max_power, sizeof(out->max_power), "%umA\n",
             (unsigned) cfg[8] * max_power_unit);

    /* cfg[6] is iConfiguration. Index 0 short-circuits usb_cache_string before
     * any transfer, so a string handed in for such a configuration is not a
     * string Linux would ever have cached -- it is dropped rather than shown.
     */
    if (cfg[6] == 0 || !cfg_string || cfg_string[0] == '\0')
        return;

    /* Truncate the string, never the newline. usb_string() caps a cached string
     * at MAX_USB_STRING_SIZE bytes including its terminator, so anything Linux
     * could have cached is at most USB_MAX_STRING_SIZE - 1 characters and
     * "%s\n" fits exactly. A caller that hands over a longer one loses the tail
     * here as it would there, but the attribute still ends in the newline
     * sysfs_emit always writes: bounding "%s" alone would let snprintf trim the
     * newline instead and emit a last line Linux never produces.
     */
    snprintf(out->configuration, sizeof(out->configuration), "%.*s\n",
             (int) (sizeof(out->configuration) - 2), cfg_string);
}
