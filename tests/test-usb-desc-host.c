/*
 * Native-host unit tests for the raw USB descriptor walks
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Configuration blobs arrive from the peripheral, so bLength and wTotalLength
 * are attacker-shaped numbers. These cases feed the walker (runtime/usb-desc.c)
 * the three malformed shapes a real device can produce -- a bLength longer than
 * the bytes that remain, a zero-length descriptor, and a header truncated
 * mid-record -- and assert the two things that must hold for every one of them:
 * the walk terminates, and its cursor never leaves the buffer. The cursor bound
 * is asserted directly rather than inferred, because a walk that steps past the
 * end and only then re-tests its guard still yields the right interface list
 * while having formed an out-of-bounds pointer; nothing but the cursor itself
 * distinguishes the two.
 *
 * Interfaces read before the malformed record must still be reported: a device
 * with a trailing junk descriptor is common, and dropping its whole
 * configuration would lose the interface dirs libusb enumerates.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "runtime/usb-desc.h"

/* Collect the bInterfaceNumbers of alternate setting 0, exactly as
 * emit_interface_dirs does, and report where the walk stopped.
 */
static int walk_interfaces(const unsigned char *buf,
                           size_t len,
                           unsigned char *out,
                           size_t *stop_off,
                           int *truncated)
{
    usb_desc_iter_t it;
    usb_desc_iter_init(&it, buf, len);
    int n = 0;
    const unsigned char *d;
    unsigned char dlen;
    while ((d = usb_desc_iter_next(&it, &dlen))) {
        /* The invariant, checked on every single step and not just at the end:
         * a cursor past the end means an out-of-bounds pointer was formed.
         */
        assert(it.off <= it.len);
        if (d[1] == USB_DT_INTERFACE && dlen >= USB_INTERFACE_DESC_LEN &&
            d[3] == 0)
            out[n++] = d[2];
    }
    assert(it.off <= it.len);
    *stop_off = it.off;
    *truncated = it.truncated;
    return n;
}

/* config descriptor header, then `nif` nine-byte interface descriptors */
static size_t build_config(unsigned char *buf,
                           unsigned cfg_value,
                           unsigned nif,
                           size_t total_override)
{
    size_t off = 0;
    size_t total = USB_CONFIG_DESC_LEN + nif * USB_INTERFACE_DESC_LEN;
    size_t declared = total_override ? total_override : total;
    buf[off++] = USB_CONFIG_DESC_LEN;
    buf[off++] = USB_DT_CONFIG;
    buf[off++] = (unsigned char) (declared & 0xff);
    buf[off++] = (unsigned char) (declared >> 8);
    buf[off++] = (unsigned char) nif; /* bNumInterfaces */
    buf[off++] = (unsigned char) cfg_value;
    buf[off++] = 0; /* iConfiguration */
    buf[off++] = 0xa0;
    buf[off++] = 50;
    for (unsigned i = 0; i < nif; i++) {
        buf[off++] = USB_INTERFACE_DESC_LEN;
        buf[off++] = USB_DT_INTERFACE;
        buf[off++] = (unsigned char) i; /* bInterfaceNumber */
        buf[off++] = 0;                 /* bAlternateSetting */
        buf[off++] = 1;                 /* bNumEndpoints */
        buf[off++] = 0xff;
        buf[off++] = 0;
        buf[off++] = 0;
        buf[off++] = 0;
    }
    return off;
}

static void test_well_formed_blob_is_fully_consumed(void)
{
    unsigned char buf[64], ifs[8];
    size_t len = build_config(buf, 1, 2, 0);
    size_t stop = 0;
    int trunc = 1;
    int n = walk_interfaces(buf, len, ifs, &stop, &trunc);
    assert(n == 2 && ifs[0] == 0 && ifs[1] == 1);
    assert(stop == len);
    assert(!trunc);
}

/* bLength claims more than the buffer still holds: the pre-fix walk advanced
 * the cursor by that claim and left the buffer behind.
 */
static void test_blength_past_the_end_stops_in_bounds(void)
{
    unsigned char buf[64], ifs[8];
    size_t len = build_config(buf, 1, 1, 0);
    size_t before = len;
    buf[len++] = 200; /* bLength far beyond the four bytes that follow */
    buf[len++] = USB_DT_INTERFACE;
    buf[len++] = 7;
    buf[len++] = 0;
    size_t stop = 0;
    int trunc = 0;
    int n = walk_interfaces(buf, len, ifs, &stop, &trunc);
    assert(n == 1 && ifs[0] == 0); /* the readable interface survives */
    assert(stop == before);        /* stopped at the bad record, not past it */
    assert(trunc);
}

static void test_zero_length_descriptor_stops(void)
{
    unsigned char buf[64], ifs[8];
    size_t len = build_config(buf, 1, 1, 0);
    size_t before = len;
    buf[len++] = 0; /* bLength 0: advancing by it would never terminate */
    buf[len++] = USB_DT_INTERFACE;
    buf[len++] = 9;
    buf[len++] = 0;
    size_t stop = 0;
    int trunc = 0;
    int n = walk_interfaces(buf, len, ifs, &stop, &trunc);
    assert(n == 1 && stop == before && trunc);
}

/* A nine-byte interface descriptor with only five bytes left behind it. */
static void test_truncated_interface_descriptor_stops(void)
{
    unsigned char buf[64], ifs[8];
    size_t len = build_config(buf, 1, 1, 0);
    size_t before = len;
    buf[len++] = USB_INTERFACE_DESC_LEN;
    buf[len++] = USB_DT_INTERFACE;
    buf[len++] = 1;
    buf[len++] = 0;
    buf[len++] = 1;
    size_t stop = 0;
    int trunc = 0;
    int n = walk_interfaces(buf, len, ifs, &stop, &trunc);
    assert(n == 1 && ifs[0] == 0);
    assert(stop == before && trunc);
}

/* One trailing byte cannot even carry bLength + bDescriptorType. */
static void test_single_trailing_byte_stops(void)
{
    unsigned char buf[64], ifs[8];
    size_t len = build_config(buf, 1, 1, 0);
    size_t before = len;
    buf[len++] = USB_INTERFACE_DESC_LEN;
    size_t stop = 0;
    int trunc = 0;
    int n = walk_interfaces(buf, len, ifs, &stop, &trunc);
    assert(n == 1 && stop == before && trunc);
}

static void test_empty_and_null_buffers(void)
{
    usb_desc_iter_t it;
    usb_desc_iter_init(&it, NULL, 99);
    assert(usb_desc_iter_next(&it, NULL) == NULL && it.off == 0);
    unsigned char buf[4] = {0};
    usb_desc_iter_init(&it, buf, 0);
    assert(usb_desc_iter_next(&it, NULL) == NULL && it.off == 0 &&
           !it.truncated);
}

/* device descriptor + two configurations, the second one selected */
static size_t build_blob(unsigned char *buf, size_t total_override)
{
    memset(buf, 0, USB_DEVICE_DESC_LEN);
    buf[0] = USB_DEVICE_DESC_LEN;
    buf[1] = USB_DT_DEVICE;
    size_t off = USB_DEVICE_DESC_LEN;
    off += build_config(buf + off, 1, 1, 0);
    off += build_config(buf + off, 2, 2, total_override);
    return off;
}

static void test_active_config_selects_by_value(void)
{
    unsigned char buf[128];
    size_t len = build_blob(buf, 0);
    size_t clen = 0;
    const unsigned char *cfg = usb_desc_active_config(buf, len, 2, &clen);
    assert(cfg && cfg[5] == 2 && clen == USB_CONFIG_DESC_LEN + 2 * 9);

    /* No such value: the first configuration, not a NULL and not the last. */
    cfg = usb_desc_active_config(buf, len, 7, &clen);
    assert(cfg && cfg[5] == 1 && clen == USB_CONFIG_DESC_LEN + 9);
}

/* wTotalLength larger than the blob: the step must clamp, not run off. */
static void test_active_config_clamps_overlong_total(void)
{
    unsigned char buf[128];
    size_t len = build_blob(buf, 60000);
    size_t clen = 0;
    const unsigned char *cfg = usb_desc_active_config(buf, len, 2, &clen);
    assert(cfg && cfg[5] == 2);
    assert(clen == len - (size_t) (cfg - buf)); /* clamped to what remains */

    /* And the walk that would have to step over it still terminates. */
    cfg = usb_desc_active_config(buf, len, 9, &clen);
    assert(cfg && cfg[5] == 1);
}

/* wTotalLength under-reported: the header is a real configuration, but the span
 * it names stops short of the interface behind it, so the cursor lands on that
 * interface descriptor. An interface descriptor's bytes 2-3 are
 * bInterfaceNumber/bAlternateSetting, which the pre-fix walk read as
 * wTotalLength, and its byte 5 is bInterfaceClass, which the pre-fix walk
 * compared against bConfigurationValue -- so the interface was returned as the
 * device's active configuration.
 */
static void test_active_config_ignores_non_config_records(void)
{
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = USB_DEVICE_DESC_LEN;
    buf[1] = USB_DT_DEVICE;
    size_t off = USB_DEVICE_DESC_LEN;

    /* Configuration value 1, under-reporting wTotalLength as the header alone
     */
    buf[off++] = USB_CONFIG_DESC_LEN;
    buf[off++] = USB_DT_CONFIG;
    buf[off++] = USB_CONFIG_DESC_LEN; /* wTotalLength lo: the header only */
    buf[off++] = 0;                   /* wTotalLength hi */
    buf[off++] = 1;                   /* bNumInterfaces */
    buf[off++] = 1;                   /* bConfigurationValue */
    buf[off++] = 0;                   /* iConfiguration */
    buf[off++] = 0xa0;                /* bmAttributes */
    buf[off++] = 50;                  /* bMaxPower */

    /* The interface the configuration failed to cover. bInterfaceNumber is 32
     * so bytes 2-3 read as a wTotalLength of 32 -- past the header minimum, so
     * the pre-fix walk accepted the record and stepped by it.
     */
    buf[off++] = USB_INTERFACE_DESC_LEN;
    buf[off++] = USB_DT_INTERFACE;
    buf[off++] = 32;   /* bInterfaceNumber (pre-fix: wTotalLength lo) */
    buf[off++] = 0;    /* bAlternateSetting (pre-fix: wTotalLength hi) */
    buf[off++] = 1;    /* bNumEndpoints */
    buf[off++] = 0x07; /* bInterfaceClass (pre-fix: bConfigurationValue) */
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    size_t len = off;

    /* Ask for the interface's bInterfaceClass as if it were a configuration
     * value: nothing in the blob has bConfigurationValue 7, so the only way to
     * return a match is to have matched the interface descriptor.
     */
    size_t clen = 0;
    const unsigned char *cfg = usb_desc_active_config(buf, len, 0x07, &clen);
    assert(cfg != NULL);
    assert(cfg[1] == USB_DT_CONFIG); /* never an interface descriptor */
    assert(cfg[0] == USB_CONFIG_DESC_LEN);
    assert(cfg[5] == 1);                 /* the real config, via fallback */
    assert(clen == USB_CONFIG_DESC_LEN); /* the span its header declared */

    /* The same blob asked for its real value still answers with the header. */
    cfg = usb_desc_active_config(buf, len, 1, &clen);
    assert(cfg && cfg[1] == USB_DT_CONFIG && cfg[5] == 1);
}

/* A configuration header whose bLength is not USB_CONFIG_DESC_LEN is not a
 * configuration header, even when bDescriptorType and wTotalLength agree.
 */
static void test_active_config_rejects_bad_header_length(void)
{
    unsigned char buf[128];
    size_t len = build_blob(buf, 0);

    buf[USB_DEVICE_DESC_LEN] = 0; /* bLength 0 */
    size_t clen = 0;
    assert(usb_desc_active_config(buf, len, 1, &clen) == NULL);

    buf[USB_DEVICE_DESC_LEN] = USB_CONFIG_DESC_LEN + 1; /* merely wrong */
    assert(usb_desc_active_config(buf, len, 1, &clen) == NULL);
}

/* bDescriptorType wrong: the record is well-formed and long enough, and its
 * byte 5 would match, but it is not a configuration.
 */
static void test_active_config_rejects_bad_header_type(void)
{
    unsigned char buf[128];
    size_t len = build_blob(buf, 0);

    buf[USB_DEVICE_DESC_LEN + 1] = USB_DT_INTERFACE;
    size_t clen = 0;
    assert(usb_desc_active_config(buf, len, 1, &clen) == NULL);

    buf[USB_DEVICE_DESC_LEN + 1] = USB_DT_DEVICE;
    assert(usb_desc_active_config(buf, len, 1, &clen) == NULL);
}

/* A malformed leading configuration must not hide a well-formed one behind it
 * -- but it does end the walk, because the bad record's span cannot be trusted
 * to say where the next one starts. The first config stays authoritative.
 */
static void test_active_config_stops_at_first_bad_record(void)
{
    unsigned char buf[128];
    size_t len = build_blob(buf, 0);

    /* Corrupt the *second* configuration's type; the first is still returned
     * for its own value, and the second is no longer reachable at all.
     */
    size_t second = USB_DEVICE_DESC_LEN + USB_CONFIG_DESC_LEN + 9;
    assert(buf[second] == USB_CONFIG_DESC_LEN &&
           buf[second + 1] == USB_DT_CONFIG);
    buf[second + 1] = 0x21; /* HID descriptor type */

    size_t clen = 0;
    const unsigned char *cfg = usb_desc_active_config(buf, len, 1, &clen);
    assert(cfg && cfg[5] == 1 && clen == USB_CONFIG_DESC_LEN + 9);

    /* Value 2 lives only in the corrupted record, so the fallback answers. */
    cfg = usb_desc_active_config(buf, len, 2, &clen);
    assert(cfg && cfg[5] == 1);
    assert(cfg[1] == USB_DT_CONFIG);
}

static void test_active_config_rejects_short_blobs(void)
{
    unsigned char buf[128];
    size_t clen = 0;
    size_t len = build_blob(buf, 0);
    assert(usb_desc_active_config(buf, USB_DEVICE_DESC_LEN, 1, &clen) == NULL);
    assert(usb_desc_active_config(NULL, len, 1, &clen) == NULL);

    /* wTotalLength below the header size names no locatable configuration. */
    buf[USB_DEVICE_DESC_LEN + 2] = 3;
    buf[USB_DEVICE_DESC_LEN + 3] = 0;
    assert(usb_desc_active_config(buf, len, 1, &clen) == NULL);
}


/* The active-configuration attribute set.
 *
 * These are the cases the attached hardware cannot reach. Both devices on the
 * development board report iConfiguration 0, so nothing local exercises the
 * branch where a configuration names a string -- and the branch where the blob
 * carries no configuration at all needs a device that does not enumerate.
 * Feeding usb_desc_actconfig_attrs a synthesized descriptor runs every branch
 * on any host, with no bus involved.
 */

/* offsets inside a configuration descriptor */
#define CFG_I_CONFIGURATION 6
#define CFG_BMATTRIBUTES 7
#define CFG_BMAXPOWER 8

static void test_actconfig_no_configuration_is_four_empty_files(void)
{
    usb_actconfig_attrs_t a;

    /* actconfig == NULL on Linux: usb_actconfig_show and configuration_show
     * both return the 0 the lock gave them, so all four attributes read empty.
     * They are still present -- dev_attr_grp has no .is_visible -- which is
     * what the caller relies on when it writes all four unconditionally.
     */
    memset(&a, 0xaa, sizeof(a));
    usb_desc_actconfig_attrs(NULL, 0, 2, "ignored", &a);
    assert(a.num_interfaces[0] == '\0');
    assert(a.bm_attributes[0] == '\0');
    assert(a.max_power[0] == '\0');
    assert(a.configuration[0] == '\0');

    /* A cfg_len below the header size is the same situation: nothing can be
     * read out of it, so nothing is claimed about it.
     */
    unsigned char buf[64];
    build_config(buf, 1, 1, 0);
    memset(&a, 0xaa, sizeof(a));
    usb_desc_actconfig_attrs(buf, USB_CONFIG_DESC_LEN - 1, 2, "ignored", &a);
    assert(a.num_interfaces[0] == '\0');
    assert(a.bm_attributes[0] == '\0');
    assert(a.max_power[0] == '\0');
    assert(a.configuration[0] == '\0');
}

static void test_actconfig_fields_use_the_kernel_formats(void)
{
    unsigned char buf[64];
    usb_actconfig_attrs_t a;
    size_t len = build_config(buf, 1, 2, 0);

    buf[CFG_BMATTRIBUTES] = 0xe0;
    buf[CFG_BMAXPOWER] = 50;
    usb_desc_actconfig_attrs(buf, len, 2, NULL, &a);
    assert(!strcmp(a.num_interfaces, " 2\n")); /* "%2d\n" */
    assert(!strcmp(a.bm_attributes, "e0\n"));  /* "%2x\n" */
    assert(!strcmp(a.max_power, "100mA\n"));   /* 50 * 2 */

    /* SuperSpeed counts in 8 mA units, and the widest value still fits. */
    buf[CFG_BMAXPOWER] = 0xff;
    usb_desc_actconfig_attrs(buf, len, 8, NULL, &a);
    assert(!strcmp(a.max_power, "2040mA\n"));
}

static void test_actconfig_configuration_string_branches(void)
{
    unsigned char buf[64];
    usb_actconfig_attrs_t a;
    size_t len = build_config(buf, 1, 1, 0);

    /* iConfiguration 0, no string: empty, and the three siblings are not. This
     * is the only shape the development board can produce.
     */
    buf[CFG_I_CONFIGURATION] = 0;
    usb_desc_actconfig_attrs(buf, len, 2, NULL, &a);
    assert(a.configuration[0] == '\0');
    assert(a.num_interfaces[0] != '\0');

    /* iConfiguration 0 with a string handed in anyway: still empty.
     * usb_cache_string returns NULL for index <= 0 before it reads anything, so
     * there is no path on Linux by which such a configuration has a string, and
     * a caller that produced one from somewhere else must not be believed.
     */
    usb_desc_actconfig_attrs(buf, len, 2, "Bus Powered Config", &a);
    assert(a.configuration[0] == '\0');

    /* iConfiguration non-zero with the string unreadable -- NULL and empty
     * alike. This is Linux's second route to an empty configuration, and the
     * one every device on this platform takes today, so it must stay empty
     * rather than become an absent file.
     */
    buf[CFG_I_CONFIGURATION] = 4;
    usb_desc_actconfig_attrs(buf, len, 2, NULL, &a);
    assert(a.configuration[0] == '\0');
    usb_desc_actconfig_attrs(buf, len, 2, "", &a);
    assert(a.configuration[0] == '\0');

    /* iConfiguration non-zero and the string readable: sysfs_emit("%s\n"). The
     * branch the board has no device for.
     */
    usb_desc_actconfig_attrs(buf, len, 2, "Bus Powered Config", &a);
    assert(!strcmp(a.configuration, "Bus Powered Config\n"));
}

static void test_actconfig_string_is_bounded(void)
{
    unsigned char buf[64];
    usb_actconfig_attrs_t a;
    char huge[USB_MAX_STRING_SIZE * 2];
    size_t len = build_config(buf, 1, 1, 0);

    /* A device can report a string longer than the kernel's own cache bound;
     * usb_string() truncates it there, and so does this. The assertion is on
     * the buffer, not on the result: a rendering that ran past USB_MAX_STRING
     * _SIZE would have smashed the struct before anything could compare it.
     */
    memset(huge, 'x', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';
    buf[CFG_I_CONFIGURATION] = 1;
    usb_desc_actconfig_attrs(buf, len, 2, huge, &a);
    assert(strlen(a.configuration) < sizeof(a.configuration));
    assert(a.configuration[0] == 'x');

    /* What gets truncated is the string, never the trailing newline. Every
     * sysfs attribute Linux emits through sysfs_emit("%s\n", ...) ends in one,
     * whatever the string did, so a rendering that dropped it to make room
     * would be emitting a last line the kernel never writes.
     */
    assert(a.configuration[strlen(a.configuration) - 1] == '\n');

    /* The longest string Linux itself could have cached -- usb_string() stops
     * at MAX_USB_STRING_SIZE counting the terminator -- still round-trips
     * whole, so the bound above only ever trims input the kernel could not have
     * produced.
     */
    char longest[USB_MAX_STRING_SIZE];
    memset(longest, 'y', sizeof(longest) - 1);
    longest[sizeof(longest) - 1] = '\0';
    usb_desc_actconfig_attrs(buf, len, 2, longest, &a);
    assert(strlen(a.configuration) == sizeof(longest));
    assert(!strncmp(a.configuration, longest, sizeof(longest) - 1));
    assert(a.configuration[strlen(a.configuration) - 1] == '\n');
}

static void test_actconfig_reads_the_selected_configuration(void)
{
    /* End to end with the locator: two configurations whose iConfiguration
     * differs, so picking the wrong one shows up as the wrong string. Byte 5
     * (bConfigurationValue) selects; byte 6 (iConfiguration) is what is read.
     */
    unsigned char blob[256];
    usb_actconfig_attrs_t a;
    size_t off = USB_DEVICE_DESC_LEN;
    memset(blob, 0, sizeof(blob));
    blob[0] = USB_DEVICE_DESC_LEN;
    blob[1] = USB_DT_DEVICE;

    size_t c1 = build_config(blob + off, 1, 1, 0);
    blob[off + CFG_I_CONFIGURATION] = 0;
    off += c1;
    size_t c2 = build_config(blob + off, 2, 3, 0);
    blob[off + CFG_I_CONFIGURATION] = 7;
    off += c2;

    size_t clen = 0;
    const unsigned char *cfg = usb_desc_active_config(blob, off, 2, &clen);
    assert(cfg && cfg[5] == 2);
    usb_desc_actconfig_attrs(cfg, clen, 2, "High Power", &a);
    assert(!strcmp(a.configuration, "High Power\n"));
    assert(!strcmp(a.num_interfaces, " 3\n"));

    cfg = usb_desc_active_config(blob, off, 1, &clen);
    assert(cfg && cfg[5] == 1);
    usb_desc_actconfig_attrs(cfg, clen, 2, "High Power", &a);
    assert(a.configuration[0] == '\0');
    assert(!strcmp(a.num_interfaces, " 1\n"));
}

/* The interface set sysfs turns into directories.
 *
 * bInterfaceNumber is a __u8, so 200 is as ordinary a number as 3; a device is
 * free to pick it. Selecting into a 32-entry table dropped every interface at
 * or above 32 -- silently, since the walk itself was still bounded and still
 * terminated, and the only visible symptom was a missing :c.i directory. These
 * numbers are chosen around that edge: 0 below it, 31 at the last value the old
 * table held, 32 at the first it dropped, and 200 well past it.
 */
static void test_interfaces_cover_the_whole_byte_range(void)
{
    static const unsigned char nums[] = {0, 31, 32, 200};
    unsigned char buf[128];
    size_t len = build_config(buf, 1, 4, 0);
    for (unsigned i = 0; i < 4; i++)
        buf[USB_CONFIG_DESC_LEN + i * USB_INTERFACE_DESC_LEN + 2] = nums[i];

    const unsigned char *ifs[USB_DESC_INTERFACES_MAX];
    bool trunc = true;
    size_t stop = 0;
    size_t n = usb_desc_interfaces(buf, len, ifs, USB_DESC_INTERFACES_MAX,
                                   &trunc, &stop);
    assert(n == 4);
    for (unsigned i = 0; i < 4; i++)
        assert(ifs[i][2] == nums[i]);
    assert(!trunc && stop == len);
}

/* Alternate settings are not interfaces: only setting 0 gets a directory, and a
 * number already emitted is not emitted twice however many times it recurs.
 */
static void test_interfaces_dedup_by_number_at_alt_zero(void)
{
    unsigned char buf[128];
    size_t len = build_config(buf, 1, 4, 0);
    unsigned char *p0 = buf + USB_CONFIG_DESC_LEN;
    p0[2] = 200;                          /* if 200, alt 0  */
    p0[USB_INTERFACE_DESC_LEN + 2] = 200; /* if 200, alt 1  */
    p0[USB_INTERFACE_DESC_LEN + 3] = 1;
    p0[2 * USB_INTERFACE_DESC_LEN + 2] = 200; /* if 200, alt 0 again */
    p0[3 * USB_INTERFACE_DESC_LEN + 2] = 5;   /* if 5,   alt 0  */

    const unsigned char *ifs[USB_DESC_INTERFACES_MAX];
    size_t n =
        usb_desc_interfaces(buf, len, ifs, USB_DESC_INTERFACES_MAX, NULL, NULL);
    assert(n == 2);
    assert(ifs[0][2] == 200 && ifs[0][3] == 0);
    assert(ifs[1][2] == 5 && ifs[1][3] == 0);
}

/* The malformed-blob contract holds through the selector too: what was read
 * before the bad record is reported, and the truncation is not hidden.
 */
static void test_interfaces_report_truncation(void)
{
    unsigned char buf[128];
    size_t len = build_config(buf, 1, 1, 0);
    size_t before = len;
    buf[len++] = 200; /* bLength far beyond the bytes that follow */
    buf[len++] = USB_DT_INTERFACE;
    buf[len++] = 7;
    buf[len++] = 0;

    const unsigned char *ifs[USB_DESC_INTERFACES_MAX];
    bool trunc = false;
    size_t stop = 0;
    size_t n = usb_desc_interfaces(buf, len, ifs, USB_DESC_INTERFACES_MAX,
                                   &trunc, &stop);
    assert(n == 1 && ifs[0][2] == 0);
    assert(trunc && stop == before);
}

int main(void)
{
    test_well_formed_blob_is_fully_consumed();
    test_blength_past_the_end_stops_in_bounds();
    test_zero_length_descriptor_stops();
    test_truncated_interface_descriptor_stops();
    test_single_trailing_byte_stops();
    test_empty_and_null_buffers();
    test_active_config_selects_by_value();
    test_active_config_clamps_overlong_total();
    test_active_config_rejects_short_blobs();
    test_active_config_ignores_non_config_records();
    test_active_config_rejects_bad_header_length();
    test_active_config_rejects_bad_header_type();
    test_active_config_stops_at_first_bad_record();
    test_actconfig_no_configuration_is_four_empty_files();
    test_actconfig_fields_use_the_kernel_formats();
    test_actconfig_configuration_string_branches();
    test_actconfig_string_is_bounded();
    test_actconfig_reads_the_selected_configuration();
    test_interfaces_cover_the_whole_byte_range();
    test_interfaces_dedup_by_number_at_alt_zero();
    test_interfaces_report_truncation();
    printf("test-usb-desc-host: all tests passed\n");
    return 0;
}
