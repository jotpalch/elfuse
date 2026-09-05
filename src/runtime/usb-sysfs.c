/*
 * Synthetic /dev/bus/usb + /sys/bus/usb built from the IOKit registry
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stage 1 of the usbdevfs emulation. Enumerates IOUSBHostDevice registry
 * entries without opening any device (device properties come from
 * IORegistryEntryCreateCFProperty; raw configuration descriptors come from
 * GetConfigurationDescriptorPtr, which is documented to need no open) and
 * materializes:
 *
 *   /sys/bus/usb/devices/<bus>-<ports>          device attr dirs
 *   /sys/bus/usb/devices/<bus>-<ports>:<c>.<i>  interface attr dirs
 *   /dev/bus/usb/BBB/DDD                        char-device nodes
 *
 * as scratch directories of real host files (the ensure_syscpu_dir pattern,
 * procemu.c). The /dev nodes are 0444 regular placeholder files on disk; the
 * stat intercept reports them as char major 189 minor (bus-1)*128+(dev-1), and
 * the open intercept diverts them (the /dev/pts placeholder trick).
 *
 * Layout deviation from Linux, by design: the /sys/bus/usb/devices entries are
 * directories, not symlinks into /sys/devices/... . realpath() of an entry
 * canonicalizes to itself, which libusb (opens attrs relative to the entry) and
 * nusb (canonicalize() of the entry path) both tolerate.
 *
 * /dev/bus/usb/BBB/DDD opens: since stage 2, every non-O_PATH open is served by
 * the typed FD_USBDEV constructor (syscall/usbdev.c) before this intercept
 * runs; the node branch here only backs O_PATH opens with a synthetic blob fd
 * (the FD_PATH + stat-stamp path). The blob it serves and the FD_USBDEV read()
 * view are the same bytes (usb_sysfs_descriptors_dup).
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include "debug/log.h"
#include "runtime/procemu-internal.h"
#include "runtime/procemu.h"
#include "runtime/tty-alias-pool.h"
#include "runtime/usb-desc.h"
#include "runtime/usb-fixture.h"
#include "runtime/usb-sysfs.h"
#include "syscall/proc.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/path.h"
#include "utils.h"

#define USB_MAJOR 189
#define USB_MAX_PORTS 6 /* locationID has six port nibbles below the bus */

/* First usb_devs[] allocation; it doubles from here as the registry is walked.
 * Not a ceiling: usbfs itself caps only at 127 devices per bus, and a chain of
 * hubs can put more than any fixed guess on one machine. A truncated model
 * would silently lose devices from both the /dev/bus/usb and the /sys views.
 */
#define USB_DEVS_INIT_CAP 16

typedef struct {
    int busnum;
    int devnum;
    uint32_t location_id;
    char name[40];    /* "2-1.4" */
    char devpath[32]; /* "1.4" */
    unsigned vid, pid, bcd_device, bcd_usb;
    unsigned dev_class, dev_subclass, dev_protocol;
    unsigned num_configs, max_packet0, cfg_value, speed_code;
    unsigned i_manufacturer, i_product, i_serial;
    char manufacturer[128], product[128], serial[128];
    uint8_t *blob; /* device descriptor + raw config descriptors */
    size_t blob_len;
} usb_dev_t;

static pthread_mutex_t usb_lock = PTHREAD_MUTEX_INITIALIZER;
static bool usb_tree_ok;
static char usb_sys_dir[64]; /* scratch root == /sys */
/* usb_sys_dir with every symlink resolved (/tmp itself is one on macOS). The
 * containment test below compares against this, never against the unresolved
 * spelling, or /tmp -> /private/tmp alone would fail it.
 */
static char usb_sys_real[PATH_MAX];
static char usb_dev_dir[64]; /* scratch root == /dev/bus     */
static usb_dev_t *usb_devs;  /* grown on demand; see USB_DEVS_INIT_CAP */
static int usb_ndevs;
static int usb_devs_cap;
static pid_t usb_owner_pid;

/* ttyACM/ttyUSB alias layer (piece 3).
 *
 * Linux exposes a CDC-ACM function as /dev/ttyACM<n> (char 166:<n>) and a
 * vendor USB-serial bridge as /dev/ttyUSB<n> (char 188:<n>); macOS exposes both
 * as /dev/cu.* callout nodes. Each enumerated callout node that has a USB
 * ancestor in the device model above becomes one alias entry: the /dev open
 * intercept diverts the alias to the host cu.* node (the /dev/pts placeholder
 * trick), and the /sys/class/tty section below gives pyserial's
 * list_ports_linux.py the sysfs walk it expects on Linux.
 *
 * The index pools are deliberately NOT reset by model_clear: an attached device
 * must keep its number across rescans (the sticky guarantee, tty-alias-pool.h),
 * so only the per-scan tty table is rebuilt.
 */
#define TTY_ACM_MAJOR 166 /* Linux ACM_TTY_MAJOR, cdc-acm.h */
#define TTY_USB_MAJOR 188 /* Linux USB_SERIAL_TTY_MAJOR, usb-serial.c */

/* One live alias per pool slot. The two caps are deliberately the same number:
 * a table smaller than the pool leaves slots no scan can reach, and a table
 * larger than it hands out aliases the pool cannot number.
 */
#define USB_TTY_MAX TTY_ALIAS_POOL_SLOTS
#define TTY_BYID_MAX 224

typedef struct {
    char cu_name[TTY_ALIAS_KEY_MAX]; /* "cu.usbmodem1101" (pool key) */
    char byid[TTY_BYID_MAX];         /* by-id leaf, "" when unbuildable */
    char host_node[136];             /* the node an open of the alias opens */
    bool is_acm;
    int index;      /* sticky per-class minor */
    int dev;        /* index into usb_devs[] */
    unsigned ifnum; /* interface the Linux driver would bind */
    unsigned port;  /* usb-serial port number (ttyUSB only) */
} usb_tty_t;

static usb_tty_t usb_ttys[USB_TTY_MAX];
static int usb_nttys;
static tty_alias_pool_t tty_pool_acm; /* sticky, survives model rebuilds */
static tty_alias_pool_t tty_pool_usb; /* sticky, survives model rebuilds */
static bool tty_pools_ready;

static void tty_model_build(void);

/* IOKit property helpers */

static long ioreg_num(io_service_t s, const char *key)
{
    CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, key,
                                              kCFStringEncodingUTF8);
    if (!k)
        return -1;
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, k, kCFAllocatorDefault, 0);
    CFRelease(k);
    long n = -1;
    if (v && CFGetTypeID(v) == CFNumberGetTypeID())
        CFNumberGetValue((CFNumberRef) v, kCFNumberLongType, &n);
    if (v)
        CFRelease(v);
    return n;
}

static bool ioreg_str(io_service_t s, const char *key, char *out, size_t n)
{
    CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, key,
                                              kCFStringEncodingUTF8);
    if (!k)
        return false;
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, k, kCFAllocatorDefault, 0);
    CFRelease(k);
    out[0] = '\0';
    bool ok = false;
    if (v && CFGetTypeID(v) == CFStringGetTypeID())
        ok = CFStringGetCString((CFStringRef) v, out, (CFIndex) n,
                                kCFStringEncodingUTF8) &&
             out[0] != '\0';
    if (v)
        CFRelease(v);
    return ok;
}

/* Port path from locationID nibbles below the top (bus) byte; empty for a root
 * hub (nusb parse_location_id).
 *
 * Returns the number of ports written.
 */
static int location_ports(uint32_t loc, unsigned ports[USB_MAX_PORTS])
{
    int n = 0;
    for (int shift = 20; shift >= 0 && n < USB_MAX_PORTS; shift -= 4) {
        unsigned nib = (loc >> shift) & 0xf;
        if (nib == 0)
            break;
        ports[n++] = nib;
    }
    return n;
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

/* Append every raw configuration descriptor (bus order, wTotalLength each) to
 * the device-descriptor blob. Uses the device user-client plug-in, which does
 * NOT open the device: GetConfigurationDescriptorPtr is explicitly documented
 * as not requiring an open (IOUSBLib.h "no open needed").
 */
static int append_config_descriptors(io_service_t svc, usb_dev_t *d)
{
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn kr = IOCreatePlugInInterfaceForService(
        svc, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    if (kr != kIOReturnSuccess || !plug) {
        log_warn(
            "usb-sysfs: device plug-in failed for %s (0x%x); "
            "descriptors blob has device descriptor only",
            d->name, kr);
        return -1;
    }
    IOUSBDeviceInterface650 **dev = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650), (LPVOID *) &dev);
    IODestroyPlugInInterface(plug);
    if (hr || !dev) {
        log_warn("usb-sysfs: QueryInterface(650) failed for %s", d->name);
        return -1;
    }

    int rc = 0;
    for (unsigned i = 0; i < d->num_configs; i++) {
        IOUSBConfigurationDescriptorPtr cfg = NULL;
        kr = (*dev)->GetConfigurationDescriptorPtr(dev, (UInt8) i, &cfg);
        if (kr != kIOReturnSuccess || !cfg) {
            log_warn(
                "usb-sysfs: GetConfigurationDescriptorPtr(%u) failed "
                "for %s (0x%x)",
                i, d->name, kr);
            rc = -1;
            continue;
        }
        const uint8_t *raw = (const uint8_t *) cfg;
        uint16_t total = get_le16(raw + 2); /* wTotalLength, bus order */
        if (total < 9)
            continue;
        uint8_t *nb = realloc(d->blob, d->blob_len + total);
        if (!nb) {
            rc = -1;
            break;
        }
        memcpy(nb + d->blob_len, raw, total);
        d->blob = nb;
        d->blob_len += total;
    }
    (*dev)->Release(dev);
    return rc;
}

/* Synthesize the 18-byte little-endian device descriptor from registry
 * properties (macOS exposes no raw device descriptor; usbfs read() fixes
 * multibyte fields to host endianness, which on LE hosts is the wire image:
 * devio.c:331-353).
 */
static void build_device_descriptor(const usb_dev_t *d, uint8_t out[18])
{
    out[0] = 18;
    out[1] = 1; /* DEVICE */
    out[2] = (uint8_t) (d->bcd_usb & 0xff);
    out[3] = (uint8_t) (d->bcd_usb >> 8);
    out[4] = (uint8_t) d->dev_class;
    out[5] = (uint8_t) d->dev_subclass;
    out[6] = (uint8_t) d->dev_protocol;
    out[7] = (uint8_t) d->max_packet0;
    out[8] = (uint8_t) (d->vid & 0xff);
    out[9] = (uint8_t) (d->vid >> 8);
    out[10] = (uint8_t) (d->pid & 0xff);
    out[11] = (uint8_t) (d->pid >> 8);
    out[12] = (uint8_t) (d->bcd_device & 0xff);
    out[13] = (uint8_t) (d->bcd_device >> 8);
    out[14] = (uint8_t) d->i_manufacturer;
    out[15] = (uint8_t) d->i_product;
    out[16] = (uint8_t) d->i_serial;
    out[17] = (uint8_t) d->num_configs;
}

/* Make room for one more entry, doubling the table when it is full.
 *
 * The new tail is zeroed because model_build fills an entry field by field and
 * relies on the rest (blob, blob_len, the string buffers) starting empty, the
 * way the file-static array used to give it for free.
 *
 * Returns false only when the allocation fails; the caller stops the walk and
 * says so rather than dropping devices quietly.
 */
static bool usb_devs_reserve(void)
{
    if (usb_ndevs < usb_devs_cap)
        return true;
    int cap = usb_devs_cap ? usb_devs_cap * 2 : USB_DEVS_INIT_CAP;
    usb_dev_t *grown = realloc(usb_devs, (size_t) cap * sizeof(*grown));
    if (!grown)
        return false;
    memset(grown + usb_devs_cap, 0,
           (size_t) (cap - usb_devs_cap) * sizeof(*grown));
    usb_devs = grown;
    usb_devs_cap = cap;
    return true;
}

static void model_clear(void)
{
    for (int i = 0; i < usb_ndevs; i++) {
        free(usb_devs[i].blob);
        usb_devs[i].blob = NULL;
    }
    usb_ndevs = 0;
    usb_nttys = 0; /* the sticky pools survive on purpose; see above */
}

/* model_clear plus the table itself, for the teardown paths: a rescan keeps the
 * allocation and refills it, but process exit must not leave it held.
 */
static void model_release(void)
{
    model_clear();
    free(usb_devs);
    usb_devs = NULL;
    usb_devs_cap = 0;
}

/* One fixture device before it is emitted: the scalar parameters model_build
 * turns into a usb_dev_t. Kept as plain data so the allocation that backs the
 * device stays lexically inside model_build, next to the compaction free, the
 * way the IOKit branch already carries its malloc.
 */
typedef struct {
    int busnum;
    int port;
    int devnum;
    unsigned vid;
    unsigned pid;
    unsigned nifaces;

    /* bInterfaceNumber of the first interface; each further one counts up from
     * it. Normally 0, so the numbers are 0, 1, ... and match the array
     * positions. The knob exists because bInterfaceNumber is a device-supplied
     * byte with the whole 0..255 range behind it while the consumers of it are
     * sized for far fewer, and no device anyone can plug in declares a large
     * one, so without a fixture that can emit one there is no way to assert
     * what happens when a device does.
     */
    unsigned ifnum_base;

    /* The endpoints every interface of this device carries, or NULL for the
     * default of one bulk IN per interface (0x81, 0x82, ...). The loopback
     * device needs a real OUT and a real interrupt IN, and the IOKit half has
     * to report the same set, so the table is shared rather than written twice
     * (runtime/usb-fixture.h).
     */
    const usb_fixture_ep_t *eps;
    unsigned neps;

    /* bInterfaceClass per interface, 0 meaning the vendor-specific 0xff the
     * rest of the set uses. Only the serial devices set it: a CDC composite has
     * to declare 0x02 on the control interface and 0x0a on the data one, or the
     * data-to-control mapping ttyACM anchoring depends on has nothing to find.
     */
    uint8_t iface_class[4];

    /* String descriptors, NULL for the device sets that carry none. The by-id
     * leaf is built from them, so a fixture that leaves them NULL is what
     * reaches udev's hex idVendor/idProduct fallback.
     */
    const char *manufacturer, *product, *serial;

    /* The macOS callout node an IOSerialBSDClient under this device would
     * carry, with the interface it hangs off. NULL for a device with no serial
     * function. See usb_fixture_ttys below.
     */
    const char *callout;
    unsigned callout_ifnum;
    unsigned callout_ifclass;
} usb_fixture_spec_t;

/* One fixture callout node, the alias half's test seam.
 *
 * The IOSerialBSDClient enumeration in tty_model_build has no fixture of its
 * own without this: it reads the live IOKit registry, so on a machine with no
 * USB serial device attached -- every CI runner -- nothing reached
 * emit_tty_sysfs, tty_alias_sync_dev, the by-id links or any of the three
 * intercepts, and the lane passed by examining zero aliases. Every entry here
 * is anchored to a fixture device by locationID, exactly as a real callout is
 * anchored by its nearest IOUSBHostInterface ancestor.
 */
typedef struct {
    uint32_t loc;
    const char *cu;
    unsigned ifnum;
    unsigned ifclass;
} usb_fixture_tty_t;

static usb_fixture_tty_t usb_fixture_ttys[USB_TTY_MAX];
static int usb_n_fixture_ttys;

/* The number of interface descriptors is the only thing that varies the blob
 * length: an 18-byte device descriptor, one configuration header, then one
 * interface descriptor per interface.
 */
static size_t usb_fixture_blob_len(const usb_fixture_spec_t *s)
{
    unsigned neps = s->neps ? s->neps : 1;
    return USB_DEVICE_DESC_LEN + USB_CONFIG_DESC_LEN +
           (size_t) s->nifaces *
               (USB_INTERFACE_DESC_LEN + (size_t) neps * USB_ENDPOINT_DESC_LEN);
}

/* Fill @d from @s, writing the device, configuration and interface descriptors
 * into @d->blob, which the caller has already allocated to
 * usb_fixture_blob_len(@s->nifaces). No allocation happens here, so ownership
 * of the blob stays with the caller.
 */
static void usb_fixture_fill(usb_dev_t *d, const usb_fixture_spec_t *s)
{
    size_t blob_len = d->blob_len;
    uint8_t *blob = d->blob;
    memset(d, 0, sizeof(*d));
    d->blob = blob;
    d->blob_len = blob_len;
    d->busnum = s->busnum;
    d->devnum = s->devnum;
    d->location_id =
        ((uint32_t) (s->busnum - 1) << 24) | ((uint32_t) s->port << 4);
    d->vid = s->vid;
    d->pid = s->pid;
    d->bcd_usb = 0x0200;
    d->bcd_device = 0x0100;
    d->max_packet0 = 64;
    d->num_configs = 1;
    d->speed_code = 1;
    d->cfg_value = 1;
    snprintf(d->devpath, sizeof(d->devpath), "%d", s->port);
    snprintf(d->name, sizeof(d->name), "%d-%d", s->busnum, s->port);
    if (s->manufacturer)
        str_copy_trunc(d->manufacturer, s->manufacturer,
                       sizeof(d->manufacturer));
    if (s->product)
        str_copy_trunc(d->product, s->product, sizeof(d->product));
    if (s->serial)
        str_copy_trunc(d->serial, s->serial, sizeof(d->serial));

    unsigned neps = s->neps ? s->neps : 1;
    size_t if_total =
        USB_INTERFACE_DESC_LEN + (size_t) neps * USB_ENDPOINT_DESC_LEN;
    size_t cfg_total = USB_CONFIG_DESC_LEN + (size_t) s->nifaces * if_total;
    build_device_descriptor(d, blob);
    uint8_t *c = blob + USB_DEVICE_DESC_LEN;
    c[0] = USB_CONFIG_DESC_LEN;
    c[1] = USB_DT_CONFIG;
    c[2] = (uint8_t) (cfg_total & 0xff);
    c[3] = (uint8_t) (cfg_total >> 8);
    c[4] = (uint8_t) s->nifaces; /* bNumInterfaces */
    c[5] = 1;                    /* bConfigurationValue */
    c[6] = 0;                    /* iConfiguration */
    c[7] = 0x80;                 /* bmAttributes: bus powered */
    c[8] = 50;                   /* bMaxPower: 100 mA */
    for (unsigned i = 0; i < s->nifaces; i++) {
        uint8_t *q = c + USB_CONFIG_DESC_LEN + (size_t) i * if_total;
        q[0] = USB_INTERFACE_DESC_LEN;
        q[1] = USB_DT_INTERFACE;
        unsigned ifnum = s->ifnum_base + i;
        q[2] = (uint8_t) ifnum; /* bInterfaceNumber */
        q[3] = 0;               /* bAlternateSetting */
        q[4] = (uint8_t) neps;  /* bNumEndpoints */
        q[5] = i < 4 && s->iface_class[i] ? s->iface_class[i]
                                          : 0xff; /* bInterfaceClass */
        q[6] = 0x00;
        q[7] = 0x00;
        q[8] = 0;

        /* The endpoint the interface descriptor above says it has. Without it
         * the blob was self-contradictory, and every endpoint-addressed
         * usbdevfs path (BULK, CLEAR_HALT, RESETEP, the control endpoint
         * recipient) had nothing to resolve against, so the fixture could not
         * reach the code that decides between "no such endpoint" and "bad
         * argument". Bulk IN, one per interface: 0x81, 0x82, ...
         */
        for (unsigned k = 0; k < neps; k++) {
            uint8_t *e =
                q + USB_INTERFACE_DESC_LEN + (size_t) k * USB_ENDPOINT_DESC_LEN;
            e[0] = USB_ENDPOINT_DESC_LEN;
            e[1] = USB_DT_ENDPOINT;
            e[2] = s->eps ? s->eps[k].addr : (uint8_t) (0x81 + i);
            e[3] = s->eps ? s->eps[k].attr : 0x02;
            uint16_t mps = s->eps ? s->eps[k].mps : 0x40;
            e[4] = (uint8_t) (mps & 0xff);
            e[5] = (uint8_t) (mps >> 8);
            e[6] = s->eps ? s->eps[k].interval : 0;
        }
    }
}

/* Fill @specs (capacity @cap) with the canned device set behind
 * ELFUSE_USB_FIXTURE and return how many were written, so the device-half
 * assertions (descriptor byte-identity, dev/rdev/minor, bNumInterfaces vs the
 * emitted interface-dir count, subsystem-link resolution) run on a host with no
 * USB device attached.
 *
 * Default: bus1/dev1 with two interfaces, bus2/dev1 with one, exercising the
 * per-bus minor arithmetic across two buses.
 *
 * ELFUSE_USB_FIXTURE=overflow: 129 address-less devices on bus 1 plus one on
 * bus 2, all routed through the fallback devnum assignment. It is the
 * regression fixture for the devnum cap -- without the cap bus1's 129th device
 * takes devnum 129 and shares minor 128 with bus2's first, so the cap must drop
 * everything past devnum 127.
 *
 * ELFUSE_USB_FIXTURE=badifnum: the default set plus /dev/bus/usb/001/002, whose
 * one interface declares bInterfaceNumber 200 and carries endpoint 0x81. It is
 * a malformed descriptor only in the sense that no sane device emits one: every
 * byte is well formed and the range is the field's own, which is why nothing
 * short of a fixture reaches the paths that index by that number. Added as a
 * separate mode rather than to the default set so the lanes that walk the tree
 * keep the device list they were written against.
 *
 * ELFUSE_USB_FIXTURE=loopback: the default set plus /dev/bus/usb/003/001, the
 * one device with an IOKit answer behind it (syscall/usbdev-fixture.c). It
 * carries interface 2 with bulk OUT 0x02, bulk IN 0x81 and interrupt IN 0x83,
 * the endpoints the out-of-tree board driver uses, and the addresses come from
 * runtime/usb-fixture.h so the descriptor blob here and GetPipeProperties there
 * cannot drift. The default devices stay in the set, and stay service-less, so
 * the fd-contract lane answers the same thing in this mode as in the default
 * one.
 *
 * ELFUSE_USB_FIXTURE=byidlong: the default set plus /dev/bus/usb/001/002,
 * carrying two string descriptors long enough that the by-id leaf cannot hold
 * them and its -ifNN suffix at once. It is the fixture for "no link at all
 * rather than a truncated one": two interfaces of one such device produced
 * byte-identical truncated leaves, so the second link replaced the first while
 * lookups kept answering with the first entry. Separate mode for the same
 * reason badifnum is.
 *
 * Both serial devices in the default set carry a callout node, so the alias
 * half runs with no hardware attached: bus 1 is a CDC-ACM composite whose
 * callout hangs off the data interface (the mapping ttyACM anchoring needs),
 * and bus 2 is a string-less vendor bridge (the hex idVendor/idProduct fallback
 * the by-id leaf needs). See usb_fixture_tty_t.
 */
static int usb_fixture_specs(usb_fixture_spec_t *specs, int cap)
{
    const char *mode = getenv("ELFUSE_USB_FIXTURE");
    int n = 0;
    if (mode && !strcmp(mode, "overflow")) {
        for (int port = 1; port <= 129 && n < cap; port++)
            specs[n++] = (usb_fixture_spec_t) {.busnum = 1,
                                               .port = port,
                                               .vid = 0x1d6b,
                                               .pid = 0x0002,
                                               .nifaces = 1};
        if (n < cap)
            specs[n++] = (usb_fixture_spec_t) {.busnum = 2,
                                               .port = 1,
                                               .vid = 0x2109,
                                               .pid = 0x0100,
                                               .nifaces = 1};
        return n;
    }
    if (n < cap)
        specs[n++] = (usb_fixture_spec_t) {
            .busnum = 1,
            .port = 1,
            .devnum = 1,
            .vid = 0x1d6b,
            .pid = 0x0002,
            .nifaces = 2,
            .iface_class = {0x02, 0x0a}, /* CDC control, CDC data */
            .manufacturer = "Elfuse",

            /* Long enough that the by-id path is wider than the 63-byte
             * descriptor stamp, which is what a real device's leaf is.
             */
            .product = "Serial Port (fixture, long enough to overrun it)",
            .serial = "FIX 0001",
            .callout = "cu.usbmodemFIX1",
            .callout_ifnum = 1, /* macOS hangs it off the data interface */
            .callout_ifclass = 0x0a,
        };
    if (n < cap)
        specs[n++] = (usb_fixture_spec_t) {
            .busnum = 2,
            .port = 1,
            .devnum = 1,
            .vid = 0x2109,
            .pid = 0x0100,
            .nifaces = 1,
            .callout = "cu.usbserial-FIX2",
            .callout_ifnum = 0,
            .callout_ifclass = 0xff,
        };
    if (mode && !strcmp(mode, "badifnum") && n < cap)
        specs[n++] = (usb_fixture_spec_t) {.busnum = 1,
                                           .port = 2,
                                           .devnum = 2,
                                           .vid = 0x1d6b,
                                           .pid = 0x0002,
                                           .nifaces = 1,
                                           .ifnum_base = 200};
    if (mode && !strcmp(mode, "byidlong") && n < cap) {
        /* 107 bytes each. Two of them plus "usb-" and the '_' between them fill
         * the leaf to 219 of its 223 usable bytes, so the strings fit and the
         * -ifNN suffix does not -- the case where a truncating append would
         * return a name that looks whole. The lane asserts no link is made at
         * all.
         */
        static const char longstr[] =
            "LongVendorNameLongVendorNameLongVendorNameLongVendorNameLongVendo"
            "rNameLongVendorNameLongVendorNameLongVendo";
        specs[n++] = (usb_fixture_spec_t) {
            .busnum = 1,
            .port = 2,
            .devnum = 2,
            .vid = 0x1d6b,
            .pid = 0x0003,
            .nifaces = 1,
            .manufacturer = longstr,
            .product = longstr,
            .callout = "cu.usbmodemFIX3",
            .callout_ifnum = 0,
            .callout_ifclass = 0x02,
        };
    }
    if (mode && !strcmp(mode, "loopback") && n < cap)
        specs[n++] = (usb_fixture_spec_t) {
            .busnum = USB_FIXTURE_LOOPBACK_BUS,
            .port = USB_FIXTURE_LOOPBACK_PORT,
            .devnum = USB_FIXTURE_LOOPBACK_DEVNUM,
            .vid = USB_FIXTURE_LOOPBACK_VID,
            .pid = USB_FIXTURE_LOOPBACK_PID,
            .nifaces = 1,
            .ifnum_base = USB_FIXTURE_LOOPBACK_IFNUM,
            .eps = usb_fixture_loopback_eps,
            .neps = USB_FIXTURE_LOOPBACK_NEPS,
        };
    return n;
}

#define USB_FIXTURE_MAX 130

/* Enumerate the IOKit registry into usb_devs[].
 *
 * Known boundary -- no usbN root-hub entries. macOS does not publish root hubs
 * as USB devices: the IOUSBDevice/IOUSBHostDevice match returns only downstream
 * devices, and the controllers are IOUSBHostController objects that carry no
 * device descriptor to synthesize one from. The tree therefore has no
 * /sys/bus/usb/devices/usbN entries and no parent link from a device to its
 * bus. libusb enumerates each device independently and leaves parent_dev NULL,
 * and nusb skips names without a port path, so both still list every device;
 * what is lost is topology, so `lsusb -t` prints each device without the bus
 * row above it. The nports == 0 skip below is the matching guard: such an entry
 * could only be named "<bus>-" with an empty port path.
 */
static void model_build(void)
{
    model_clear();

    /* Test seam: a canned model, host-independent, so the device-half coverage
     * runs without hardware. Off in every normal run (the env var is unset), so
     * production still enumerates only the real IOKit registry.
     */
    usb_n_fixture_ttys = 0;
    if (getenv("ELFUSE_USB_FIXTURE")) {
        usb_fixture_spec_t specs[USB_FIXTURE_MAX];
        int n = usb_fixture_specs(specs, USB_FIXTURE_MAX);
        for (int k = 0; k < n; k++) {
            if (!usb_devs_reserve())
                break;
            usb_dev_t *d = &usb_devs[usb_ndevs];

            /* Allocate here, in the same procedure as the compaction free
             * below, so the blob's ownership is the registry branch's: a
             * canned-model allocation stashed in a callee would read to the
             * leak analyzer as unowned once it escaped into usb_devs[].
             */
            d->blob = malloc(usb_fixture_blob_len(&specs[k]));
            if (!d->blob)
                continue;
            d->blob_len = usb_fixture_blob_len(&specs[k]);
            usb_fixture_fill(d, &specs[k]);
            if (specs[k].callout && usb_n_fixture_ttys < USB_TTY_MAX)
                usb_fixture_ttys[usb_n_fixture_ttys++] = (usb_fixture_tty_t) {
                    d->location_id,
                    specs[k].callout,
                    specs[k].callout_ifnum,
                    specs[k].callout_ifclass,
                };
            usb_ndevs++;
        }
        goto assign_devnums; /* run the same fallback+cap the registry path does
                              */
    }

    CFMutableDictionaryRef match = IOServiceMatching("IOUSBDevice");
    if (!match)
        return;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) !=
        kIOReturnSuccess)
        return;

    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        /* Reserve before the entry pointer below is taken, so the growth can
         * never move the table out from under it mid-iteration.
         */
        if (!usb_devs_reserve()) {
            log_warn(
                "usb: cannot grow the device table past %d entries; "
                "the USB tree is truncated",
                usb_ndevs);
            IOObjectRelease(svc);
            break;
        }
        long loc = ioreg_num(svc, "locationID");
        long vid = ioreg_num(svc, "idVendor");
        long pid = ioreg_num(svc, "idProduct");
        if (loc < 0 || vid < 0 || pid < 0) {
            IOObjectRelease(svc);
            continue;
        }
        unsigned ports[USB_MAX_PORTS];
        int nports = location_ports((uint32_t) loc, ports);
        if (nports == 0) { /* unnameable: no port path (see above) */
            IOObjectRelease(svc);
            continue;
        }
        bool dup = false;
        for (int i = 0; i < usb_ndevs; i++)
            if (usb_devs[i].location_id == (uint32_t) loc)
                dup = true;
        if (dup) {
            IOObjectRelease(svc);
            continue;
        }

        usb_dev_t *d = &usb_devs[usb_ndevs];
        memset(d, 0, sizeof(*d));
        d->location_id = (uint32_t) loc;

        /* macOS bus indices (locationID top byte) start at 0; Linux busnums are
         * 1-based (minor arithmetic and BBB names break at bus 0), so shift by
         * one. Deviation from a literal locationID>>24 is deliberate and
         * stable: the top byte is constant per controller.
         */
        d->busnum = (int) ((uint32_t) loc >> 24) + 1;
        long addr = ioreg_num(svc, "USB Address");
        if (addr < 0)
            addr = ioreg_num(svc, "kUSBAddress");
        d->devnum = addr > 0 && addr < 128 ? (int) addr : 0;
        d->vid = (unsigned) vid & 0xffff;
        d->pid = (unsigned) pid & 0xffff;

        long v;
        d->bcd_device =
            (v = ioreg_num(svc, "bcdDevice")) >= 0 ? (unsigned) v : 0;
        d->bcd_usb =
            (v = ioreg_num(svc, "bcdUSB")) >= 0 ? (unsigned) v : 0x0200;
        d->dev_class =
            (v = ioreg_num(svc, "bDeviceClass")) >= 0 ? (unsigned) v : 0;
        d->dev_subclass =
            (v = ioreg_num(svc, "bDeviceSubClass")) >= 0 ? (unsigned) v : 0;
        d->dev_protocol =
            (v = ioreg_num(svc, "bDeviceProtocol")) >= 0 ? (unsigned) v : 0;
        d->num_configs =
            (v = ioreg_num(svc, "bNumConfigurations")) > 0 ? (unsigned) v : 1;
        d->max_packet0 =
            (v = ioreg_num(svc, "bMaxPacketSize0")) > 0 ? (unsigned) v : 64;
        d->speed_code =
            (v = ioreg_num(svc, "Device Speed")) >= 0 ? (unsigned) v : 1;
        d->i_manufacturer =
            (v = ioreg_num(svc, "iManufacturer")) > 0 ? (unsigned) v : 0;
        d->i_product = (v = ioreg_num(svc, "iProduct")) > 0 ? (unsigned) v : 0;
        d->i_serial =
            (v = ioreg_num(svc, "iSerialNumber")) > 0 ? (unsigned) v : 0;
        d->cfg_value = (v = ioreg_num(svc, "kUSBCurrentConfiguration")) > 0
                           ? (unsigned) v
                           : 0;

        if (!ioreg_str(svc, "kUSBVendorString", d->manufacturer,
                       sizeof(d->manufacturer)))
            ioreg_str(svc, "USB Vendor Name", d->manufacturer,
                      sizeof(d->manufacturer));
        if (!ioreg_str(svc, "kUSBProductString", d->product,
                       sizeof(d->product)))
            ioreg_str(svc, "USB Product Name", d->product, sizeof(d->product));
        if (!ioreg_str(svc, "kUSBSerialNumberString", d->serial,
                       sizeof(d->serial)))
            ioreg_str(svc, "USB Serial Number", d->serial, sizeof(d->serial));

        /* "<bus>-<port[.port]*>" (usb.c:704-726) and devpath */
        size_t off = 0;
        for (int i = 0; i < nports; i++)
            off += (size_t) snprintf(d->devpath + off, sizeof(d->devpath) - off,
                                     "%s%u", i ? "." : "", ports[i]);
        snprintf(d->name, sizeof(d->name), "%d-%s", d->busnum, d->devpath);

        d->blob = malloc(18);
        if (!d->blob) {
            IOObjectRelease(svc);
            continue;
        }
        d->blob_len = 18;
        append_config_descriptors(svc, d);
        build_device_descriptor(d, d->blob);

        /* Fall back to the first config's bConfigurationValue when the registry
         * has no current-configuration key. Byte 5 is bConfigurationValue only
         * once the record is known to be a configuration header, so the same
         * two-field check the descriptor walk applies is applied here rather
         * than reading the field out of whatever the device happened to send.
         */
        if (d->cfg_value == 0 &&
            d->blob_len >= USB_DEVICE_DESC_LEN + USB_CONFIG_DESC_LEN &&
            d->blob[USB_DEVICE_DESC_LEN] == USB_CONFIG_DESC_LEN &&
            d->blob[USB_DEVICE_DESC_LEN + 1] == USB_DT_CONFIG)
            d->cfg_value = d->blob[USB_DEVICE_DESC_LEN + 5];
        if (d->cfg_value == 0)
            d->cfg_value = 1;

        usb_ndevs++;
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);

assign_devnums:
    /* Fallback devnum assignment: stable 1..n per bus in locationID order for
     * devices without a 'USB Address' property, avoiding taken numbers.
     */
    for (int pass = 0; pass < usb_ndevs; pass++) {
        int best = -1;
        for (int i = 0; i < usb_ndevs; i++) {
            if (usb_devs[i].devnum != 0)
                continue;
            if (best < 0 ||
                usb_devs[i].location_id < usb_devs[best].location_id)
                best = i;
        }
        if (best < 0)
            break;
        int devnum = 1;
        for (int again = 1; again;) {
            again = 0;
            for (int i = 0; i < usb_ndevs; i++)
                if (i != best && usb_devs[i].busnum == usb_devs[best].busnum &&
                    usb_devs[i].devnum == devnum) {
                    devnum++;
                    again = 1;
                }
        }
        if (devnum > 127) {
            /* usbfs numbers devices 1..127 per bus: devnum-1 is the low 7 bits
             * of the minor (usb_minor()), so a 128th device on one bus would
             * take the first minor of the next bus (bus1 devnum129 and bus2
             * devnum1 both map to minor 128). The registry-address path already
             * clamps to <128; cap the fallback the same way and drop the
             * overflow rather than alias a node onto another bus's range.
             */
            log_warn(
                "usb: bus %d already holds 127 devices; dropping the device at "
                "locationID 0x%08x (usbfs caps devnum at 127)",
                usb_devs[best].busnum, (unsigned) usb_devs[best].location_id);
            usb_devs[best].devnum = -1; /* tombstone; compacted out below */
            continue;
        }
        usb_devs[best].devnum = devnum;
    }

    /* Compact the tombstones the cap left behind so no later pass, emit, or
     * lookup sees a devnum < 1.
     */
    int kept = 0;
    for (int i = 0; i < usb_ndevs; i++) {
        if (usb_devs[i].devnum >= 1) {
            if (kept != i)
                usb_devs[kept] = usb_devs[i];
            kept++;
        } else {
            free(usb_devs[i].blob);
            usb_devs[i].blob = NULL;
        }
    }
    usb_ndevs = kept;

    tty_model_build();
}

/* tty alias model */

/* Locate the active configuration descriptor inside the blob: the one whose
 * bConfigurationValue matches cfg_value, else the first. Every "current
 * configuration's attributes" reader (bNumInterfaces, bmAttributes, bMaxPower,
 * the interface dirs) must go through this, or the attribute files and the
 * emitted :c.i directories can describe two different configurations.
 *
 * Returns the descriptor with *len_out set, or NULL when the blob carries none.
 */
static const uint8_t *active_config(const usb_dev_t *d, size_t *len_out)
{
    return usb_desc_active_config(d->blob, d->blob_len, d->cfg_value, len_out);
}

/* The 9-byte alternate-setting-0 interface descriptor for ifnum in the active
 * configuration, or NULL when the device has no such interface.
 */
static const uint8_t *find_iface_desc(const usb_dev_t *d, unsigned ifnum)
{
    size_t cfg_len = 0;
    const uint8_t *cfg = active_config(d, &cfg_len);
    if (!cfg)
        return NULL;
    usb_desc_iter_t it;
    usb_desc_iter_init(&it, cfg, cfg_len);
    const uint8_t *q;
    uint8_t qlen;
    while ((q = usb_desc_iter_next(&it, &qlen))) {
        if (q[1] == USB_DT_INTERFACE && qlen >= USB_INTERFACE_DESC_LEN &&
            q[2] == ifnum && q[3] == 0)
            return q;
    }
    return NULL;
}


static bool tty_name_is_acm(const char *cu)
{
    return strncmp(cu, "cu.usbmodem", 11) == 0;
}

static bool tty_name_is_usb_serial(const char *cu)
{
    /* The vendor-bridge callout spellings macOS drivers use: Apple's own
     * FTDI/generic driver (cu.usbserial*), the WCH CH34x driver
     * (cu.wchusbserial*), and Silicon Labs' CP210x driver (cu.SLAB_USBtoUART*).
     * Everything else -- cu.Bluetooth*, cu.debug-console, cu.wlan-debug and the
     * tty.* dial-in twins -- is not a USB serial bridge and gets no Linux
     * alias.
     */
    return strncmp(cu, "cu.usbserial", 12) == 0 ||
           strncmp(cu, "cu.wchusbserial", 15) == 0 ||
           strncmp(cu, "cu.SLAB_USBtoUART", 17) == 0;
}

/* Interface number the Linux driver would bind the tty to.
 *
 * macOS hangs the IOSerialBSDClient for a CDC-ACM function under the DATA
 * interface (AppleUSBACMData), but Linux cdc-acm registers the tty on the
 * CONTROL interface, and that is the directory /sys/class/tty/ttyACMn/device
 * points at on Linux (pyserial then walks one dirname up to the device dir).
 * Map data to control as the nearest Communications-class (0x02) interface at
 * or below the data interface in the active configuration; a composite with
 * several CDC functions keeps each pair together that way. Vendor-class bridges
 * (ttyUSB) keep the interface they sit on, like Linux usb-serial.
 */
static unsigned tty_linux_ifnum(const usb_dev_t *d,
                                unsigned iokit_ifnum,
                                unsigned iokit_ifclass,
                                bool is_acm)
{
    if (!is_acm || iokit_ifclass == 2)
        return iokit_ifnum;

    size_t cfg_len = 0;
    const uint8_t *cfg = active_config(d, &cfg_len);
    if (!cfg)
        return iokit_ifnum;
    usb_desc_iter_t it;
    usb_desc_iter_init(&it, cfg, cfg_len);
    int best = -1;
    const uint8_t *q;
    uint8_t qlen;
    while ((q = usb_desc_iter_next(&it, &qlen))) {
        if (q[1] == USB_DT_INTERFACE && qlen >= USB_INTERFACE_DESC_LEN &&
            q[3] == 0 && q[5] == 2 /* Communications */ &&
            q[2] <= iokit_ifnum && (int) q[2] > best)
            best = q[2];
    }
    return best >= 0 ? (unsigned) best : iokit_ifnum;
}

/* The bytes udev leaves alone in a device node name: systemd's
 * allow_listed_char_for_devnode (src/shared/device-nodes.c) accepts ASCII
 * letters and digits plus "#+-.:=@_", and udev_replace_chars additionally lets
 * a valid multi-byte UTF-8 sequence through untouched.
 */
static bool byid_char_ok(unsigned char c)
{
    return c >= 0x80 || isalnum(c) || c == '#' || c == '+' || c == '-' ||
           c == '.' || c == ':' || c == '=' || c == '@' || c == '_';
}

/* Append one sanitized by-id segment, the way udev builds it: whitespace runs
 * collapse to a single '_' with leading and trailing runs dropped
 * (udev_replace_whitespace), then every remaining byte outside the allowlist
 * becomes '_' (udev_replace_chars).
 *
 * Returns false when the segment does not fit, leaving *off where it was; the
 * caller turns that into "no link", which is what an absent string already
 * does. The earlier spelling appended with a truncating snprintf and returned
 * true anyway, so a device with two long strings produced two identical
 * 223-byte leaves for its two interfaces: the second link overwrote the first
 * on disk while the lookup kept answering with the first entry.
 */
static bool byid_append(char *buf, size_t bufsz, size_t *off, const char *seg)
{
    size_t o = *off;
    bool pending_ws = false, wrote = false;
    for (const unsigned char *c = (const unsigned char *) seg; *c; c++) {
        if (isspace(*c)) {
            pending_ws = wrote; /* a leading run is dropped, not collapsed */
            continue;
        }
        if (pending_ws) {
            if (o + 1 >= bufsz)
                return false;
            buf[o++] = '_';
            pending_ws = false;
        }
        if (o + 1 >= bufsz)
            return false;
        buf[o++] = byid_char_ok(*c) ? (char) *c : '_';
        wrote = true;
    }
    buf[o] = '\0';
    *off = o;
    return true;
}

/* by-id leaf, the name 60-serial.rules builds:
 *
 *   usb-$ID_SERIAL-if$ID_USB_INTERFACE_NUM[-port$attr{port_number}]
 *
 * ID_SERIAL is usb_id's vendor_model[_serial], where an absent manufacturer or
 * product string falls back to the four hex digits of idVendor / idProduct --
 * so udev always has an ID_SERIAL and a serial-less bridge still gets a link,
 * where the earlier spelling here made none. ID_USB_INTERFACE_NUM is the raw
 * bInterfaceNumber sysattr, which Linux renders "%02x", the same radix this
 * file writes into its own interface directory. The -port suffix is added only
 * for a usb-serial port, whose port_number Linux sets to the port index
 * (drivers/usb/serial/usb-serial.c, port->port_number = i), so a single-port
 * bridge is -port0.
 *
 * Returns false when the leaf does not fit, so no link is made rather than a
 * truncated and possibly colliding one.
 */
static bool tty_byid_leaf(const usb_dev_t *d,
                          const usb_tty_t *t,
                          char *buf,
                          size_t bufsz)
{
    char vendor[8], model[8];
    const char *man = d->manufacturer;
    const char *prod = d->product;
    if (!man[0]) {
        snprintf(vendor, sizeof(vendor), "%04x", d->vid & 0xffff);
        man = vendor;
    }
    if (!prod[0]) {
        snprintf(model, sizeof(model), "%04x", d->pid & 0xffff);
        prod = model;
    }

    buf[0] = '\0';
    if (bufsz < 6)
        return false;
    memcpy(buf, "usb-", 5);
    size_t off = 4;
    if (!byid_append(buf, bufsz, &off, man))
        goto too_long;
    if (off + 1 >= bufsz)
        goto too_long;
    buf[off++] = '_';
    buf[off] = '\0';
    if (!byid_append(buf, bufsz, &off, prod))
        goto too_long;
    if (d->serial[0]) {
        if (off + 1 >= bufsz)
            goto too_long;
        buf[off++] = '_';
        buf[off] = '\0';
        if (!byid_append(buf, bufsz, &off, d->serial))
            goto too_long;
    }
    int n;
    if (t->is_acm)
        n = snprintf(buf + off, bufsz - off, "-if%02x", t->ifnum & 0xff);
    else
        n = snprintf(buf + off, bufsz - off, "-if%02x-port%u", t->ifnum & 0xff,
                     t->port);
    if (n < 0 || (size_t) n >= bufsz - off)
        goto too_long;
    return true;

too_long:
    buf[0] = '\0';
    return false;
}

static int find_dev_by_location(uint32_t loc)
{
    for (int i = 0; i < usb_ndevs; i++)
        if (usb_devs[i].location_id == loc)
            return i;
    return -1;
}

/* Record one callout node as an alias candidate.
 *
 * @host is the node an open of the alias opens. It is /dev/<cu> for a real
 * callout; the fixture points it at /dev/null instead, which carries no tty
 * behavior but does let the open/stat/fstat identity contract be asserted on a
 * machine with no serial device attached.
 */
static void tty_add(const char *cu,
                    const char *host,
                    int di,
                    unsigned ifnum,
                    unsigned ifclass)
{
    if (usb_nttys >= USB_TTY_MAX) {
        /* Say so, the way the devnum cap does: a silent break made which
         * aliases survived depend on IOKit's iteration order.
         */
        log_warn(
            "usb-sysfs: already tracking %d serial aliases; dropping the "
            "callout node %s",
            USB_TTY_MAX, cu);
        return;
    }
    bool is_acm = tty_name_is_acm(cu);
    usb_tty_t *t = &usb_ttys[usb_nttys];
    memset(t, 0, sizeof(*t));
    str_copy_trunc(t->cu_name, cu, sizeof(t->cu_name));
    str_copy_trunc(t->host_node, host, sizeof(t->host_node));
    t->is_acm = is_acm;
    t->dev = di;
    t->index = -1;

    /* One tty per bridge here, so the usb-serial port index is 0, which is what
     * Linux numbers the first port of a serial device (port->port_number = i).
     */
    t->port = 0;
    t->ifnum = tty_linux_ifnum(&usb_devs[di], ifnum, ifclass, is_acm);
    if (!tty_byid_leaf(&usb_devs[di], t, t->byid, sizeof(t->byid)))
        t->byid[0] = '\0';
    usb_nttys++;
}

static int tty_cmp(const void *a, const void *b)
{
    return strcmp(((const usb_tty_t *) a)->cu_name,
                  ((const usb_tty_t *) b)->cu_name);
}

/* Walk the live IOSerialBSDClient nodes into usb_ttys[]. */
static void tty_scan_iokit(void)
{
    CFMutableDictionaryRef match = IOServiceMatching("IOSerialBSDClient");
    io_iterator_t it = IO_OBJECT_NULL;
    if (!match || IOServiceGetMatchingServices(kIOMainPortDefault, match,
                                               &it) != kIOReturnSuccess)
        it = IO_OBJECT_NULL;

    io_service_t svc;
    while (it != IO_OBJECT_NULL && (svc = IOIteratorNext(it))) {
        char callout[128];
        if (!ioreg_str(svc, "IOCalloutDevice", callout, sizeof(callout)) ||
            strncmp(callout, "/dev/", 5) != 0) {
            IOObjectRelease(svc);
            continue;
        }
        const char *cu = callout + 5;
        bool is_acm = tty_name_is_acm(cu);
        if (!is_acm && !tty_name_is_usb_serial(cu)) {
            IOObjectRelease(svc);
            continue;
        }

        /* Nearest IOUSBHostInterface ancestor carries the locationID that keys
         * the device model plus the macOS-side interface identity.
         */
        long loc = -1, ifnum = -1, ifclass = -1;
        io_object_t cur = svc;
        IOObjectRetain(cur);
        for (int depth = 0; depth < 12 && cur != IO_OBJECT_NULL; depth++) {
            io_object_t parent = IO_OBJECT_NULL;
            if (IORegistryEntryGetParentEntry(cur, kIOServicePlane, &parent) !=
                KERN_SUCCESS)
                parent = IO_OBJECT_NULL;
            IOObjectRelease(cur);
            cur = parent;
            if (cur != IO_OBJECT_NULL &&
                IOObjectConformsTo(cur, "IOUSBHostInterface")) {
                loc = ioreg_num(cur, "locationID");
                ifnum = ioreg_num(cur, "bInterfaceNumber");
                ifclass = ioreg_num(cur, "bInterfaceClass");
                break;
            }
        }
        if (cur != IO_OBJECT_NULL)
            IOObjectRelease(cur);
        IOObjectRelease(svc);

        if (loc < 0 || ifnum < 0)
            continue;
        int di = find_dev_by_location((uint32_t) loc);
        if (di < 0)
            continue;

        tty_add(cu, callout, di, (unsigned) ifnum,
                ifclass < 0 ? 0 : (unsigned) ifclass);
    }
    if (it != IO_OBJECT_NULL)
        IOObjectRelease(it);
}

/* Enumerate the callout nodes into usb_ttys[] and reconcile the sticky pools.
 * Runs after model_build so every alias can anchor to a device in usb_devs[] (a
 * callout node with no USB ancestor in the model -- the macOS Bluetooth and
 * debug consoles, or a device that vanished mid-scan -- gets no alias).
 */
static void tty_model_build(void)
{
    usb_nttys = 0;
    if (!tty_pools_ready) {
        tty_alias_pool_init(&tty_pool_acm);
        tty_alias_pool_init(&tty_pool_usb);
        tty_pools_ready = true;
    }

    /* Test seam, the model_build one carried through to this half: the callout
     * set is canned, so every consumer of it -- emit_tty_sysfs, the by-id
     * leaves, tty_alias_sync_dev and the three intercepts -- runs on a machine
     * with no USB serial device attached. Off in every normal run.
     */
    if (getenv("ELFUSE_USB_FIXTURE")) {
        for (int i = 0; i < usb_n_fixture_ttys; i++) {
            int di = find_dev_by_location(usb_fixture_ttys[i].loc);
            if (di < 0)
                continue;
            tty_add(usb_fixture_ttys[i].cu, "/dev/null", di,
                    usb_fixture_ttys[i].ifnum, usb_fixture_ttys[i].ifclass);
        }
    } else {
        tty_scan_iokit();
    }

    /* Name-sorted before anything reads the table, so the emit order, the /dev
     * sweep order and the pool's first-scan assignment do not depend on the
     * order IOKit happened to hand the nodes over.
     */
    qsort(usb_ttys, (size_t) usb_nttys, sizeof(usb_ttys[0]), tty_cmp);

    /* Reconcile each class pool with the callout names seen this scan; attached
     * devices keep their index, departed ones free it.
     */
    const char *acm_keys[USB_TTY_MAX];
    const char *usbser_keys[USB_TTY_MAX];
    size_t nacm = 0, nusbser = 0;
    for (int i = 0; i < usb_nttys; i++) {
        if (usb_ttys[i].is_acm)
            acm_keys[nacm++] = usb_ttys[i].cu_name;
        else
            usbser_keys[nusbser++] = usb_ttys[i].cu_name;
    }

    /* Each rescan reads only [0, n), and the split loop above wrote every entry
     * it counted: nacm + nusbser is usb_nttys, which tty_add caps at
     * USB_TTY_MAX, the size of both arrays. The checker cannot bound the two
     * counts against the writes, so it measures the arrays as a whole.
     */
    /* cppcheck-suppress uninitvar */
    tty_alias_pool_rescan(&tty_pool_acm, acm_keys, nacm);
    /* cppcheck-suppress uninitvar */
    tty_alias_pool_rescan(&tty_pool_usb, usbser_keys, nusbser);
    for (int i = 0; i < usb_nttys; i++) {
        usb_tty_t *t = &usb_ttys[i];
        t->index = tty_alias_pool_index(
            t->is_acm ? &tty_pool_acm : &tty_pool_usb, t->cu_name);
    }
}

/* scratch tree construction */

static int usb_write_file(const char *dir,
                          const char *name,
                          const void *data,
                          size_t len)
{
    char path[256];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
        (int) sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0444);
    if (fd < 0)
        return -1;
    const uint8_t *p = data;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR)
            continue; /* retry like syscpu_write_file: a stray signal must
                       * not abort a one-shot tree build
                       */
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        left -= (size_t) n;
    }
    close(fd);
    return 0;
}

__attribute__((format(printf, 3, 4))) static int usb_write_fmt(const char *dir,
                                                               const char *name,
                                                               const char *fmt,
                                                               ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;
    if ((size_t) n >= sizeof(buf))
        n = (int) sizeof(buf) - 1;
    return usb_write_file(dir, name, buf, (size_t) n);
}

/* sysfs speed strings (sysfs.c:145-178) keyed by the registry's Device Speed
 * code (USB.h: 0 Low, 1 Full, 2 High, 3 Super, 4 Super+, 5 Super+x2).
 */
static const char *speed_string(unsigned code)
{
    switch (code) {
    case 0:
        return "1.5";
    case 1:
        return "12";
    case 2:
        return "480";
    case 3:
        return "5000";
    case 4:
        return "10000";
    case 5:
        return "20000";
    default:
        return "12";
    }
}

static int usb_minor(const usb_dev_t *d)
{
    return (d->busnum - 1) * 128 + (d->devnum - 1);
}

/* Emit one interface dir <name>:<cfg>.<if> per bInterfaceNumber (alternate
 * setting 0) of the active configuration, parsed from the raw config descriptor
 * already in the blob -- registry children vanish under capture, so they are
 * deliberately not consulted.
 */
static void emit_interface_dirs(const char *devices_dir, const usb_dev_t *d)
{
    size_t cfg_len = 0;
    const uint8_t *cfg = active_config(d, &cfg_len);
    if (!cfg)
        return;

    /* The blob is device-supplied, so the walk is a bounded iteration that can
     * only ever stop early (usb-desc.h), never step off the end of cfg_len.
     * usb_desc_interfaces owns the selection -- alternate setting 0, first
     * appearance of each bInterfaceNumber -- and is sized to the whole byte
     * range the field can hold, so no number is dropped for being large.
     */
    const uint8_t *ifaces[USB_DESC_INTERFACES_MAX];
    bool truncated = false;
    size_t stop_off = 0;
    size_t nif = usb_desc_interfaces(cfg, cfg_len, ifaces, ARRAY_SIZE(ifaces),
                                     &truncated, &stop_off);
    if (truncated)
        log_warn(
            "usb-sysfs: %s: config descriptor truncated after %zu of %zu bytes",
            d->name, stop_off, cfg_len);

    for (size_t i = 0; i < nif; i++) {
        const uint8_t *q = ifaces[i];
        unsigned ifnum = q[2], alt = q[3], neps = q[4];
        unsigned icls = q[5], isub = q[6], ipro = q[7];
        char idir[256];
        if (snprintf(idir, sizeof(idir), "%s/%s:%u.%u", devices_dir, d->name,
                     d->cfg_value, ifnum) >= (int) sizeof(idir) ||
            mkdir(idir, 0755) != 0)
            continue;
        usb_write_fmt(idir, "bInterfaceNumber", "%02x\n", ifnum);
        usb_write_fmt(idir, "bAlternateSetting", "%2d\n", alt);
        usb_write_fmt(idir, "bNumEndpoints", "%02x\n", neps);
        usb_write_fmt(idir, "bInterfaceClass", "%02x\n", icls);
        usb_write_fmt(idir, "bInterfaceSubClass", "%02x\n", isub);
        usb_write_fmt(idir, "bInterfaceProtocol", "%02x\n", ipro);
        char ilink[300];
        if (snprintf(ilink, sizeof(ilink), "%s/subsystem", idir) <
            (int) sizeof(ilink))
            symlink("../../../usb", ilink);
        usb_write_fmt(idir, "uevent",
                      "DEVTYPE=usb_interface\n"
                      "PRODUCT=%x/%x/%x\n"
                      "TYPE=%u/%u/%u\n"
                      "INTERFACE=%u/%u/%u\n"
                      "MODALIAS=usb:v%04Xp%04Xd%04Xdc%02Xdsc%02Xdp%02X"
                      "ic%02Xisc%02Xip%02Xin%02X\n",
                      d->vid, d->pid, d->bcd_device, d->dev_class,
                      d->dev_subclass, d->dev_protocol, icls, isub, ipro,
                      d->vid, d->pid, d->bcd_device, d->dev_class,
                      d->dev_subclass, d->dev_protocol, icls, isub, ipro,
                      ifnum);
    }
}

static void emit_device_dir(const char *devices_dir, const usb_dev_t *d)
{
    char dir[256];
    if (snprintf(dir, sizeof(dir), "%s/%s", devices_dir, d->name) >=
        (int) sizeof(dir))
        return;
    if (mkdir(dir, 0755) < 0)
        return;

    usb_write_fmt(dir, "busnum", "%d\n", d->busnum);
    usb_write_fmt(dir, "devnum", "%d\n", d->devnum);
    usb_write_fmt(dir, "devpath", "%s\n", d->devpath);
    usb_write_fmt(dir, "idVendor", "%04x\n", d->vid);
    usb_write_fmt(dir, "idProduct", "%04x\n", d->pid);
    usb_write_fmt(dir, "bcdDevice", "%04x\n", d->bcd_device);
    usb_write_fmt(dir, "bDeviceClass", "%02x\n", d->dev_class);
    usb_write_fmt(dir, "bDeviceSubClass", "%02x\n", d->dev_subclass);
    usb_write_fmt(dir, "bDeviceProtocol", "%02x\n", d->dev_protocol);
    usb_write_fmt(dir, "bNumConfigurations", "%u\n", d->num_configs);
    usb_write_fmt(dir, "bMaxPacketSize0", "%u\n", d->max_packet0);
    usb_write_fmt(dir, "bConfigurationValue", "%u\n", d->cfg_value);
    usb_write_fmt(dir, "version", "%2x.%02x\n", d->bcd_usb >> 8,
                  d->bcd_usb & 0xff);
    usb_write_fmt(dir, "speed", "%s\n", speed_string(d->speed_code));
    usb_write_fmt(dir, "dev", "%d:%d\n", USB_MAJOR, usb_minor(d));

    /* Current configuration's attributes (sysfs.c:29-88, 782-786), read from
     * the same descriptor emit_interface_dirs walks.
     *
     * All four are written on every device, including when the blob carried no
     * usable configuration at all. Linux's dev_attr_grp has no .is_visible
     * (sysfs.c:815-817), so these files exist on every USB device directory and
     * a value the kernel cannot supply shows up as a zero-length read; writing
     * only the ones whose value is known would answer ENOENT where Linux
     * answers "nothing", which is a different fact about the device. See
     * usb_desc_actconfig_attrs for the rest of the rule.
     *
     * cfg_string is NULL here, and that is the whole of what this stage can
     * say. iConfiguration names a string descriptor, and a string descriptor is
     * fetched over an ep0 control transfer on an open device -- which this
     * layer deliberately does not do. IOKit offers no way around it: an
     * IOUSBHostDevice registry entry publishes iManufacturer, iProduct and
     * iSerialNumber together with the three strings the family caches for them
     * ("USB Vendor Name", "USB Product Name", kUSBSerialNumberString), but it
     * publishes neither an iConfiguration index nor any configuration string,
     * and IOUSBDeviceInterface has no cached-string call to stand in for the
     * transfer the way GetConfigurationDescriptorPtr stands in for fetching a
     * configuration descriptor.
     *
     * A NULL cfg_string is not a lie about the device, and this is why the file
     * stays present and empty rather than being left out: usb_cache_string
     * returns NULL "if the index is 0 or the string could not be read", so
     * every device here takes the second of Linux's own two paths to an empty
     * configuration. Known deviation, and a fidelity gap rather than a
     * correctness one: a device whose iConfiguration is non-zero and whose
     * string descriptor is readable shows that string on Linux and shows
     * nothing here. Closing it needs the ep0 path.
     */
    size_t cfg_len = 0;
    const uint8_t *cfg = active_config(d, &cfg_len);
    usb_actconfig_attrs_t actcfg;

    /* bMaxPower is in 2 mA units below SuperSpeed and 8 mA at and above it
     * (usb_get_max_power); speed_code is IOKit's "Device Speed", whose 3 is
     * SuperSpeed.
     */
    usb_desc_actconfig_attrs(cfg, cfg_len, d->speed_code >= 3 ? 8 : 2, NULL,
                             &actcfg);
    usb_write_file(dir, "bNumInterfaces", actcfg.num_interfaces,
                   strlen(actcfg.num_interfaces));
    usb_write_file(dir, "bmAttributes", actcfg.bm_attributes,
                   strlen(actcfg.bm_attributes));
    usb_write_file(dir, "bMaxPower", actcfg.max_power,
                   strlen(actcfg.max_power));
    usb_write_file(dir, "configuration", actcfg.configuration,
                   strlen(actcfg.configuration));

    /* Downstream port count. Hub descriptors need a control transfer on an open
     * device, which stage 1 deliberately does not do, so every device reports
     * the non-hub value. Known deviation: a hub's real port count is not
     * modeled, and neither is the parent/child topology that would use it.
     */
    usb_write_fmt(dir, "maxchild", "%d\n", 0);

    /* Lane counts (hub.c:3036-3041): SuperSpeed+ Gen 2x2 -- the registry's
     * Device Speed 5 -- runs two lanes each way, everything else one.
     */
    unsigned lanes = d->speed_code == 5 ? 2 : 1;
    usb_write_fmt(dir, "rx_lanes", "%u\n", lanes);
    usb_write_fmt(dir, "tx_lanes", "%u\n", lanes);
    if (d->manufacturer[0])
        usb_write_fmt(dir, "manufacturer", "%s\n", d->manufacturer);
    if (d->product[0])
        usb_write_fmt(dir, "product", "%s\n", d->product);
    if (d->serial[0])
        usb_write_fmt(dir, "serial", "%s\n", d->serial);
    usb_write_fmt(dir, "uevent",
                  "MAJOR=%d\n"
                  "MINOR=%d\n"
                  "DEVNAME=bus/usb/%03d/%03d\n"
                  "DEVTYPE=usb_device\n"
                  "DRIVER=usb\n"
                  "PRODUCT=%x/%x/%x\n"
                  "TYPE=%u/%u/%u\n"
                  "BUSNUM=%03d\n"
                  "DEVNUM=%03d\n",
                  USB_MAJOR, usb_minor(d), d->busnum, d->devnum, d->vid, d->pid,
                  d->bcd_device, d->dev_class, d->dev_subclass, d->dev_protocol,
                  d->busnum, d->devnum);
    usb_write_file(dir, "descriptors", d->blob, d->blob_len);

    /* libudev derives the subsystem from readlink(<dev>/subsystem) and keeps
     * only its basename; the relative target also resolves inside the scratch
     * tree (devices/<name>/../../../usb == bus/usb).
     */
    char linkpath[300];
    if (snprintf(linkpath, sizeof(linkpath), "%s/subsystem", dir) <
        (int) sizeof(linkpath))
        symlink("../../../usb", linkpath);

    emit_interface_dirs(devices_dir, d);
}

/* Alias name ("ttyACM0") for one tty entry.
 *
 * Returns false when the entry got no index (pool exhausted).
 */
static bool tty_alias_name(const usb_tty_t *t, char *buf, size_t bufsz)
{
    if (t->index < 0)
        return false;
    snprintf(buf, bufsz, "%s%d", t->is_acm ? "ttyACM" : "ttyUSB", t->index);
    return true;
}

/* Emit the sysfs pieces pyserial's list_ports_linux.py dereferences for one
 * alias (read against pyserial 3.5, lines 30-62):
 *
 *   /sys/class/tty/<name>/device -> nested interface dir (ttyACM) or the
 *       usb-serial port dir one level below it (ttyUSB)
 *   realpath(<device>/subsystem) basename == "usb" / "usb-serial"
 *   dirname chain from there reaches the PR-B device dir, whose idVendor /
 *   idProduct / serial / manufacturer / product / bNumInterfaces already
 *   exist -- nothing is duplicated at that level.
 *
 * The nested interface dir <dev>/<dev>:<c>.<i> exists because pyserial takes
 * os.path.dirname() of the interface path to find the device dir: the flat
 * sibling layout PR-B emits for libusb would dirname into devices/ itself.
 * Linux nests interfaces under the device the same way; the flat entries stay
 * because libusb wants them.
 */
static void emit_tty_sysfs(const char *sys_dir, const usb_tty_t *t)
{
    char alias[32];
    if (!tty_alias_name(t, alias, sizeof(alias)))
        return;
    const usb_dev_t *d = &usb_devs[t->dev];

    char ifname[64];
    snprintf(ifname, sizeof(ifname), "%s:%u.%u", d->name, d->cfg_value,
             t->ifnum);

    /* Nested interface dir inside the PR-B device dir. */
    char ifdir[300];
    if (snprintf(ifdir, sizeof(ifdir), "%s/bus/usb/devices/%s/%s", sys_dir,
                 d->name, ifname) >= (int) sizeof(ifdir))
        return;
    if (mkdir(ifdir, 0755) < 0 && errno != EEXIST)
        return;
    const uint8_t *idesc = find_iface_desc(d, t->ifnum);
    usb_write_fmt(ifdir, "bInterfaceNumber", "%02x\n", t->ifnum);
    if (idesc) {
        usb_write_fmt(ifdir, "bAlternateSetting", "%2d\n", idesc[3]);
        usb_write_fmt(ifdir, "bNumEndpoints", "%02x\n", idesc[4]);
        usb_write_fmt(ifdir, "bInterfaceClass", "%02x\n", idesc[5]);
        usb_write_fmt(ifdir, "bInterfaceSubClass", "%02x\n", idesc[6]);
        usb_write_fmt(ifdir, "bInterfaceProtocol", "%02x\n", idesc[7]);
    }
    char lnk[360];
    if (snprintf(lnk, sizeof(lnk), "%s/subsystem", ifdir) < (int) sizeof(lnk))
        symlink("../../../../../bus/usb", lnk);

    /* ttyUSB gets the intermediate usb-serial port dir: on Linux the tty hangs
     * off a usb-serial port device below the interface, and pyserial detects
     * that layout by the port dir's subsystem resolving to .../bus/usb-serial
     * before it dirnames up to the interface.
     */
    char devlink_target[420];
    if (t->is_acm) {
        snprintf(devlink_target, sizeof(devlink_target),
                 "../../../bus/usb/devices/%s/%s", d->name, ifname);
    } else {
        char portdir[360];
        if (snprintf(portdir, sizeof(portdir), "%s/%s", ifdir, alias) >=
            (int) sizeof(portdir))
            return;
        if (mkdir(portdir, 0755) < 0 && errno != EEXIST)
            return;
        if (snprintf(lnk, sizeof(lnk), "%s/subsystem", portdir) <
            (int) sizeof(lnk))
            symlink("../../../../../../bus/usb-serial", lnk);

        /* The attribute 60-serial.rules reads to build the -port<N> half of the
         * by-id name (drivers/usb/serial/bus.c, port_number_show).
         */
        usb_write_fmt(portdir, "port_number", "%u\n", t->port);
        snprintf(devlink_target, sizeof(devlink_target),
                 "../../../bus/usb/devices/%s/%s/%s", d->name, ifname, alias);
    }

    /* /sys/class/tty/<name>: Linux puts the class attributes (dev, uevent) here
     * and the device symlink into the nested tree built above.
     */
    char classdir[300];
    if (snprintf(classdir, sizeof(classdir), "%s/class/tty/%s", sys_dir,
                 alias) >= (int) sizeof(classdir))
        return;
    if (mkdir(classdir, 0755) < 0 && errno != EEXIST)
        return;
    int major = t->is_acm ? TTY_ACM_MAJOR : TTY_USB_MAJOR;
    usb_write_fmt(classdir, "dev", "%d:%d\n", major, t->index);
    usb_write_fmt(classdir, "uevent", "MAJOR=%d\nMINOR=%d\nDEVNAME=%s\n", major,
                  t->index, alias);
    if (snprintf(lnk, sizeof(lnk), "%s/device", classdir) < (int) sizeof(lnk))
        symlink(devlink_target, lnk);
    if (snprintf(lnk, sizeof(lnk), "%s/subsystem", classdir) <
        (int) sizeof(lnk))
        symlink("../../../class/tty", lnk);
}

/* Strict "ttyACM<n>"/"ttyUSB<n>" name parse (Linux devtmpfs spelling: plain
 * decimal, no leading zero).
 *
 * Returns the index or -1, with *acm_out set.
 */
static int tty_alias_parse(const char *name, bool *acm_out)
{
    bool acm;
    if (strncmp(name, "ttyACM", 6) == 0)
        acm = true;
    else if (strncmp(name, "ttyUSB", 6) == 0)
        acm = false;
    else
        return -1;
    const char *digits = name + 6;
    if (!*digits || (digits[0] == '0' && digits[1] != '\0'))
        return -1;
    long n = 0;
    for (const char *c = digits; *c; c++) {
        if (*c < '0' || *c > '9')
            return -1;
        n = n * 10 + (*c - '0');
        if (n > 4096)
            return -1;
    }
    *acm_out = acm;
    return (int) n;
}

/* Ownership marker for everything this file plants in the sysroot's /dev: an
 * APFS user xattr, set at creation on alias placeholders, by-id symlinks and
 * the serial/by-id directories. The sweeps below delete ONLY entries carrying
 * it, so nothing a user put there -- even an empty, alias-shaped file -- is
 * ever removed or overwritten. XATTR_NOFOLLOW makes the calls operate on a
 * symlink itself rather than its (possibly missing) target.
 *
 * The value is "pid=<n>", the run that created the entry, and the sweeps
 * reclaim only what this process created or what an owner no longer running
 * left behind. The marker alone said "elfuse's", not "this run's", so two
 * guests sharing one sysroot deleted each other's live placeholders: measured,
 * a second run with a different device set emptied the first's /dev of names
 * its guest was still opening.
 */
#define USB_ALIAS_XATTR "user.elfuse.usb-alias"

static void usb_alias_mark(const char *path)
{
    char v[24];
    int vn = snprintf(v, sizeof(v), "pid=%d", (int) getpid());
    if (vn > 0 && (size_t) vn < sizeof(v) &&
        setxattr(path, USB_ALIAS_XATTR, v, (size_t) vn, 0, XATTR_NOFOLLOW) == 0)
        return;

    /* A sysroot on a filesystem that cannot carry a user xattr -- exFAT, FAT,
     * many NFS mounts, or a tree copied without them -- leaves every entry this
     * function creates unmarked, so the sweep below stops reclaiming stale
     * aliases and every later run reports its own droppings as foreign. Say it
     * once: nothing here can repair it, and silence made it look like a user
     * had planted the files.
     */
    static bool warned;
    if (!warned) {
        warned = true;
        log_warn(
            "usb-sysfs: cannot mark %s as ours (%s); stale serial aliases in "
            "the sysroot will not be reclaimed",
            path, strerror(errno));
    }
}

static bool usb_alias_marked(const char *path)
{
    return getxattr(path, USB_ALIAS_XATTR, NULL, 0, 0, XATTR_NOFOLLOW) >= 0;
}

/* Ours AND safe to delete: created by this process, or by one that has since
 * exited. A marker this build cannot parse counts as reclaimable, so an entry
 * left by an older spelling is not stranded.
 */
static bool usb_alias_reclaimable(const char *path)
{
    char v[24];
    ssize_t n =
        getxattr(path, USB_ALIAS_XATTR, v, sizeof(v) - 1, 0, XATTR_NOFOLLOW);
    if (n < 0)
        return false;
    v[n] = '\0';
    if (strncmp(v, "pid=", 4) != 0)
        return true;
    long pid = strtol(v + 4, NULL, 10);
    if (pid <= 0 || pid == (long) getpid())
        return true;
    return kill((pid_t) pid, 0) < 0 && errno == ESRCH;
}

/* Materialize the alias placeholders in the sysroot's /dev so a plain
 * readdir("/dev") -- the glob("/dev/ttyACM*") every Linux serial consumer
 * starts with -- lists them. The files are empty 0644 regulars on disk (the
 * /dev/pts placeholder trick): the absolute-path stat and open intercepts
 * answer before the host filesystem does, so the guest sees char devices.
 * Without a sysroot /dev is the real macOS /dev, which elfuse must not (and
 * cannot) write to; direct opens of /dev/ttyACM<n> still work through the
 * intercepts, only readdir misses them.
 *
 * The sweep removes only entries stamped with USB_ALIAS_XATTR, i.e. what a
 * previous run of this function created: a user-planted file under the same
 * name carries no marker and survives, and a live alias whose name is already
 * taken by an unmarked user file is skipped with a warning rather than
 * overwritten. Entries persist across exit on purpose (the guest may still hold
 * them; a fresh run resweeps) -- persistence is safe now that the marker scopes
 * every future sweep to our own droppings.
 */
static void tty_alias_sync_dev(void)
{
    char sr[1024];
    if (!proc_sysroot_snapshot(sr, sizeof(sr)))
        return;
    char devdir[1100];
    if (snprintf(devdir, sizeof(devdir), "%s/dev", sr) >= (int) sizeof(devdir))
        return;
    struct stat st;
    if (stat(devdir, &st) < 0 || !S_ISDIR(st.st_mode))
        return;

    bool have[2][USB_TTY_MAX] = {{false}};
    for (int i = 0; i < usb_nttys; i++)
        if (usb_ttys[i].index >= 0 && usb_ttys[i].index < USB_TTY_MAX)
            have[usb_ttys[i].is_acm ? 1 : 0][usb_ttys[i].index] = true;

    DIR *dp = opendir(devdir);
    if (dp) {
        struct dirent *ent;
        while ((ent = readdir(dp))) {
            bool acm;
            int idx = tty_alias_parse(ent->d_name, &acm);
            if (idx < 0)
                continue;
            if (idx < USB_TTY_MAX && have[acm ? 1 : 0][idx])
                continue;
            char path[1200];
            if (snprintf(path, sizeof(path), "%s/%s", devdir, ent->d_name) >=
                (int) sizeof(path))
                continue;
            if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
                usb_alias_reclaimable(path))
                unlink(path);
        }
        closedir(dp);
    }

    /* Only bring /dev/serial/by-id into existence when there is a link to put
     * in it. Creating it unconditionally left the two directories behind in a
     * sysroot whose run had no serial device at all, and nothing sweeps a
     * directory.
     */
    bool want_byid = false;
    for (int i = 0; i < usb_nttys && !want_byid; i++)
        if (usb_ttys[i].byid[0] && usb_ttys[i].index >= 0)
            want_byid = true;

    char byiddir[1160];
    if (want_byid) {
        snprintf(byiddir, sizeof(byiddir), "%s/serial", devdir);
        if (mkdir(byiddir, 0755) == 0)
            usb_alias_mark(byiddir);
    }
    snprintf(byiddir, sizeof(byiddir), "%s/serial/by-id", devdir);
    if (want_byid && mkdir(byiddir, 0755) == 0)
        usb_alias_mark(byiddir);

    /* Sweep stale by-id links before (re)creating the live set. */
    dp = opendir(byiddir);
    if (dp) {
        struct dirent *ent;
        while ((ent = readdir(dp))) {
            if (strncmp(ent->d_name, "usb-", 4) != 0)
                continue;
            bool live = false;
            char alias[32];
            for (int i = 0; i < usb_nttys && !live; i++)
                if (usb_ttys[i].byid[0] &&
                    tty_alias_name(&usb_ttys[i], alias, sizeof(alias)) &&
                    strcmp(usb_ttys[i].byid, ent->d_name) == 0)
                    live = true;
            if (live)
                continue;
            char path[1400];
            if (snprintf(path, sizeof(path), "%s/%s", byiddir, ent->d_name) >=
                (int) sizeof(path))
                continue;
            if (usb_alias_reclaimable(path))
                unlink(path);
        }
        closedir(dp);
    }

    for (int i = 0; i < usb_nttys; i++) {
        const usb_tty_t *t = &usb_ttys[i];
        char alias[32];
        if (!tty_alias_name(t, alias, sizeof(alias)))
            continue;
        char path[1400];
        if (snprintf(path, sizeof(path), "%s/%s", devdir, alias) <
            (int) sizeof(path)) {
            int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
            if (fd >= 0) {
                close(fd);
                usb_alias_mark(path);
            } else if (errno == EEXIST && !usb_alias_marked(path)) {
                log_warn(
                    "usb-sysfs: /dev/%s exists and is not ours; "
                    "leaving it alone",
                    alias);
            }
        }
        if (!t->byid[0])
            continue;
        char target[64];
        snprintf(target, sizeof(target), "../../%s", alias);
        if (snprintf(path, sizeof(path), "%s/%s", byiddir, t->byid) >=
            (int) sizeof(path))
            continue;
        char tgt[64];
        ssize_t n = readlink(path, tgt, sizeof(tgt) - 1);
        if (n > 0) {
            tgt[n] = '\0';
            if (strcmp(tgt, target) == 0)
                continue;
            if (!usb_alias_marked(path)) {
                log_warn(
                    "usb-sysfs: by-id link %s exists and is not ours; "
                    "leaving it alone",
                    t->byid);
                continue;
            }
            unlink(path); /* our link to a renumbered alias; recreate */
        }
        if (symlink(target, path) == 0)
            usb_alias_mark(path);
    }
}

static void usb_remove_tree(const char *dir, int depth)
{
    if (depth > 6)
        return;
    DIR *dp = opendir(dir);
    if (dp) {
        struct dirent *ent;
        while ((ent = readdir(dp))) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
            char path[512];
            if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >=
                (int) sizeof(path))
                continue;
            struct stat st;
            if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
                usb_remove_tree(path, depth + 1);
            else
                unlink(path);
        }
        closedir(dp);
    }
    rmdir(dir);
}

static void usb_tree_cleanup(void)
{
    pthread_mutex_lock(&usb_lock);
    if (usb_tree_ok && usb_owner_pid == getpid()) {
        usb_remove_tree(usb_sys_dir, 0);
        usb_remove_tree(usb_dev_dir, 0);
    }
    usb_tree_ok = false;
    model_release();
    pthread_mutex_unlock(&usb_lock);
}

/* One-shot build under usb_lock (the ensure_syscpu_dir pattern). The model is a
 * boot-time snapshot: hotplug support would clear usb_tree_ok here so the next
 * call re-enumerates, once something (the uevent layer) can observe
 * attach/detach and call in.
 * Returns 0 with both scratch roots valid, or -1 with errno set.
 */
static int ensure_usb_tree(void)
{
    if (usb_tree_ok)
        return 0;

    str_copy_trunc(usb_sys_dir, "/tmp/elfuse-usbsys-XXXXXX",
                   sizeof(usb_sys_dir));
    if (!mkdtemp(usb_sys_dir)) {
        usb_sys_dir[0] = '\0';
        return -1;
    }
    if (!realpath(usb_sys_dir, usb_sys_real)) {
        int saved = errno;
        usb_remove_tree(usb_sys_dir, 0);
        usb_sys_dir[0] = usb_sys_real[0] = '\0';
        errno = saved;
        return -1;
    }
    str_copy_trunc(usb_dev_dir, "/tmp/elfuse-usbdev-XXXXXX",
                   sizeof(usb_dev_dir));
    if (!mkdtemp(usb_dev_dir)) {
        usb_remove_tree(usb_sys_dir, 0);
        usb_sys_dir[0] = usb_dev_dir[0] = usb_sys_real[0] = '\0';
        return -1;
    }

    model_build();

    char devices_dir[128];
    {
        char sub[128];
        snprintf(sub, sizeof(sub), "%s/bus", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;
        snprintf(sub, sizeof(sub), "%s/bus/usb", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;
        snprintf(sub, sizeof(sub), "%s/class", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;
        snprintf(sub, sizeof(sub), "%s/class/tty", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;

        /* Present even with no ttyUSB device, like /sys/bus/usb-serial on a
         * Linux system with the usb-serial core loaded; an empty-but-valid
         * structure beats a dangling subsystem link target.
         */
        snprintf(sub, sizeof(sub), "%s/bus/usb-serial", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;
    }
    snprintf(devices_dir, sizeof(devices_dir), "%s/bus/usb/devices",
             usb_sys_dir);
    if (mkdir(devices_dir, 0755) < 0)
        goto fail;
    char usbdir[128];
    snprintf(usbdir, sizeof(usbdir), "%s/usb", usb_dev_dir);
    if (mkdir(usbdir, 0755) < 0)
        goto fail;

    for (int i = 0; i < usb_ndevs; i++) {
        const usb_dev_t *d = &usb_devs[i];
        emit_device_dir(devices_dir, d);

        char busdir[160];
        if (snprintf(busdir, sizeof(busdir), "%s/%03d", usbdir, d->busnum) >=
            (int) sizeof(busdir))
            continue;
        if (mkdir(busdir, 0755) < 0 && errno != EEXIST)
            continue;
        char node[8];
        snprintf(node, sizeof(node), "%03d", d->devnum);
        /* Placeholder: 0444 empty regular file; open/stat divert it. */
        usb_write_file(busdir, node, "", 0);
    }

    for (int i = 0; i < usb_nttys; i++)
        emit_tty_sysfs(usb_sys_dir, &usb_ttys[i]);
    tty_alias_sync_dev();

    static bool atexit_armed;
    if (!atexit_armed) {
        atexit(usb_tree_cleanup);
        atexit_armed = true;
    }
    usb_owner_pid = getpid();
    usb_tree_ok = true;
    return 0;

fail:;
    int saved = errno;
    usb_remove_tree(usb_sys_dir, 0);
    usb_remove_tree(usb_dev_dir, 0);
    usb_sys_dir[0] = usb_dev_dir[0] = usb_sys_real[0] = '\0';
    model_release();
    errno = saved;
    return -1;
}

/* path classification */

typedef enum {
    USB_PATH_NONE,
    USB_PATH_DEV_ROOT,     /* /dev itself (alias materialization hook) */
    USB_PATH_DEV_BUS,      /* /dev/bus            */
    USB_PATH_DEV_USB,      /* /dev/bus/usb        */
    USB_PATH_DEV_BUSNUM,   /* /dev/bus/usb/BBB    */
    USB_PATH_DEV_NODE,     /* /dev/bus/usb/BBB/DDD */
    USB_PATH_DEV_NODE_SUB, /* the node used as a directory: BBB/DDD/ or /x */
    USB_PATH_DEV_ABSENT,   /* under /dev/bus/usb but no such device */
    USB_PATH_DEV_FOREIGN,  /* under /dev/bus but on no bus we model */
    USB_PATH_TTY,          /* /dev/ttyACM<n> or /dev/ttyUSB<n> */
    USB_PATH_TTY_SUB,      /* the alias used as a directory: ttyACM0/ or /x */
    USB_PATH_BYID,         /* /dev/serial/by-id/<leaf> */
    USB_PATH_SYS,          /* /sys[/suffix] (whole sysfs view) */
} usb_path_kind_t;

/* Parse exactly three decimal digits followed by '\0' or '/'. */
static int parse_ddd(const char *s, const char **rest)
{
    if (!isdigit((unsigned char) s[0]) || !isdigit((unsigned char) s[1]) ||
        !isdigit((unsigned char) s[2]))
        return -1;
    if (s[3] != '\0' && s[3] != '/')
        return -1;
    *rest = s + 3;
    return (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0');
}

/* Skip one or more '/' and report whether anything follows. */
static const char *skip_slashes(const char *s)
{
    while (*s == '/')
        s++;
    return s;
}

static usb_path_kind_t classify_path(const char *path,
                                     int *bus_out,
                                     int *dev_out,
                                     const char **sys_suffix_out)
{
    if (path_prefix_match(path, "/sys", 4)) {
        /* /sys/devices/system/cpu stays with the syscpu stub, which the procemu
         * dispatchers consult before this layer.
         */
        if (path_prefix_match(path, "/sys/devices/system/cpu", 23))
            return USB_PATH_NONE;
        const char *sfx = skip_slashes(path + 4);
        *sys_suffix_out = sfx;
        return USB_PATH_SYS;
    }
    if (!strcmp(path, "/dev") || !strcmp(path, "/dev/"))
        return USB_PATH_DEV_ROOT;
    if (!strncmp(path, "/dev/tty", 8)) {
        const char *q = path + 5;
        size_t nlen = strcspn(q, "/");
        char name[40];
        if (nlen >= sizeof(name))
            return USB_PATH_NONE;
        memcpy(name, q, nlen);
        name[nlen] = '\0';
        bool acm;
        int idx = tty_alias_parse(name, &acm);
        if (idx < 0)
            return USB_PATH_NONE; /* /dev/tty itself, ttyS0, ... */
        *bus_out = acm ? 1 : 0;
        *dev_out = idx;

        /* Anything after the name uses a character device as a directory, which
         * Linux answers ENOTDIR for; the /dev/bus node arm spells the same case
         * USB_PATH_DEV_NODE_SUB.
         */
        return q[nlen] ? USB_PATH_TTY_SUB : USB_PATH_TTY;
    }
    if (path_prefix_match(path, "/dev/serial", 11)) {
        /* Only the by-id leaves are claimed: their host backing is a symlink
         * onto the empty placeholder file, so a host-side open would hand the
         * guest a plain file instead of the serial device. The directories
         * themselves stay host-served (they physically exist in the sysroot
         * once tty_alias_sync_dev ran).
         */
        const char *q = skip_slashes(path + 11);
        if (strncmp(q, "by-id", 5) != 0 || q[5] != '/')
            return USB_PATH_NONE;
        q = skip_slashes(q + 5);
        if (!*q || strchr(q, '/'))
            return USB_PATH_NONE;

        /* "." and ".." belong to the host-served directory itself (a Linux
         * readdir stats them through the dir), not to any link.
         */
        if (!strcmp(q, ".") || !strcmp(q, ".."))
            return USB_PATH_NONE;
        *sys_suffix_out = q;
        return USB_PATH_BYID;
    }
    if (!path_prefix_match(path, "/dev/bus", 8))
        return USB_PATH_NONE;

    const char *p = skip_slashes(path + 8);
    if (!*p)
        return USB_PATH_DEV_BUS;
    if (strncmp(p, "usb", 3) != 0 || (p[3] != '\0' && p[3] != '/'))
        return USB_PATH_DEV_FOREIGN;
    p = skip_slashes(p + 3);
    if (!*p)
        return USB_PATH_DEV_USB;
    const char *rest;
    int bus = parse_ddd(p, &rest);
    if (bus < 0)
        return USB_PATH_DEV_ABSENT;
    rest = skip_slashes(rest);
    if (!*rest) {
        *bus_out = bus;
        return USB_PATH_DEV_BUSNUM;
    }
    const char *rest2;
    int dev = parse_ddd(rest, &rest2);
    if (dev < 0)
        return USB_PATH_DEV_ABSENT;
    *bus_out = bus;
    *dev_out = dev;

    /* Any separator after the node -- a bare trailing slash included, which is
     * why this tests rest2 itself rather than what survives skip_slashes -- is
     * the node being used as a directory. Linux answers ENOTDIR for that, but
     * only once the node exists; a missing node still reports ENOENT, so the
     * decision is deferred to the lookup rather than made here.
     */
    if (rest2[0] != '\0')
        return USB_PATH_DEV_NODE_SUB;
    return USB_PATH_DEV_NODE;
}

/* True when a folded /sys-relative suffix names something under the one subtree
 * this layer synthesizes, /sys/bus/usb. It gates a single decision: what to do
 * when a /sys name resolves to nothing in the scratch tree. Under /sys/bus/usb
 * an absence is authoritative -- a missing device is ENOENT, the way a real
 * sysfs answers -- so this returns true and the caller keeps the ENOENT.
 * Anywhere else under /sys (/sys/class, /sys/devices, /sys/kernel, a bus other
 * than usb) we model nothing, so a miss must not be reported as ENOENT: that
 * would shadow a populated sysroot /sys. This returns false there and the
 * caller reports PROC_NOT_INTERCEPTED so the sysroot backing answers.
 *
 * The /sys root and its /sys/bus parent are not "owned" by this test, but they
 * exist as real directories in the scratch tree, so they resolve and are served
 * before this test is ever consulted; only the resolve-failure path asks it.
 * The @suffix arrives with '.'/'..' folded, so "bus/usb/../class" is "class"
 * and correctly disowned, while "bus/usb/devices/1-1" stays ours.
 */
static bool usb_sys_suffix_owned(const char *suffix)
{
    /* Exactly the bus/usb directory, or a name that continues it past a '/'.
     * Spelled with whole-string compares rather than a suffix[7] index so the
     * boundary byte is never read on its own -- the folded builder output that
     * reaches here is NUL-terminated, but an explicit index past the compared
     * prefix reads to the analyzer as a maybe-uninitialized byte.
     */
    return !strcmp(suffix, "bus/usb") || !strncmp(suffix, "bus/usb/", 8);
}

static usb_dev_t *find_dev(int busnum, int devnum)
{
    for (int i = 0; i < usb_ndevs; i++)
        if (usb_devs[i].busnum == busnum && usb_devs[i].devnum == devnum)
            return &usb_devs[i];
    return NULL;
}

static bool bus_exists(int busnum)
{
    for (int i = 0; i < usb_ndevs; i++)
        if (usb_devs[i].busnum == busnum)
            return true;
    return false;
}

static usb_tty_t *find_tty(bool acm, int index)
{
    for (int i = 0; i < usb_nttys; i++)
        if (usb_ttys[i].is_acm == acm && usb_ttys[i].index == index)
            return &usb_ttys[i];
    return NULL;
}

static usb_tty_t *find_tty_byid(const char *leaf)
{
    for (int i = 0; i < usb_nttys; i++)
        if (usb_ttys[i].byid[0] && strcmp(usb_ttys[i].byid, leaf) == 0)
            return &usb_ttys[i];
    return NULL;
}

/* Open the macOS callout node behind one alias. Character-device open: keep the
 * access mode and the descriptor flags, drop creation/truncation semantics (the
 * procemu.c /dev/null pattern -- O_CREAT without a mode arg would be a variadic
 * bug on the host open). A cu.* callout never blocks waiting for carrier (that
 * is the tty.* dial-in side), so a blocking guest open cannot hang here.
 *
 * O_NOCTTY is kept, the same mask procemu-pty.c passes through for the slave
 * open. An earlier comment here asserted that a cu.* callout open never becomes
 * a controlling terminal and so needed no translation; measured on this host
 * with a session leader, a callout opened without O_NOCTTY does acquire one
 * (/dev/tty opens afterwards where it answered ENXIO before), so dropping the
 * flag handed line-discipline SIGINT and hangup SIGHUP to a session that asked
 * not to have a terminal. pyserial passes O_NOCTTY on every port open.
 *
 * Identity caveat: the only handle this open has is the macOS callout NAME.
 * cu.usbmodem* names are derived from the port location (plus driver), not from
 * the device's serial, so if the modeled device was swapped for another serial
 * device on the same port between rescans, this open reaches the newcomer --
 * unlike the usbdevfs open path, which cross-checks vid/pid/serial against the
 * model before binding. Accepted residual risk: the tty layer has no per-open
 * registry identity to verify against.
 */
static int tty_alias_host_open(const usb_tty_t *t, int linux_flags)
{
    int oflags = translate_open_flags(linux_flags);
    return open(t->host_node,
                oflags & (O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_NOCTTY));
}

/* Fold '.' and '..' in a /sys-relative suffix, lexically.
 *
 * This is the ours/not-ours gate and nothing more: a suffix that folds away
 * above /sys is not a name this layer serves, and the caller reports
 * PROC_NOT_INTERCEPTED for it. Rejecting '..' outright (the syscpu_suffix_safe
 * contract) answered EACCES for /sys/bus/usb/devices/../devices/2-1, which
 * Linux resolves without complaint, so this folds instead.
 *
 * The fold is NOT how the served path is built. An earlier version claimed the
 * lexical fold was exact because `subsystem` links are always the last
 * component -- that is false, `<dev>/subsystem/..` puts one in the middle, and
 * so does <tty>/device/.. among the /sys/class/tty links. Linux applies '..' to
 * what the link resolved to rather than to the directory the link sits in.
 * usb_sys_resolve_suffix does the real resolution; see it for how '..' and
 * symlinks are ordered.
 *
 * A trailing slash survives the fold: it is what makes an attribute file used
 * as a directory report ENOTDIR.
 *
 * Returns 1 with out filled, 0 when the walk climbs above /sys (no longer ours;
 * the caller reports PROC_NOT_INTERCEPTED), -1 when the result does not fit.
 */
static int usb_suffix_normalize(const char *suffix, char *out, size_t outsz)
{
    size_t len = 0;
    size_t marks[64];
    size_t depth = 0;

    out[0] = '\0';
    for (const char *p = suffix; *p;) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t seglen = (size_t) (p - seg);
        while (*p == '/')
            p++;
        if (seglen == 0 || (seglen == 1 && seg[0] == '.'))
            continue;
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth == 0)
                return 0; /* above /sys */
            len = marks[--depth];
            out[len] = '\0';
            continue;
        }
        if (depth >= ARRAY_SIZE(marks))
            return -1;
        marks[depth++] = len;
        if (len + (len ? 1 : 0) + seglen + 1 > outsz)
            return -1;
        if (len)
            out[len++] = '/';
        memcpy(out + len, seg, seglen);
        len += seglen;
        out[len] = '\0';
    }

    /* Preserve a trailing slash only when something remains to apply it to;
     * "/sys/bus/.." folds to /sys itself, which is a directory either way.
     */
    if (len > 0 && suffix[0] && suffix[strlen(suffix) - 1] == '/') {
        if (len + 2 > outsz)
            return -1;
        out[len++] = '/';
        out[len] = '\0';
    }
    return 1;
}

/* Synthetic stat identities, mirroring procemu.c's PROC_SYNTH_DEV scheme with a
 * distinct device so /sys/bus/usb nodes never collide with /proc ones.
 */
#define USB_SYNTH_DEV ((dev_t) 0x5553)

/* st_ino identifies the object, not the spelling that reached it: hashing the
 * caller's path handed /sys/bus/usb/devices and /sys/bus/usb/devices/../devices
 * two different inodes for one directory, which is a thing no filesystem does
 * and which every (st_dev, st_ino) same-file test -- realpath loop detection,
 * find -L, hardlink accounting -- would believe. Callers pass the canonical
 * spelling built by usb_canon_path.
 */
static ino_t usb_synth_ino(const char *canon)
{
    uint64_t h = fnv1a64(canon, strlen(canon));
    h &= 0x7fffffffffffffffULL;
    return (ino_t) (h ? h : 1);
}

/* One spelling per object: the guest-visible path with '.'/'..' already folded
 * (the suffix arrives normalized) and any trailing slash dropped.
 */
static void usb_canon_path(usb_path_kind_t kind,
                           const char *sfx,
                           int bus,
                           int dev,
                           char *out,
                           size_t outsz)
{
    switch (kind) {
    case USB_PATH_SYS:
        if (*sfx)
            snprintf(out, outsz, "/sys/%s", sfx);
        else
            str_copy_trunc(out, "/sys", outsz);
        break;
    case USB_PATH_DEV_BUS:
        str_copy_trunc(out, "/dev/bus", outsz);
        break;
    case USB_PATH_DEV_USB:
        str_copy_trunc(out, "/dev/bus/usb", outsz);
        break;
    case USB_PATH_DEV_BUSNUM:
        snprintf(out, outsz, "/dev/bus/usb/%03d", bus);
        break;
    case USB_PATH_DEV_NODE:
    case USB_PATH_DEV_NODE_SUB:
        snprintf(out, outsz, "/dev/bus/usb/%03d/%03d", bus, dev);
        break;

    /* bus/dev carry (is_acm, index) for a tty alias, and the by-id leaf comes
     * in as the suffix; both get the same one-spelling treatment as the /sys
     * and /dev/bus entries above.
     */
    case USB_PATH_TTY:
    case USB_PATH_TTY_SUB:
        snprintf(out, outsz, "/dev/tty%s%d", bus ? "ACM" : "USB", dev);
        break;
    case USB_PATH_BYID:
        snprintf(out, outsz, "/dev/serial/by-id/%s", sfx);
        break;
    case USB_PATH_DEV_ROOT:
        str_copy_trunc(out, "/dev", outsz);
        break;
    case USB_PATH_DEV_ABSENT:
    case USB_PATH_DEV_FOREIGN:
    case USB_PATH_NONE:
        str_copy_trunc(out, "/dev/bus", outsz);
        break;
    }
    size_t n = strlen(out);
    while (n > 1 && out[n - 1] == '/')
        out[--n] = '\0';
}

static void fill_synth_dir(struct stat *st, const char *canon)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
}

static void fill_synth_file(struct stat *st, const char *canon)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
}

static void fill_synth_chardev(struct stat *st,
                               const char *canon,
                               const usb_dev_t *d)
{
    memset(st, 0, sizeof(*st));

    /* 0666 rather than udev's root:root 0660 policy: the single-user guest must
     * be able to open its own device nodes, which is what a desktop Linux
     * spells as a uaccess ACL for the seat owner. The owner reported below is
     * the host user, and the guest's own uid need not equal it, so 0664 left
     * access(W_OK) answering EACCES for a node that open(O_RDWR) then served --
     * the two entry points onto one permission question disagreeing. Stage 1
     * had no writable open to disagree with; stage 2 does.
     */
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();

    /* macOS dev_t encoding (major<<24 | minor); translate_stat converts.
     * Composed in uint32_t: dev_t is a signed 32-bit int here, so shifting
     * major 189 left by 24 lands in the sign bit and is undefined -- the SDK's
     * own makedev() has the same defect, which is why the encoding is spelled
     * out rather than borrowed.
     */
    st->st_rdev =
        (dev_t) (((uint32_t) USB_MAJOR << 24) | (uint32_t) usb_minor(d));
    st->st_blksize = 4096;
    st->st_size = (off_t) d->blob_len;
}

/* Alias char-dev stat: Linux major 166 (cdc-acm) or 188 (usb-serial), minor is
 * the sticky index. 0666 for exactly the reason the usbfs nodes above are: the
 * owner reported here is the host user and the guest's uid need not equal it,
 * so the guest is in the "other" class and 0664 answered access(W_OK) EACCES
 * for a node open(O_RDWR) then served. This is the entry-point disagreement
 * fill_synth_chardev's comment describes; it was reintroduced here by citing
 * that comment and then choosing the mode it rules out. Measured: with 0664 the
 * guest saw access(R|W)=EACCES and open(O_RDWR)=ok on the same path, which no
 * Linux configuration produces.
 */
static void fill_synth_tty_stat(struct stat *st,
                                const char *canon,
                                const usb_tty_t *t)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();

    /* macOS dev_t encoding (major<<24 | minor); translate_stat converts.
     * Composed in uint32_t for the same reason the USB node's is: dev_t is a
     * signed 32-bit int here, so both 166 and 188 shifted left by 24 land in
     * the sign bit.
     */
    st->st_rdev =
        (dev_t) (((uint32_t) (t->is_acm ? TTY_ACM_MAJOR : TTY_USB_MAJOR)
                  << 24) |
                 (uint32_t) t->index);
    st->st_blksize = 4096;
}

/* Synthetic descriptor-blob fd (the proc_synthetic_fd pattern): unlinked temp
 * file so lseek/pread work.
 */
static int usb_blob_fd(const usb_dev_t *d)
{
    char template[] = "/tmp/elfuse-usbnode-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return -1;
    unlink(template);
    const uint8_t *p = d->blob;
    size_t left = d->blob_len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR)
            continue; /* retry like syscpu_write_file: a stray signal must
                       * not abort a one-shot tree build
                       */
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        left -= (size_t) n;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* intercept entry points */

/* Shared entry-point preamble: fold the name, then decide whose it is, before
 * any lock is taken. Both halves fold; see the /dev/bus arm below and
 * usb_suffix_normalize for what the fold is and is not.
 *
 * *sfx_out receives the /sys suffix as the guest spelled it -- unfolded,
 * because usb_sys_resolve_suffix has to see the '..' in their original
 * positions to order them against the symlinks they follow. `norm` holds the
 * folded spelling, which decides only whether the name is ours.
 *
 * Every name whose spelling alone settles ownership is settled here, so that no
 * entry point re-derives it: a /sys name that folds above /sys, a /dev/bus name
 * that folds above /dev/bus, and a /dev/bus name on a bus we do not model all
 * leave as USB_PATH_NONE, and every caller reports PROC_NOT_INTERCEPTED. See
 * docs/internals.md, "Ownership Of /sys And /dev Names", for why a name we do
 * not serve must fall through rather than answer ENOENT.
 *
 * The one ours/not-ours question this cannot answer is the /sys name that has
 * to be resolved first; usb_resolve_or_disown owns that half.
 *
 * Returns the kind, or USB_PATH_NONE when the folded path is not ours; *err_out
 * non-zero means classify itself failed (ENAMETOOLONG) and the caller must
 * report it rather than pass the path on.
 */
static usb_path_kind_t classify_and_normalize(const char *path,
                                              int *bus_out,
                                              int *dev_out,
                                              const char **sfx_out,
                                              char *norm,
                                              size_t normsz,
                                              int *err_out)
{
    *err_out = 0;

    /* Leading duplicate slashes and leading "." components name the root the
     * same object Linux does, and the prefix tests below read the first
     * component literally, so //dev/ttyACM0 and /./dev/ttyACM0 reached neither
     * half of the layer. A chain that pops back to the root through a name
     * elsewhere (/etc/../dev/ttyACM0) is deliberately left not-ours: nothing
     * here can say whether that name exists.
     */
    while (path[0] == '/' && path[1] == '/')
        path++;
    while (!strncmp(path, "/./", 3))
        path += 2;

    /* Fold the /dev suffix before classify_path reads it, so both halves of the
     * layer reach ownership the same way. The /sys half has always folded first
     * and decided after; the /dev half used to classify the guest's spelling as
     * written, and a '..' crossing the boundary then went wrong in both
     * directions. /dev/bus/usb/../other/f reached parse_ddd's failure arm and
     * came back USB_PATH_DEV_ABSENT, so the layer claimed the name and answered
     * ENOENT for a file the sysroot really has; /dev/bus/other/../usb/001/002
     * classified as USB_PATH_DEV_FOREIGN, fell through, and missed the
     * synthetic node because no sysroot carries a /dev/bus/usb. Both spellings
     * are matrix columns now (dev-fold-out and dev-fold-in).
     *
     * The fold starts at /dev rather than at /dev/bus because the alias arms
     * added below sit directly under /dev, and reading the guest's raw spelling
     * for them reproduced the same split: /dev/ttyACM0 named the character
     * device while //dev/ttyACM0, /dev/./ttyACM0 and
     * /dev/serial/by-id/../../ttyACM0 all named the placeholder file behind it,
     * so one object answered as two. The tty-fold matrix column holds it.
     *
     * The fold is lexical, and that is the right walk here: every component of
     * /dev/bus this layer serves is a plain directory it materialized itself,
     * and so is every component between /dev and an alias name, so there is no
     * symlink of ours for a kernel-order walk to resolve differently. A '..'
     * through a symlink the sysroot's own /dev carries is the residual case,
     * and it is the same one the /dev/bus arm has always had. The result is
     * written into `norm`, which the /sys arm below would use for its own
     * folded suffix -- the two never both run -- and classify_path's
     * sys_suffix_out is only set on the /sys arm, so it keeps pointing into
     * live storage either way.
     *
     * A suffix that folds away above /dev leaves as USB_PATH_NONE, the same
     * answer the /sys arm gives a name that climbs above /sys: the layer serves
     * nothing there and the caller reports PROC_NOT_INTERCEPTED.
     */
    if (path_prefix_match(path, "/dev", 4)) {
        char folded[LINUX_PATH_MAX];
        int frc = usb_suffix_normalize(skip_slashes(path + 4), folded,
                                       sizeof(folded));
        if (frc < 0) {
            *err_out = ENAMETOOLONG;
            return USB_PATH_NONE;
        }
        if (frc == 0)
            return USB_PATH_NONE; /* climbed above /dev; not ours */
        int n = folded[0] ? snprintf(norm, normsz, "/dev/%s", folded)
                          : snprintf(norm, normsz, "/dev");
        if (n < 0 || (size_t) n >= normsz) {
            *err_out = ENAMETOOLONG;
            return USB_PATH_NONE;
        }
        path = norm;
    }

    usb_path_kind_t kind = classify_path(path, bus_out, dev_out, sfx_out);
    if (kind == USB_PATH_DEV_FOREIGN)
        return USB_PATH_NONE; /* another bus's /dev/bus subtree; not ours */
    if (kind != USB_PATH_SYS)
        return kind;
    int rc = usb_suffix_normalize(*sfx_out, norm, normsz);
    if (rc < 0) {
        *err_out = ENAMETOOLONG;
        return USB_PATH_NONE;
    }
    if (rc == 0)
        return USB_PATH_NONE; /* climbed above /sys; not ours */
    return USB_PATH_SYS;
}

/* Resolve a host path inside the sysfs scratch tree and prove the result is
 * still inside it, so the caller can open it with symlinks followed.
 *
 * Following is safe because the links are ours -- emit_* writes them with fixed
 * relative targets into a tree the guest cannot write -- so procemu.c's "do not
 * follow symlinks the guest created" has nothing to bite on, and a positive
 * containment check replaces the blanket refusal.
 *
 * The escape guarantee: the suffix arrives lexically folded, so host_path
 * cannot climb out on its own and a symlink is the only way out; realpath()
 * resolves every one of them, leaf and intermediate alike, and the canonical
 * result is tested against the canonical root. A path that resolved outside is
 * reported absent. The open still passes O_NOFOLLOW, which closes the swap
 * window on the final component; a symlink spun into an intermediate directory
 * between the resolve and the open would still be followed, and that residual
 * TOCTOU is unreachable -- a sysrooted guest cannot name the host scratch tree
 * to plant one, and a sysroot-less guest already has the host filesystem.
 *
 * Returns 0 with `out` filled, or -1 with errno set (realpath's errno, or
 * ENOENT for a path that resolved outside the tree).
 */
static bool usb_sys_contained(const char *canonical)
{
    size_t rootlen = strlen(usb_sys_real);
    return rootlen != 0 && !strncmp(canonical, usb_sys_real, rootlen) &&
           (canonical[rootlen] == '\0' || canonical[rootlen] == '/');
}

static int usb_sys_resolve(const char *host_path, char *out, size_t outsz)
{
    char resolved[PATH_MAX];
    if (!realpath(host_path, resolved))
        return -1;
    if (!usb_sys_contained(resolved)) {
        log_warn("usb-sysfs: %s resolves outside the tree; refusing",
                 host_path);
        errno = ENOENT;
        return -1;
    }
    if (str_copy_trunc(out, resolved, outsz) >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Resolve a /sys-relative suffix to a host path inside the scratch tree, the
 * way the kernel resolves it: each component is applied to what the previous
 * one resolved to, so a '..' after a symlink pops the *target's* parent.
 *
 * This is what makes <dev>/subsystem/.. name /sys/bus, the way Linux does,
 * rather than the device directory a lexical fold would have kept it in. The
 * lexical fold in usb_suffix_normalize decides only whether the name is ours.
 *
 * realpath() performs the whole walk -- symlinks in the leaf and in every
 * intermediate component, and '..' in kernel order -- and its canonical result
 * is tested against the canonical root. That containment test is the sole
 * escape authority, which is why the raw, unfolded suffix is safe to hand it.
 *
 * `nofollow` keeps the semantics O_NOFOLLOW and lstat need: everything up to
 * the final component is resolved and contained, and the leaf is appended
 * without being followed and contained again afterwards. A '.' or '..' leaf is
 * not held back -- it cannot be a symlink, and it is the one leaf whose
 * reattachment can move the name (see below).
 *
 * *canon_out receives the resolved location as a /sys-relative suffix, so the
 * synthetic identity is keyed on the object rather than on the spelling.
 *
 * Returns 0, or -1 with errno set (realpath's errno, or ENOENT for a path that
 * resolved outside the tree).
 */
static int usb_sys_resolve_suffix(const char *raw_sfx,
                                  bool nofollow,
                                  char *host_out,
                                  size_t host_sz,
                                  char *canon_out,
                                  size_t canon_sz)
{
    char joined[PATH_MAX];
    int n = *raw_sfx ? snprintf(joined, sizeof(joined), "%s/%s", usb_sys_dir,
                                raw_sfx)
                     : snprintf(joined, sizeof(joined), "%s", usb_sys_dir);
    if (n < 0 || (size_t) n >= sizeof(joined)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char resolved[PATH_MAX];
    char leaf[NAME_MAX + 1];
    leaf[0] = '\0';

    if (nofollow && *raw_sfx) {
        /* Split off the final component, resolve the rest, reattach it. A
         * trailing slash means the caller is using the name as a directory, so
         * there is no unfollowed leaf to protect and the whole path resolves.
         */
        size_t jlen = strlen(joined);
        if (joined[jlen - 1] != '/') {
            char *slash = strrchr(joined, '/');
            if (!slash) {
                errno = EINVAL;
                return -1;
            }
            if (strlen(slash + 1) >= sizeof(leaf)) {
                errno = ENAMETOOLONG;
                return -1;
            }

            /* '.' and '..' are never symlinks, so there is nothing for
             * O_NOFOLLOW to protect -- and holding one back turns the walk
             * inside out: the prefix is contained, the dot-dot is reattached to
             * the *canonical* result afterwards, and one applied to the tree
             * root then names the host directory the root sits in. The
             * containment test has already run and does not run again, so that
             * spelling leaves the tree. Let the whole path go to
             * usb_sys_resolve, which resolves the dot-dot in kernel order and
             * tests what it actually reached.
             */
            const char *last = slash + 1;
            bool dots = !strcmp(last, ".") || !strcmp(last, "..");
            if (!dots) {
                str_copy_trunc(leaf, last, sizeof(leaf));
                *slash = '\0';
            }
        }
    }

    if (usb_sys_resolve(joined, resolved, sizeof(resolved)) < 0)
        return -1;

    if (leaf[0]) {
        size_t rl = strlen(resolved);
        if (rl + 1 + strlen(leaf) + 1 > sizeof(resolved)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        resolved[rl] = '/';
        str_copy_trunc(resolved + rl + 1, leaf, sizeof(resolved) - rl - 1);

        /* Reattaching is the one step that can move the name after the
         * containment test ran, so the test is applied to what the caller will
         * actually be handed rather than to the prefix it was derived from. It
         * stays the single authority: no spelling reaches a caller without
         * having passed it last.
         */
        if (!usb_sys_contained(resolved)) {
            log_warn("usb-sysfs: %s resolves outside the tree; refusing",
                     resolved);
            errno = ENOENT;
            return -1;
        }

        /* Probe the leaf that was reattached without being walked. Without this
         * the nofollow resolve succeeds for every name whose *parent* exists --
         * the scratch /sys root exists, so "/sys/class" resolved -- and the
         * caller's ours/not-ours escape hatch, which only the failure path
         * consults, was never reached. The lstat that followed then failed
         * ENOENT and that became the answer, shadowing a populated sysroot for
         * lstat, open(O_NOFOLLOW) and readlink while stat and plain open (which
         * resolve the leaf too, and so fail here) fell through correctly.
         *
         * lstat, not stat: a symlink leaf is the object the caller named.
         */
        struct stat leaf_st;
        if (lstat(resolved, &leaf_st) < 0) {
            if (!errno)
                errno = ENOENT;
            return -1;
        }
    }

    if (str_copy_trunc(host_out, resolved, host_sz) >= host_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* usb_sys_resolve proved `resolved` is usb_sys_real or below it, so the
     * remainder after the root is exactly the /sys-relative spelling.
     */
    const char *rel = resolved + strlen(usb_sys_real);
    while (*rel == '/')
        rel++;
    if (str_copy_trunc(canon_out, rel, canon_sz) >= canon_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Resolve a /sys name and settle, in one place, whether this layer answers for
 * it at all -- the resolve half of the fall-through decision classify_and_
 * normalize makes for every other name. Every /sys entry point goes through
 * here so none of them can disagree about which names are ours.
 *
 * Returns true with @host_out and @canon_out filled.
 *
 * Returns false with *err_out set to 0 when the name is not ours (the caller
 * reports PROC_NOT_INTERCEPTED so the sysroot backing answers), or to an errno
 * when the name is ours and the resolve genuinely failed. An absence under
 * /sys/bus/usb is authoritative -- that subtree is the one thing this layer
 * synthesizes -- so it comes back as ENOENT rather than as a fall-through.
 */
static bool usb_resolve_or_disown(const char *raw_sfx,
                                  const char *norm,
                                  bool nofollow,
                                  char *host_out,
                                  size_t host_sz,
                                  char *canon_out,
                                  size_t canon_sz,
                                  int *err_out)
{
    if (usb_sys_resolve_suffix(raw_sfx, nofollow, host_out, host_sz, canon_out,
                               canon_sz) == 0) {
        *err_out = 0;
        return true;
    }
    int reserr = errno;
    *err_out = (reserr == ENOENT && !usb_sys_suffix_owned(norm)) ? 0 : reserr;
    return false;
}

int usb_sysfs_guest_path_for_fd(int host_fd, char *out, size_t outsz)
{
    char host_path[PATH_MAX];
    if (fcntl(host_fd, F_GETPATH, host_path) < 0)
        return 0;

    pthread_mutex_lock(&usb_lock);
    int rc = 0;
    if (usb_sys_real[0] && usb_sys_contained(host_path)) {
        /* usb_sys_contained proved the remainder after the root is either empty
         * or starts with '/', so "/sys" plus it is the guest spelling.
         */
        const char *rel = host_path + strlen(usb_sys_real);
        int n = snprintf(out, outsz, "/sys%s", rel);
        rc = (n > 0 && (size_t) n < outsz) ? 1 : 0;
    }
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

/* What an intercept entry point returns for a path the USB tree does not own:
 * PROC_NOT_INTERCEPTED normally, or -1 with errno set when the path was ours in
 * shape but malformed. Stated once so the three entry points cannot drift.
 */
static int usb_not_intercepted(int cerr)
{
    if (cerr) {
        errno = cerr;
        return -1;
    }
    return PROC_NOT_INTERCEPTED;
}

int usb_sysfs_intercept_open(const char *path, int linux_flags, int mode)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind == USB_PATH_NONE)
        return usb_not_intercepted(cerr);

    /* Opening /dev itself stays a host open of the sysroot's dev directory, but
     * it is the last moment the ttyACM/ttyUSB placeholders can still appear:
     * every Linux serial consumer starts with a readdir of /dev, so build the
     * tree (which materializes them, inside ensure_usb_tree, so any earlier
     * /sys or /dev/bus touch has already done it) before falling through.
     */
    if (kind == USB_PATH_DEV_ROOT) {
        pthread_mutex_lock(&usb_lock);
        (void) ensure_usb_tree(); /* best effort; readdir just misses them */
        pthread_mutex_unlock(&usb_lock);
        return PROC_NOT_INTERCEPTED;
    }

    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    int err = 0;
    bool disown = false;
    if (ensure_usb_tree() < 0) {
        err = errno;
        goto out;
    }

    switch (kind) {
    case USB_PATH_TTY:
    case USB_PATH_TTY_SUB:
    case USB_PATH_BYID: {
        usb_tty_t *t = kind == USB_PATH_BYID ? find_tty_byid(sfx)
                                             : find_tty(bus != 0, dev);

        /* An alias-shaped name with no alias behind it is not ours. Unlike
         * /dev/bus/usb, the directories these names live in belong to the
         * sysroot, so claiming the whole shape and answering ENOENT made a
         * rootfs image's own /dev/ttyUSB0 unreachable and left readdir listing
         * names every lookup then denied. Only PROC_NOT_INTERCEPTED means "ask
         * the backing"; see docs/internals.md, "Ownership Of /sys And /dev
         * Names".
         */
        if (!t) {
            disown = true;
            goto out;
        }
        if (kind == USB_PATH_TTY_SUB) {
            err = ENOTDIR;
            goto out;
        }

        /* The by-id name is a symlink, so O_NOFOLLOW on it is ELOOP and
         * O_CREAT|O_EXCL on either name is EEXIST, the way Linux answers for a
         * node that already exists.
         */
        if (kind == USB_PATH_BYID && (linux_flags & LINUX_O_NOFOLLOW) &&
            !(linux_flags & LINUX_O_PATH)) {
            err = ELOOP;
            goto out;
        }
        if ((linux_flags & LINUX_O_CREAT) && (linux_flags & LINUX_O_EXCL)) {
            err = EEXIST;
            goto out;
        }
        if (linux_flags & LINUX_O_DIRECTORY) {
            err = ENOTDIR;
            goto out;
        }
        if (linux_flags & LINUX_O_PATH) {
            /* Path-only fd: harmless backing fd, the /dev/ptmx O_PATH pattern.
             * FD_PATH gates I/O and the stamped guest path routes fstat through
             * the synthetic char-dev stat.
             */
            int oflags = O_RDONLY;
            if (linux_flags & LINUX_O_CLOEXEC)
                oflags |= O_CLOEXEC;
            rc = open("/dev/null", oflags);
        } else {
            rc = tty_alias_host_open(t, linux_flags);
        }
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_SYS: {
        bool nofollow = (linux_flags & LINUX_O_NOFOLLOW) != 0;
        int accmode = translate_open_flags(linux_flags) & O_ACCMODE;
        bool mutating = accmode != O_RDONLY ||
                        (linux_flags & (LINUX_O_CREAT | LINUX_O_TRUNC));
        char host_path[PATH_MAX], canon_sfx[PATH_MAX];

        /* Resolve in kernel order first: '..' after a symlink has to pop the
         * target's parent before anything is decided about the name.
         */
        int reserr = 0;
        if (!usb_resolve_or_disown(sfx, norm, nofollow, host_path,
                                   sizeof(host_path), canon_sfx,
                                   sizeof(canon_sfx), &reserr)) {
            /* Not ours: hand it back to the sysroot backing instead of
             * shadowing it with ENOENT.
             */
            if (!reserr) {
                pthread_mutex_unlock(&usb_lock);
                return PROC_NOT_INTERCEPTED;
            }

            /* A create names something that does not exist yet, so the resolve
             * failing is expected there and says nothing about the request. It
             * is still a mutating open of a read-only tree, which is what the
             * guest has to be told -- not the ENOENT of the name it picked.
             */
            err = mutating ? EACCES : reserr;
            goto out;
        }

        /* O_NOFOLLOW on a symlink is ELOOP, and Linux decides that before it
         * looks at the access mode: open("<dev>/subsystem", O_WRONLY |
         * O_NOFOLLOW) is ELOOP on a real sysfs, not the EISDIR the link's
         * target would earn (measured on /sys/class/net/lo/subsystem, 6.19).
         * Deciding the read-only refusal first would answer for the target of a
         * link the caller explicitly asked not to follow. O_PATH is the
         * documented exception: O_PATH|O_NOFOLLOW names the link itself.
         */
        if (nofollow && !(linux_flags & LINUX_O_PATH)) {
            struct stat lst;
            if (lstat(host_path, &lst) == 0 && S_ISLNK(lst.st_mode)) {
                err = ELOOP;
                goto out;
            }
        }

        /* Read-only tree, syscpu contract: reject mutating opens -- with the
         * errno Linux gives, which depends on what the name resolves to. A
         * sysfs directory answers EISDIR, because open(2) refuses write access
         * to a directory before it ever consults permissions; a sysfs attribute
         * is a mode 0444 regular file, so it answers EACCES.
         */
        if (mutating) {
            struct stat wst;
            err = (stat(host_path, &wst) == 0 && S_ISDIR(wst.st_mode)) ? EISDIR
                                                                       : EACCES;
            goto out;
        }

        /* In the follow case the leaf is already resolved and by construction
         * not a symlink, so O_NOFOLLOW changes nothing on the intended path and
         * closes the swap window on that final component only: open(2) re-walks
         * the resolved path string, so a symlink spun into an intermediate
         * directory after the resolve would still be followed. That residual
         * window is unreachable (a sysrooted guest cannot name the scratch tree
         * to plant one; see usb_sys_resolve above).
         *
         * In the nofollow case the flags are passed through untouched: the
         * guest's intent is already encoded there, and O_PATH|O_NOFOLLOW maps
         * to macOS O_SYMLINK -- "open the link itself" -- which OR-ing
         * O_NOFOLLOW back in would turn into an ELOOP.
         */
        int oflags = translate_open_flags(linux_flags);
        if (!nofollow)
            oflags |= O_NOFOLLOW;
        rc = open(host_path, oflags, mode);
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_DEV_BUS:
        rc = proc_open_dir_fd(usb_dev_dir, linux_flags);
        if (rc < 0)
            err = errno;
        goto out;
    case USB_PATH_DEV_USB:
    case USB_PATH_DEV_BUSNUM: {
        char host_path[256];
        int n;
        if (kind == USB_PATH_DEV_USB)
            n = snprintf(host_path, sizeof(host_path), "%s/usb", usb_dev_dir);
        else {
            if (!bus_exists(bus)) {
                err = ENOENT;
                goto out;
            }
            n = snprintf(host_path, sizeof(host_path), "%s/usb/%03d",
                         usb_dev_dir, bus);
        }
        if (n < 0 || (size_t) n >= sizeof(host_path)) {
            err = ENAMETOOLONG;
            goto out;
        }
        rc = proc_open_dir_fd(host_path, linux_flags);
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_DEV_NODE_SUB:
        err = find_dev(bus, dev) ? ENOTDIR : ENOENT;
        goto out;
    case USB_PATH_DEV_NODE: {
        usb_dev_t *d = find_dev(bus, dev);
        if (!d) {
            err = ENOENT;
            goto out;
        }
        if (linux_flags & LINUX_O_DIRECTORY) {
            err = ENOTDIR;
            goto out;
        }
        int accmode = translate_open_flags(linux_flags) & O_ACCMODE;
        if (accmode != O_RDONLY) {
            /* Unreachable through sys_openat_path: usbdev_open_path claims
             * every non-O_PATH open of a node before proc_intercept_open runs
             * (stage 2, syscall/usbdev.c). Kept as a guard for any other caller
             * of the intercept.
             */
            log_warn(
                "usb-sysfs: writable open of %s bypassed the FD_USBDEV "
                "constructor",
                path);
            err = EACCES;
            goto out;
        }
        rc = usb_blob_fd(d);
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_DEV_ABSENT:
        err = ENOENT;
        goto out;
    case USB_PATH_DEV_FOREIGN:
    case USB_PATH_DEV_ROOT: /* handled before the lock */
    case USB_PATH_NONE:
        break; /* folded to USB_PATH_NONE by classify_and_normalize */
    }

out:
    pthread_mutex_unlock(&usb_lock);
    if (disown)
        return PROC_NOT_INTERCEPTED;
    if (rc < 0)
        errno = err ? err : EIO;
    return rc;
}

int usb_sysfs_intercept_stat(const char *path, struct stat *st, bool follow)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind == USB_PATH_NONE || kind == USB_PATH_DEV_ROOT)
        return usb_not_intercepted(cerr);

    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    int err = 0;
    bool disown = false;
    if (ensure_usb_tree() < 0) {
        err = errno;
        goto out;
    }

    char canon[LINUX_PATH_MAX];
    usb_canon_path(kind, sfx, bus, dev, canon, sizeof(canon));

    switch (kind) {
    case USB_PATH_TTY:
    case USB_PATH_TTY_SUB: {
        usb_tty_t *t = find_tty(bus != 0, dev);
        if (!t) {
            disown = true; /* the sysroot's own file, if it has one */
            goto out;
        }
        if (kind == USB_PATH_TTY_SUB) {
            err = ENOTDIR;
            goto out;
        }
        fill_synth_tty_stat(st, canon, t);
        rc = 0;
        goto out;
    }
    case USB_PATH_BYID: {
        /* lstat reports the link, stat reports what it resolves to -- which is
         * the alias character device, so stat() of a by-id name renders exactly
         * what stat() of /dev/tty* renders. The earlier spelling answered
         * S_IFLNK for both, a shape Linux stat() can never return; it was
         * borrowed from the sysfs subsystem links, which resolve to directories
         * nobody type-checks, and does not transfer to a name standing in for a
         * character device.
         */
        usb_tty_t *t = find_tty_byid(sfx);
        if (!t) {
            disown = true;
            goto out;
        }
        char alias[32];
        if (follow) {
            /* Identified as the node it resolves to, inode included: a by-id
             * name and the alias node are one object, and stat through either
             * has to say so.
             */
            char node[64];
            if (!tty_alias_name(t, alias, sizeof(alias))) {
                err = ENOENT;
                goto out;
            }
            snprintf(node, sizeof(node), "/dev/%s", alias);
            fill_synth_tty_stat(st, node, t);
            rc = 0;
            goto out;
        }
        fill_synth_file(st, canon);
        st->st_mode = S_IFLNK | 0777;
        if (tty_alias_name(t, alias, sizeof(alias)))
            st->st_size = (off_t) (strlen(alias) + 6); /* "../../" */
        rc = 0;
        goto out;
    }
    case USB_PATH_SYS: {
        if (!*sfx) {
            fill_synth_dir(st, canon);
            rc = 0;
            goto out;
        }

        /* Resolve in kernel order, and only then decide what was named: with
         * `follow` the leaf symlink is resolved too, so stat() of a subsystem
         * link reports the directory it points at, the way it does on Linux.
         * lstat() (follow == false) still reports the link itself.
         */
        char host_path[PATH_MAX], canon_sfx[PATH_MAX];
        int reserr = 0;
        if (!usb_resolve_or_disown(sfx, norm, !follow, host_path,
                                   sizeof(host_path), canon_sfx,
                                   sizeof(canon_sfx), &reserr)) {
            /* Not ours: let the sysroot backing answer rather than shadow it
             * with ENOENT, so stat and open agree on it.
             */
            if (!reserr) {
                pthread_mutex_unlock(&usb_lock);
                return PROC_NOT_INTERCEPTED;
            }
            err = reserr;
            goto out;
        }
        usb_canon_path(kind, canon_sfx, bus, dev, canon, sizeof(canon));

        struct stat host_st;
        if (lstat(host_path, &host_st) < 0) {
            err = errno;
            goto out;
        }
        if (S_ISDIR(host_st.st_mode))
            fill_synth_dir(st, canon);
        else if (S_ISLNK(host_st.st_mode)) {
            /* Only reachable with follow == false; the follow case resolved the
             * link away above.
             */
            fill_synth_file(st, canon);
            st->st_mode = S_IFLNK | 0777;
            st->st_size = host_st.st_size;
        } else {
            fill_synth_file(st, canon);
            st->st_size = host_st.st_size; /* attrs read as sized files */
        }
        rc = 0;
        goto out;
    }
    case USB_PATH_DEV_BUS:
    case USB_PATH_DEV_USB:
        fill_synth_dir(st, canon);
        rc = 0;
        goto out;
    case USB_PATH_DEV_BUSNUM:
        if (!bus_exists(bus)) {
            err = ENOENT;
            goto out;
        }
        fill_synth_dir(st, canon);
        rc = 0;
        goto out;
    case USB_PATH_DEV_NODE_SUB:
        err = find_dev(bus, dev) ? ENOTDIR : ENOENT;
        goto out;
    case USB_PATH_DEV_NODE: {
        usb_dev_t *d = find_dev(bus, dev);
        if (!d) {
            err = ENOENT;
            goto out;
        }
        fill_synth_chardev(st, canon, d);
        rc = 0;
        goto out;
    }
    case USB_PATH_DEV_ABSENT:
        err = ENOENT;
        goto out;
    case USB_PATH_DEV_FOREIGN:
    case USB_PATH_DEV_ROOT: /* answered before the lock */
    case USB_PATH_NONE:
        break; /* folded to USB_PATH_NONE by classify_and_normalize */
    }

out:
    pthread_mutex_unlock(&usb_lock);
    if (disown)
        return PROC_NOT_INTERCEPTED;
    if (rc < 0)
        errno = err ? err : EIO;
    return rc;
}

int usb_sysfs_intercept_readlink(const char *path, char *buf, size_t bufsiz)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind == USB_PATH_NONE || kind == USB_PATH_DEV_ROOT)
        return usb_not_intercepted(cerr);

    if (kind == USB_PATH_BYID) {
        /* Answer the link content directly instead of trusting the sysroot
         * backing link: the two agree when tty_alias_sync_dev ran, and a
         * sysroot-less run (macOS /dev is not writable) has no backing at all
         * yet must still resolve the Linux-shaped name.
         */
        pthread_mutex_lock(&usb_lock);
        int rc = -1;
        int err = 0;
        bool disown = false;
        char target[64];
        if (ensure_usb_tree() < 0) {
            err = errno;
        } else {
            usb_tty_t *t = find_tty_byid(sfx);
            char alias[32];
            if (!t) {
                disown = true;
            } else if (!tty_alias_name(t, alias, sizeof(alias))) {
                err = ENOENT;
            } else {
                int n = snprintf(target, sizeof(target), "../../%s", alias);
                if (n < 0 || (size_t) n >= sizeof(target)) {
                    err = ENAMETOOLONG;
                } else {
                    size_t copy = (size_t) n < bufsiz ? (size_t) n : bufsiz;
                    memcpy(buf, target, copy);
                    rc = (int) copy;
                }
            }
        }
        pthread_mutex_unlock(&usb_lock);
        if (disown)
            return PROC_NOT_INTERCEPTED; /* the sysroot's own by-id entry */
        if (rc < 0)
            errno = err ? err : EIO;
        return rc;
    }

    if (kind == USB_PATH_SYS) {
        /* The scratch tree holds real symlinks for `subsystem` entries;
         * readlink passes their targets through. Plain dirs/files answer EINVAL
         * and missing paths ENOENT, exactly as sysfs would.
         */
        pthread_mutex_lock(&usb_lock);
        int rc = -1;
        int err = 0;
        if (ensure_usb_tree() < 0) {
            err = errno;
        } else if (!*sfx) {
            err = EINVAL; /* /sys itself is a directory */
        } else {
            /* The same resolution the open and stat paths use, for the same two
             * reasons. The suffix arrives as the guest spelled it, so a '..'
             * behind a `subsystem` link still has to be applied to what that
             * link resolved to; and usb_sys_resolve_suffix carries the only
             * containment check in this layer. Joining the raw suffix onto the
             * scratch root instead would let a name whose lexical fold stays
             * inside resolve, through the link, onto a host symlink outside the
             * tree and report its target to the guest.
             *
             * nofollow, because readlink names the link itself and never the
             * object behind it.
             */
            char host_path[PATH_MAX], canon_sfx[PATH_MAX];
            if (!usb_resolve_or_disown(sfx, norm, true, host_path,
                                       sizeof(host_path), canon_sfx,
                                       sizeof(canon_sfx), &err)) {
                /* Not ours: fall through to the sysroot backing rather than
                 * shadow it, as the open and stat paths do.
                 */
                if (!err) {
                    pthread_mutex_unlock(&usb_lock);
                    return PROC_NOT_INTERCEPTED;
                }
            } else {
                ssize_t n = readlink(host_path, buf, bufsiz);
                if (n < 0)
                    err = errno;
                else
                    rc = (int) n;
            }
        }
        pthread_mutex_unlock(&usb_lock);
        if (rc < 0)
            errno = err ? err : EIO;
        return rc;
    }

    struct stat st;
    int rc = usb_sysfs_intercept_stat(path, &st, false);
    if (rc == PROC_NOT_INTERCEPTED)
        return PROC_NOT_INTERCEPTED;
    if (rc < 0)
        return -1; /* errno already set (ENOENT etc.) */
    /* The /dev/bus tree and the tty aliases hold dirs and device nodes, never
     * symlinks; Linux answers EINVAL for readlink on those.
     */
    errno = EINVAL;
    return -1;
}

/* Apply a '/'-separated component sequence to a /sys-relative spelling, the way
 * a lexical walk does: '.' and an empty component are skipped, '..' pops the
 * last component, anything else is appended. marks[] records where each
 * component began so a pop is exact.
 *
 * Returns false when the sequence climbs above /sys or does not fit, which the
 * caller turns into "no rewrite" rather than an answer.
 */
static bool usb_rel_apply(char *rel,
                          size_t relsz,
                          size_t *len_io,
                          size_t *marks,
                          size_t maxmarks,
                          size_t *depth_io,
                          const char *seq)
{
    size_t len = *len_io, depth = *depth_io;
    for (const char *p = seq; *p;) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t seglen = (size_t) (p - seg);
        while (*p == '/')
            p++;
        if (seglen == 0 || (seglen == 1 && seg[0] == '.'))
            continue;
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth == 0)
                return false;
            len = marks[--depth];
            rel[len] = '\0';
            continue;
        }
        if (depth >= maxmarks)
            return false;
        marks[depth++] = len;
        if (len + (len ? 1 : 0) + seglen + 1 > relsz)
            return false;
        if (len)
            rel[len++] = '/';
        memcpy(rel + len, seg, seglen);
        len += seglen;
        rel[len] = '\0';
    }
    *len_io = len;
    *depth_io = depth;
    return true;
}

int usb_sysfs_resolve_guest_path(const char *guest_path,
                                 char *out,
                                 size_t outsz)
{
    /* Two subtrees carry links a walk can pass through: /sys/bus/usb/devices
     * (the device and interface subsystem links) and /sys/class/tty (an alias's
     * device and subsystem links). Nothing else can move a walk, and a path
     * that cannot contain one is rejected before the tree is touched.
     *
     * /sys/class/tty was missing here when the alias links were added, and both
     * halves of the bug this function exists for came back for them: the
     * listing of <tty>/subsystem/.. offered the sysroot's net, hwmon and block
     * while every lookup of <tty>/subsystem/../net answered ENOENT, and
     * <tty>/device/../idVendor resolved only when spelled absolutely.
     */
    if (strncmp(guest_path, "/sys/bus/usb/devices/", 21) != 0 &&
        strncmp(guest_path, "/sys/class/tty/", 15) != 0)
        return 0;
    if (!strstr(guest_path, "/subsystem") && !strstr(guest_path, "/device"))
        return 0;

    pthread_mutex_lock(&usb_lock);
    int rc = 0;
    if (ensure_usb_tree() < 0)
        goto out;

    char rel[LINUX_PATH_MAX];
    size_t len = 0;
    size_t marks[64];
    size_t depth = 0;
    int hops = 0;
    bool rewrote = false;
    rel[0] = '\0';

    for (const char *p = guest_path + 5; *p;) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t seglen = (size_t) (p - seg);
        const char *after = p;
        while (*after == '/')
            after++;
        p = after;

        if (seglen == 0 || (seglen == 1 && seg[0] == '.'))
            continue;
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth == 0)
                goto out; /* above /sys; not a name this layer can place */
            len = marks[--depth];
            rel[len] = '\0';
            continue;
        }
        if (depth >= ARRAY_SIZE(marks))
            goto out;
        marks[depth++] = len;
        if (len + (len ? 1 : 0) + seglen + 1 > sizeof(rel))
            goto out;
        if (len)
            rel[len++] = '/';
        memcpy(rel + len, seg, seglen);
        len += seglen;
        rel[len] = '\0';

        /* A link with nothing after it is the object the caller named, and
         * lstat/readlink/O_NOFOLLOW have to keep seeing the link itself, so
         * only a link the walk continues through is substituted. What it is
         * substituted with is where it points, applied to the directory the
         * link sits in, so the components that follow are applied to the target
         * -- which is what makes subsystem/.. name /sys/bus and <tty>/device/..
         * name the interface's parent, the way the kernel does.
         *
         * The target is read rather than assumed: an earlier spelling matched
         * the component name "subsystem" and substituted the one target every
         * such link then had, which is why the alias links -- device, and a
         * subsystem link pointing at class/tty rather than bus/usb -- were left
         * out when they arrived.
         */
        if (!*p)
            break;
        char host[PATH_MAX], tgt[PATH_MAX];
        int hn = snprintf(host, sizeof(host), "%s/%s", usb_sys_dir, rel);
        if (hn < 0 || (size_t) hn >= sizeof(host))
            goto out;
        ssize_t tn = readlink(host, tgt, sizeof(tgt) - 1);
        if (tn <= 0)
            continue; /* a plain directory, or a name the tree does not carry */
        tgt[tn] = '\0';
        if (++hops > 16 || depth == 0)
            goto out;
        len = marks[--depth]; /* pop the link itself */
        rel[len] = '\0';
        if (!usb_rel_apply(rel, sizeof(rel), &len, marks, ARRAY_SIZE(marks),
                           &depth, tgt))
            goto out;
        rewrote = true;
    }

    if (!rewrote)
        goto out;

    /* A trailing slash survives: it is what makes a non-directory named as a
     * directory report ENOTDIR, and the rewrite must not answer that question.
     */
    const char *tail = guest_path[strlen(guest_path) - 1] == '/' ? "/" : "";
    int n = snprintf(out, outsz, "/sys%s%s%s", len ? "/" : "", rel, tail);
    rc = (n > 0 && (size_t) n < outsz) ? 1 : 0;

out:
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

bool usb_sysfs_dir_unions_backing(const char *guest_path)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(guest_path, &bus, &dev, &sfx,
                                                  norm, sizeof(norm), &cerr);
    if (kind == USB_PATH_DEV_BUS)
        return true;
    if (kind != USB_PATH_SYS)
        return false;

    /* The same ownership test the lookup path uses, so the listing and the
     * lookups can never disagree about which names this layer answers for.
     */
    return !usb_sys_suffix_owned(norm);
}

uint8_t *usb_sysfs_descriptors_dup(int busnum, int devnum, size_t *len_out)
{
    pthread_mutex_lock(&usb_lock);
    uint8_t *copy = NULL;
    if (ensure_usb_tree() == 0) {
        usb_dev_t *d = find_dev(busnum, devnum);
        if (d) {
            copy = malloc(d->blob_len);
            if (copy) {
                memcpy(copy, d->blob, d->blob_len);
                *len_out = d->blob_len;
            }
        } else {
            errno = ENODEV;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return copy;
}

int usb_sysfs_device_info(int busnum, int devnum, usb_sysfs_devinfo_t *out)
{
    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    if (ensure_usb_tree() == 0) {
        usb_dev_t *d = find_dev(busnum, devnum);
        if (d) {
            out->location_id = d->location_id;
            out->speed_code = d->speed_code;
            out->cfg_value = d->cfg_value;
            out->minor = usb_minor(d);
            out->blob_len = d->blob_len;
            out->vid = d->vid;
            out->pid = d->pid;
            str_copy_trunc(out->serial, d->serial, sizeof(out->serial));
            rc = 0;
        } else {
            errno = ENODEV;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

int usb_sysfs_node_stat(int busnum, int devnum, struct stat *st)
{
    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    if (ensure_usb_tree() == 0) {
        usb_dev_t *d = find_dev(busnum, devnum);
        if (d) {
            char node[64];
            snprintf(node, sizeof(node), "/dev/bus/usb/%03d/%03d", busnum,
                     devnum);
            fill_synth_chardev(st, node, d);
            rc = 0;
        } else {
            errno = ENODEV;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

bool usb_sysfs_path_might_be_ours(const char *path)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    return kind != USB_PATH_NONE || cerr != 0;
}

bool usb_tty_alias_node(const char *path, char *out, size_t outsz)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind != USB_PATH_TTY && kind != USB_PATH_BYID)
        return false;

    pthread_mutex_lock(&usb_lock);
    bool ok = false;
    if (ensure_usb_tree() == 0) {
        usb_tty_t *t = kind == USB_PATH_BYID ? find_tty_byid(sfx)
                                             : find_tty(bus != 0, dev);
        char alias[32];
        if (t && tty_alias_name(t, alias, sizeof(alias))) {
            char node[64];
            snprintf(node, sizeof(node), "/dev/%s", alias);
            ok = str_copy_trunc(out, node, outsz) < outsz;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return ok;
}

bool usb_tty_alias_dir(const char *path, char *out, size_t outsz)
{
    while (path[0] == '/' && path[1] == '/')
        path++;
    while (!strncmp(path, "/./", 3))
        path += 2;
    if (!path_prefix_match(path, "/dev", 4))
        return false;
    char folded[LINUX_PATH_MAX];
    if (usb_suffix_normalize(skip_slashes(path + 4), folded, sizeof(folded)) !=
        1)
        return false;
    size_t n = strlen(folded);
    while (n && folded[n - 1] == '/')
        folded[--n] = '\0';
    const char *canon = NULL;
    if (!*folded)
        canon = "/dev";
    else if (!strcmp(folded, "serial"))
        canon = "/dev/serial";
    else if (!strcmp(folded, "serial/by-id"))
        canon = "/dev/serial/by-id";
    if (!canon)
        return false;
    str_copy_trunc(out, canon, outsz);
    return true;
}

bool usb_tty_alias_canon(const char *path, char *out, size_t outsz)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = "";
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind != USB_PATH_TTY && kind != USB_PATH_BYID)
        return false;
    usb_canon_path(kind, sfx, bus, dev, out, outsz);
    return true;
}

bool usb_tty_alias_path(const char *path)
{
    if (!strncmp(path, "/dev/tty", 8)) {
        bool acm;
        return tty_alias_parse(path + 5, &acm) >= 0;
    }

    /* The by-id leaf names the same object as the alias node, and an open of it
     * goes through the same host open, so it needs the same stamp: without it
     * fstat of a by-id fd reported the macOS cu.* identity (9:7 on this host)
     * while fstat of the alias fd reported 166:0 for the one device.
     */
    if (strncmp(path, "/dev/serial/by-id/", 18) != 0)
        return false;
    const char *leaf = path + 18;
    return *leaf && !strchr(leaf, '/') && strcmp(leaf, ".") != 0 &&
           strcmp(leaf, "..") != 0;
}
