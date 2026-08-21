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
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include "debug/log.h"
#include "runtime/procemu-internal.h"
#include "runtime/procemu.h"
#include "runtime/usb-sysfs.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/path.h"
#include "utils.h"

#define USB_MAJOR 189
#define USB_MAX_DEVICES 64
#define USB_MAX_PORTS 6 /* locationID has six port nibbles below the bus */

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
static char usb_dev_dir[64]; /* scratch root == /dev/bus     */
static usb_dev_t usb_devs[USB_MAX_DEVICES];
static int usb_ndevs;
static pid_t usb_owner_pid;

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

static void model_clear(void)
{
    for (int i = 0; i < usb_ndevs; i++) {
        free(usb_devs[i].blob);
        usb_devs[i].blob = NULL;
    }
    usb_ndevs = 0;
}

/* Enumerate the IOKit registry into usb_devs[]. Devices whose locationID has no
 * port nibbles are root hubs; they are skipped (no usbN entries: nusb drops
 * them and libusb tolerates a missing parent).
 */
static void model_build(void)
{
    model_clear();

    CFMutableDictionaryRef match = IOServiceMatching("IOUSBDevice");
    if (!match)
        return;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) !=
        kIOReturnSuccess)
        return;

    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        if (usb_ndevs >= USB_MAX_DEVICES) {
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
        if (nports == 0) {
            /* root hub */
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
         * has no current-configuration key.
         */
        if (d->cfg_value == 0 && d->blob_len >= 18 + 9)
            d->cfg_value = d->blob[18 + 5];
        if (d->cfg_value == 0)
            d->cfg_value = 1;

        usb_ndevs++;
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);

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
        usb_devs[best].devnum = devnum;
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
    /* Find the active config in the blob. */
    const uint8_t *p = d->blob + 18;
    const uint8_t *end = d->blob + d->blob_len;
    const uint8_t *cfg = NULL;
    size_t cfg_len = 0;
    while (p + 9 <= end) {
        uint16_t total = get_le16(p + 2);
        if (total < 9 || p + total > end)
            break;
        if (p[5] == (uint8_t) d->cfg_value) {
            cfg = p;
            cfg_len = total;
            break;
        }
        p += total;
    }
    if (!cfg && d->blob_len >= 18 + 9) { /* fall back to first config */
        cfg = d->blob + 18;
        cfg_len = get_le16(cfg + 2);
        if (cfg_len > d->blob_len - 18)
            cfg_len = d->blob_len - 18;
    }
    if (!cfg)
        return;

    const uint8_t *q = cfg;
    const uint8_t *cend = cfg + cfg_len;
    int seen[32] = {0};
    while (q + 2 <= cend && q[0] >= 2) {
        if (q[1] == 4 /* INTERFACE */ && q + 9 <= cend) {
            unsigned ifnum = q[2], alt = q[3], neps = q[4];
            unsigned icls = q[5], isub = q[6], ipro = q[7];
            if (alt == 0 && ifnum < 32 && !seen[ifnum]) {
                seen[ifnum] = 1;
                char idir[256];
                if (snprintf(idir, sizeof(idir), "%s/%s:%u.%u", devices_dir,
                             d->name, d->cfg_value,
                             ifnum) < (int) sizeof(idir) &&
                    mkdir(idir, 0755) == 0) {
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
                    usb_write_fmt(
                        idir, "uevent",
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
        }
        q += q[0];
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
    if (d->blob_len >= 18 + 9) {
        unsigned bnumif = d->blob[18 + 4]; /* first config bNumInterfaces */
        usb_write_fmt(dir, "bNumInterfaces", "%2d\n", bnumif);
    }
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
    model_clear();
    pthread_mutex_unlock(&usb_lock);
}

/* One-shot build under usb_lock (the ensure_syscpu_dir pattern); a refresh
 * clears usb_tree_ok so the next call re-enumerates (hotplug hook).
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
    str_copy_trunc(usb_dev_dir, "/tmp/elfuse-usbdev-XXXXXX",
                   sizeof(usb_dev_dir));
    if (!mkdtemp(usb_dev_dir)) {
        usb_remove_tree(usb_sys_dir, 0);
        usb_sys_dir[0] = usb_dev_dir[0] = '\0';
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
    usb_sys_dir[0] = usb_dev_dir[0] = '\0';
    model_clear();
    errno = saved;
    return -1;
}

void usb_sysfs_refresh(void)
{
    pthread_mutex_lock(&usb_lock);
    if (usb_tree_ok) {
        usb_remove_tree(usb_sys_dir, 0);
        usb_remove_tree(usb_dev_dir, 0);
        usb_sys_dir[0] = usb_dev_dir[0] = '\0';
        usb_tree_ok = false;
    }
    model_clear();
    pthread_mutex_unlock(&usb_lock);
}

/* path classification */

typedef enum {
    USB_PATH_NONE,
    USB_PATH_DEV_BUS,    /* /dev/bus            */
    USB_PATH_DEV_USB,    /* /dev/bus/usb        */
    USB_PATH_DEV_BUSNUM, /* /dev/bus/usb/BBB    */
    USB_PATH_DEV_NODE,   /* /dev/bus/usb/BBB/DDD */
    USB_PATH_DEV_ABSENT, /* under /dev/bus but nothing we model */
    USB_PATH_SYS,        /* /sys[/suffix] (whole sysfs view) */
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
    if (!path_prefix_match(path, "/dev/bus", 8))
        return USB_PATH_NONE;

    const char *p = skip_slashes(path + 8);
    if (!*p)
        return USB_PATH_DEV_BUS;
    if (strncmp(p, "usb", 3) != 0 || (p[3] != '\0' && p[3] != '/'))
        return USB_PATH_DEV_ABSENT;
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
    if (dev < 0 || *skip_slashes(rest2))
        return USB_PATH_DEV_ABSENT;
    *bus_out = bus;
    *dev_out = dev;
    return USB_PATH_DEV_NODE;
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

/* Reject '..' components so a joined host path cannot escape the scratch dir
 * (same contract as syscpu_suffix_safe).
 */
static bool usb_suffix_safe(const char *suffix)
{
    const char *p = suffix;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        if ((size_t) (p - seg) == 2 && seg[0] == '.' && seg[1] == '.')
            return false;
        if (*p == '/')
            p++;
    }
    return true;
}

/* Synthetic stat identities, mirroring procemu.c's PROC_SYNTH_DEV scheme with a
 * distinct device so /sys/bus/usb nodes never collide with /proc ones.
 */
#define USB_SYNTH_DEV ((dev_t) 0x5553)

static ino_t usb_synth_ino(const char *path)
{
    uint64_t h = fnv1a64(path, strlen(path));
    h &= 0x7fffffffffffffffULL;
    return (ino_t) (h ? h : 1);
}

static void fill_synth_dir(struct stat *st, const char *path)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(path);
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
}

static void fill_synth_file(struct stat *st, const char *path)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(path);
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
}

static void fill_synth_chardev(struct stat *st,
                               const char *path,
                               const usb_dev_t *d)
{
    memset(st, 0, sizeof(*st));

    /* 0664 rather than udev's root:root 0660 policy: the single-user guest must
     * be able to open its own device nodes.
     */
    st->st_mode = S_IFCHR | 0664;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(path);
    st->st_uid = getuid();
    st->st_gid = getgid();
    /* macOS dev_t encoding (major<<24 | minor); translate_stat converts. */
    st->st_rdev = ((dev_t) USB_MAJOR << 24) | (dev_t) usb_minor(d);
    st->st_blksize = 4096;
    st->st_size = (off_t) d->blob_len;
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

int usb_sysfs_intercept_open(const char *path, int linux_flags, int mode)
{
    int bus = 0, dev = 0;
    const char *sfx = NULL;
    usb_path_kind_t kind = classify_path(path, &bus, &dev, &sfx);
    if (kind == USB_PATH_NONE)
        return PROC_NOT_INTERCEPTED;

    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    int err = 0;
    if (ensure_usb_tree() < 0) {
        err = errno;
        goto out;
    }

    switch (kind) {
    case USB_PATH_SYS: {
        /* Read-only tree, syscpu contract: reject mutating opens. */
        int accmode = translate_open_flags(linux_flags) & O_ACCMODE;
        if (accmode != O_RDONLY ||
            (linux_flags & (LINUX_O_CREAT | LINUX_O_TRUNC))) {
            err = EACCES;
            goto out;
        }
        if (!usb_suffix_safe(sfx)) {
            err = EACCES;
            goto out;
        }
        char host_path[512];
        int n = *sfx
                    ? snprintf(host_path, sizeof(host_path), "%s/%s",
                               usb_sys_dir, sfx)
                    : snprintf(host_path, sizeof(host_path), "%s", usb_sys_dir);
        if (n < 0 || (size_t) n >= sizeof(host_path)) {
            err = ENAMETOOLONG;
            goto out;
        }
        int oflags = translate_open_flags(linux_flags);
        rc = open(host_path, oflags | O_NOFOLLOW, mode);
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
    case USB_PATH_NONE:
        break;
    }

out:
    pthread_mutex_unlock(&usb_lock);
    if (rc < 0)
        errno = err ? err : EIO;
    return rc;
}

int usb_sysfs_intercept_stat(const char *path, struct stat *st)
{
    int bus = 0, dev = 0;
    const char *sfx = NULL;
    usb_path_kind_t kind = classify_path(path, &bus, &dev, &sfx);
    if (kind == USB_PATH_NONE)
        return PROC_NOT_INTERCEPTED;

    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    int err = 0;
    if (ensure_usb_tree() < 0) {
        err = errno;
        goto out;
    }

    switch (kind) {
    case USB_PATH_SYS: {
        if (!usb_suffix_safe(sfx)) {
            err = EACCES;
            goto out;
        }
        if (!*sfx) {
            fill_synth_dir(st, path);
            rc = 0;
            goto out;
        }
        char host_path[512];
        if (snprintf(host_path, sizeof(host_path), "%s/%s", usb_sys_dir, sfx) >=
            (int) sizeof(host_path)) {
            err = ENAMETOOLONG;
            goto out;
        }
        struct stat host_st;
        if (lstat(host_path, &host_st) < 0) {
            err = errno;
            goto out;
        }
        if (S_ISDIR(host_st.st_mode))
            fill_synth_dir(st, path);
        else if (S_ISLNK(host_st.st_mode)) {
            /* subsystem links; reported as S_IFLNK for follow and no-follow
             * alike (proc_intercept_stat carries no flags -- consumers only
             * readlink these, never stat them).
             */
            fill_synth_file(st, path);
            st->st_mode = S_IFLNK | 0777;
            st->st_size = host_st.st_size;
        } else {
            fill_synth_file(st, path);
            st->st_size = host_st.st_size; /* attrs read as sized files */
        }
        rc = 0;
        goto out;
    }
    case USB_PATH_DEV_BUS:
    case USB_PATH_DEV_USB:
        fill_synth_dir(st, path);
        rc = 0;
        goto out;
    case USB_PATH_DEV_BUSNUM:
        if (!bus_exists(bus)) {
            err = ENOENT;
            goto out;
        }
        fill_synth_dir(st, path);
        rc = 0;
        goto out;
    case USB_PATH_DEV_NODE: {
        usb_dev_t *d = find_dev(bus, dev);
        if (!d) {
            err = ENOENT;
            goto out;
        }
        fill_synth_chardev(st, path, d);
        rc = 0;
        goto out;
    }
    case USB_PATH_DEV_ABSENT:
        err = ENOENT;
        goto out;
    case USB_PATH_NONE:
        break;
    }

out:
    pthread_mutex_unlock(&usb_lock);
    if (rc < 0)
        errno = err ? err : EIO;
    return rc;
}

int usb_sysfs_intercept_readlink(const char *path, char *buf, size_t bufsiz)
{
    int bus = 0, dev = 0;
    const char *sfx = NULL;
    usb_path_kind_t kind = classify_path(path, &bus, &dev, &sfx);
    if (kind == USB_PATH_NONE)
        return PROC_NOT_INTERCEPTED;

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
        } else if (!usb_suffix_safe(sfx)) {
            err = EACCES;
        } else if (!*sfx) {
            err = EINVAL; /* /sys itself is a directory */
        } else {
            char host_path[512];
            if (snprintf(host_path, sizeof(host_path), "%s/%s", usb_sys_dir,
                         sfx) >= (int) sizeof(host_path)) {
                err = ENAMETOOLONG;
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
    int rc = usb_sysfs_intercept_stat(path, &st);
    if (rc == PROC_NOT_INTERCEPTED)
        return PROC_NOT_INTERCEPTED;
    if (rc < 0)
        return -1; /* errno already set (ENOENT etc.) */
    /* The /dev/bus tree holds real dirs and device nodes, never symlinks. */
    errno = EINVAL;
    return -1;
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
