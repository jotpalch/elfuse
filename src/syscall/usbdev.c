/*
 * usbdevfs (/dev/bus/usb/BBB/DDD) fd emulation over IOKit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stage 2: a typed FD_USBDEV fd whose synchronous usbdevfs ioctls are mapped
 * onto IOUSBDeviceInterface650 / IOUSBInterfaceInterface800 plugin calls
 * (research doc D's op table). Semantics mirror drivers/usb/core/devio.c (doc A
 * §A1/§A2):
 *
 *   - open of any access mode succeeds; read() serves the descriptors blob
 *     (byte-identical to the sysfs `descriptors` attribute) at a per-open
 *     file position; SEEK_END is -EINVAL (no_seek_end_llseek).
 *   - every ioctl requires a writable fd: O_RDONLY fd -> -EPERM
 *     (devio.c:2607-2608 FMODE_WRITE gate).
 *   - CLAIMINTERFACE returns -EBUSY when a macOS kernel driver is bound; the
 *     "kernel driver" test is an IORegistry child of the IOUSBHostInterface
 *     service in the service plane (libusb darwin_usb.c:2746-2770), and the
 *     claim itself is USBInterfaceOpen (kIOReturnExclusiveAccess -> -EBUSY).
 *   - CONTROL/BULK are Linux's sync paths (do_proc_control/do_proc_bulk):
 *     bounce buffers around DeviceRequestTO / Read|WritePipeTO, timeout in ms
 *     (0 = unlimited on both sides), -ETIMEDOUT from
 *     kIOUSBTransactionTimeout, stall -> -EPIPE, and Linux's implicit
 *     claim of the recipient interface (check_ctrlrecip/checkintf).
 *
 * Documented stage-2 deviations from Linux:
 *   - USBDEVFS_RESET does not re-enumerate: USBDeviceReEnumerate(0) would
 *     tear down every open plugin handle (doc D "reset" row), so RESET clears
 *     the stall state of all claimed pipes and returns 0. TODO(stage 3+):
 *     full re-enumeration with pending_device adoption.
 *   - Sync BULK on an interrupt endpoint is -EINVAL (Linux converts it to an
 *     interrupt URB; IOKit's ReadPipeTO/WritePipeTO reject interrupt pipes,
 *     IOUSBLib.h "BadArgument if TO on interrupt pipe"). TODO(later): route
 *     through the async path with a watchdog.
 *   - SUBMITURB/DISCARDURB/REAPURB* are -ENOTTY until stage 3.
 *   - dup()/fork() of an FD_USBDEV fd are refused (-EBADF): IOKit plugin
 *     handles are process-local and the side table is keyed by the guest fd.
 *     TODO(later): explicit dup alias (fuse_dup_fd pattern).
 *   - DISCONNECT/CONNECT/DISCONNECT_CLAIM cannot unbind Apple drivers without
 *     root or the com.apple.vm.device-access entitlement, so a bound kernel
 *     driver yields -EACCES (matching Linux's privileges-dropped answer).
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/usb/USB.h>

#include "core/guest.h"
#include "debug/log.h"
#include "runtime/usb-sysfs.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/proc.h"
#include "syscall/usbdev.h"
#include "utils.h"

/* usbdevfs wire ABI (LP64; x86_64 == aarch64) */

#define USBDEVFS_CONTROL 0xc0185500u
#define USBDEVFS_BULK 0xc0185502u
#define USBDEVFS_RESETEP 0x80045503u
#define USBDEVFS_SETINTERFACE 0x80085504u
#define USBDEVFS_SETCONFIGURATION 0x80045505u
#define USBDEVFS_GETDRIVER 0x41045508u
#define USBDEVFS_SUBMITURB 0x8038550au
#define USBDEVFS_DISCARDURB 0x0000550bu
#define USBDEVFS_REAPURB 0x4008550cu
#define USBDEVFS_REAPURBNDELAY 0x4008550du
#define USBDEVFS_DISCSIGNAL 0x8010550eu
#define USBDEVFS_CLAIMINTERFACE 0x8004550fu
#define USBDEVFS_RELEASEINTERFACE 0x80045510u
#define USBDEVFS_CONNECTINFO 0x40085511u
#define USBDEVFS_IOCTL 0xc0105512u
#define USBDEVFS_RESET 0x00005514u
#define USBDEVFS_CLEAR_HALT 0x80045515u
#define USBDEVFS_GET_CAPABILITIES 0x8004551au
#define USBDEVFS_DISCONNECT_CLAIM 0x8108551bu
#define USBDEVFS_GET_SPEED 0x0000551fu

/* Sub-codes of USBDEVFS_IOCTL (_IO('U', 22) / _IO('U', 23)). */
#define USBDEVFS_IOCTL_DISCONNECT 0x00005516
#define USBDEVFS_IOCTL_CONNECT 0x00005517

/* Capability bits (uapi/linux/usbdevice_fs.h:152-161). Stage 2 advertises the
 * transfer-shape caps a Linux 7.x kernel always sets (libusb keys URB splitting
 * and ZLP behavior off them) and deliberately clears MMAP, DROP_PRIVILEGES,
 * CONNINFO_EX, and SUSPEND, which name ioctls this layer does not serve (doc A
 * §A7.7).
 */
#define USBDEVFS_CAP_ZERO_PACKET 0x01u
#define USBDEVFS_CAP_BULK_CONTINUATION 0x02u
#define USBDEVFS_CAP_NO_PACKET_SIZE_LIM 0x04u
#define USBDEVFS_CAP_BULK_SCATTER_GATHER 0x08u
#define USBDEVFS_CAP_REAP_AFTER_DISCONNECT 0x10u
#define USBDEV_CAPS                                                       \
    (USBDEVFS_CAP_ZERO_PACKET | USBDEVFS_CAP_BULK_CONTINUATION |          \
     USBDEVFS_CAP_NO_PACKET_SIZE_LIM | USBDEVFS_CAP_BULK_SCATTER_GATHER | \
     USBDEVFS_CAP_REAP_AFTER_DISCONNECT)

#define USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER 0x01u
#define USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER 0x02u

typedef struct {
    uint8_t bRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t timeout; /* ms; 0 = unlimited */
    uint32_t pad;     /* natural LP64 hole before the pointer */
    uint64_t data;
} linux_usbdevfs_ctrltransfer_t; /* sizeof == 24, data at offset 16 */

typedef struct {
    uint32_t ep;
    uint32_t len;
    uint32_t timeout; /* ms; 0 = unlimited */
    uint32_t pad;
    uint64_t data;
} linux_usbdevfs_bulktransfer_t; /* sizeof == 24, data at offset 16 */

typedef struct {
    uint32_t interface;
    uint32_t altsetting;
} linux_usbdevfs_setinterface_t;

typedef struct {
    uint32_t interface;
    char driver[256];
} linux_usbdevfs_getdriver_t; /* sizeof == 260 */

typedef struct {
    uint32_t devnum;
    uint8_t slow;
    uint8_t pad[3];
} linux_usbdevfs_connectinfo_t; /* sizeof == 8 */

typedef struct {
    int32_t ifno;
    int32_t ioctl_code;
    uint64_t data;
} linux_usbdevfs_ioctl_t; /* sizeof == 16 */

typedef struct {
    uint32_t interface;
    uint32_t flags;
    char driver[256];
} linux_usbdevfs_disconnect_claim_t; /* sizeof == 264 */

/* do_proc_control caps wLength at PAGE_SIZE (devio.c:1185). */
#define USBDEV_CTRL_MAX 4096
/* usbfs_memory_mb default: 16 MB of in-flight buffer (devio.c:134). */
#define USBDEV_BULK_MAX (16u * 1024 * 1024)

/* side table */

#define USBDEV_MAX_FDS 16
#define USBDEV_MAX_IFACES 32 /* claimintf: ifnum >= 32 is -EINVAL */
#define USBDEV_MAX_PIPES 30

typedef struct {
    bool claimed;
    IOUSBInterfaceInterface800 **intf;
    int npipes;
    uint8_t pipe_ep[USBDEV_MAX_PIPES];   /* pipeRef-1 -> bEndpointAddress */
    uint8_t pipe_type[USBDEV_MAX_PIPES]; /* kUSBControl..kUSBInterrupt */
} usbdev_iface_t;

typedef struct {
    bool used; /* slot allocated (table lock) */
    bool dead; /* torn down, awaiting slot release (entry lock) */
    int guest_fd;
    uint64_t generation; /* fd-table generation captured at open (ABA) */
    int busnum, devnum;
    uint32_t location_id;
    unsigned speed_code; /* raw registry 'Device Speed' */
    unsigned cfg_value;  /* active bConfigurationValue */
    uint8_t *blob;       /* usbfs descriptors blob (read() source) */
    size_t blob_len;
    off_t pos;   /* read()/lseek() file position */
    int pipe_wr; /* write end of the readiness pipe (stage-3 completions) */
    io_service_t service;          /* retained IOUSBDevice service */
    IOUSBDeviceInterface650 **dev; /* lazily created device plugin */
    bool dev_open;                 /* USBDeviceOpen succeeded */
    bool dev_open_tried;
    usbdev_iface_t ifaces[USBDEV_MAX_IFACES];

    /* Lock-free mirrors for cross-fd reads (SETCONFIGURATION's device-wide
     * claim check): claimed_mask mirrors ifaces[].claimed bit-per-interface,
     * devkey names the bound device (nonzero while bound). A handler runs under
     * its own entry lock and the order is table -> entry, so another slot's
     * entry lock cannot be taken there; atomics are read instead.
     */
    _Atomic uint32_t claimed_mask;
    _Atomic uint64_t devkey;

    /* Guards every field above except used/guest_fd/generation, which the table
     * lock guards, and the atomic mirrors. Held across blocking IOKit transfer
     * calls, which serializes concurrent ioctls on one fd exactly like the
     * Linux kernel's per-device lock (dropped-during-transfer refinement is a
     * TODO).
     */
    pthread_mutex_t lock;
} usbdev_t;

_Static_assert(USBDEV_MAX_IFACES <= 32,
               "claimed_mask carries one bit per interface");

/* Lock order: usbdev_table_lock -> entry lock. The table lock is a leaf with
 * respect to fd_lock (never held while taking it, and vice versa).
 */
static pthread_mutex_t usbdev_table_lock = PTHREAD_MUTEX_INITIALIZER;
static usbdev_t usbdev_fds[USBDEV_MAX_FDS];
static bool usbdev_ready;

/* IOReturn -> -LINUX_E* (doc D table (b)) */

#ifndef kUSBHostReturnPipeStalled
#define kUSBHostReturnPipeStalled 0xe0005000u
#endif

static int64_t ioret_neg_errno(IOReturn r)
{
    switch ((uint32_t) r) {
    case kIOReturnSuccess:
    case kIOReturnUnderrun: /* short transfer == success for usbfs */
        return 0;
    case kIOUSBPipeStalled:
    case kUSBHostReturnPipeStalled:
        return -LINUX_EPIPE;
    case kIOUSBTransactionTimeout:
        return -LINUX_ETIMEDOUT;
    case kIOReturnNoDevice:
    case kIOReturnNotOpen:
    case kIOReturnNotAttached:
        return -LINUX_ENODEV;
    case kIOReturnOverrun:
        return -LINUX_EOVERFLOW;
    case kIOReturnAborted:
        /* A sync transfer that comes back Aborted was already on the wire
         * (another thread's teardown aborted the pipe), so the dispatcher must
         * not re-execute the ioctl and send it again.
         */
        syscall_restart_forbid();
        return -LINUX_EINTR;
    case kIOReturnExclusiveAccess:
    case kIOReturnBusy:
        return -LINUX_EBUSY;
    case kIOReturnNotPermitted:
    case kIOReturnNotPrivileged:
        return -LINUX_EACCES;
    case kIOReturnBadArgument:
        return -LINUX_EINVAL;
    case kIOReturnNoMemory:
    case kIOReturnNoResources:
    case kIOReturnCannotWire:
        return -LINUX_ENOMEM;
    case kIOReturnUnsupported:
        return -LINUX_ENOTTY;
    case kIOUSBUnknownPipeErr:
    case kIOUSBEndpointNotFound:
    case kIOUSBInterfaceNotFound:
        return -LINUX_ENOENT;
    case kIOReturnNotResponding:
        return -LINUX_ETIME;
    default:
        return -LINUX_EPROTO;
    }
}

/* IOKit helpers */

static long usbdev_ioreg_num(io_service_t s, const char *key)
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

/* Retained IOUSBDevice service whose locationID matches, or IO_OBJECT_NULL. */
static io_service_t usbdev_service_for_location(uint32_t location_id)
{
    CFMutableDictionaryRef match = IOServiceMatching("IOUSBDevice");
    if (!match)
        return IO_OBJECT_NULL;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) !=
        kIOReturnSuccess)
        return IO_OBJECT_NULL;
    io_service_t found = IO_OBJECT_NULL;
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        if (found == IO_OBJECT_NULL &&
            usbdev_ioreg_num(svc, "locationID") == (long) location_id) {
            found = svc; /* keep the iterator's reference */
            continue;
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return found;
}

/* Create u->dev on first use. GetConfigurationDescriptorPtr-class calls and
 * CreateInterfaceIterator need only the plugin, not USBDeviceOpen.
 */
static int64_t usbdev_ensure_dev_plugin(usbdev_t *u)
{
    if (u->dev)
        return 0;
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn r = IOCreatePlugInInterfaceForService(
        u->service, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    if (r != kIOReturnSuccess || !plug) {
        log_warn("usbdev: device plugin for %d-%d failed 0x%x", u->busnum,
                 u->devnum, r);
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : ioret_neg_errno(r);
    }
    IOUSBDeviceInterface650 **dev = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650), (LPVOID *) &dev);
    (*plug)->Release(plug);
    if (hr != S_OK || !dev)
        return -LINUX_ENOMEM;
    u->dev = dev;
    return 0;
}

/* Lazy exclusive device open; kIOReturnExclusiveAccess is tolerated the way
 * libusb tolerates it (device stays usable for ep0 requests and interface
 * claims; only SetConfiguration demands a real open).
 */
static void usbdev_lazy_device_open(usbdev_t *u)
{
    if (u->dev_open || u->dev_open_tried || !u->dev)
        return;
    u->dev_open_tried = true;
    IOReturn r = (*u->dev)->USBDeviceOpen(u->dev);
    if (r == kIOReturnSuccess)
        u->dev_open = true;
    else
        log_debug("usbdev: USBDeviceOpen %d-%d -> 0x%x (tolerated)", u->busnum,
                  u->devnum, r);
}

/* Retained IOUSBHostInterface service for bInterfaceNumber ifnum in the active
 * configuration, or IO_OBJECT_NULL. Uses CreateInterfaceIterator so "exists"
 * means exactly what claimintf's usb_ifnum_to_if means.
 */
static io_service_t usbdev_iface_service(usbdev_t *u, unsigned ifnum)
{
    if (usbdev_ensure_dev_plugin(u) < 0)
        return IO_OBJECT_NULL;
    IOUSBFindInterfaceRequest fr = {
        .bInterfaceClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
        .bAlternateSetting = kIOUSBFindInterfaceDontCare,
    };
    io_iterator_t it = IO_OBJECT_NULL;
    if ((*u->dev)->CreateInterfaceIterator(u->dev, &fr, &it) !=
        kIOReturnSuccess)
        return IO_OBJECT_NULL;
    io_service_t found = IO_OBJECT_NULL;
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        if (found == IO_OBJECT_NULL &&
            usbdev_ioreg_num(svc, "bInterfaceNumber") == (long) ifnum) {
            found = svc;
            continue;
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return found;
}

/* "Kernel driver bound" == the interface service has a child in the service
 * plane (libusb darwin_usb.c:2746-2770). Fills name (class name, truncated)
 * when a child exists.
 */
static bool usbdev_iface_driver(io_service_t ifs, char *name, size_t n)
{
    io_registry_entry_t child = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildEntry(ifs, kIOServicePlane, &child) !=
            kIOReturnSuccess ||
        child == IO_OBJECT_NULL)
        return false;
    io_name_t cls;
    if (IOObjectGetClass(child, cls) == kIOReturnSuccess)
        str_copy_trunc(name, cls, n);
    else
        str_copy_trunc(name, "unknown", n);
    IOObjectRelease(child);
    return true;
}

static int usbdev_build_pipe_map(usbdev_iface_t *fi)
{
    fi->npipes = 0;
    UInt8 ne = 0;
    if ((*fi->intf)->GetNumEndpoints(fi->intf, &ne) != kIOReturnSuccess)
        return -1;
    if (ne > USBDEV_MAX_PIPES)
        ne = USBDEV_MAX_PIPES;
    for (UInt8 p = 1; p <= ne; p++) {
        UInt8 dir = 0, num = 0, type = 0, interval = 0;
        UInt16 mps = 0;
        if ((*fi->intf)->GetPipeProperties(fi->intf, p, &dir, &num, &type, &mps,
                                           &interval) != kIOReturnSuccess)
            continue;
        fi->pipe_ep[p - 1] = (uint8_t) (num | (dir == kUSBIn ? 0x80 : 0));
        fi->pipe_type[p - 1] = type;
        fi->npipes = p;
    }
    return 0;
}

/* claim / release (entry lock held) */

static int64_t usbdev_claim_locked(usbdev_t *u, unsigned ifnum)
{
    if (ifnum >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL; /* claimintf devio.c:786 */
    usbdev_iface_t *fi = &u->ifaces[ifnum];
    if (fi->claimed)
        return 0; /* already ours */

    io_service_t ifs = usbdev_iface_service(u, ifnum);
    if (ifs == IO_OBJECT_NULL)
        return -LINUX_ENOENT;

    /* Linux: a bound kernel driver makes CLAIMINTERFACE -EBUSY
     * (usb_driver_claim_interface, driver.c:558). USBInterfaceOpen would
     * sometimes succeed anyway when the Apple driver is idle (AppleUSBACMData
     * with no tty holder), so check the registry explicitly for fidelity.
     */
    char drv[64];
    if (usbdev_iface_driver(ifs, drv, sizeof(drv))) {
        log_debug("usbdev: claim %u refused, %s bound", ifnum, drv);
        IOObjectRelease(ifs);
        return -LINUX_EBUSY;
    }

    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn r = IOCreatePlugInInterfaceForService(
        ifs, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    IOObjectRelease(ifs);
    if (r != kIOReturnSuccess || !plug)
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : ioret_neg_errno(r);
    IOUSBInterfaceInterface800 **intf = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID800),
        (LPVOID *) &intf);
    (*plug)->Release(plug);
    if (hr != S_OK || !intf)
        return -LINUX_ENOMEM;

    r = (*intf)->USBInterfaceOpen(intf);
    if (r != kIOReturnSuccess) {
        (*intf)->Release(intf);
        int64_t e = ioret_neg_errno(r);
        return e == 0 ? -LINUX_EBUSY : e;
    }
    fi->intf = intf;
    if (usbdev_build_pipe_map(fi) < 0) {
        (*intf)->USBInterfaceClose(intf);
        (*intf)->Release(intf);
        fi->intf = NULL;
        return -LINUX_EIO;
    }
    fi->claimed = true;
    atomic_fetch_or(&u->claimed_mask, 1u << ifnum);
    return 0;
}

static int64_t usbdev_release_locked(usbdev_t *u, unsigned ifnum)
{
    if (ifnum >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    usbdev_iface_t *fi = &u->ifaces[ifnum];
    if (!fi->claimed) {
        /* releaseintf checks usb_ifnum_to_if first: a nonexistent interface is
         * -ENOENT, an existing unclaimed one -EINVAL (devio.c:815-833).
         */
        io_service_t ifs = usbdev_iface_service(u, ifnum);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_ENOENT;
        IOObjectRelease(ifs);
        return -LINUX_EINVAL;
    }
    (*fi->intf)->USBInterfaceClose(fi->intf);
    (*fi->intf)->Release(fi->intf);
    fi->intf = NULL;
    fi->claimed = false;
    atomic_fetch_and(&u->claimed_mask, ~(1u << ifnum));
    fi->npipes = 0;
    return 0;
}

/* findintfep (devio.c:856-879): which interface of the active config carries
 * bEndpointAddress ep, searching every altsetting. Parsed from the descriptors
 * blob.
 *
 * Returns -1 when not found.
 */
static int usbdev_ep_owner_iface(const usbdev_t *u, uint8_t ep)
{
    const uint8_t *b = u->blob;
    size_t len = u->blob_len;
    size_t off = 18;
    while (off + 9 <= len && b[off + 1] == 0x02 /* CONFIG */) {
        size_t total = (size_t) b[off + 2] | ((size_t) b[off + 3] << 8);
        if (total < 9 || off + total > len)
            break;
        bool active = b[off + 5] == (uint8_t) u->cfg_value;
        if (active) {
            size_t p = off + 9;
            int cur_if = -1;
            while (p + 2 <= off + total && b[p] >= 2) {
                uint8_t dlen = b[p], dtype = b[p + 1];
                if (p + dlen > off + total)
                    break;
                if (dtype == 0x04 && dlen >= 9) /* INTERFACE */
                    cur_if = b[p + 2];
                else if (dtype == 0x05 && dlen >= 7 && /* ENDPOINT */
                         b[p + 2] == ep && cur_if >= 0)
                    return cur_if;
                p += dlen;
            }
        }
        off += total;
    }
    return -1;
}

/* Resolve ep -> (claimed iface, pipeRef), implicitly claiming the owner
 * interface the way checkintf does for the sync paths. -ENOENT when no
 * altsetting of the active config carries the endpoint.
 */
static int64_t usbdev_pipe_for_ep(usbdev_t *u,
                                  uint8_t ep,
                                  usbdev_iface_t **fi_out,
                                  uint8_t *pipe_out)
{
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed)
                continue;
            for (int p = 0; p < fi->npipes; p++) {
                if (fi->pipe_ep[p] == ep) {
                    *fi_out = fi;
                    *pipe_out = (uint8_t) (p + 1);
                    return 0;
                }
            }
        }
        if (pass == 1)
            break;
        int owner = usbdev_ep_owner_iface(u, ep);
        if (owner < 0)
            return -LINUX_ENOENT;
        if (u->ifaces[owner].claimed)
            return -LINUX_ENOENT; /* claimed but ep not in current alt */
        int64_t rc = usbdev_claim_locked(u, (unsigned) owner);
        if (rc < 0)
            return rc;
    }
    return -LINUX_ENOENT;
}

/* check_ctrlrecip's endpoint-recipient arm (devio.c:905-938) for the control
 * paths: wIndex is masked to its low byte first, exactly like Linux.
 */
static int64_t usbdev_check_ep_recip(usbdev_t *u, uint16_t wIndex)
{
    uint8_t index = (uint8_t) (wIndex & 0xff);

    /* The default control endpoint belongs to no interface: allowed with no
     * claim and no lookup (devio.c:909-911) -- lsusb -v sends GET_STATUS to
     * endpoint 0 this way.
     */
    if ((index & 0x7f) == 0)
        return 0;

    /* findintfep rejects the reserved bits 0x10-0x70 outright
     * (devio.c:857-858); folding them away would collapse two encodings onto
     * one endpoint address.
     */
    if (index & 0x70)
        return -LINUX_EINVAL;

    usbdev_iface_t *fi = NULL;
    uint8_t pipe = 0;
    int64_t rc = usbdev_pipe_for_ep(u, index, &fi, &pipe);
    if (rc == -LINUX_ENOENT) {
        /* Some Win apps pass the endpoint number where the address (with its
         * direction bit) belongs; Linux flips the direction, warns, and lets
         * the request through (devio.c:913-928).
         */
        rc = usbdev_pipe_for_ep(u, index ^ 0x80, &fi, &pipe);
        if (rc == 0)
            log_warn(
                "usbdev: control recipient requests ep %02x but needs "
                "%02x",
                index, index ^ 0x80);
    }
    return rc;
}

/* side-table lookup */

/* Find the entry for guest fd and return it with its lock held; NULL when the
 * fd is not a live FD_USBDEV fd (or was closed+reused: generation mismatch).
 */
static usbdev_t *usbdev_acquire(int fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return NULL;
    usbdev_t *u = NULL;
    pthread_mutex_lock(&usbdev_table_lock);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        if (usbdev_fds[i].used && usbdev_fds[i].guest_fd == fd &&
            usbdev_fds[i].generation == snap.generation) {
            u = &usbdev_fds[i];
            break;
        }
    }

    /* Take the entry lock before dropping the table lock (table -> entry order)
     * so the slot cannot be torn down and reallocated in between. The cost:
     * while one thread's sync transfer holds the entry lock, a second ioctl on
     * the SAME fd queues here with the table lock held, briefly stalling other
     * fds' lookups. Linux serializes per-device too; the cross-fd stall is a
     * stage-2 simplification.
     */
    if (u)
        pthread_mutex_lock(&u->lock);
    pthread_mutex_unlock(&usbdev_table_lock);
    if (u && u->dead) {
        pthread_mutex_unlock(&u->lock);
        return NULL;
    }
    return u;
}

static void usbdev_teardown_locked(usbdev_t *u)
{
    for (int i = 0; i < USBDEV_MAX_IFACES; i++)
        if (u->ifaces[i].claimed)
            (void) usbdev_release_locked(u, (unsigned) i);
    if (u->dev) {
        if (u->dev_open)
            (*u->dev)->USBDeviceClose(u->dev);
        (*u->dev)->Release(u->dev);
        u->dev = NULL;
    }
    u->dev_open = false;
    u->dev_open_tried = false;
    if (u->service != IO_OBJECT_NULL) {
        IOObjectRelease(u->service);
        u->service = IO_OBJECT_NULL;
    }
    if (u->pipe_wr >= 0) {
        close(u->pipe_wr);
        u->pipe_wr = -1;
    }
    free(u->blob);
    u->blob = NULL;

    /* Retire the lock-free mirrors last so no cross-fd reader can match a slot
     * that is mid-teardown.
     */
    atomic_store(&u->claimed_mask, 0);
    atomic_store(&u->devkey, 0);
}

static void usbdev_fd_cleanup(int guest_fd)
{
    /* Find and tear down under table -> entry so a concurrent teardown + slot
     * reuse cannot hand this call somebody else's live entry. A sync transfer
     * in flight on this fd holds the entry lock, so this close waits for it
     * (with the table lock held; see usbdev_acquire's note).
     */
    pthread_mutex_lock(&usbdev_table_lock);
    usbdev_t *u = NULL;
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        if (usbdev_fds[i].used && usbdev_fds[i].guest_fd == guest_fd) {
            u = &usbdev_fds[i];
            break;
        }
    }
    if (!u) {
        pthread_mutex_unlock(&usbdev_table_lock);
        return;
    }
    pthread_mutex_lock(&u->lock);
    usbdev_teardown_locked(u);
    u->dead = true;
    u->used = false;
    u->guest_fd = -1;
    pthread_mutex_unlock(&u->lock);
    pthread_mutex_unlock(&usbdev_table_lock);
}

void usbdev_init(void)
{
    pthread_mutex_lock(&usbdev_table_lock);
    if (!usbdev_ready) {
        for (int i = 0; i < USBDEV_MAX_FDS; i++) {
            memset(&usbdev_fds[i], 0, sizeof(usbdev_fds[i]));
            usbdev_fds[i].guest_fd = -1;
            usbdev_fds[i].pipe_wr = -1;
            pthread_mutex_init(&usbdev_fds[i].lock, NULL);
        }
        usbdev_ready = true;
    }
    pthread_mutex_unlock(&usbdev_table_lock);
    fd_register_cleanup(FD_USBDEV, usbdev_fd_cleanup);
}

/* constructor */

static bool usbdev_parse_node(const char *path, int *bus, int *dev)
{
    unsigned b, d;
    char tail;
    if (sscanf(path, "/dev/bus/usb/%3u/%3u%c", &b, &d, &tail) != 2)
        return false;

    /* Reject non-canonical spellings the tree never lists ("/dev/bus/usb/1/1"
     * still parses above; the scratch tree only carries %03d names, and the
     * stage-1 stat intercept agrees, so keep both views consistent).
     */
    char canon[64];
    snprintf(canon, sizeof(canon), "/dev/bus/usb/%03u/%03u", b, d);
    if (strcmp(canon, path) != 0)
        return false;
    *bus = (int) b;
    *dev = (int) d;
    return true;
}

int64_t usbdev_open_path(const char *path, int linux_flags)
{
    int bus, dev;
    if (!usbdev_parse_node(path, &bus, &dev))
        return INT64_MIN;

    /* O_PATH fds carry no I/O capability; the stage-1 placeholder (blob fd
     * typed FD_PATH, stat-stamped) serves them without burning a slot here.
     */
    if (linux_flags & LINUX_O_PATH)
        return INT64_MIN;
    if (linux_flags & LINUX_O_DIRECTORY)
        return -LINUX_ENOTDIR;

    usb_sysfs_devinfo_t info;
    if (usb_sysfs_device_info(bus, dev, &info) < 0)
        return -LINUX_ENOENT;
    size_t blob_len = 0;
    uint8_t *blob = usb_sysfs_descriptors_dup(bus, dev, &blob_len);
    if (!blob)
        return -LINUX_ENOENT;
    io_service_t svc = usbdev_service_for_location(info.location_id);
    if (svc == IO_OBJECT_NULL) {
        free(blob);
        return -LINUX_ENODEV;
    }

    usbdev_t *u = NULL;
    pthread_mutex_lock(&usbdev_table_lock);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        if (!usbdev_fds[i].used) {
            u = &usbdev_fds[i];
            u->used = true;
            u->guest_fd = -1;
            break;
        }
    }
    pthread_mutex_unlock(&usbdev_table_lock);
    if (!u) {
        IOObjectRelease(svc);
        free(blob);
        return -LINUX_EMFILE;
    }

    /* Stays {-1, -1} when pipe() itself fails: the error arm below must not
     * close two indeterminate descriptors (netlink_socket's split).
     */
    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) < 0 || fd_set_nonblock(pipefd[0]) < 0 ||
        fd_set_nonblock(pipefd[1]) < 0) {
        if (pipefd[0] >= 0) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        pthread_mutex_lock(&usbdev_table_lock);
        u->used = false;
        pthread_mutex_unlock(&usbdev_table_lock);
        IOObjectRelease(svc);
        free(blob);
        return -LINUX_EMFILE;
    }
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    pthread_mutex_lock(&u->lock);
    u->dead = false;
    u->busnum = bus;
    u->devnum = dev;
    u->location_id = info.location_id;
    u->speed_code = info.speed_code;
    u->cfg_value = info.cfg_value;
    u->blob = blob;
    u->blob_len = blob_len;
    u->pos = 0;
    u->pipe_wr = pipefd[1];
    u->service = svc;
    u->dev = NULL;
    u->dev_open = false;
    u->dev_open_tried = false;
    memset(u->ifaces, 0, sizeof(u->ifaces));
    atomic_store(&u->claimed_mask, 0);
    /* Nonzero while bound; equal for every fd open on the same device node. */
    atomic_store(&u->devkey, (1ull << 63) | ((uint64_t) (uint32_t) bus << 32) |
                                 (uint32_t) dev);
    pthread_mutex_unlock(&u->lock);

    /* fd_alloc publishes the slot before the side table binds the guest fd; a
     * guest racing close() on a guessed fd number in that window leaks this
     * entry, the same accepted race as netlink_socket -> nl_alloc.
     */
    int guest_fd = fd_alloc(FD_USBDEV, pipefd[0], usbdev_fd_cleanup);
    if (guest_fd < 0) {
        close(pipefd[0]);
        pthread_mutex_lock(&u->lock);
        usbdev_teardown_locked(u);
        u->dead = true;
        pthread_mutex_unlock(&u->lock);
        pthread_mutex_lock(&usbdev_table_lock);
        u->used = false;
        pthread_mutex_unlock(&usbdev_table_lock);
        return -LINUX_EMFILE;
    }

    /* Stamp the node path so /proc/self/fd/N readlink reports the guest
     * spelling (stage-1 mechanism), and publish the fd's flags.
     */
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_USBDEV &&
        fd_table[guest_fd].host_fd == pipefd[0])
        str_copy_trunc(fd_table[guest_fd].proc_path, path,
                       sizeof(fd_table[guest_fd].proc_path));
    pthread_mutex_unlock(&fd_lock);
    fd_publish_linux_flags(guest_fd, linux_flags);

    /* Snapshot the generation before taking the table lock: reading it inside
     * would nest fd_lock under usbdev_table_lock, and the table lock is
     * documented as never held together with fd_lock. The value is the same
     * either way -- it only changes if the guest closes the fd, which is the
     * same accepted race as the fd_alloc publish window above.
     */
    uint64_t gen = fd_current_generation(guest_fd);
    pthread_mutex_lock(&usbdev_table_lock);
    u->guest_fd = guest_fd;
    u->generation = gen;
    pthread_mutex_unlock(&usbdev_table_lock);
    return guest_fd;
}

/* read / lseek / fstat */

int64_t usbdev_read(int fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    if ((snap.linux_flags & LINUX_O_ACCMODE) == LINUX_O_WRONLY)
        return -LINUX_EBADF; /* vfs: read needs FMODE_READ */
    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;
    int64_t ret;
    if ((uint64_t) u->pos >= u->blob_len || count == 0) {
        ret = 0;
    } else {
        size_t avail = u->blob_len - (size_t) u->pos;
        size_t n = count < avail ? (size_t) count : avail;
        if (guest_write(g, buf_gva, u->blob + u->pos, n) < 0) {
            ret = -LINUX_EFAULT;
        } else {
            u->pos += (off_t) n;
            ret = (int64_t) n;
        }
    }
    pthread_mutex_unlock(&u->lock);
    return ret;
}

/* pread(2)/preadv(2) arm: the same descriptors blob, served at the caller's
 * offset. A positional read never moves the fd position (vfs pread), a negative
 * offset is -EINVAL (ksys_pread64 refuses it before the fd lookup, so it
 * outranks even -EBADF), and count 0 reads nothing.
 */
int64_t usbdev_pread(int fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t count,
                     int64_t offset)
{
    if (offset < 0)
        return -LINUX_EINVAL;
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    if ((snap.linux_flags & LINUX_O_ACCMODE) == LINUX_O_WRONLY)
        return -LINUX_EBADF; /* vfs: read needs FMODE_READ */
    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;
    int64_t ret;
    if ((uint64_t) offset >= u->blob_len || count == 0) {
        ret = 0;
    } else {
        size_t avail = u->blob_len - (size_t) offset;
        size_t n = count < avail ? (size_t) count : avail;
        if (guest_write(g, buf_gva, u->blob + offset, n) < 0)
            ret = -LINUX_EFAULT;
        else
            ret = (int64_t) n;
    }
    pthread_mutex_unlock(&u->lock);
    return ret;
}

int64_t usbdev_lseek_fd(int fd, int64_t offset, int whence)
{
    if (fd_get_type(fd) != FD_USBDEV)
        return INT64_MIN;
    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;
    int64_t ret;
    int64_t base;
    switch (whence) {
    case 0: /* SEEK_SET */
        base = 0;
        break;
    case 1: /* SEEK_CUR */
        base = u->pos;
        break;
    default: /* SEEK_END and friends: no_seek_end_llseek -> -EINVAL */
        pthread_mutex_unlock(&u->lock);
        return -LINUX_EINVAL;
    }
    int64_t npos = base + offset;
    if (npos < 0) {
        ret = -LINUX_EINVAL;
    } else {
        u->pos = (off_t) npos;
        ret = npos;
    }
    pthread_mutex_unlock(&u->lock);
    return ret;
}

int64_t usbdev_fstat(int fd, struct stat *st)
{
    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;
    int bus = u->busnum, dev = u->devnum;
    pthread_mutex_unlock(&u->lock);
    if (usb_sysfs_node_stat(bus, dev, st) < 0)
        return -LINUX_ENODEV;
    return 0;
}

/* ioctl handlers (entry lock held unless noted) */

static int64_t usbdev_do_control(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_ctrltransfer_t ct;
    if (guest_read_small(g, arg, &ct, sizeof(ct)) < 0)
        return -LINUX_EFAULT;
    if (ct.wLength > USBDEV_CTRL_MAX)
        return -LINUX_EINVAL;

    /* check_ctrlrecip (devio.c:881-938): vendor-type requests bypass the
     * recipient check; interface/endpoint recipients implicitly claim the
     * owning interface first.
     */
    if ((ct.bRequestType & 0x60) != 0x40) {
        unsigned recip = ct.bRequestType & 0x1f;
        if (recip == 1) { /* interface */
            int64_t rc = usbdev_claim_locked(u, ct.wIndex & 0xff);
            if (rc < 0)
                return rc;
        } else if (recip == 2) { /* endpoint */
            int64_t rc = usbdev_check_ep_recip(u, ct.wIndex);
            if (rc < 0)
                return rc;
        }
    }

    int64_t rc = usbdev_ensure_dev_plugin(u);
    if (rc < 0)
        return rc;
    usbdev_lazy_device_open(u);

    uint8_t *buf = NULL;
    if (ct.wLength > 0) {
        buf = malloc(ct.wLength);
        if (!buf)
            return -LINUX_ENOMEM;
    }
    bool in = (ct.bRequestType & 0x80) != 0;
    if (!in && ct.wLength > 0 && guest_read(g, ct.data, buf, ct.wLength) < 0) {
        free(buf);
        return -LINUX_EFAULT;
    }

    IOUSBDevRequestTO req = {
        .bmRequestType = ct.bRequestType,
        .bRequest = ct.bRequest,
        .wValue = ct.wValue,
        .wIndex = ct.wIndex,
        .wLength = ct.wLength,
        .pData = buf,
        .noDataTimeout = ct.timeout,
        .completionTimeout = ct.timeout,
    };
    IOReturn r = (*u->dev)->DeviceRequestTO(u->dev, &req);
    if ((uint32_t) r == (uint32_t) kIOReturnNotOpen && !u->dev_open) {
        /* Some requests demand an open device; retry once after opening. */
        IOReturn ro = (*u->dev)->USBDeviceOpen(u->dev);
        if (ro == kIOReturnSuccess) {
            u->dev_open = true;
            r = (*u->dev)->DeviceRequestTO(u->dev, &req);
        }
    }
    int64_t err = ioret_neg_errno(r);
    if (err < 0) {
        /* On -ETIMEDOUT/-EINTR partial IN data is NOT copied out
         * (devio.c:1230).
         */
        free(buf);
        return err;
    }
    int64_t actlen = req.wLenDone;
    if (in && actlen > 0 && guest_write(g, ct.data, buf, (size_t) actlen) < 0) {
        free(buf);
        return -LINUX_EFAULT;
    }
    free(buf);
    return actlen;
}

static int64_t usbdev_do_bulk(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_bulktransfer_t bt;
    if (guest_read_small(g, arg, &bt, sizeof(bt)) < 0)
        return -LINUX_EFAULT;
    if ((bt.ep & 0x70) != 0)
        return -LINUX_EINVAL;

    /* proc_bulk: only a near-INT_MAX length is malformed (-EINVAL,
     * devio.c:1301); a merely-too-large one fails the usbfs_memory_mb allowance
     * with -ENOMEM (devio.c:1311-1318).
     */
    if (bt.len >= (uint32_t) INT32_MAX)
        return -LINUX_EINVAL;
    if (bt.len > USBDEV_BULK_MAX)
        return -LINUX_ENOMEM;

    usbdev_iface_t *fi;
    uint8_t pipe;
    int64_t rc = usbdev_pipe_for_ep(u, (uint8_t) bt.ep, &fi, &pipe);
    if (rc < 0)
        return rc;
    uint8_t type = fi->pipe_type[pipe - 1];
    if (type == kUSBInterrupt) {
        /* Linux converts BULK-on-interrupt-ep to an interrupt URB
         * (devio.c:1327); ReadPipeTO/WritePipeTO reject interrupt pipes.
         * TODO(later): async submit + timed wait.
         */
        log_warn("usbdev: sync BULK on interrupt ep 0x%02x unsupported", bt.ep);
        return -LINUX_EINVAL;
    }
    if (type != kUSBBulk)
        return -LINUX_EINVAL; /* control/iso ep: proc_bulk EINVAL */

    uint8_t *buf = NULL;
    if (bt.len > 0) {
        buf = malloc(bt.len);
        if (!buf)
            return -LINUX_ENOMEM;
    }
    int64_t ret;
    if (bt.ep & 0x80) {
        UInt32 size = bt.len;
        IOReturn r = (*fi->intf)->ReadPipeTO(fi->intf, pipe, buf, &size,
                                             bt.timeout, bt.timeout);
        int64_t err = ioret_neg_errno(r);
        if (err < 0) {
            ret = err; /* partial data not copied on error, as Linux */
        } else if (size > 0 && guest_write(g, bt.data, buf, size) < 0) {
            ret = -LINUX_EFAULT;
        } else {
            ret = size;
        }
    } else {
        if (bt.len > 0 && guest_read(g, bt.data, buf, bt.len) < 0) {
            free(buf);
            return -LINUX_EFAULT;
        }
        IOReturn r = (*fi->intf)->WritePipeTO(fi->intf, pipe, buf, bt.len,
                                              bt.timeout, bt.timeout);
        int64_t err = ioret_neg_errno(r);
        ret = err < 0 ? err : bt.len;
    }
    free(buf);
    return ret;
}

static int64_t usbdev_do_getdriver(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_getdriver_t gd;
    if (guest_read_small(g, arg, &gd, sizeof(gd)) < 0)
        return -LINUX_EFAULT;

    /* proc_getdriver: no such interface and no driver are the same answer,
     * -ENODATA (devio.c:1445-1446); usb_ifnum_to_if has no range error.
     */
    if (gd.interface >= USBDEV_MAX_IFACES)
        return -LINUX_ENODATA;
    memset(gd.driver, 0, sizeof(gd.driver));
    if (u->ifaces[gd.interface].claimed) {
        str_copy_trunc(gd.driver, "usbfs", sizeof(gd.driver));
    } else {
        io_service_t ifs = usbdev_iface_service(u, gd.interface);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_ENODATA; /* usb_ifnum_to_if NULL */
        bool bound = usbdev_iface_driver(ifs, gd.driver, sizeof(gd.driver));
        IOObjectRelease(ifs);
        if (!bound)
            return -LINUX_ENODATA;
    }
    if (guest_write_small(g, arg, &gd, sizeof(gd)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

static int64_t usbdev_do_setinterface(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_setinterface_t si;
    if (guest_read_small(g, arg, &si, sizeof(si)) < 0)
        return -LINUX_EFAULT;
    int64_t rc = usbdev_claim_locked(u, si.interface); /* implicit claim */
    if (rc < 0)
        return rc;
    usbdev_iface_t *fi = &u->ifaces[si.interface];
    IOReturn r =
        (*fi->intf)->SetAlternateInterface(fi->intf, (UInt8) si.altsetting);
    if (r != kIOReturnSuccess) {
        int64_t err = ioret_neg_errno(r);
        /* usb_set_interface: unknown altsetting -> -EINVAL */
        return err == -LINUX_ENOENT ? -LINUX_EINVAL : err;
    }
    if (usbdev_build_pipe_map(fi) < 0)
        return -LINUX_EIO;
    return 0;
}

/* proc_setconfig's claim check is device-wide (usb_interface_claimed,
 * devio.c:1561-1576): a claim through ANY usbfs open of this device blocks
 * SetConfiguration, not only one through the calling fd. The caller holds its
 * own entry lock and the order is table -> entry, so the other slots' entry
 * locks cannot be taken here; their lock-free mirrors are read instead.
 */
static bool usbdev_claimed_elsewhere(usbdev_t *u)
{
    uint64_t key = atomic_load(&u->devkey);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        usbdev_t *o = &usbdev_fds[i];
        if (o == u)
            continue;
        if (atomic_load(&o->devkey) == key &&
            atomic_load(&o->claimed_mask) != 0)
            return true;
    }
    return false;
}

static int64_t usbdev_do_setconfiguration(usbdev_t *u, guest_t *g, uint64_t arg)
{
    uint32_t cfg;
    if (guest_read_small(g, arg, &cfg, sizeof(cfg)) < 0)
        return -LINUX_EFAULT;
    /* -1/0 -> unconfigure (message.c:2064); SetConfiguration(0) does that. */
    if (cfg == 0xffffffffu)
        cfg = 0;
    if (cfg > 255)
        return -LINUX_EINVAL;

    /* proc_setconfig: -EBUSY when ANY interface of the device is claimed -- by
     * this fd, by another usbfs fd, or by a bound host driver
     * (devio.c:1561-1578).
     */
    for (int i = 0; i < USBDEV_MAX_IFACES; i++)
        if (u->ifaces[i].claimed)
            return -LINUX_EBUSY;
    if (usbdev_claimed_elsewhere(u))
        return -LINUX_EBUSY;
    int64_t rc = usbdev_ensure_dev_plugin(u);
    if (rc < 0)
        return rc;

    /* A bound host (Apple) driver claims its interface exactly like a Linux
     * driver would (usb_interface_claimed covers every driver, not just usbfs):
     * one iterator pass over the device's interfaces.
     */
    IOUSBFindInterfaceRequest fr = {
        .bInterfaceClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
        .bAlternateSetting = kIOUSBFindInterfaceDontCare,
    };
    io_iterator_t it = IO_OBJECT_NULL;
    if ((*u->dev)->CreateInterfaceIterator(u->dev, &fr, &it) ==
        kIOReturnSuccess) {
        bool bound = false;
        io_service_t svc;
        while ((svc = IOIteratorNext(it))) {
            char drv[64];
            if (!bound && usbdev_iface_driver(svc, drv, sizeof(drv)))
                bound = true;
            IOObjectRelease(svc);
        }
        IOObjectRelease(it);
        if (bound)
            return -LINUX_EBUSY;
    }
    usbdev_lazy_device_open(u);
    if (!u->dev_open)
        return -LINUX_EBUSY; /* exclusive holder elsewhere */
    IOReturn r = (*u->dev)->SetConfiguration(u->dev, (UInt8) cfg);
    if (r != kIOReturnSuccess) {
        int64_t err = ioret_neg_errno(r);
        return err == -LINUX_ENOENT ? -LINUX_EINVAL : err;
    }
    u->cfg_value = cfg;
    return 0;
}

static int64_t usbdev_do_clear_halt(usbdev_t *u, guest_t *g, uint64_t arg)
{
    uint32_t ep;
    if (guest_read_small(g, arg, &ep, sizeof(ep)) < 0)
        return -LINUX_EFAULT;
    usbdev_iface_t *fi;
    uint8_t pipe;
    int64_t rc = usbdev_pipe_for_ep(u, (uint8_t) ep, &fi, &pipe);
    if (rc < 0)
        return rc;

    /* ClearPipeStallBothEnds == CLEAR_FEATURE(ENDPOINT_HALT) + host-side toggle
     * reset (IOUSBLib.h:2928-2941), exactly usb_clear_halt.
     */
    return ioret_neg_errno((*fi->intf)->ClearPipeStallBothEnds(fi->intf, pipe));
}

static int64_t usbdev_do_resetep(usbdev_t *u, guest_t *g, uint64_t arg)
{
    /* proc_resetep is a host-side toggle/seq reset only (message.c:1377).
     * ClearPipeStallBothEnds is the closest IOKit equivalent (it also sends the
     * wire CLEAR_FEATURE, a benign superset).
     */
    return usbdev_do_clear_halt(u, g, arg);
}

static int64_t usbdev_do_disconnect_claim(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_disconnect_claim_t dc;
    if (guest_read_small(g, arg, &dc, sizeof(dc)) < 0)
        return -LINUX_EFAULT;
    if (dc.interface >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    dc.driver[sizeof(dc.driver) - 1] = '\0';

    char drv[256] = "";
    bool bound = false;
    if (u->ifaces[dc.interface].claimed) {
        str_copy_trunc(drv, "usbfs", sizeof(drv));
        bound = true;
    } else {
        io_service_t ifs = usbdev_iface_service(u, dc.interface);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_ENOENT;
        bound = usbdev_iface_driver(ifs, drv, sizeof(drv));
        IOObjectRelease(ifs);
    }
    if (bound) {
        if ((dc.flags & USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER) &&
            strcmp(dc.driver, drv) != 0)
            return -LINUX_EBUSY;
        if ((dc.flags & USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER) &&
            strcmp(dc.driver, drv) == 0)
            return -LINUX_EBUSY;
        if (strcmp(drv, "usbfs") != 0) {
            /* A real (Apple) driver would need whole-device capture, which
             * requires root or com.apple.vm.device-access; mirror the
             * privileges-dropped Linux answer (devio.c:2482).
             */
            return -LINUX_EACCES;
        }
    }
    return usbdev_claim_locked(u, dc.interface);
}

static int64_t usbdev_do_driver_ioctl(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_ioctl_t ic;
    if (guest_read_small(g, arg, &ic, sizeof(ic)) < 0)
        return -LINUX_EFAULT;
    if (ic.ifno < 0 || ic.ifno >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    unsigned ifnum = (unsigned) ic.ifno;
    switch ((uint32_t) ic.ioctl_code) {
    case USBDEVFS_IOCTL_DISCONNECT: {
        if (u->ifaces[ifnum].claimed)
            return usbdev_release_locked(u, ifnum); /* unbind "usbfs" */
        io_service_t ifs = usbdev_iface_service(u, ifnum);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_EINVAL;
        char drv[64];
        bool bound = usbdev_iface_driver(ifs, drv, sizeof(drv));
        IOObjectRelease(ifs);
        if (!bound)
            return -LINUX_ENODATA;
        return -LINUX_EACCES; /* cannot unbind Apple drivers non-root */
    }
    case USBDEVFS_IOCTL_CONNECT:
        return -LINUX_EACCES; /* device_attach needs the host's consent */
    default:
        return -LINUX_ENOTTY;
    }
}

/* Registry 'Device Speed' -> USB_SPEED_* enum (ch9.h:1217-1222): the ioctl's
 * return value, not an out parameter.
 */
static int64_t usbdev_speed_enum(unsigned code)
{
    switch (code) {
    case 0:
        return 1; /* LOW */
    case 1:
        return 2; /* FULL */
    case 2:
        return 3; /* HIGH */
    case 3:
        return 5; /* SUPER */
    case 4:
    case 5:
        return 6; /* SUPER_PLUS */
    default:
        return 2;
    }
}

int64_t usbdev_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    /* Every usbdev ioctl needs FMODE_WRITE (devio.c:2607-2608). */
    if ((snap.linux_flags & LINUX_O_ACCMODE) == LINUX_O_RDONLY)
        return -LINUX_EPERM;

    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;

    int64_t ret;
    switch ((uint32_t) request) {
    case USBDEVFS_CLAIMINTERFACE: {
        uint32_t ifnum;
        ret = guest_read_small(g, arg, &ifnum, sizeof(ifnum)) < 0
                  ? -LINUX_EFAULT
                  : usbdev_claim_locked(u, ifnum);
        break;
    }
    case USBDEVFS_RELEASEINTERFACE: {
        uint32_t ifnum;
        ret = guest_read_small(g, arg, &ifnum, sizeof(ifnum)) < 0
                  ? -LINUX_EFAULT
                  : usbdev_release_locked(u, ifnum);
        break;
    }
    case USBDEVFS_SETINTERFACE:
        ret = usbdev_do_setinterface(u, g, arg);
        break;
    case USBDEVFS_SETCONFIGURATION:
        ret = usbdev_do_setconfiguration(u, g, arg);
        break;
    case USBDEVFS_CLEAR_HALT:
        ret = usbdev_do_clear_halt(u, g, arg);
        break;
    case USBDEVFS_RESETEP:
        ret = usbdev_do_resetep(u, g, arg);
        break;
    case USBDEVFS_GETDRIVER:
        ret = usbdev_do_getdriver(u, g, arg);
        break;
    case USBDEVFS_GET_CAPABILITIES: {
        uint32_t caps = USBDEV_CAPS;
        ret = guest_write_small(g, arg, &caps, sizeof(caps)) < 0 ? -LINUX_EFAULT
                                                                 : 0;
        break;
    }
    case USBDEVFS_GET_SPEED:
        ret = usbdev_speed_enum(u->speed_code);
        break;
    case USBDEVFS_CONNECTINFO: {
        linux_usbdevfs_connectinfo_t ci = {
            .devnum = (uint32_t) u->devnum,
            .slow = u->speed_code == 0,
        };
        ret =
            guest_write_small(g, arg, &ci, sizeof(ci)) < 0 ? -LINUX_EFAULT : 0;
        break;
    }
    case USBDEVFS_CONTROL:
        ret = usbdev_do_control(u, g, arg);
        break;
    case USBDEVFS_BULK:
        ret = usbdev_do_bulk(u, g, arg);
        break;
    case USBDEVFS_RESET: {
        /* Stage-2 deviation (see file header): clear stalls on every claimed
         * pipe instead of re-enumerating, and report success.
         */
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed)
                continue;
            for (int p = 1; p <= fi->npipes; p++)
                (void) (*fi->intf)->ClearPipeStallBothEnds(fi->intf, (UInt8) p);
        }
        log_debug(
            "usbdev: RESET emulated as pipe-stall clear (no "
            "re-enumeration)");
        ret = 0;
        break;
    }
    case USBDEVFS_DISCONNECT_CLAIM:
        ret = usbdev_do_disconnect_claim(u, g, arg);
        break;
    case USBDEVFS_IOCTL:
        ret = usbdev_do_driver_ioctl(u, g, arg);
        break;
    case USBDEVFS_SUBMITURB:
        log_warn("usbdev: SUBMITURB not implemented (stage 3)");
        ret = -LINUX_ENOTTY;
        break;
    case USBDEVFS_DISCARDURB:
    case USBDEVFS_REAPURB:
    case USBDEVFS_REAPURBNDELAY:
    case USBDEVFS_DISCSIGNAL:
        log_debug("usbdev: async URB ioctl 0x%llx not implemented (stage 3)",
                  (unsigned long long) request);
        ret = -LINUX_ENOTTY;
        break;
    default:
        ret = -LINUX_ENOTTY;
        break;
    }
    pthread_mutex_unlock(&u->lock);
    return ret;
}
