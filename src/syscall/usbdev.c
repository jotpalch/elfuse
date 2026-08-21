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
 * Stage 3 adds async URBs and poll semantics:
 *
 *   - SUBMITURB/DISCARDURB/REAPURB/REAPURBNDELAY (doc A §A3): URB buffers
 *     bounce through host memory (copy-in at submit on the vCPU thread,
 *     copy-out at reap on the vCPU thread); IOKit completions run on ONE
 *     lazily-started host thread driving a CFRunLoop (the libusb darwin
 *     model, doc D §c) fed by CreateDeviceAsyncEventSource /
 *     CreateInterfaceAsyncEventSource. That thread touches only
 *     usbdev-owned host memory (static fd slots + malloc'd URB records),
 *     never guest memory, so it is safe across guest_destroy/exec
 *     (netlink.c:853-857 precedent).
 *   - DISCARDURB must kill exactly one URB, but IOKit's AbortPipe aborts
 *     every outstanding transfer on the pipe (doc D mismatch #1). So at most
 *     ONE URB per endpoint is in flight at IOKit at a time; later submissions
 *     queue inside elfuse and are started from the completion callback
 *     (throughput tradeoff, ep0 serialized the same way).
 *   - URBs get no IOKit timeout (0 = infinite): usbfs URBs never time out,
 *     guests cancel with DISCARDURB (kIOReturnAborted -> -ENOENT when
 *     discarding, -ECONNRESET otherwise, mirroring usb_kill_urb vs async
 *     unlink).
 *   - ZERO_PACKET on a maxpacket-multiple OUT issues a synchronous
 *     WritePipe(pipeRef, buf, 0) from the completion callback
 *     (darwin_usb.c:3193-3204). SHORT_NOT_OK is emulated at completion
 *     (-EREMOTEIO on a short IN). Both flags are honoured only for their
 *     Linux-defined direction (devio.c:1710-1737). BULK_CONTINUATION is
 *     accepted but its error-cascade unlink has no IOKit counterpart.
 *   - poll()/select()/epoll on the fd: the backing pipe's read end raises
 *     host POLLIN when a completion (one byte per completed URB) arrives;
 *     poll.c remaps that to the guest-visible POLLOUT|POLLWRNORM
 *     (devio.c:2832-2846) via the usbdev_poll_* helpers below.
 *   - Disconnect: IOServiceAddInterestNotification (terminate message) or
 *     kIOReturnNoDevice/NotAttached on any op marks the fd disconnected:
 *     poll -> POLLERR|POLLHUP, REAPURB drains completed then -ENODEV, every
 *     other ioctl -ENODEV.
 *   - DISCSIGNAL stores signr/context but never delivers the signal (no
 *     async guest-signal injection from the event thread); URB signr is
 *     ignored the same way. ISO URBs are -EINVAL (doc A §A7.4, skipped).
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
 *   - dup()/fork() of an FD_USBDEV fd are refused (-EBADF): IOKit plugin
 *     handles are process-local and the side table is keyed by the guest fd.
 *     TODO(later): explicit dup alias (fuse_dup_fd pattern).
 *   - DISCONNECT/CONNECT/DISCONNECT_CLAIM cannot unbind Apple drivers without
 *     root or the com.apple.vm.device-access entitlement, so a bound kernel
 *     driver yields -EACCES (matching Linux's privileges-dropped answer).
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/usb/USB.h>

#include "core/guest.h"
#include "debug/log.h"
#include "runtime/usb-sysfs.h"
#include "syscall/internal.h"
#include "syscall/io.h"
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

/* struct usbdevfs_urb, LP64 (buffer at 16, usercontext at 48, sizeof 56). */
typedef struct {
    uint8_t type;
    uint8_t endpoint;
    uint16_t pad0;
    int32_t status;
    uint32_t flags;
    uint32_t pad1; /* natural hole before the pointer */
    uint64_t buffer;
    int32_t buffer_length;
    int32_t actual_length;
    int32_t start_frame;
    int32_t number_of_packets; /* union with stream_id */
    int32_t error_count;
    uint32_t signr;
    uint64_t usercontext;
} linux_usbdevfs_urb_t;

typedef struct {
    uint32_t signr;
    uint32_t pad;
    uint64_t context;
} linux_usbdevfs_disconnectsignal_t; /* sizeof == 16 */

#define LINUX_URB_TYPE_ISO 0u
#define LINUX_URB_TYPE_INTERRUPT 1u
#define LINUX_URB_TYPE_CONTROL 2u
#define LINUX_URB_TYPE_BULK 3u

/* URB flags (uapi/linux/usbdevice_fs.h). devio.c:1635-1645 rejects anything
 * outside this set for non-ISO URBs.
 */
#define LINUX_URB_SHORT_NOT_OK 0x01u
#define LINUX_URB_ISO_ASAP 0x02u
#define LINUX_URB_BULK_CONTINUATION 0x04u
#define LINUX_URB_NO_FSBR 0x20u
#define LINUX_URB_ZERO_PACKET 0x40u
#define LINUX_URB_NO_INTERRUPT 0x80u
#define LINUX_URB_FLAGS_ALLOWED                             \
    (LINUX_URB_SHORT_NOT_OK | LINUX_URB_BULK_CONTINUATION | \
     LINUX_URB_NO_FSBR | LINUX_URB_ZERO_PACKET | LINUX_URB_NO_INTERRUPT)

/* Linux poll bits (asm-generic/poll.h). POLLWRNORM differs from macOS (0x100 vs
 * 0x004), so the guest-facing remap must use these, never the host's <poll.h>
 * values.
 */
#define LINUX_POLLIN 0x0001
#define LINUX_POLLOUT 0x0004
#define LINUX_POLLERR 0x0008
#define LINUX_POLLHUP 0x0010
#define LINUX_POLLNVAL 0x0020
#define LINUX_POLLWRNORM 0x0100

/* do_proc_control caps wLength at PAGE_SIZE (devio.c:1185). */
#define USBDEV_CTRL_MAX 4096
/* usbfs_memory_mb default: 16 MB of in-flight buffer (devio.c:134). */
#define USBDEV_BULK_MAX (16u * 1024 * 1024)
/* Backstop on live URB records per fd (pending + unreaped completed). */
#define USBDEV_MAX_URBS 256

/* side table */

#define USBDEV_MAX_FDS 16
#define USBDEV_MAX_IFACES 32 /* claimintf: ifnum >= 32 is -EINVAL */
#define USBDEV_MAX_PIPES 30

typedef struct {
    bool claimed;
    IOUSBInterfaceInterface800 **intf;
    CFRunLoopSourceRef src; /* async event source, on the event runloop */
    int npipes;
    uint8_t pipe_ep[USBDEV_MAX_PIPES];   /* pipeRef-1 -> bEndpointAddress */
    uint8_t pipe_type[USBDEV_MAX_PIPES]; /* kUSBControl..kUSBInterrupt */
    uint16_t pipe_mps[USBDEV_MAX_PIPES]; /* wMaxPacketSize (ZLP check) */
} usbdev_iface_t;

typedef enum { URB_QUEUED, URB_INFLIGHT, URB_COMPLETED } urb_state_t;

struct usbdev; /* fwd */

/* One SUBMITURB. Guest data bounces through buf: copy-in at submit and copy-out
 * at reap both happen on the vCPU thread; the completion callback (event
 * thread) touches only this record and its owning static fd slot.
 */
typedef struct usbdev_urb {
    struct usbdev_urb *next;
    struct usbdev *u;  /* owning slot (static array, never freed) */
    uint64_t userurb;  /* guest pointer to struct usbdevfs_urb (reap key) */
    uint64_t data_gva; /* where IN data lands (urb buffer, +8 for control) */
    uint8_t type;      /* LINUX_URB_TYPE_* */
    uint8_t ep;        /* bEndpointAddress from the urb */
    uint8_t ep_key;    /* per-endpoint FIFO key; 0 = default control pipe */
    uint8_t pipe;      /* pipeRef; 0 = device ep0 */
    bool is_in;
    bool discarding;     /* DISCARDURB issued: abort reports -ENOENT */
    bool orphaned;       /* teardown timed out: callback frees the record */
    bool zero_packet;    /* OUT + URB_ZERO_PACKET */
    bool short_not_ok;   /* IN + URB_SHORT_NOT_OK */
    bool pipe_interrupt; /* pipe is interrupt-type (no *TO entry points) */
    urb_state_t state;
    int32_t status; /* linux URB status, valid once COMPLETED */
    uint32_t actual;
    uint32_t data_len; /* bounce buffer length (excludes control setup) */
    uint16_t mps;      /* endpoint wMaxPacketSize for the ZLP check */
    IOUSBInterfaceInterface800 **intf; /* pinned at submit; NULL for ep0 */
    uint8_t *buf;                      /* host bounce buffer */
    IOUSBDevRequestTO req;             /* control only */
} usbdev_urb_t;

typedef struct usbdev {
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
    int pipe_wr; /* write end of the readiness pipe (one byte/completion) */
    io_service_t service;          /* retained IOUSBDevice service */
    IOUSBDeviceInterface650 **dev; /* lazily created device plugin */
    bool dev_open;                 /* USBDeviceOpen succeeded */
    bool dev_open_tried;
    CFRunLoopSourceRef dev_src; /* ep0 async event source (lazy) */
    io_object_t notif;          /* interest notification (disconnect) */
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

    /* --- async URB state, guarded by async_lock (never held across a blocking
     * IOKit call other than the callback-side ZLP WritePipe). The completion
     * callback and the disconnect notification run on the event thread and take
     * ONLY this lock, so a vCPU thread parked in a sync transfer under `lock`
     * cannot stall completions on other endpoints. Lock order: lock ->
     * async_lock. pipe_wr may additionally be written under async_lock
     * (teardown sets it to -1 under both locks before closing).
     */
    pthread_mutex_t async_lock;
    pthread_cond_t async_cv; /* completion / in-flight drain */
    usbdev_urb_t *pending_head, *pending_tail;     /* QUEUED + INFLIGHT */
    usbdev_urb_t *completed_head, *completed_tail; /* reapable, FIFO */
    int inflight;                                  /* URB_INFLIGHT count */
    int nurbs;              /* live records (pending + completed) */
    size_t inflight_bytes;  /* usbfs_memory_mb-style cap accounting */
    bool disconnected;      /* device gone; mirrored in usbdev_disc_map */
    uint32_t discsig_signr; /* DISCSIGNAL, stored but never delivered */
    uint64_t discsig_context;
} usbdev_t;

_Static_assert(USBDEV_MAX_IFACES <= 32,
               "claimed_mask carries one bit per interface");

/* Lock order: usbdev_table_lock -> entry lock. The table lock is a leaf with
 * respect to fd_lock (never held while taking it, and vice versa).
 */
static pthread_mutex_t usbdev_table_lock = PTHREAD_MUTEX_INITIALIZER;
static usbdev_t usbdev_fds[USBDEV_MAX_FDS];
static bool usbdev_ready;

/* Lock-free "this guest fd's usbdev device is gone" map for the poll/epoll
 * remap helpers: they run on hot poll paths and must not queue behind an entry
 * lock held across a blocking sync transfer. Set by the event thread at
 * disconnect, cleared when the guest fd is bound or torn down. A stale bit on a
 * reused fd number is harmless: the helpers check the fd type first, and
 * binding a new usbdev fd clears it.
 */
static _Atomic uint8_t usbdev_disc_map[FD_TABLE_SIZE];

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
         * (another thread's DISCARDURB/teardown aborted the pipe), so the
         * dispatcher must not re-execute the ioctl and send it again. The flag
         * is thread-local; on the event thread (urb status mapping, never a
         * syscall return) it is dead state and harmless.
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
        fi->pipe_mps[p - 1] = mps;
        fi->npipes = p;
    }
    return 0;
}

/* async engine: event thread, URB lists, completions
 *
 * One host thread per elfuse process runs a CFRunLoop; per-open-device
 * (CreateDeviceAsyncEventSource) and per-claimed-interface
 * (CreateInterfaceAsyncEventSource) sources are added to it from vCPU threads,
 * exactly libusb's darwin model (darwin_usb.c:1894-1911, 2261-2272). Chosen
 * over the CreateDeviceAsyncPort + mach_msg alternative because the runloop
 * also carries the IONotificationPort for disconnect interest messages with no
 * extra plumbing.
 *
 * The thread is started lazily on the first async submit and never joined: exec
 * keeps the host process (side tables survive), and after guest_destroy the
 * callbacks only touch usbdev-owned host memory (static fd slots, malloc'd URB
 * records, the completion pipe), never guest memory -- the copy-in/copy-out
 * happens on vCPU threads (netlink.c:853-857 warning).
 */

#ifndef kIOUSBTransactionReturned
#define kIOUSBTransactionReturned 0xe0004050u
#endif

static pthread_mutex_t usbdev_loop_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t usbdev_loop_cv = PTHREAD_COND_INITIALIZER;
static CFRunLoopRef usbdev_loop; /* set once by the event thread */
static bool usbdev_loop_started;
static IONotificationPortRef usbdev_notify_port; /* loop lock */

static void usbdev_loop_keepalive(void *info)
{
    (void) info;
}

static void *usbdev_loop_main(void *arg)
{
    (void) arg;

    /* A permanent dummy source keeps CFRunLoopRun from returning while no
     * device/interface source is attached.
     */
    CFRunLoopSourceContext ctx = {.perform = usbdev_loop_keepalive};
    CFRunLoopSourceRef keep =
        CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &ctx);
    if (keep)
        CFRunLoopAddSource(CFRunLoopGetCurrent(), keep, kCFRunLoopDefaultMode);
    pthread_mutex_lock(&usbdev_loop_lock);
    usbdev_loop = CFRunLoopGetCurrent();
    pthread_cond_broadcast(&usbdev_loop_cv);
    pthread_mutex_unlock(&usbdev_loop_lock);
    CFRunLoopRun();

    /* Unreached in practice: the keepalive source pins the loop until the
     * process exits.
     */
    if (keep)
        CFRelease(keep);
    return NULL;
}

/* Start (once) and return the event runloop; NULL only if thread creation
 * failed.
 */
static CFRunLoopRef usbdev_loop_get(void)
{
    pthread_mutex_lock(&usbdev_loop_lock);
    if (!usbdev_loop_started) {
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &at, usbdev_loop_main, NULL) == 0)
            usbdev_loop_started = true;
        else
            log_warn("usbdev: event thread creation failed");
        pthread_attr_destroy(&at);
    }
    while (usbdev_loop_started && !usbdev_loop)
        pthread_cond_wait(&usbdev_loop_cv, &usbdev_loop_lock);
    CFRunLoopRef l = usbdev_loop;
    pthread_mutex_unlock(&usbdev_loop_lock);
    return l;
}

/* The runloop if the event thread already exists; never starts it. */
static CFRunLoopRef usbdev_loop_current(void)
{
    pthread_mutex_lock(&usbdev_loop_lock);
    CFRunLoopRef l = usbdev_loop;
    pthread_mutex_unlock(&usbdev_loop_lock);
    return l;
}

static IONotificationPortRef usbdev_notify_get(void)
{
    CFRunLoopRef loop = usbdev_loop_get();
    if (!loop)
        return NULL;
    pthread_mutex_lock(&usbdev_loop_lock);
    if (!usbdev_notify_port) {
        usbdev_notify_port = IONotificationPortCreate(kIOMainPortDefault);
        if (usbdev_notify_port)
            CFRunLoopAddSource(
                loop, IONotificationPortGetRunLoopSource(usbdev_notify_port),
                kCFRunLoopDefaultMode);
    }
    IONotificationPortRef p = usbdev_notify_port;
    pthread_mutex_unlock(&usbdev_loop_lock);
    return p;
}

/* Event-thread-safe disconnect stamp: async_lock only, no guest memory. Wakes
 * pollers with one extra pipe byte (the remap turns it into POLLERR|POLLHUP)
 * and REAPURB waiters via the cv.
 */
static void usbdev_mark_disconnected_locked(usbdev_t *u)
{
    if (!u->disconnected) {
        u->disconnected = true;

        /* guest_fd is table-lock-guarded; this unlocked read races only with
         * teardown, which clears the map bit again afterwards.
         */
        int gfd = u->guest_fd;
        if (RANGE_CHECK(gfd, 0, FD_TABLE_SIZE))
            atomic_store(&usbdev_disc_map[gfd], 1);
        if (u->pipe_wr >= 0) {
            char b = 0;
            (void) !write(u->pipe_wr, &b, 1);
        }
        pthread_cond_broadcast(&u->async_cv);
    }
}

static void usbdev_mark_disconnected(usbdev_t *u)
{
    pthread_mutex_lock(&u->async_lock);
    usbdev_mark_disconnected_locked(u);
    pthread_mutex_unlock(&u->async_lock);
}

/* The interest refcon packs the slot index with the open's fd-table generation
 * so a callback that outlives IOObjectRelease(u->notif) -- IOKit can have one
 * already dispatched on the event thread -- cannot mark a reused slot: the
 * generation of a later open never matches. The top four generation bits are
 * traded for the index; a collision needs 2^60 opens of one slot.
 */
#define USBDEV_WATCH_GEN_MASK ((UINT64_C(1) << 60) - 1)

static void *usbdev_watch_token(const usbdev_t *u)
{
    uintptr_t idx = (uintptr_t) (u - usbdev_fds);
    uintptr_t gen = (uintptr_t) (u->generation & USBDEV_WATCH_GEN_MASK);
    return (void *) ((gen << 4) | idx);
}

static void usbdev_interest_cb(void *refcon,
                               io_service_t service,
                               natural_t msg,
                               void *arg)
{
    (void) service;
    (void) arg;
    if (msg != kIOMessageServiceIsTerminated)
        return;

    /* Re-validate the token before marking: used/generation are table-lock
     * fields, and holding the table lock here also orders this against a
     * concurrent teardown + slot reuse (table -> async is the documented order,
     * so the nested mark is safe).
     */
    uintptr_t token = (uintptr_t) refcon;
    unsigned idx = (unsigned) (token & 0xF);
    uint64_t gen = (uint64_t) (token >> 4);
    if (idx >= USBDEV_MAX_FDS)
        return;
    usbdev_t *u = &usbdev_fds[idx];
    pthread_mutex_lock(&usbdev_table_lock);
    if (u->used && (u->generation & USBDEV_WATCH_GEN_MASK) == gen)
        usbdev_mark_disconnected(u);
    pthread_mutex_unlock(&usbdev_table_lock);
}

/* Register the terminate-interest notification (entry lock held). Best effort:
 * kIOReturnNoDevice detection on ops is the fallback.
 */
static void usbdev_arm_disconnect_watch(usbdev_t *u)
{
    if (u->notif != IO_OBJECT_NULL || u->service == IO_OBJECT_NULL)
        return;
    IONotificationPortRef port = usbdev_notify_get();
    if (!port)
        return;
    if (IOServiceAddInterestNotification(
            port, u->service, kIOGeneralInterest, usbdev_interest_cb,
            usbdev_watch_token(u), &u->notif) != kIOReturnSuccess)
        u->notif = IO_OBJECT_NULL;
}

/* Create + attach the ep0 async event source (entry lock held). */
static int64_t usbdev_ensure_dev_async(usbdev_t *u)
{
    int64_t rc = usbdev_ensure_dev_plugin(u);
    if (rc < 0)
        return rc;
    usbdev_lazy_device_open(u);
    if (u->dev_src)
        return 0;
    CFRunLoopRef loop = usbdev_loop_get();
    if (!loop)
        return -LINUX_ENOMEM;
    CFRunLoopSourceRef src = NULL;
    IOReturn r = (*u->dev)->CreateDeviceAsyncEventSource(u->dev, &src);
    if (r != kIOReturnSuccess || !src)
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : ioret_neg_errno(r);
    CFRunLoopAddSource(loop, src, kCFRunLoopDefaultMode);
    u->dev_src = src;
    usbdev_arm_disconnect_watch(u);
    return 0;
}

/* Create + attach the interface async event source (entry lock held; fi is
 * claimed).
 */
static int64_t usbdev_ensure_iface_async(usbdev_t *u, usbdev_iface_t *fi)
{
    if (fi->src)
        return 0;
    CFRunLoopRef loop = usbdev_loop_get();
    if (!loop)
        return -LINUX_ENOMEM;
    CFRunLoopSourceRef src = NULL;
    IOReturn r = (*fi->intf)->CreateInterfaceAsyncEventSource(fi->intf, &src);
    if (r != kIOReturnSuccess || !src)
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : ioret_neg_errno(r);
    CFRunLoopAddSource(loop, src, kCFRunLoopDefaultMode);
    fi->src = src;
    usbdev_arm_disconnect_watch(u);
    return 0;
}

/* URB lists (async_lock held) */

static void urb_list_append(usbdev_urb_t **head,
                            usbdev_urb_t **tail,
                            usbdev_urb_t *rec)
{
    rec->next = NULL;
    if (*tail)
        (*tail)->next = rec;
    else
        *head = rec;
    *tail = rec;
}

static void urb_pending_unlink(usbdev_t *u, usbdev_urb_t *rec)
{
    usbdev_urb_t **pp = &u->pending_head, *prev = NULL;
    while (*pp && *pp != rec) {
        prev = *pp;
        pp = &(*pp)->next;
    }
    if (!*pp)
        return;
    *pp = rec->next;
    if (u->pending_tail == rec)
        u->pending_tail = prev;
    rec->next = NULL;
}

static void urb_free_locked(usbdev_t *u, usbdev_urb_t *rec)
{
    u->nurbs--;
    u->inflight_bytes -= rec->data_len;
    free(rec->buf);
    free(rec);
}

/* Move rec to the completed list and signal readiness: one pipe byte per
 * completed URB is the poll()/REAPURB contract (async_lock held).
 */
static void urb_complete_locked(usbdev_t *u, usbdev_urb_t *rec, int32_t status)
{
    rec->status = status;
    rec->state = URB_COMPLETED;
    urb_list_append(&u->completed_head, &u->completed_tail, rec);
    if (u->pipe_wr >= 0) {
        char b = 0;
        (void) !write(u->pipe_wr, &b, 1);
    }
}

/* kIOReturn -> linux URB status (doc D table (b); differs from the sync ioctl
 * map in the Aborted row: DISCARDURB = usb_kill_urb = -ENOENT, any other abort
 * = async unlink = -ECONNRESET).
 */
static int32_t usbdev_urb_status(const usbdev_urb_t *rec, IOReturn r)
{
    switch ((uint32_t) r) {
    case kIOReturnSuccess:
    case kIOReturnUnderrun: /* short transfer == success */
        return 0;
    case kIOReturnAborted:
    case kIOUSBTransactionReturned:
        return rec->discarding ? -LINUX_ENOENT : -LINUX_ECONNRESET;
    case kIOReturnNoDevice:
    case kIOReturnNotOpen:
    case kIOReturnNotAttached:
        return -LINUX_ENODEV;
    default:
        return (int32_t) ioret_neg_errno(r);
    }
}

static void usbdev_async_cb(void *refcon, IOReturn result, void *arg0);

/* Hand rec to IOKit. Called with async_lock held: the async entry points do not
 * block, and their callbacks arrive later on the event thread.
 */
static IOReturn usbdev_urb_start(usbdev_urb_t *rec)
{
    usbdev_t *u = rec->u;
    if (rec->type == LINUX_URB_TYPE_CONTROL) {
        rec->req.pData = rec->buf;
        if (rec->pipe == 0)
            return (*u->dev)->DeviceRequestAsyncTO(u->dev, &rec->req,
                                                   usbdev_async_cb, rec);
        return (*rec->intf)
            ->ControlRequestAsyncTO(rec->intf, rec->pipe, &rec->req,
                                    usbdev_async_cb, rec);
    }

    /* Interrupt pipes reject the *TO entry points (IOUSBLib.h: BadArgument);
     * bulk gets the TO variants with 0 = infinite, matching usbfs URBs that
     * never time out. A BULK URB on an interrupt endpoint lands here with
     * pipe_interrupt set, i.e. Linux's silent bulk->interrupt conversion
     * (devio.c:1718-1721).
     */
    if (rec->pipe_interrupt) {
        if (rec->is_in)
            return (*rec->intf)
                ->ReadPipeAsync(rec->intf, rec->pipe, rec->buf, rec->data_len,
                                usbdev_async_cb, rec);
        return (*rec->intf)
            ->WritePipeAsync(rec->intf, rec->pipe, rec->buf, rec->data_len,
                             usbdev_async_cb, rec);
    }
    if (rec->is_in)
        return (*rec->intf)
            ->ReadPipeAsyncTO(rec->intf, rec->pipe, rec->buf, rec->data_len, 0,
                              0, usbdev_async_cb, rec);
    return (*rec->intf)
        ->WritePipeAsyncTO(rec->intf, rec->pipe, rec->buf, rec->data_len, 0, 0,
                           usbdev_async_cb, rec);
}

/* Restart the FIFO on one endpoint key: submit the oldest QUEUED record if
 * nothing is in flight there; locally fail records IOKit refuses (async_lock
 * held).
 */
static void usbdev_kick_ep_locked(usbdev_t *u, uint8_t key)
{
    for (;;) {
        usbdev_urb_t *next = NULL;
        for (usbdev_urb_t *r = u->pending_head; r; r = r->next) {
            if (r->ep_key != key)
                continue;
            if (r->state == URB_INFLIGHT)
                return; /* endpoint busy */
            next = r;
            break;
        }
        if (!next)
            return;
        IOReturn ir = usbdev_urb_start(next);
        if (ir == kIOReturnSuccess) {
            next->state = URB_INFLIGHT;
            u->inflight++;
            return;
        }
        int32_t st = (int32_t) ioret_neg_errno(ir);
        urb_pending_unlink(u, next);
        urb_complete_locked(u, next, st ? st : -LINUX_EPROTO);
    }
}

/* IOKit completion (event thread). arg0 carries the transferred byte count for
 * pipe reads/writes and wLenDone for device requests.
 */
static void usbdev_async_cb(void *refcon, IOReturn result, void *arg0)
{
    usbdev_urb_t *rec = refcon;
    usbdev_t *u = rec->u;
    pthread_mutex_lock(&u->async_lock);

    /* A drain timeout already unlinked this record and settled the slot's
     * nurbs/inflight/inflight_bytes; the slot may since have been reused by a
     * new open. Free only what the record owns -- no counters, no disconnect
     * map, no pipe byte. Checked under async_lock, and everything below stays
     * under this one hold so the orphan mark cannot land mid-processing.
     */
    if (rec->orphaned) {
        free(rec->buf);
        free(rec);
        pthread_mutex_unlock(&u->async_lock);
        return;
    }
    if ((uint32_t) result == (uint32_t) kIOReturnNoDevice ||
        (uint32_t) result == (uint32_t) kIOReturnNotAttached)
        usbdev_mark_disconnected_locked(u);
    rec->actual = (uint32_t) (uintptr_t) arg0;
    int32_t st = usbdev_urb_status(rec, result);
    if (st == 0 && rec->short_not_ok && rec->actual < rec->data_len)
        st = -LINUX_EREMOTEIO; /* URB_SHORT_NOT_OK, devio.c error-codes */
    /* ZLP: a maxpacket-multiple OUT gets its terminating zero-length packet as
     * a separate synchronous WritePipe from the callback
     * (darwin_usb.c:3193-3204). Blocks the event thread for one packet time,
     * same as libusb.
     */
    if (st == 0 && rec->zero_packet && rec->intf && rec->pipe > 0 &&
        rec->data_len > 0 && rec->mps != 0 && rec->data_len % rec->mps == 0)
        (void) (*rec->intf)->WritePipe(rec->intf, rec->pipe, rec->buf, 0);
    urb_pending_unlink(u, rec);
    u->inflight--;
    uint8_t key = rec->ep_key;
    urb_complete_locked(u, rec, st);
    usbdev_kick_ep_locked(u, key);
    pthread_cond_broadcast(&u->async_cv);
    pthread_mutex_unlock(&u->async_lock);
}

/* Abort and drain every URB whose interface matches intf (NULL = all, including
 * ep0). QUEUED records complete as killed (-ENOENT, usb_kill_urb) and stay
 * reapable; INFLIGHT ones are aborted and drained through the callback.
 *
 * Returns false when the drain timed out: survivors were orphaned (the late
 * callback frees them) and the caller must NOT release the IOKit handles they
 * still reference. Entry lock held.
 */
static bool usbdev_kill_urbs_locked(usbdev_t *u,
                                    IOUSBInterfaceInterface800 **intf)
{
    pthread_mutex_lock(&u->async_lock);
    usbdev_urb_t *r = u->pending_head;
    bool any_inflight = false;
    while (r) {
        usbdev_urb_t *nx = r->next;
        bool match = intf == NULL || r->intf == intf;
        if (match && r->state == URB_QUEUED) {
            urb_pending_unlink(u, r);
            urb_complete_locked(u, r, -LINUX_ENOENT);
        } else if (match && r->state == URB_INFLIGHT) {
            r->discarding = true;
            any_inflight = true;
        }
        r = nx;
    }
    pthread_mutex_unlock(&u->async_lock);

    if (any_inflight) {
        if (intf == NULL && u->dev && u->dev_src)
            (void) (*u->dev)->USBDeviceAbortPipeZero(u->dev);
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed || (intf != NULL && fi->intf != intf))
                continue;
            for (int p = 1; p <= fi->npipes; p++)
                (void) (*fi->intf)->AbortPipe(fi->intf, (UInt8) p);
        }
    }

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    pthread_mutex_lock(&u->async_lock);
    for (;;) {
        bool busy = false;
        for (r = u->pending_head; r; r = r->next) {
            if ((intf == NULL || r->intf == intf) && r->state == URB_INFLIGHT) {
                busy = true;
                break;
            }
        }
        if (!busy)
            break;
        if (pthread_cond_timedwait(&u->async_cv, &u->async_lock, &deadline) ==
            ETIMEDOUT) {
            /* Settle each survivor's slot accounting now and unlink it, so a
             * reused slot's counters are never touched by the late callback
             * (which sees orphaned and frees only the record), and so a later
             * kill/teardown scan cannot re-find it and wait another 2s.
             */
            int n = 0;
            r = u->pending_head;
            while (r) {
                usbdev_urb_t *nx2 = r->next;
                if ((intf == NULL || r->intf == intf) &&
                    r->state == URB_INFLIGHT) {
                    urb_pending_unlink(u, r);
                    u->inflight--;
                    u->nurbs--;
                    u->inflight_bytes -= r->data_len;
                    r->orphaned = true;
                    n++;
                }
                r = nx2;
            }
            log_warn("usbdev: %d in-flight URB(s) did not drain; orphaned", n);
            pthread_mutex_unlock(&u->async_lock);
            return false;
        }
    }
    pthread_mutex_unlock(&u->async_lock);
    return true;
}

/* Free every reapable completion (fd close: Linux frees unreaped completed URBs
 * too). Entry lock held.
 */
static void usbdev_free_completed(usbdev_t *u)
{
    pthread_mutex_lock(&u->async_lock);
    while (u->completed_head) {
        usbdev_urb_t *rec = u->completed_head;
        u->completed_head = rec->next;
        if (!u->completed_head)
            u->completed_tail = NULL;
        urb_free_locked(u, rec);
    }
    pthread_mutex_unlock(&u->async_lock);
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

    /* releaseintf kills the interface's URBs (devio.c:2304-2316); they stay
     * reapable with -ENOENT.
     */
    bool drained = usbdev_kill_urbs_locked(u, fi->intf);
    if (fi->src) {
        CFRunLoopRef loop = usbdev_loop_current();
        if (loop && drained)
            CFRunLoopRemoveSource(loop, fi->src, kCFRunLoopDefaultMode);
        if (drained)
            CFRelease(fi->src);
        fi->src = NULL;
    }
    if (drained) {
        (*fi->intf)->USBInterfaceClose(fi->intf);
        (*fi->intf)->Release(fi->intf);
    } else {
        /* Orphaned in-flight URBs still reference the handle and its event
         * source; leak both rather than hand the late callback a freed plugin.
         */
        log_warn("usbdev: leaking interface %u handle (undrained URBs)", ifnum);
    }
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
    /* Async teardown first: kill/drain every URB (release close: Linux kills
     * pending and frees completed, devio.c:1092-1128), then the notification
     * and the ep0 event source, so no callback can arrive for this slot after
     * the handles go away.
     */
    bool drained = usbdev_kill_urbs_locked(u, NULL);
    usbdev_free_completed(u);
    if (u->notif != IO_OBJECT_NULL) {
        IOObjectRelease(u->notif);
        u->notif = IO_OBJECT_NULL;
    }
    if (u->dev_src) {
        CFRunLoopRef loop = usbdev_loop_current();
        if (loop && drained)
            CFRunLoopRemoveSource(loop, u->dev_src, kCFRunLoopDefaultMode);
        if (drained)
            CFRelease(u->dev_src);
        u->dev_src = NULL;
    }
    for (int i = 0; i < USBDEV_MAX_IFACES; i++)
        if (u->ifaces[i].claimed)
            (void) usbdev_release_locked(u, (unsigned) i);
    if (u->dev) {
        if (drained) {
            if (u->dev_open)
                (*u->dev)->USBDeviceClose(u->dev);
            (*u->dev)->Release(u->dev);
        } else {
            log_warn("usbdev: leaking device handle (undrained URBs)");
        }
        u->dev = NULL;
    }
    u->dev_open = false;
    u->dev_open_tried = false;
    if (u->service != IO_OBJECT_NULL) {
        IOObjectRelease(u->service);
        u->service = IO_OBJECT_NULL;
    }

    /* Orphaned callbacks skip the pipe write, so closing it here is safe even
     * on the timeout path; -1 under async_lock keeps the callback's check and
     * this close ordered.
     */
    pthread_mutex_lock(&u->async_lock);
    int pw = u->pipe_wr;
    u->pipe_wr = -1;
    u->disconnected = false;
    pthread_mutex_unlock(&u->async_lock);
    if (pw >= 0)
        close(pw);
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
    if (RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        atomic_store(&usbdev_disc_map[guest_fd], 0);
}

void usbdev_init(void)
{
    pthread_mutex_lock(&usbdev_table_lock);
    if (!usbdev_ready) {
        for (int i = 0; i < USBDEV_MAX_FDS; i++) {
            memset(&usbdev_fds[i], 0, sizeof(usbdev_fds[i]));
            usbdev_fds[i].guest_fd = -1;
            usbdev_fds[i].pipe_wr = -1;
            usbdev_fds[i].notif = IO_OBJECT_NULL;
            pthread_mutex_init(&usbdev_fds[i].lock, NULL);
            pthread_mutex_init(&usbdev_fds[i].async_lock, NULL);
            pthread_cond_init(&usbdev_fds[i].async_cv, NULL);
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
    u->dev_src = NULL;
    u->notif = IO_OBJECT_NULL;
    memset(u->ifaces, 0, sizeof(u->ifaces));
    atomic_store(&u->claimed_mask, 0);
    /* Nonzero while bound; equal for every fd open on the same device node. */
    atomic_store(&u->devkey, (1ull << 63) | ((uint64_t) (uint32_t) bus << 32) |
                                 (uint32_t) dev);
    u->pending_head = u->pending_tail = NULL;
    u->completed_head = u->completed_tail = NULL;
    u->inflight = 0;
    u->nurbs = 0;
    u->inflight_bytes = 0;
    u->disconnected = false;
    u->discsig_signr = 0;
    u->discsig_context = 0;
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
    if (RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        atomic_store(&usbdev_disc_map[guest_fd], 0);
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
    /* usbdev_read serves nothing once the device is gone (-ENODEV,
     * devio.c:325-328); lseek keeps working, as its llseek has no gate.
     */
    if (usbdev_fd_disconnected(fd))
        return -LINUX_ENODEV;
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
    /* Same -ENODEV gate as usbdev_read: no read path serves a gone device. */
    if (usbdev_fd_disconnected(fd))
        return -LINUX_ENODEV;
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

    /* proc_setintf kills the interface's URBs before switching altsettings
     * (devio.c:1529-1544); in-flight pipeRefs die with the old pipe table.
     */
    (void) usbdev_kill_urbs_locked(u, fi->intf);
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

/* async URB ioctls */

/* SUBMITURB (proc_do_submiturb, doc A §A3). Entry lock held. */
static int64_t usbdev_do_submiturb(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_urb_t uu;
    if (guest_read_small(g, arg, &uu, sizeof(uu)) < 0)
        return -LINUX_EFAULT;
    if (uu.buffer_length < 0)
        return -LINUX_EINVAL;

    /* A NULL buffer with a positive length is malformed before any guest memory
     * is touched (devio.c:1649-1650), not an -EFAULT from reading guest address
     * 0.
     */
    if (uu.buffer == 0 && uu.buffer_length > 0)
        return -LINUX_EINVAL;

    switch (uu.type) {
    case LINUX_URB_TYPE_CONTROL:
    case LINUX_URB_TYPE_BULK:
    case LINUX_URB_TYPE_INTERRUPT:
        if (uu.flags & ~LINUX_URB_FLAGS_ALLOWED)
            return -LINUX_EINVAL; /* devio.c:1635-1645 */
        break;
    case LINUX_URB_TYPE_ISO:
        log_warn("usbdev: ISO URBs unsupported (doc A §A7.4)");
        return -LINUX_EINVAL;
    default:
        return -LINUX_EINVAL;
    }
    if (uu.signr)
        log_debug("usbdev: URB completion signal %u ignored", uu.signr);

    bool is_in;
    uint32_t data_len;
    uint64_t data_gva;
    usbdev_iface_t *fi = NULL;
    uint8_t pipe = 0;
    bool pipe_interrupt = false;
    uint16_t mps = 0;
    IOUSBDevRequestTO req;
    memset(&req, 0, sizeof(req));

    if (uu.type == LINUX_URB_TYPE_CONTROL) {
        /* Buffer = 8-byte setup + wLength data (devio.c:1671-1683). */
        uint8_t setup[8];
        if (uu.buffer_length < 8)
            return -LINUX_EINVAL;
        if (guest_read_small(g, uu.buffer, setup, sizeof(setup)) < 0)
            return -LINUX_EFAULT;
        uint16_t wLength = (uint16_t) (setup[6] | (setup[7] << 8));
        if ((uint32_t) uu.buffer_length - 8 < wLength)
            return -LINUX_EINVAL;

        /* check_ctrlrecip: vendor requests bypass; IF/EP recipients claim the
         * owning interface implicitly (devio.c:881-938).
         */
        if ((setup[0] & 0x60) != 0x40) {
            unsigned recip = setup[0] & 0x1f;
            uint16_t wIndex = (uint16_t) (setup[4] | (setup[5] << 8));
            if (recip == 1) {
                int64_t rc = usbdev_claim_locked(u, wIndex & 0xff);
                if (rc < 0)
                    return rc;
            } else if (recip == 2) {
                int64_t rc = usbdev_check_ep_recip(u, wIndex);
                if (rc < 0)
                    return rc;
            }
        }
        is_in = (setup[0] & 0x80) != 0;
        data_len = wLength;
        data_gva = uu.buffer + 8;
        req.bmRequestType = setup[0];
        req.bRequest = setup[1];
        req.wValue = (UInt16) (setup[2] | (setup[3] << 8));
        req.wIndex = (UInt16) (setup[4] | (setup[5] << 8));
        req.wLength = wLength;
        req.noDataTimeout = 0; /* usbfs URBs never time out */
        req.completionTimeout = 0;
        if ((uu.endpoint & 0x7f) != 0) {
            int64_t rc = usbdev_pipe_for_ep(u, uu.endpoint, &fi, &pipe);
            if (rc < 0)
                return rc;
            if (fi->pipe_type[pipe - 1] != kUSBControl)
                return -LINUX_EINVAL;
            rc = usbdev_ensure_iface_async(u, fi);
            if (rc < 0)
                return rc;
        } else {
            int64_t rc = usbdev_ensure_dev_async(u);
            if (rc < 0)
                return rc;
        }
    } else {
        is_in = (uu.endpoint & 0x80) != 0;
        int64_t rc = usbdev_pipe_for_ep(u, uu.endpoint, &fi, &pipe);
        if (rc < 0)
            return rc;
        uint8_t ptype = fi->pipe_type[pipe - 1];
        if (uu.type == LINUX_URB_TYPE_BULK) {
            if (ptype != kUSBBulk && ptype != kUSBInterrupt)
                return -LINUX_EINVAL; /* control/iso ep (devio.c:1718) */
        } else {
            if (ptype != kUSBInterrupt)
                return -LINUX_EINVAL;
        }
        pipe_interrupt = ptype == kUSBInterrupt;
        rc = usbdev_ensure_iface_async(u, fi);
        if (rc < 0)
            return rc;
        data_len = (uint32_t) uu.buffer_length;
        data_gva = uu.buffer;
        mps = fi->pipe_mps[pipe - 1];
    }

    /* Caps: 16 MB of in-flight buffer (usbfs_memory_mb, devio.c:134) and a
     * record-count backstop.
     */
    pthread_mutex_lock(&u->async_lock);
    if (u->nurbs >= USBDEV_MAX_URBS ||
        u->inflight_bytes + data_len > USBDEV_BULK_MAX) {
        pthread_mutex_unlock(&u->async_lock);
        return -LINUX_ENOMEM;
    }
    u->nurbs++;
    u->inflight_bytes += data_len;
    pthread_mutex_unlock(&u->async_lock);

    usbdev_urb_t *rec = calloc(1, sizeof(*rec));
    uint8_t *buf = NULL;
    if (rec && data_len > 0)
        buf = malloc(data_len);
    if (!rec || (data_len > 0 && !buf)) {
        free(buf);
        free(rec);
        pthread_mutex_lock(&u->async_lock);
        u->nurbs--;
        u->inflight_bytes -= data_len;
        pthread_mutex_unlock(&u->async_lock);
        return -LINUX_ENOMEM;
    }
    if (!is_in && data_len > 0 && guest_read(g, data_gva, buf, data_len) < 0) {
        free(buf);
        free(rec);
        pthread_mutex_lock(&u->async_lock);
        u->nurbs--;
        u->inflight_bytes -= data_len;
        pthread_mutex_unlock(&u->async_lock);
        return -LINUX_EFAULT;
    }

    rec->u = u;
    rec->userurb = arg;
    rec->data_gva = data_gva;
    rec->type = uu.type;
    rec->ep = uu.endpoint;
    /* Both ep0 directions share the default control pipe: one FIFO key. */
    rec->ep_key =
        (uu.type == LINUX_URB_TYPE_CONTROL && (uu.endpoint & 0x7f) == 0)
            ? 0
            : uu.endpoint;
    rec->pipe = pipe;
    rec->intf = fi ? fi->intf : NULL;
    rec->is_in = is_in;

    /* Direction-mismatched flags are ignored, not rejected (devio.c honours
     * SHORT_NOT_OK for IN and ZERO_PACKET for OUT only, 1710-1737).
     */
    rec->short_not_ok = is_in && (uu.flags & LINUX_URB_SHORT_NOT_OK) != 0;
    rec->zero_packet = !is_in && (uu.flags & LINUX_URB_ZERO_PACKET) != 0;
    rec->pipe_interrupt = pipe_interrupt;
    rec->state = URB_QUEUED;
    rec->data_len = data_len;
    rec->mps = mps;
    rec->buf = buf;
    rec->req = req;

    pthread_mutex_lock(&u->async_lock);
    bool busy = false;
    for (usbdev_urb_t *r = u->pending_head; r; r = r->next) {
        if (r->ep_key == rec->ep_key) {
            busy = true;
            break;
        }
    }
    urb_list_append(&u->pending_head, &u->pending_tail, rec);
    if (!busy) {
        /* Endpoint idle: hand it to IOKit now. Queued follow-ups start from the
         * completion callback (one in-flight URB per endpoint keeps DISCARDURB
         * per-URB, see file header).
         */
        IOReturn ir = usbdev_urb_start(rec);
        if (ir != kIOReturnSuccess) {
            urb_pending_unlink(u, rec);
            urb_free_locked(u, rec);
            pthread_mutex_unlock(&u->async_lock);
            if ((uint32_t) ir == (uint32_t) kIOReturnNoDevice ||
                (uint32_t) ir == (uint32_t) kIOReturnNotAttached)
                usbdev_mark_disconnected(u);
            int64_t e = ioret_neg_errno(ir);
            return e < 0 ? e : -LINUX_EPROTO;
        }
        rec->state = URB_INFLIGHT;
        u->inflight++;
    }
    pthread_mutex_unlock(&u->async_lock);
    return 0;
}

/* DISCARDURB (proc_unlinkurb): arg is the user URB pointer. Entry lock held. A
 * QUEUED record completes locally as killed (-ENOENT); an INFLIGHT one is
 * flagged and aborted -- with one in-flight URB per endpoint the AbortPipe
 * cannot cancel bystanders. Linux's usb_kill_urb is synchronous; here the
 * -ENOENT completion arrives via the callback, which REAPURB then observes
 * (deviation noted in the file header).
 */
static int64_t usbdev_do_discardurb(usbdev_t *u, uint64_t arg)
{
    pthread_mutex_lock(&u->async_lock);
    usbdev_urb_t *rec = u->pending_head;
    while (rec && (rec->userurb != arg || rec->discarding))
        rec = rec->next;
    if (!rec) {
        pthread_mutex_unlock(&u->async_lock);
        return -LINUX_EINVAL; /* not pending (completed counts as gone) */
    }
    if (rec->state == URB_QUEUED) {
        urb_pending_unlink(u, rec);
        urb_complete_locked(u, rec, -LINUX_ENOENT);
        pthread_mutex_unlock(&u->async_lock);
        return 0;
    }
    rec->discarding = true;
    uint8_t pipe = rec->pipe;
    IOUSBInterfaceInterface800 **intf = rec->intf;
    pthread_mutex_unlock(&u->async_lock);

    /* The interface handle cannot be released concurrently: release paths need
     * the entry lock this thread holds.
     */
    if (pipe == 0)
        (void) (*u->dev)->USBDeviceAbortPipeZero(u->dev);
    else
        (void) (*intf)->AbortPipe(intf, pipe);
    return 0;
}

/* Copy one completion back to the guest (vCPU thread): IN data into the urb's
 * buffer, then status/actual_length/error_count into the guest urb, then the
 * userurb pointer into *arg (processcompl, devio.c:2042-2078).
 */
static int64_t usbdev_reap_copyout(guest_t *g, usbdev_urb_t *rec, uint64_t arg)
{
    if (rec->is_in && rec->actual > 0 &&
        guest_write(g, rec->data_gva, rec->buf,
                    rec->actual < rec->data_len ? rec->actual : rec->data_len) <
            0)
        return -LINUX_EFAULT;
    int32_t st = rec->status;
    int32_t act = (int32_t) rec->actual;
    int32_t ec = 0;
    if (guest_write_small(g,
                          rec->userurb + offsetof(linux_usbdevfs_urb_t, status),
                          &st, sizeof(st)) < 0 ||
        guest_write_small(
            g, rec->userurb + offsetof(linux_usbdevfs_urb_t, actual_length),
            &act, sizeof(act)) < 0 ||
        guest_write_small(
            g, rec->userurb + offsetof(linux_usbdevfs_urb_t, error_count), &ec,
            sizeof(ec)) < 0)
        return -LINUX_EFAULT;
    if (guest_write_small(g, arg, &rec->userurb, sizeof(rec->userurb)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* REAPURB / REAPURBNDELAY. Called WITHOUT the entry lock held so a blocked reap
 * never stalls submits or discards; each pass revalidates the fd. Blocking
 * follows reap_as (devio.c:2080-2118): wake on completion or disconnect, -EINTR
 * without restart on a signal, -ENODEV once disconnected and drained
 * (REAP_AFTER_DISCONNECT).
 */
static int64_t usbdev_do_reap(guest_t *g, int fd, uint64_t arg, bool block)
{
    for (;;) {
        fd_entry_t snap;
        if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
            return -LINUX_EBADF;
        usbdev_t *u = usbdev_acquire(fd);
        if (!u)
            return -LINUX_EBADF;
        pthread_mutex_lock(&u->async_lock);
        usbdev_urb_t *rec = u->completed_head;
        if (rec) {
            u->completed_head = rec->next;
            if (!u->completed_head)
                u->completed_tail = NULL;
        }
        bool disc = u->disconnected;
        pthread_mutex_unlock(&u->async_lock);
        if (rec) {
            /* Drain this completion's readiness byte and copy out while the
             * entry lock still pins the pipe's host fd open (cleanup waits on
             * it).
             */
            char b;
            (void) !read(snap.host_fd, &b, 1);
            int64_t ret = usbdev_reap_copyout(g, rec, arg);
            pthread_mutex_lock(&u->async_lock);
            urb_free_locked(u, rec);
            pthread_mutex_unlock(&u->async_lock);
            pthread_mutex_unlock(&u->lock);
            return ret;
        }
        pthread_mutex_unlock(&u->lock);
        if (disc)
            return -LINUX_ENODEV;
        if (!block)
            return -LINUX_EAGAIN;
        int64_t rc = io_wait_fd_or_interrupted(snap.host_fd, POLLIN);
        if (rc < 0) {
            /* reap_as returns -EINTR with no restart (devio.c:2115). */
            syscall_restart_forbid();
            return rc;
        }
    }
}

/* poll/select/epoll remap helpers (see poll.c call sites) */

bool usbdev_fd_disconnected(int guest_fd)
{
    return RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE) &&
           atomic_load(&usbdev_disc_map[guest_fd]) != 0;
}

bool usbdev_poll_host_events(int guest_fd,
                             short guest_events,
                             short *host_events)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap) || snap.type != FD_USBDEV)
        return false;

    /* The host interest is always POLLIN on the completion pipe: the fd never
     * carries guest-readable bytes, and a disconnect mid-wait wakes the parked
     * poll through the pipe byte usbdev_mark_disconnected writes even when the
     * guest asked for nothing the pipe can signal (POLLERR|POLLHUP are
     * unmaskable, devio.c:2842-2845). usbdev_poll_guest_revents filters what
     * the guest actually sees, and the callers re-block when a wake maps to
     * nothing guest-visible.
     */
    (void) guest_events;
    *host_events = POLLIN;
    return true;
}

short usbdev_poll_guest_revents(int guest_fd,
                                short guest_events,
                                short host_revents)
{
    fd_entry_t snap;
    bool writable = fd_snapshot(guest_fd, &snap) && snap.type == FD_USBDEV &&
                    (snap.linux_flags & LINUX_O_ACCMODE) != LINUX_O_RDONLY;
    short out = 0;
    if (usbdev_fd_disconnected(guest_fd))
        out |= LINUX_POLLERR | LINUX_POLLHUP; /* devio.c:2842-2845 */
    if (writable && (host_revents & POLLIN))
        out |= LINUX_POLLOUT | LINUX_POLLWRNORM; /* completions reapable */
    /* do_pollfd masks by demanded events plus the unmaskable bits. */
    return (short) (out & (guest_events | LINUX_POLLERR | LINUX_POLLHUP |
                           LINUX_POLLNVAL));
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

    /* The reaps manage their own locking: a blocked REAPURB must not hold the
     * entry lock against concurrent SUBMITURB/DISCARDURB, and they stay usable
     * after disconnect (devio.c:2612-2635).
     */
    if ((uint32_t) request == USBDEVFS_REAPURB ||
        (uint32_t) request == USBDEVFS_REAPURBNDELAY)
        return usbdev_do_reap(g, fd, arg,
                              (uint32_t) request == USBDEVFS_REAPURB);

    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;

    /* usbdev_ioctl's connected() gate: everything except the reaps above is
     * -ENODEV once the device is gone.
     */
    bool disc;
    pthread_mutex_lock(&u->async_lock);
    disc = u->disconnected;
    pthread_mutex_unlock(&u->async_lock);
    if (disc) {
        pthread_mutex_unlock(&u->lock);
        return -LINUX_ENODEV;
    }

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
        ret = usbdev_do_submiturb(u, g, arg);
        break;
    case USBDEVFS_DISCARDURB:
        ret = usbdev_do_discardurb(u, arg);
        break;
    case USBDEVFS_DISCSIGNAL: {
        /* Stored for fidelity but never delivered (file header): elfuse has no
         * async guest-signal injection from the event thread.
         */
        linux_usbdevfs_disconnectsignal_t ds;
        if (guest_read_small(g, arg, &ds, sizeof(ds)) < 0) {
            ret = -LINUX_EFAULT;
        } else {
            u->discsig_signr = ds.signr;
            u->discsig_context = ds.context;
            if (ds.signr)
                log_warn(
                    "usbdev: DISCSIGNAL %u accepted but will not be "
                    "delivered",
                    ds.signr);
            ret = 0;
        }
        break;
    }
    default:
        ret = -LINUX_ENOTTY;
        break;
    }
    pthread_mutex_unlock(&u->lock);
    return ret;
}
