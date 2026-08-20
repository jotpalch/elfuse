/*
 * usbdevfs (/dev/bus/usb/BBB/DDD) fd emulation over IOKit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stages 2+3 of the usbdevfs emulation: a real FD_USBDEV fd type whose
 * synchronous ioctls (CLAIMINTERFACE, CONTROL, BULK, ...) and async URBs
 * (SUBMITURB/DISCARDURB/REAPURB*) are served by
 * IOUSBDeviceInterface/IOUSBInterfaceInterface plugins plus one CFRunLoop
 * completion thread.
 */

#pragma once

#include <stdbool.h>

#include <stdint.h>
#include <sys/stat.h>

#include "core/guest.h"

/* Register the FD_USBDEV cleanup hook. Called once from syscall_init(). */
void usbdev_init(void);

/* Constructor: open("/dev/bus/usb/BBB/DDD") for any access mode except
 * O_PATH. Returns the guest fd, -LINUX_* on error, or INT64_MIN when the path
 * is not a usbdev node (caller falls through to the generic intercepts; the
 * O_PATH case falls through on purpose so the stage-1 placeholder keeps
 * serving path-only fds).
 */
int64_t usbdev_open_path(const char *path, int linux_flags);

/* read() on an FD_USBDEV fd: the usbfs descriptors blob at the fd's file
 * position (device descriptor then raw config descriptors, devio.c:311-390).
 */
int64_t usbdev_read(int fd, guest_t *g, uint64_t buf_gva, uint64_t count);

/* lseek() arm: SEEK_SET/SEEK_CUR against the blob position, SEEK_END is
 * -EINVAL (no_seek_end_llseek). Returns INT64_MIN when fd is not FD_USBDEV.
 */
int64_t usbdev_lseek_fd(int fd, int64_t offset, int whence);

/* fstat(): char device 189:minor, matching the path-stat intercept. */
int64_t usbdev_fstat(int fd, struct stat *st);

/* The USBDEVFS_* ioctl set. Returns -LINUX_* or the (possibly positive)
 * ioctl result.
 */
int64_t usbdev_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg);

/* poll/select/epoll remap: the usbfs fd signals guest POLLOUT|POLLWRNORM
 * ("completed URBs reapable", devio.c:2832-2846) while its backing pipe's
 * read end raises host POLLIN, and disconnect must surface as
 * POLLERR|POLLHUP. usbdev_poll_host_events returns false when guest_fd is
 * not FD_USBDEV; otherwise it yields the host-side events to poll the pipe
 * with, and usbdev_poll_guest_revents converts the host result back into
 * Linux poll bits (already masked by the demanded events).
 */
bool usbdev_poll_host_events(int guest_fd,
                             short guest_events,
                             short *host_events);
short usbdev_poll_guest_revents(int guest_fd,
                                short guest_events,
                                short host_revents);

/* Lock-free "device gone" test for the epoll merge path. */
bool usbdev_fd_disconnected(int guest_fd);
