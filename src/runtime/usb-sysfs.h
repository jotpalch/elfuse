/*
 * Synthetic /dev/bus/usb + /sys/bus/usb built from the IOKit registry
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stage 1 of the usbdevfs emulation: enumeration only. The IOKit registry is
 * read without opening any device (GetConfigurationDescriptorPtr needs no
 * open), and the result is materialized as two scratch-dir trees that the
 * procemu interceptors expose as /sys/bus/usb and /dev/bus/usb.
 *
 * The intercept functions follow the procemu contract:
 *   open:      host fd on match, -1 with errno on error,
 *              PROC_NOT_INTERCEPTED (-2) when the path is not ours.
 *   stat:      0 on match (st filled), -1 with errno, -2 not ours.
 *   readlink:  link length on match, -1 with errno, -2 not ours.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

struct guest;

int usb_sysfs_intercept_open(const char *path, int linux_flags, int mode);

/* `follow` selects stat() vs lstat() semantics for a symlink leaf: with it set,
 * a `subsystem` link reports the directory it resolves to, as on Linux; without
 * it the link itself is reported.
 */
int usb_sysfs_intercept_stat(const char *path, struct stat *st, bool follow);
int usb_sysfs_intercept_readlink(const char *path, char *buf, size_t bufsiz);

/* Malloc'd copy of the usbfs descriptors blob (18-byte little-endian device
 * descriptor followed by every raw configuration descriptor in index order) for
 * the device at busnum/devnum. This is the exact byte sequence read() returns
 * on the /dev/bus/usb node and on the sysfs `descriptors` attribute; stage 2's
 * usbdevfs fd constructor must serve reads from this generator so the two views
 * stay byte-identical.
 *
 * Returns the blob (caller frees) with *len_out set, or NULL with errno set
 * (ENODEV when no such device).
 */
uint8_t *usb_sysfs_descriptors_dup(int busnum, int devnum, size_t *len_out);

/* The guest /sys spelling of the object an open descriptor holds, for stamping
 * a synthetic identity on it.
 *
 * The name the guest opened is not always the name it got: a `subsystem` link
 * opened for following names the directory it resolves to, and every relative
 * openat off that descriptor must walk from there. Asking the descriptor
 * instead of the request is what makes the two agree -- F_GETPATH reports the
 * link's own path for the O_PATH|O_NOFOLLOW open that deliberately named the
 * link, and the target's path for every open that followed it.
 *
 * Returns 1 with `out` filled, or 0 when the descriptor is not in the sysfs
 * tree (including when the tree does not exist).
 */
int usb_sysfs_guest_path_for_fd(int host_fd, char *out, size_t outsz);
