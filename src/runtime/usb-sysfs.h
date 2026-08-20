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
int usb_sysfs_intercept_stat(const char *path, struct stat *st);
int usb_sysfs_intercept_readlink(const char *path, char *buf, size_t bufsiz);

/* Malloc'd copy of the usbfs descriptors blob (18-byte little-endian device
 * descriptor followed by every raw configuration descriptor in index order)
 * for the device at busnum/devnum. This is the exact byte sequence read()
 * returns on the /dev/bus/usb node and on the sysfs `descriptors` attribute;
 * stage 2's usbdevfs fd constructor must serve reads from this generator so
 * the two views stay byte-identical.
 *
 * Returns the blob (caller frees) with *len_out set, or NULL with errno set
 * (ENODEV when no such device).
 */
uint8_t *usb_sysfs_descriptors_dup(int busnum, int devnum, size_t *len_out);

/* Drop the cached device model and scratch trees; the next intercept rebuilds
 * from a fresh IOKit enumeration. Hook point for hotplug (uevent) later.
 */
void usb_sysfs_refresh(void);
