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

/* True when @guest_path names a directory this layer serves but does not own,
 * so its listing has to be the union of the synthetic entries and whatever the
 * host/sysroot backing carries under the same name.
 *
 * /sys and /dev/bus exist on both sides: a Linux sysroot has class/, devices/,
 * kernel/ under /sys and other buses under /dev/bus, while this layer adds only
 * bus/usb and usb. Serving the synthetic directory alone made getdents64
 * replace that listing rather than extend it, so `ls /sys` saw an almost-empty
 * sysfs while every hidden name stayed openable by its exact path --
 * enumeration and direct access disagreed.
 *
 * False for the one subtree this layer does own, /sys/bus/usb and /dev/bus/usb:
 * there an absence is authoritative (lookup answers ENOENT rather than falling
 * through), so the listing has to be authoritative too.
 */
bool usb_sysfs_dir_unions_backing(const char *guest_path);

/* Rewrite @guest_path into the canonical guest spelling of the object it names,
 * when its walk passes *through* one of the synthetic `subsystem` symlinks this
 * layer plants and continues past it.
 *
 * Those links are the only way a /sys walk can leave this layer's subtree
 * without saying so lexically: `<dev>/subsystem` points at /sys/bus/usb, so
 * `<dev>/subsystem/../pci` names /sys/bus/pci, exactly as the kernel resolves
 * it. Deciding ownership on the lexical fold instead reads that name as
 * `<dev>/pci`, claims it as ours because it starts with bus/usb, and answers
 * ENOENT -- shadowing a populated backing /sys/bus/pci that the *listing* of
 * `<dev>/subsystem/..` had just offered. Resolving first, once, in the path
 * layer, is what keeps the listing and every lookup answering from the same
 * name.
 *
 * A link named as the final component is left alone: it is the object the
 * caller asked for, and lstat, readlink and O_NOFOLLOW must keep seeing it.
 *
 * Returns 1 with @out filled, or 0 when no rewrite applies (including when the
 * link named does not exist, so a missing device stays ENOENT).
 */
int usb_sysfs_resolve_guest_path(const char *guest_path,
                                 char *out,
                                 size_t outsz);

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

/* Identity snapshot of one enumerated device, for the stage-2 usbdevfs fd
 * (syscall/usbdev.c): location_id keys the IOKit service lookup, speed_code is
 * the raw registry 'Device Speed' code, cfg_value the active
 * bConfigurationValue, minor the usbfs char-dev minor. vid/pid/serial carry the
 * modeled identity so the fd constructor can verify the service it looked up by
 * location is still the device this bus/dev number was modeled from (locationID
 * names the port, not the device).
 */
typedef struct {
    uint32_t location_id;
    unsigned speed_code;
    unsigned cfg_value;
    int minor;
    size_t blob_len;
    unsigned vid, pid;
    char serial[128]; /* "" when the device reports none */
} usb_sysfs_devinfo_t;

/* Fill *out for the device at busnum/devnum.
 *
 * Returns 0, or -1 with errno set (ENODEV when no such device).
 */
int usb_sysfs_device_info(int busnum, int devnum, usb_sysfs_devinfo_t *out);

/* Synthesize the char-dev stat for /dev/bus/usb/BBB/DDD (same bytes the path
 * stat intercept reports).
 *
 * Returns 0, or -1 with errno set.
 */
int usb_sysfs_node_stat(int busnum, int devnum, struct stat *st);

/* True when path is a canonical Linux serial alias name this layer owns:
 * exactly "/dev/ttyACM<n>", "/dev/ttyUSB<n>" or "/dev/serial/by-id/<leaf>".
 * Pure string check (no lock, no device lookup): sys_fstat uses it to route an
 * alias fd's stat through proc_intercept_stat instead of leaking the macOS cu.*
 * identity of the host fd behind it, and the stamp it reads is canonical by
 * construction. A caller holding the guest's own spelling wants
 * usb_tty_alias_canon below instead.
 */
bool usb_tty_alias_path(const char *path);

/* Whether @path, in any spelling this layer folds, names a serial alias node or
 * a by-id leaf; @out receives the one canonical spelling of it. Callers that
 * see the guest's raw spelling use this rather than usb_tty_alias_path, which
 * reads the canonical form only.
 */
bool usb_tty_alias_canon(const char *path, char *out, size_t outsz);

/* Whether @path, in any spelling this layer folds, names one of the three
 * host-served directories a serial alias name appears in (/dev, /dev/serial,
 * /dev/serial/by-id); @out receives the canonical spelling. A descriptor opened
 * on one carries that spelling so a relative lookup through it re-enters the
 * intercepts.
 */
bool usb_tty_alias_dir(const char *path, char *out, size_t outsz);

/* The alias NODE spelling behind @path, which may itself be a by-id leaf, or
 * false when this layer serves no such alias. Unlike usb_tty_alias_canon this
 * takes the layer's lock and looks the device up, because that is the only way
 * to know which ttyACM<n> a by-id name resolves to.
 *
 * It is the spelling a descriptor is stamped with: the two names are one
 * object, so a by-id fd has to fstat as the node -- and the node spelling is
 * also the only one that fits, since a by-id leaf can be 224 bytes and the
 * stamp is 63.
 */
bool usb_tty_alias_node(const char *path, char *out, size_t outsz);

/* Whether @path could name anything under /sys or /dev that this layer serves,
 * decided by the same fold-then-classify the intercepts use. The stat gate asks
 * this instead of matching prefixes itself: matching them left //dev/ttyACM0
 * and /dev/./ttyACM0 out of the stat intercept while the unconditional open
 * intercept still served them, so one name opened the device and stat'd the
 * placeholder behind it.
 */
bool usb_sysfs_path_might_be_ours(const char *path);
