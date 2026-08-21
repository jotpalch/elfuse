/*
 * Sticky index pools for the Linux ttyACM/ttyUSB alias names
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mirrors the Linux idr_alloc semantics that cdc-acm and usb-serial use for
 * minor numbers: a device keeps its index for as long as it stays attached, a
 * detached device releases its index, and a new arrival takes the lowest free
 * one. The pool is keyed by the macOS callout node name (cu.*), which
 * identifies one host serial device for the lifetime of an elfuse run.
 *
 * Pure string/array bookkeeping with no locking and no I/O so the rescan
 * semantics are unit-testable without hardware (tests/test-tty-alias-pool-
 * host.c); the caller (runtime/usb-sysfs.c) serializes access under its
 * usb_lock.
 */

#pragma once

#include <stddef.h>

/* Linux cdc-acm carries 256 minors per major; far more callout nodes than any
 * one macOS host exposes, so the pool caps well below that.
 */
#define TTY_ALIAS_POOL_SLOTS 64
#define TTY_ALIAS_KEY_MAX 64

typedef struct {
    /* keys[i][0] == '\0' means index i is free. */
    char keys[TTY_ALIAS_POOL_SLOTS][TTY_ALIAS_KEY_MAX];
} tty_alias_pool_t;

void tty_alias_pool_init(tty_alias_pool_t *pool);

/* Reconcile the pool with the key set currently present on the host.
 *
 * Keys already holding a slot keep it (the sticky guarantee: a later arrival
 * that sorts earlier never renames a device in use, unlike a re-sort on every
 * scan would). Slots whose key vanished are freed. Keys not seen before are
 * assigned the lowest free slot in ascending strcmp order, which makes the very
 * first scan a predictable name-sorted assignment, exactly like the Linux
 * boot-time enumeration order for a fixed device set.
 *
 * Keys longer than TTY_ALIAS_KEY_MAX-1 bytes are truncated for matching;
 * duplicates in `keys` collapse to one slot. When the pool is full the
 * remaining new keys stay unassigned (tty_alias_pool_index answers -1).
 */
void tty_alias_pool_rescan(tty_alias_pool_t *pool,
                           const char *const *keys,
                           size_t nkeys);

/* Index held by `key`, or -1 when the key holds no slot. */
int tty_alias_pool_index(const tty_alias_pool_t *pool, const char *key);
