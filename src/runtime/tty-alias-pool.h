/*
 * Sticky index pools for the Linux ttyACM/ttyUSB alias names
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The idr_alloc semantics cdc-acm and usb-serial give their minors: a device
 * keeps its index while attached, and a new arrival takes the lowest free one.
 * Keyed by the macOS callout name (cu.*). No locking: usb-sysfs.c holds
 * usb_lock around every call.
 */

#pragma once

#include <stddef.h>

/* Below the 256 minors cdc-acm carries; no host exposes that many callouts. */
#define TTY_ALIAS_POOL_SLOTS 64
#define TTY_ALIAS_KEY_MAX 64

typedef struct {
    /* keys[i][0] == '\0' means index i is free. */
    char keys[TTY_ALIAS_POOL_SLOTS][TTY_ALIAS_KEY_MAX];
} tty_alias_pool_t;

void tty_alias_pool_init(tty_alias_pool_t *pool);

/* Reconcile the pool with the keys present now. A key holding a slot keeps it,
 * a vanished key frees its slot, and new keys take the lowest free slots in
 * strcmp order, whatever order @keys lists them in. Keys are compared truncated
 * to TTY_ALIAS_KEY_MAX - 1 bytes, and duplicates share one slot. With the pool
 * full, only new keys go unassigned.
 */
void tty_alias_pool_rescan(tty_alias_pool_t *pool,
                           const char *const *keys,
                           size_t nkeys);

/* Index held by key, or -1 when the key holds no slot. */
int tty_alias_pool_index(const tty_alias_pool_t *pool, const char *key);
