/*
 * Sticky index pools for the Linux ttyACM/ttyUSB alias names
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See tty-alias-pool.h for the contract. The rejected alternatives, for the
 * record: re-sorting every scan renames a device the guest already has open
 * (Linux never does that), and hashing the macOS callout name into the index
 * fabricates names like ttyACM48213 that no Linux kernel would produce and
 * collides for serial-less devices. Cross-run stability is the by-id layer's
 * job, same as on Linux where /dev/serial/by-id carries identity across boots
 * while the minor numbers do not.
 */

#include <string.h>

#include "runtime/tty-alias-pool.h"

void tty_alias_pool_init(tty_alias_pool_t *pool)
{
    memset(pool, 0, sizeof(*pool));
}

static int pool_find(const tty_alias_pool_t *pool, const char *key)
{
    for (int i = 0; i < TTY_ALIAS_POOL_SLOTS; i++)
        if (pool->keys[i][0] != '\0' && strcmp(pool->keys[i], key) == 0)
            return i;
    return -1;
}

/* Truncate to the stored width so lookup and storage agree on one spelling. */
static void key_copy(char *dst, const char *src)
{
    size_t n = strlen(src);
    if (n >= TTY_ALIAS_KEY_MAX)
        n = TTY_ALIAS_KEY_MAX - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void tty_alias_pool_rescan(tty_alias_pool_t *pool,
                           const char *const *keys,
                           size_t nkeys)
{
    char present[TTY_ALIAS_POOL_SLOTS][TTY_ALIAS_KEY_MAX];
    size_t npresent = 0;

    for (size_t i = 0; i < nkeys && npresent < TTY_ALIAS_POOL_SLOTS; i++) {
        if (!keys[i] || keys[i][0] == '\0')
            continue;
        char trunc[TTY_ALIAS_KEY_MAX];
        key_copy(trunc, keys[i]);
        int dup = 0;
        for (size_t j = 0; j < npresent; j++)
            if (strcmp(present[j], trunc) == 0)
                dup = 1;
        if (!dup)
            key_copy(present[npresent++], trunc);
    }

    /* Free the slots of departed keys; a slot freed here is reusable by the
     * new-arrival pass below, matching how a Linux idr hands a released minor
     * to the next hotplug.
     */
    for (int i = 0; i < TTY_ALIAS_POOL_SLOTS; i++) {
        if (pool->keys[i][0] == '\0')
            continue;
        int still = 0;
        for (size_t j = 0; j < npresent; j++)
            if (strcmp(pool->keys[i], present[j]) == 0)
                still = 1;
        if (!still)
            pool->keys[i][0] = '\0';
    }

    /* Assign new arrivals lowest-free in ascending name order: selection sort
     * over the not-yet-slotted keys, smallest name first, so the initial scan
     * of a fixed device set lands the same way a Linux boot enumeration would.
     */
    for (;;) {
        const char *best = NULL;
        for (size_t j = 0; j < npresent; j++) {
            if (pool_find(pool, present[j]) >= 0)
                continue;
            if (!best || strcmp(present[j], best) < 0)
                best = present[j];
        }
        if (!best)
            break;
        int slot = -1;
        for (int i = 0; i < TTY_ALIAS_POOL_SLOTS; i++)
            if (pool->keys[i][0] == '\0') {
                slot = i;
                break;
            }
        if (slot < 0)
            break; /* pool full; the leftovers stay unassigned */
        key_copy(pool->keys[slot], best);
    }
}

int tty_alias_pool_index(const tty_alias_pool_t *pool, const char *key)
{
    if (!key || key[0] == '\0')
        return -1;
    char trunc[TTY_ALIAS_KEY_MAX];
    key_copy(trunc, key);
    return pool_find(pool, trunc);
}
