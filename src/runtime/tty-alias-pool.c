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

#include <stdbool.h>
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
    /* Which slots are still held by a key the caller listed. Surveyed directly
     * against keys rather than through a capped copy of it: the copy was
     * TTY_ALIAS_POOL_SLOTS entries long and dropped everything past the cap
     * INCLUDING keys that already held a slot, so the departure pass below then
     * freed a slot whose device was still attached and a newcomer took it. It
     * needed more keys than slots and the wrong input order to show, which the
     * caller could not produce -- but the contract in the header is stated
     * without either condition, and the unit is a standalone leaf.
     */
    bool keep[TTY_ALIAS_POOL_SLOTS] = {false};
    for (size_t i = 0; i < nkeys; i++) {
        if (!keys[i] || keys[i][0] == '\0')
            continue;
        char trunc[TTY_ALIAS_KEY_MAX];
        key_copy(trunc, keys[i]);
        int at = pool_find(pool, trunc);
        if (at >= 0)
            keep[at] = true;
    }

    /* Free the slots of departed keys; a slot freed here is reusable by the
     * new-arrival pass below, matching how a Linux idr hands a released minor
     * to the next hotplug.
     */
    for (int i = 0; i < TTY_ALIAS_POOL_SLOTS; i++)
        if (pool->keys[i][0] != '\0' && !keep[i])
            pool->keys[i][0] = '\0';

    /* Assign new arrivals lowest-free in ascending name order: selection sort
     * over the not-yet-slotted keys, smallest name first, so the initial scan
     * of a fixed device set lands the same way a Linux boot enumeration would.
     * A key that already holds a slot is skipped, which is also what collapses
     * duplicates: the second copy finds the first one's slot.
     */
    for (;;) {
        char best[TTY_ALIAS_KEY_MAX];
        bool have_best = false;
        for (size_t j = 0; j < nkeys; j++) {
            if (!keys[j] || keys[j][0] == '\0')
                continue;
            char trunc[TTY_ALIAS_KEY_MAX];
            key_copy(trunc, keys[j]);
            if (pool_find(pool, trunc) >= 0)
                continue;
            if (!have_best || strcmp(trunc, best) < 0) {
                memcpy(best, trunc, sizeof(best));
                have_best = true;
            }
        }
        if (!have_best)
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
