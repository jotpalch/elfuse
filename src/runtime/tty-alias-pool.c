/*
 * Sticky index pools for the Linux ttyACM/ttyUSB alias names
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Re-sorting on every scan would rename a device the guest has open, and
 * hashing the callout name would produce names no Linux kernel does. Identity
 * across runs is /dev/serial/by-id's, as on Linux.
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
    /* Survey @keys whole, not a copy capped at the pool size: a capped copy
     * drops keys that hold a slot when more keys than slots are listed.
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

    /* Free departed keys' slots before assigning, as an idr reuses a minor. */
    for (int i = 0; i < TTY_ALIAS_POOL_SLOTS; i++)
        if (pool->keys[i][0] != '\0' && !keep[i])
            pool->keys[i][0] = '\0';

    /* Smallest unslotted name first. A duplicate finds the first copy's slot
     * and is skipped.
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
