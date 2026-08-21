/*
 * Native-host unit tests for the sticky ttyACM/ttyUSB index pools.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the Linux idr_alloc-style semantics the alias layer promises
 * (runtime/tty-alias-pool.c) without any hardware: sticky indices across
 * rescans, lowest-free reuse after detach, and the name-sorted first scan.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "runtime/tty-alias-pool.h"

static void test_first_scan_is_name_sorted(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    const char *scan[] = {"cu.usbmodem31", "cu.usbmodem11", "cu.usbmodem21"};
    tty_alias_pool_rescan(&pool, scan, 3);
    assert(tty_alias_pool_index(&pool, "cu.usbmodem11") == 0);
    assert(tty_alias_pool_index(&pool, "cu.usbmodem21") == 1);
    assert(tty_alias_pool_index(&pool, "cu.usbmodem31") == 2);
}

static void test_attached_devices_keep_their_index(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    const char *scan1[] = {"cu.usbmodem50"};
    tty_alias_pool_rescan(&pool, scan1, 1);
    assert(tty_alias_pool_index(&pool, "cu.usbmodem50") == 0);

    /* A later arrival that sorts earlier must not steal index 0 the way a
     * per-scan re-sort would; Linux keeps the attached device's minor.
     */
    const char *scan2[] = {"cu.usbmodem10", "cu.usbmodem50"};
    tty_alias_pool_rescan(&pool, scan2, 2);
    assert(tty_alias_pool_index(&pool, "cu.usbmodem50") == 0);
    assert(tty_alias_pool_index(&pool, "cu.usbmodem10") == 1);
}

static void test_detach_frees_and_lowest_free_is_reused(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    const char *scan1[] = {"cu.usbmodemA", "cu.usbmodemB", "cu.usbmodemC"};
    tty_alias_pool_rescan(&pool, scan1, 3);

    const char *scan2[] = {"cu.usbmodemA", "cu.usbmodemC"};
    tty_alias_pool_rescan(&pool, scan2, 2);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemB") == -1);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemC") == 2);

    /* New arrival takes the freed slot 1, not slot 3. */
    const char *scan3[] = {"cu.usbmodemA", "cu.usbmodemC", "cu.usbmodemZ"};
    tty_alias_pool_rescan(&pool, scan3, 3);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemZ") == 1);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemA") == 0);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemC") == 2);
}

static void test_reattach_after_detach_may_move(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    const char *scan1[] = {"cu.usbmodemA", "cu.usbmodemB"};
    tty_alias_pool_rescan(&pool, scan1, 2);

    /* Unplug A, plug C: C takes A's freed slot 0. Replug A: A is a new arrival
     * now and lands on the lowest free slot 2, exactly like a Linux replug that
     * lost its old minor to another device.
     */
    const char *scan2[] = {"cu.usbmodemB", "cu.usbmodemC"};
    tty_alias_pool_rescan(&pool, scan2, 2);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemC") == 0);
    const char *scan3[] = {"cu.usbmodemA", "cu.usbmodemB", "cu.usbmodemC"};
    tty_alias_pool_rescan(&pool, scan3, 3);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemA") == 2);
    assert(tty_alias_pool_index(&pool, "cu.usbmodemB") == 1);
}

static void test_duplicates_empties_and_empty_scan(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    const char *scan1[] = {"cu.usbserial-10", "", "cu.usbserial-10", NULL};
    tty_alias_pool_rescan(&pool, scan1, 4);
    assert(tty_alias_pool_index(&pool, "cu.usbserial-10") == 0);
    assert(tty_alias_pool_index(&pool, "") == -1);
    assert(tty_alias_pool_index(&pool, NULL) == -1);

    tty_alias_pool_rescan(&pool, NULL, 0);
    assert(tty_alias_pool_index(&pool, "cu.usbserial-10") == -1);
}

static void test_long_keys_truncate_consistently(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    char lots[TTY_ALIAS_KEY_MAX + 16];
    memset(lots, 'x', sizeof(lots) - 1);
    lots[sizeof(lots) - 1] = '\0';
    const char *scan[] = {lots};
    tty_alias_pool_rescan(&pool, scan, 1);
    assert(tty_alias_pool_index(&pool, lots) == 0);
}

static void test_pool_full_leaves_extras_unassigned(void)
{
    tty_alias_pool_t pool;
    tty_alias_pool_init(&pool);
    char names[TTY_ALIAS_POOL_SLOTS + 4][24];
    const char *scan[TTY_ALIAS_POOL_SLOTS + 4];
    for (int i = 0; i < TTY_ALIAS_POOL_SLOTS + 4; i++) {
        snprintf(names[i], sizeof(names[i]), "cu.usbmodem%03d", i);
        scan[i] = names[i];
    }
    tty_alias_pool_rescan(&pool, scan, TTY_ALIAS_POOL_SLOTS + 4);
    assert(tty_alias_pool_index(&pool, names[0]) == 0);
    assert(tty_alias_pool_index(&pool, names[TTY_ALIAS_POOL_SLOTS - 1]) ==
           TTY_ALIAS_POOL_SLOTS - 1);
    assert(tty_alias_pool_index(&pool, names[TTY_ALIAS_POOL_SLOTS]) == -1);
}

int main(void)
{
    test_first_scan_is_name_sorted();
    test_attached_devices_keep_their_index();
    test_detach_frees_and_lowest_free_is_reused();
    test_reattach_after_detach_may_move();
    test_duplicates_empties_and_empty_scan();
    test_long_keys_truncate_consistently();
    test_pool_full_leaves_extras_unassigned();
    printf("test-tty-alias-pool-host: all tests passed\n");
    return 0;
}
