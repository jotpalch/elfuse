/*
 * spin-forever.c -- a guest that never yields, for the vCPU watchdog lane.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A fixture for tests/test-vcpu-watchdog.sh, not a standalone test: it never
 * exits on its own, so adding it to tests/manifest.txt would hang the driver.
 *
 * Writes one line so the harness knows it started, then spins in EL0 issuing no
 * syscall at all. Nothing inside the guest can end it; only the host watchdog
 * can.
 */

#include <unistd.h>

int main(void)
{
    write(1, "spinning\n", 9);
    for (;;)
        __asm__ __volatile__("" ::: "memory");
    return 0;
}
