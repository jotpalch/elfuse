/*
 * sys/sysctl.h, for the analyzer only
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frama-C's libc does not model this header, which stopped syscall/sys.c and
 * runtime/procemu.c before either reached the analyzer. It was recorded as one
 * of the gaps no stub could honestly supply, alongside sys/event.h and
 * sys/mount.h, but sysctl is not like those: the tree asks it two questions and
 * both are answerable by declaration.
 *
 * runtime/procemu.c reads KERN_BOOTTIME to date /proc/stat's btime and
 * /proc/uptime, and syscall/sys.c reads HW_MEMSIZE for the totalram sysinfo
 * reports. Two calls, four constants.
 *
 * Declarations only, and deliberately so. What sysctl does is a kernel lookup
 * the memory model cannot see into, so a body would be fiction; unspecified
 * leaves WP treating the output buffer as written with unknown contents, which
 * is what both callers already assume and check the return value for.
 *
 * The SDK spells the buffer parameters with __sized_by, a bounds attribute
 * Frama-C's parser does not take. Dropping it loses nothing here: it documents
 * a relationship between two arguments that no proof in this tree reasons
 * about, and the callers pass a sizeof of a local either way.
 *
 * Same placement rule as the other Darwin stubs: outside src/, reachable only
 * through FRAMAC_STUB_DIR in mk/verify.mk, never on a compile's include path.
 */

#pragma once

#include <stddef.h>
#include <sys/types.h>

/* Top-level sysctl namespaces. */
#define CTL_KERN 1
#define CTL_HW 6

/* KERN_BOOTTIME yields a struct timeval, HW_MEMSIZE a uint64_t. */
#define KERN_BOOTTIME 21
#define HW_MEMSIZE 24

int sysctl(int *name,
           unsigned int namelen,
           void *oldp,
           size_t *oldlenp,
           void *newp,
           size_t newlen);

int sysctlbyname(const char *name,
                 void *oldp,
                 size_t *oldlenp,
                 void *newp,
                 size_t newlen);
