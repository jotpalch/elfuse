/*
 * mach/mach.h, for the analyzer only
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The last header keeping syscall/sys.c and runtime/procemu.c out of the
 * parsing set. Both ask the same question in the same way: host_statistics64
 * with HOST_VM_INFO64, for the page counts behind sysinfo's freeram and
 * /proc/meminfo. sys.c reads free_count and purgeable_count, procemu.c reads
 * free_count and inactive_count. host_page_size scales them.
 *
 * Declarations only, like the other Darwin stubs. What these calls do is
 * kernel-side and invisible to the memory model, so a body would be fiction.
 *
 * struct vm_statistics64 is reproduced in full rather than trimmed to the four
 * fields the tree reads, because HOST_VM_INFO64_COUNT is derived from its size
 * and both callers pass that count to host_statistics64. A short struct would
 * silently pass a different count than the real build does, which is the same
 * class of quiet wrongness that had HV_EXIT_REASON_CANCELED at 1 for a value
 * the SDK enumerates as 0.
 *
 * Same placement rule as the other Darwin stubs: outside src/, reachable only
 * through FRAMAC_STUB_DIR in mk/verify.mk, never on a compile's include path.
 */

#pragma once

#include <stdint.h>

typedef int kern_return_t;
typedef unsigned int natural_t;
typedef int integer_t;
typedef unsigned int mach_port_t;
typedef unsigned int mach_msg_type_number_t;
typedef unsigned long vm_size_t;
typedef integer_t *host_info64_t;

#define KERN_SUCCESS 0
#define MACH_PORT_NULL 0
#define HOST_VM_INFO64 4

/* mach/vm_statistics.h, reproduced verbatim; see the note above on why in full.
 */
struct vm_statistics64 {
    natural_t free_count;
    natural_t active_count;
    natural_t inactive_count;
    natural_t wire_count;
    uint64_t zero_fill_count;
    uint64_t reactivations;
    uint64_t pageins;
    uint64_t pageouts;
    uint64_t faults;
    uint64_t cow_faults;
    uint64_t lookups;
    uint64_t hits;
    uint64_t purges;
    natural_t purgeable_count;
    natural_t speculative_count;
    uint64_t decompressions;
    uint64_t compressions;
    uint64_t swapins;
    uint64_t swapouts;
    natural_t compressor_page_count;
    natural_t throttled_count;
    natural_t external_page_count;
    natural_t internal_page_count;
    uint64_t total_uncompressed_pages_in_compressor;
    uint64_t swapped_count;
    uint64_t total_tag_storage_pages;
    uint64_t nontag_pageable_tag_storage_pages;
    uint64_t nontag_wired_tag_storage_pages;
    uint64_t free_tag_storage_pages;
    uint64_t tag_storing_tag_storage_pages;
    uint64_t total_tagged_pages;
    uint64_t resident_tagged_pages;
    uint64_t compressed_tagged_pages;
    uint64_t tagged_compressions;
    uint64_t tagged_decompressions;
    uint64_t compressed_tag_storage_bytes;
};

typedef struct vm_statistics64 vm_statistics64_data_t;
typedef struct vm_statistics64 *vm_statistics64_t;

#define HOST_VM_INFO64_COUNT                                    \
    ((mach_msg_type_number_t) (sizeof(vm_statistics64_data_t) / \
                               sizeof(integer_t)))

mach_port_t mach_host_self(void);
kern_return_t host_page_size(mach_port_t host, vm_size_t *out_page_size);
kern_return_t host_statistics64(mach_port_t host_priv,
                                int flavor,
                                integer_t *host_info64_out,
                                mach_msg_type_number_t *host_info64_outCnt);
