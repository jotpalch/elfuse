/*
 * brk growth bound arithmetic
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One region's effect on how far a break may grow. sys_brk starts from the
 * stack and folds every tracked region through this, so the bound can only come
 * down; the caller's loop and the sorted region array around it stay
 * test-covered rather than proved.
 *
 * The refusal on a stale region tracker is not here. It is a policy the
 * caller applies before asking this anything, and proving that an || short
 * circuits says nothing about a bound.
 */

#pragma once

#include <stdint.h>

/*@
  requires from <= limit;
  assigns \nothing;
  ensures bounded: from <= \result <= limit;
  ensures unchanged:
            (start >= limit || end <= from) ==> \result == limit;
  ensures straddles:
            (start < limit && end > from && start <= from) ==>
                \result == from;
  ensures neighbor:
            (start < limit && end > from && start > from) ==>
                \result == start;
 */
static inline uint64_t brk_limit_region(uint64_t from,
                                        uint64_t limit,
                                        uint64_t start,
                                        uint64_t end)
{
    if (start >= limit || end <= from)
        return limit;
    return start <= from ? from : start;
}
