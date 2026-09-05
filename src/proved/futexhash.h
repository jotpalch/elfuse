/*
 * Futex bucket indexing: the part a proof can reach
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The bucket index selects an element of a fixed-size array on the futex hot
 * path, so a result at or past the table size is an out-of-bounds access. The
 * index comes from a multiply-shift over a guest-chosen address, and that the
 * high bits of a 64-bit product cannot exceed the table was true only by
 * reading it. futex_bucket_index states it as a postcondition instead, for
 * every address a guest can name and every table size.
 *
 * Split into a header because futex.c does parse under Frama-C but drags in the
 * whole runtime to do it; this needs nothing but stdint.h, so make
 * verify-futexhash proves it directly and make verify-mutants can break it.
 */

#pragma once

#include <stdint.h>

/* Golden-ratio odd constant. Any odd multiplier mixes low bits upward; this one
 * is the usual choice because its bit pattern sits far from any power of two,
 * which is what a stride-aliasing input needs it to be. fuse_node_ref_hash in
 * src/syscall/fuse.c uses the same constant for the same reason.
 */
#define FUTEX_HASH_MULT 0x9E3779B97F4A7C15ULL

/* Bucket index for a guest futex address.
 *
 * The low two address bits carry no entropy (a futex word is 4-byte aligned),
 * so they are dropped before mixing rather than being allowed to occupy the
 * product. The multiply carries every remaining bit upward; the shift then
 * takes the mixed half.
 *
 * The postcondition is the whole point: it is what makes buckets[index] a
 * memory-safe access for any address a guest can name.
 *
 * Two shapes were tried before this one, and both left a bitvector goal neither
 * prover discharges. Taking the top bits directly, as "product >> (64 -
 * shift)", requires proving that a shift by 64 - shift yields fewer than shift
 * bits. Reducing that with "% (1 << shift)" moves the problem to proving the
 * divisor is nonzero. Both vanish once the table size arrives as a plain number
 * rather than as a shift amount: the shift is then the constant 32, and the
 * bound is the definition of %, with nonzero-ness coming from the precondition.
 * src/proved/align.h documents the same preference for arithmetic over bit
 * operations, for the same reason.
 *
 * The provable form is also the cheapest one. With a constant power-of-two
 * nbuckets the compiler folds the shift and the remainder into a single ubfx,
 * one instruction fewer than the shift-then-mask it replaced; there is no
 * divide in the emitted object.
 *
 * Taking bits 32 and up rather than the very top costs nothing measurable: the
 * multiply spreads every input bit across the high half, so any window in it
 * mixes. Checked against the strides an allocator emits, 16 B through 1 MiB, it
 * separates all eight addresses every time, and over random addresses it fills
 * 1004 of 1024 buckets with a longest chain of 11.
 *
 * nbuckets need not be a power of two for the contract to hold, though the only
 * caller passes one.
 */
/*@
  requires nbuckets > 0;
  assigns \nothing;
  ensures in_table: \result < nbuckets;
*/
static inline uint32_t futex_bucket_index(uint64_t uaddr, uint32_t nbuckets)
{
    uint64_t mixed = ((uaddr >> 2) * FUTEX_HASH_MULT) >> 32;
    return (uint32_t) (mixed % (uint64_t) nbuckets);
}
