/*
 * Frama-C prelude: the headers Frama-C ships but never reaches on its own
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two things a compiler supplies for free and Frama-C does not reach on its
 * own. Force-included through FRAMAC_CPP_ARGS; a real compile resolves through
 * -Isrc and never sees this file.
 *
 * __fc_gcc_builtins.h is where Frama-C models __builtin_ctzll,
 * __builtin_add_overflow, __atomic_thread_fence and __sync_synchronize, with
 * contracts. Nothing in the modeled libc includes it, so without this line
 * those are implicit declarations whose argument types are inferred per
 * translation unit, and two files that pass different widths conflict the
 * moment they load together.
 *
 * stdatomic.h carries Frama-C's own handling of the _Atomic qualifier, which
 * its front end cannot parse: "#define _Atomic" with the comment "_Atomic is
 * currently ignored by Frama-C". Taken from that header rather than restated as
 * a -D, so the concession stays the analyzer's stated position and moves when
 * Frama-C's does. The same header models atomic_load_explicit,
 * atomic_store_explicit, atomic_exchange_explicit, the fetch_ forms and
 * compare_exchange, which is the whole vocabulary this tree calls. The tree
 * includes stdatomic.h in the sources that need it, but the qualifier appears
 * in headers those sources reach first, so the definition has to arrive ahead
 * of everything.
 *
 * Ignoring _Atomic carries a limit: sound for the per-function runtime-error
 * and bounds obligations these targets discharge, NOT sound for any analysis of
 * concurrent behaviour. No target here is one. See mk/verify.mk.
 */

#pragma once

#include <__fc_gcc_builtins.h>
#include <stdatomic.h>
