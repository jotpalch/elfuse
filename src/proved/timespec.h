/*
 * Guest timespec arithmetic: the parts a proof can reach
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * nanosleep, clock_nanosleep, ppoll, pselect6, futex, timerfd and epoll_pwait2
 * all take a timespec the guest wrote, and every one of them turns it into
 * either a nanosecond count or a millisecond poll timeout. Both conversions
 * multiply a guest-chosen tv_sec, so both can overflow, and signed overflow is
 * undefined behavior rather than a large number.
 *
 * time.c's converter guarded the product only for a normalized tv_nsec: with
 * tv_sec=1 and tv_nsec=INT64_MAX it took the "no overflow" branch and computed
 * 1000000000 + INT64_MAX. Every caller happened to validate first or pass a
 * kernel-normalized host value, so the overflow was unreachable by provenance
 * rather than by construction. timespec_to_ns_sat is total: it saturates for
 * any pair of int64_t values, so the callers' validation is a policy choice
 * rather than a safety obligation.
 *
 * poll.c carried the second conversion twice, and the two copies disagreed: one
 * truncated the sub-millisecond remainder and one rounded it up. Truncating
 * turns ppoll with a 500 us timeout into poll(0), which returns immediately, so
 * a guest sleeping in sub-millisecond ppoll spun at full CPU instead of
 * waiting. Linux rounds up. timespec_to_poll_ms rounds up, once.
 *
 * Split into a header because time.c and poll.c cannot be given to Frama-C:
 * they include the macOS time and poll headers, which the analyzer's libc does
 * not model. This header needs nothing but stdint.h, so make verify-timespec
 * proves it directly.
 */

#pragma once

#include <stdint.h>

#define TIMESPEC_NSEC_PER_SEC 1000000000LL
#define TIMESPEC_NSEC_PER_MSEC 1000000LL

/* Prefixed rather than plain NSEC_PER_SEC: src/utils.h already defines that
 * name with a different literal suffix, and this header has to stand alone for
 * the prover. time.c static asserts the two agree.
 */

/* Largest tv_sec whose nanosecond product still fits int64_t. */
#define TIMESPEC_SEC_MAX (INT64_MAX / TIMESPEC_NSEC_PER_SEC)

_Static_assert(TIMESPEC_NSEC_PER_SEC == 1000LL * TIMESPEC_NSEC_PER_MSEC,
               "the two scales must agree or the ms conversion drifts");
_Static_assert(TIMESPEC_SEC_MAX > 0,
               "the saturation bound must leave a usable range");

/* The saturating nanosecond value, as a logic term: the whole conversion in one
 * place, defined for every pair of int64_t values. Both contracts below are
 * written against it, which is what makes them total. Stating the same thing as
 * a set of case hypotheses instead leaves whatever the cases do not cover
 * unconstrained, and the uncovered case is exactly where a conforming
 * implementation is free to return a wait of zero.
 *
 * A definition, not an axiom: it unfolds, so nothing here is assumed.
 */
/*@
  logic integer timespec_ns_sat(integer sec, integer nsec) =
      (sec < 0 || nsec < 0) ? 0 :
      (sec > TIMESPEC_SEC_MAX ||
       nsec > INT64_MAX - sec * TIMESPEC_NSEC_PER_SEC) ? INT64_MAX :
      sec * TIMESPEC_NSEC_PER_SEC + nsec;
 */

/* Whether a guest timespec is one Linux would accept.
 *
 * Linux rejects a negative tv_sec and any tv_nsec outside [0, 1e9) with EINVAL
 * on the sleep and wait paths. Kept separate from the conversions below because
 * it is a policy answer, not a safety one: the conversions are total, so a
 * caller that wants Linux's EINVAL asks for it explicitly.
 */
/*@
  assigns \nothing;
  ensures \result == 0 || \result == 1;
  ensures \result != 0 <==> (sec >= 0 && 0 <= nsec < TIMESPEC_NSEC_PER_SEC);
 */
static inline int timespec_valid(int64_t sec, int64_t nsec)
{
    return sec >= 0 && nsec >= 0 && nsec < TIMESPEC_NSEC_PER_SEC;
}

/* Whether a guest timespec is one Linux would accept AND whose seconds fit a
 * caller-supplied ceiling.
 *
 * The ceiling is what a caller adds when it will convert the value and needs
 * the product to stay well inside int64: futex caps at INT64_MAX/4 so the
 * deadline arithmetic downstream cannot saturate. Expressed here rather than
 * open-coded beside timespec_valid at each call site, so the cap is inside the
 * same <==> the prover checks instead of sitting outside it untested.
 */
/*@
  requires cap >= 0;
  assigns \nothing;
  ensures \result == 0 || \result == 1;
  ensures \result != 0 <==>
      (sec >= 0 && 0 <= nsec < TIMESPEC_NSEC_PER_SEC && sec <= cap);
 */
static inline int timespec_valid_capped(int64_t sec, int64_t nsec, int64_t cap)
{
    return timespec_valid(sec, nsec) && sec <= cap;
}

/* Nanoseconds in a timespec, saturating at INT64_MAX and flooring at 0.
 *
 * Total by construction: the multiplication happens only under the proved
 * tv_sec bound, and the addition only under a proved headroom check. No
 * precondition, so no caller can be the one that gets it wrong.
 */
/*@
  assigns \nothing;
  ensures in_range: 0 <= \result <= INT64_MAX;
  ensures exact: \result == timespec_ns_sat(sec, nsec);
 */
static inline int64_t timespec_to_ns_sat(int64_t sec, int64_t nsec)
{
    if (sec < 0 || nsec < 0)
        return 0;
    if (sec > TIMESPEC_SEC_MAX)
        return INT64_MAX;

    int64_t whole = sec * TIMESPEC_NSEC_PER_SEC;
    if (nsec > INT64_MAX - whole)
        return INT64_MAX;
    return whole + nsec;
}

/* Milliseconds for poll(2), rounded up and clamped to what its int argument
 * holds.
 *
 * Rounding up is the whole point: a timeout the caller asked to wait for must
 * not become a poll that returns immediately, or the caller spins. The residue
 * test is written on the already-divided value so nothing has to add 999999 to
 * a value that may be INT64_MAX.
 */
/*@
  assigns \nothing;
  ensures in_range: 0 <= \result <= INT32_MAX;
  ensures never_returns_early:
            timespec_ns_sat(sec, nsec) <=
              INT32_MAX * TIMESPEC_NSEC_PER_MSEC ==>
              \result * TIMESPEC_NSEC_PER_MSEC >= timespec_ns_sat(sec, nsec);
  ensures waits_less_than_a_millisecond_too_long:
            \result > 0 ==>
              (\result - 1) * TIMESPEC_NSEC_PER_MSEC <
                timespec_ns_sat(sec, nsec);
  ensures clamps_to_int:
            timespec_ns_sat(sec, nsec) >
              INT32_MAX * TIMESPEC_NSEC_PER_MSEC ==> \result == INT32_MAX;
 */
static inline int timespec_to_poll_ms(int64_t sec, int64_t nsec)
{
    int64_t ns = timespec_to_ns_sat(sec, nsec);
    int64_t ms = ns / TIMESPEC_NSEC_PER_MSEC;

    if (ns % TIMESPEC_NSEC_PER_MSEC != 0)
        ms++;
    if (ms > INT32_MAX)
        return INT32_MAX;
    return (int) ms;
}
