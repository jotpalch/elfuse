# bash-compat.sh -- Shared bash 3.2+ compatibility helpers for the elfuse test
# harness.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# macOS still ships bash 3.2.57 as /bin/bash (frozen since 2007 over the GPLv3
# move). The Makefile invokes scripts via `bash tests/foo.sh`, so stock macOS
# picks up /bin/bash regardless of the env-bash shebang. This helper
# consolidates the small set of cross-version shims the suite needs so each
# script does not have to re-derive them.
#
# Source it as the first action after `set -uo pipefail`:
#
# # shellcheck source=tests/lib/bash-compat.sh
#     . "$(dirname "${BASH_SOURCE[0]}")/lib/bash-compat.sh"
#
# Provides:
#   epoch_us                  -- print current wall-clock time in microseconds
#   bash_compat_require       -- abort with a helpful message if BASH is too old
#   test_host_is_busy         -- true when the host is too loaded for timing
#   test_host_busy_mark       -- record that verdict as a timed region starts
#   test_host_busy_since_mark -- true when busy at the mark or busy now
#
# Conventions for portable bash:
#   - Do not expand "${array[@]}" when the array may be empty under set -u
#     (bash 3.2 reports "unbound variable"). Use "${array[@]:+...}" or
#     "${array[@]:0}" / "${array[@]:1}" offset forms instead, which are
#     safe even on empty arrays.
#   - Do not use 'declare -A' (associative arrays); use parallel indexed
#     arrays plus a lookup helper.
#   - Do not use $EPOCHREALTIME / $EPOCHSECONDS directly; call epoch_us
#     from this helper.
#   - Do not use ${var^^} / ${var,,} case-conversion; pipe through tr.
#   - Do not use 'mapfile' / 'readarray'; use a 'while read' loop.

# Minimum bash version that the elfuse harness supports. Stays at 3.2 so the
# stock macOS /bin/bash works without Homebrew.
: "${BASH_COMPAT_MIN_MAJOR:=3}"
: "${BASH_COMPAT_MIN_MINOR:=2}"

bash_compat_require()
{
    if [ -z "${BASH_VERSINFO+set}" ]; then
        echo "elfuse test harness must run under bash, not /bin/sh." >&2
        exit 127
    fi
    local maj="${BASH_VERSINFO[0]}"
    local min="${BASH_VERSINFO[1]}"
    if [ "$maj" -lt "$BASH_COMPAT_MIN_MAJOR" ] \
        || {
            [ "$maj" -eq "$BASH_COMPAT_MIN_MAJOR" ] \
                && [ "$min" -lt "$BASH_COMPAT_MIN_MINOR" ]
        }; then
        echo "elfuse test harness requires bash >=" \
            "${BASH_COMPAT_MIN_MAJOR}.${BASH_COMPAT_MIN_MINOR}" \
            "(found ${BASH_VERSION:-unknown})." >&2
        exit 127
    fi
}

bash_compat_require

# Pick the best available microsecond clock source. The chosen implementation is
# bound to 'epoch_us' so callers stay version-agnostic.
#
# Ordered for lowest per-call cost first:
#   1. $EPOCHREALTIME (bash 5.0+) -- builtin, no fork.
#   2. date '+%s %N'              -- one fork; works under GNU date and
#                                    BSD date on macOS 14+ (Sonoma added
#                                    %N to the system date).
#   3. python3 -c ...             -- one fork plus interpreter spin-up.
#   4. perl  -MTime::HiRes ...    -- one fork plus interpreter spin-up.
#   5. date +%s * 1e6             -- whole-second fallback so the suite
#                                    does not silently abort. Comparisons
#                                    lose microsecond resolution; callers
#                                    that need it should ensure one of the
#                                    earlier sources is available.
if [ -n "${EPOCHREALTIME:-}" ]; then
    epoch_us()
    {
        local t="$EPOCHREALTIME"
        local sec="${t%%.*}"
        local frac="${t##*.}000000"
        printf '%s\n' "$((sec * 1000000 + 10#${frac:0:6}))"
    }
else
    _bash_compat_ns_probe="$(date '+%N' 2> /dev/null || true)"
    if [ "${#_bash_compat_ns_probe}" -eq 9 ] \
        && [ "${_bash_compat_ns_probe#N}" = "$_bash_compat_ns_probe" ]; then
        epoch_us()
        {
            local out sec ns
            out="$(date '+%s %N')"
            sec="${out%% *}"
            ns="${out##* }"
            printf '%s\n' "$((sec * 1000000 + 10#$ns / 1000))"
        }
    elif command -v python3 > /dev/null 2>&1; then
        epoch_us()
        {
            python3 -c 'import time; print(int(time.time()*1000000))'
        }
    elif command -v perl > /dev/null 2>&1; then
        epoch_us()
        {
            perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000000'
        }
    else
        epoch_us()
        {
            printf '%s\n' "$(($(date '+%s') * 1000000))"
        }
    fi
    unset _bash_compat_ns_probe
fi

# True when this machine is too loaded for a wall-clock measurement to mean
# anything. One threshold for every caller, directly here for the throughput
# guardrail and through the mark pair below for the watchdogs, so they cannot
# drift apart on what "busy" means.
#
# The threshold is deliberately generous: below it, a timing failure is the code
# and gets reported; above it, the number is measuring the neighbours. Observed
# on this project with an unrelated prover run in the background, correct code
# ran 2 to 3 times slower and tripped several bounds at once.
test_host_is_busy()
{
    sysctl -n vm.loadavg hw.ncpu 2> /dev/null \
        | awk 'NR == 1 { l = $2 } NR == 2 { n = $1 }
               END { exit !(NR == 2 && n > 0 && l > n * 0.6) }'
}

# Asking only "is the host busy now" after a watchdog fires misses contention
# that was already easing when the run began: the reading is a 1-minute average,
# so a spike ending near the start of the test has decayed out of it by the time
# the test gives up. Mark the load as the timed region starts and let the check
# afterwards accept either end.
#
# Two readings cover the window and a third taken mid-run would add nothing. The
# average decays with a 60s time constant, so a spike must end roughly 40s
# before a reading to fall under the threshold, which inside a 60s watchdog puts
# it at or before the mark. One brief enough to hide from both readings is too
# brief to have eaten the run's headroom.
#
# Its own pair rather than a change to test_host_is_busy: the throughput
# guardrail wants the instantaneous reading, and one predicate cannot mean both.

# Set by test_host_busy_mark, read by test_host_busy_since_mark.
test_host_busy_at_mark=0

test_host_busy_mark()
{
    # if/else rather than "test_host_is_busy && x=1", so the status returned is
    # an assignment's and never the predicate's: this must return 0 on an idle
    # host, including inside the set -e regions the callers run under.
    if test_host_is_busy; then
        test_host_busy_at_mark=1
    else
        test_host_busy_at_mark=0
    fi
}

test_host_busy_since_mark()
{
    [ "$test_host_busy_at_mark" -eq 1 ] || test_host_is_busy
}
