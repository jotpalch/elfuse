# Shared shell test runner helpers for elfuse integration suites.
#
# Copyright 2026 elfuse contributors
# Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2034

# shellcheck source=tests/lib/bash-compat.sh
. "$(dirname "${BASH_SOURCE[0]}")/bash-compat.sh"
. "$(dirname "${BASH_SOURCE[0]}")/hang-sample.sh"

: "${TEST_LABEL_WIDTH:=14}"
: "${TEST_TIMEOUT:=10}"

# Resolve a working 'timeout' binary. macOS doesn't ship one, so fall back to
# GNU coreutils' gtimeout. Wrap as a function so callers keep using the bare
# name 'timeout'. Resolution order: TIMEOUT_BIN env override, 'timeout' on PATH,
# 'gtimeout' on PATH, then Homebrew's stable opt symlinks for ARM and Intel
# macOS (the install prefix differs between the two).
if [ -n "${TIMEOUT_BIN:-}" ]; then
    timeout()
    {
        "$TIMEOUT_BIN" "$@"
    }
elif ! command -v timeout > /dev/null 2>&1; then
    _timeout_bin=
    if command -v gtimeout > /dev/null 2>&1; then
        _timeout_bin=gtimeout
    else
        for _candidate in /opt/homebrew/opt/coreutils/bin/gtimeout \
            /usr/local/opt/coreutils/bin/gtimeout; do
            if [ -x "$_candidate" ]; then
                _timeout_bin="$_candidate"
                break
            fi
        done
    fi
    if [ -n "$_timeout_bin" ]; then
        # shellcheck disable=SC2317  # Invoked indirectly via 'timeout' callers.
        eval "timeout() { \"$_timeout_bin\" \"\$@\"; }"
    else
        echo "test-runner: no 'timeout' or 'gtimeout' in PATH." >&2
        echo "  Install GNU coreutils (brew install coreutils), put gtimeout" >&2
        echo "  on PATH, or set TIMEOUT_BIN=/path/to/timeout." >&2
        exit 127
    fi
    unset _timeout_bin _candidate
fi

# epoch_us is provided by bash-compat.sh: it picks the lowest-cost microsecond
# clock the host supports ($EPOCHREALTIME on bash 5.0+, 'date +%s %N' on macOS
# 14+/GNU coreutils, python3, perl, or a whole-second fallback). run() uses it
# to disambiguate the guest timeout(1) returning rc=124 from the harness
# watchdog firing at TEST_TIMEOUT; SECONDS resolution would mistake either case
# at short caps.

if [ -t 1 ]; then

    # Use ANSI-C quoting so the variables hold real ESC bytes, not the literal
    # 4-char "\033" sequence. Without this, callers that pass colors as printf
    # %s arguments (e.g. tests/test-busybox.sh) emit the escape sequence as
    # plain text instead of activating the color.
    GREEN=$'\033[0;32m'
    RED=$'\033[0;31m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'
    RESET=$'\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    BLUE=''
    RESET=''
fi

pass=0
fail=0
skip=0
expected_fail=0

test_label()
{
    printf "%-${TEST_LABEL_WIDTH}s" "$1"
}

test_report()
{
    local state="$1"
    local label="$2"
    local detail="${3:-}"
    local name
    name=$(test_label "$label")

    case "$state" in
        ok) printf "%s [ ${GREEN}OK${RESET} ]%s\n" "$name" "$detail" ;;
        fail) printf "%s [ ${RED}FAIL${RESET} ]%s\n" "$name" "$detail" ;;
        skip) printf "%s [ ${YELLOW}SKIP${RESET} ]%s\n" "$name" "$detail" ;;
        xfail) printf "%s [ ${YELLOW}XFAIL${RESET} ]%s\n" "$name" "$detail" ;;

        # No bracketed verdict, because the test has not been decided yet and
        # every other state here is one the summary counts. The blanks are as
        # wide as the FAIL and SKIP tags, which is the closest a single width
        # gets: the verdicts do not share a column either (OK is 7 wide, FAIL
        # and SKIP 9, XFAIL 10).
        info) printf "%s %-8s%s\n" "$name" "" "$detail" ;;
    esac
}

test_excerpt()
{
    local output="$1"

    # The closing lines carry the actual assertion failure; the opening line is
    # usually just an elfuse WARN banner.
    printf "%s\n" "$output" | tail -10 | cut -c -200 | sed 's/^/  /'
}

test_tool_path()
{
    printf "%s/%s" "$BIN" "$1"
}

test_skip_missing_tool()
{
    local tool="$1"
    if [ "${TEST_SKIP_MISSING_TOOLS:-0}" = "1" ] && [ ! -e "$(test_tool_path "$tool")" ]; then
        run_skip "$tool" "binary not found"
        return 0
    fi
    return 1
}

run()
{
    local tool="$1"
    shift
    local expect_rc="${1:-0}"
    shift || true
    local output rc detail

    if test_skip_missing_tool "$tool"; then
        return
    fi

    # Wrap every invocation in 'timeout' so a hanging guest tool cannot freeze
    # the entire suite. run_pipe and run_timeout already do this; the omission
    # here used to let a deadlocked elfuse syscall path hang make check forever.
    #
    # GNU timeout reports rc=124 on its own timeout, but coreutils-suite also
    # runs the guest's own timeout(1) with expect_rc=124. Exit code alone cannot
    # tell the two apart, so wall-clock elapsed time is used as an out-of-band
    # marker: a harness firing means elapsed is at or above TEST_TIMEOUT, while
    # the guest case completes well under it. epoch_us (from bash-compat.sh)
    # gives microsecond resolution; comparing seconds alone via SECONDS could
    # undercount by almost a full second and let a real harness timeout slip
    # through as a guest-OK at small TEST_TIMEOUT values.
    local start_us end_us elapsed_us limit_us
    hang_sample_arm "$tool" "$TEST_TIMEOUT" \
        "${BUILD_DIR:-build}/test-timeouts/$(basename "$tool")-hang.txt"
    test_host_busy_mark
    start_us=$(epoch_us)
    if output=$(timeout "$TEST_TIMEOUT" ${TEST_RUNNER[@]+"${TEST_RUNNER[@]}"} \
        "$(test_tool_path "$tool")" "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    end_us=$(epoch_us)
    elapsed_us=$((end_us - start_us))
    limit_us=$((TEST_TIMEOUT * 1000000))
    local harness_timed_out=0
    if [ "$rc" -eq 124 ] && [ "$elapsed_us" -ge "$limit_us" ]; then
        harness_timed_out=1
    fi
    hang_sample_finish "$harness_timed_out"

    # A watchdog firing on a loaded machine says as much about the neighbours as
    # about the code, and this suite has spent real time chasing timeouts that
    # reproduced 0 times out of 60 on an idle host. Retry once, and only when
    # the host is actually busy, so an idle machine still reports a timeout
    # immediately and pays nothing. Every genuine hang this has caught (an
    # execve deadlock, a restarted timeout that never expired) reproduced on
    # every attempt, so a second one still fails. The retry samples to its own
    # file so the first attempt's stack, taken in the state that produced the
    # timeout, survives.
    if [ "$harness_timed_out" -eq 1 ] && test_host_busy_since_mark; then

        # Informational, not a verdict: the test has not been decided yet, so
        # this must not advance the skip counter the summary reports.
        test_report info "$tool" " (timeout under host load; re-running)"
        hang_sample_arm "$tool" "$TEST_TIMEOUT" \
            "${BUILD_DIR:-build}/test-timeouts/$(basename "$tool")-hang-retry.txt"
        start_us=$(epoch_us)
        if output=$(timeout "$TEST_TIMEOUT" ${TEST_RUNNER[@]+"${TEST_RUNNER[@]}"} \
            "$(test_tool_path "$tool")" "$@" 2>&1); then
            rc=0
        else
            rc=$?
        fi
        end_us=$(epoch_us)
        elapsed_us=$((end_us - start_us))
        harness_timed_out=0
        if [ "$rc" -eq 124 ] && [ "$elapsed_us" -ge "$limit_us" ]; then
            harness_timed_out=1
        fi
        hang_sample_finish "$harness_timed_out"
    fi

    if [ "$harness_timed_out" -eq 1 ]; then
        test_report fail "$tool" " (timeout after ${TEST_TIMEOUT}s)"
        test_excerpt "$output"
        fail=$((fail + 1))
    elif [ "$rc" = "$expect_rc" ]; then
        detail=""
        [ "$expect_rc" -ne 0 ] && detail=" (exit $rc)"
        test_report ok "$tool" "$detail"
        pass=$((pass + 1))
    elif [ "$rc" -eq 124 ]; then
        test_report fail "$tool" " (timeout after ${TEST_TIMEOUT}s)"
        test_excerpt "$output"
        fail=$((fail + 1))
    else
        test_report fail "$tool" " (got $rc, expected $expect_rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

run_check()
{
    local tool="$1"
    shift
    local pattern="$1"
    shift
    local output rc

    if test_skip_missing_tool "$tool"; then
        return
    fi

    # See run() for the timeout-vs-expected ordering rationale. run_check has no
    # explicit expect_rc parameter (zero is implied), so any rc=124 here is
    # treated as a harness timeout.
    hang_sample_arm "$tool" "$TEST_TIMEOUT" \
        "${BUILD_DIR:-build}/test-timeouts/$(basename "$tool")-hang.txt"
    if output=$(timeout "$TEST_TIMEOUT" ${TEST_RUNNER[@]+"${TEST_RUNNER[@]}"} \
        "$(test_tool_path "$tool")" "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -eq 124 ]; then
        hang_sample_finish 1
    else
        hang_sample_finish 0
    fi

    if [ "$rc" -eq 124 ]; then
        test_report fail "$tool" " (timeout after ${TEST_TIMEOUT}s)"
        test_excerpt "$output"
        fail=$((fail + 1))
    elif [ "$rc" -ne 0 ]; then
        test_report fail "$tool" " (exit rc=$rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    elif grep -qE "$pattern" <<< "$output"; then
        test_report ok "$tool"
        pass=$((pass + 1))
    else
        test_report fail "$tool" " (pattern '$pattern' not found, rc=$rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

run_xfail()
{
    local tool="$1"
    shift
    local reason="$1"
    test_report xfail "$tool" " ($reason)"
    expected_fail=$((expected_fail + 1))
}

run_skip()
{
    local tool="$1"
    shift
    local reason="$1"
    test_report skip "$tool" " ($reason)"
    skip=$((skip + 1))
}

run_pipe()
{
    local tool="$1"
    shift
    local pattern="$1"
    shift
    local input="${1:-}"
    shift || true
    local output rc

    if test_skip_missing_tool "$tool"; then
        return
    fi

    hang_sample_arm "$tool" "$TEST_TIMEOUT" \
        "${BUILD_DIR:-build}/test-timeouts/$(basename "$tool")-hang.txt"
    if output=$(printf '%s' "$input" \
        | timeout "$TEST_TIMEOUT" ${TEST_RUNNER[@]+"${TEST_RUNNER[@]}"} "$(test_tool_path "$tool")" "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -eq 124 ]; then
        hang_sample_finish 1
    else
        hang_sample_finish 0
    fi

    if [ "$rc" -ne 0 ]; then
        test_report fail "$tool" " (exit rc=$rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    elif grep -qE "$pattern" <<< "$output"; then
        test_report ok "$tool"
        pass=$((pass + 1))
    else
        test_report fail "$tool" " (pattern '$pattern' not found, rc=$rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

# Deliberately does not arm the hang sampler. Its callers pass their own cap and
# an expected rc, and the coreutils suite expects rc=124 from the guest's own
# timeout(1), so a 124 here does not mean the harness watchdog fired. run()
# tells the two apart with elapsed wall time; this wrapper has no such marker,
# and a sampler armed on a timeout the caller intends to hit would collect on
# every pass.
run_timeout()
{
    local secs="$1"
    shift
    local tool="$1"
    shift
    local expect_rc="${1:-0}"
    shift || true
    local output rc

    if test_skip_missing_tool "$tool"; then
        return
    fi

    if output=$(timeout "$secs" ${TEST_RUNNER[@]+"${TEST_RUNNER[@]}"} "$(test_tool_path "$tool")" "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi

    if [ "$rc" = "$expect_rc" ]; then
        test_report ok "$tool"
        pass=$((pass + 1))
    else
        test_report fail "$tool" " (got $rc, expected $expect_rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

check_host()
{
    local label="$1"
    shift

    if "$@"; then
        test_report ok "$label"
        pass=$((pass + 1))
    else
        test_report fail "$label"
        fail=$((fail + 1))
    fi
}
