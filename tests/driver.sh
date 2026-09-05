#!/usr/bin/env bash

# driver.sh - Data-driven test driver for elfuse
#
# Copyright 2026 elfuse contributors
# Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/driver.sh [options] [test-name ...]
#
# Options:
#   -e ELFUSE    Path to elfuse binary (default: build/elfuse)
#   -d TESTDIR   Directory containing guest test binaries (default: build)
#   -t TIMEOUT   Per-test timeout in seconds (default: 60)
#   -f FILTER    Run only tests matching this grep pattern
#   -l           List available tests without running them
#   -v           Verbose: show test stdout/stderr on failure
#   -T           TAP output format
# If test-name arguments are given, only those tests run. The test list is read
# from tests/manifest.txt.

set -uo pipefail

ELFUSE="${ELFUSE:-build/elfuse}"
TESTDIR="${TESTDIR:-build}"
TIMEOUT="${TEST_TIMEOUT:-60}"
FILTER=""
SECTION=""
LIST_ONLY=0
VERBOSE=0
TAP=0

# Three values: 0 (strict, default), 1 (skip missing), auto (legacy). In strict
# mode any missing test binary is a FAIL. The legacy "auto" value flips to skip
# when TESTDIR is not the canonical build/ or build/bin tree, which used to
# silently turn a partial out-of-tree fixture set into a wall of green skips.
# Callers that genuinely want permissive-skip-mode behavior should set
# ALLOW_MISSING_BINARIES=1 explicitly.
ALLOW_MISSING_BINARIES="${ALLOW_MISSING_BINARIES:-0}"

usage()
{
    echo "Usage: $0 [-e elfuse] [-d testdir] [-t timeout] [-f filter] [-s section] [-l] [-v] [-T] [test ...]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -e)
            ELFUSE="${2:?missing argument for -e}"
            shift 2
            ;;
        -d)
            TESTDIR="${2:?missing argument for -d}"
            shift 2
            ;;
        -t)
            TIMEOUT="${2:?missing argument for -t}"
            shift 2
            ;;
        -s)
            SECTION="${2:?missing argument for -s}"
            shift 2
            ;;
        -f)
            FILTER="${2:?missing argument for -f}"
            shift 2
            ;;
        -l)
            LIST_ONLY=1
            shift
            ;;
        -v)
            VERBOSE=1
            shift
            ;;
        -T)
            TAP=1
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_LIST="$SCRIPT_DIR/manifest.txt"

# shellcheck source=tests/test-config.sh
source "$SCRIPT_DIR/test-config.sh"
source "$SCRIPT_DIR/lib/hang-sample.sh"
source "$SCRIPT_DIR/lib/bash-compat.sh" # test_host_busy_mark/_since_mark

# Capture a stack sample from a test about to hit the watchdog. A hang that only
# reproduces under suite load is otherwise reported as a bare "timeout after Ns"
# with nothing to diagnose. Runs detached, reads only, writes under build/. Set
# TEST_SAMPLE_TIMEOUTS=0 to turn it off.

case "$ELFUSE" in
    /*) ;;
    *) ELFUSE="$REPO_ROOT/$ELFUSE" ;;
esac

case "$TESTDIR" in
    /*) TESTDIR_ABS="$TESTDIR" ;;
    *) TESTDIR_ABS="$REPO_ROOT/$TESTDIR" ;;
esac

# Canonicalize before the auto-policy comparison so that equivalent paths
# (./build, symlinked build dir, trailing-slash) still resolve to the
# default-strict branch instead of silently flipping into allow-missing mode. If
# the dir does not exist yet, fall back to the raw string; the per-test "not
# built" check still fires later.
canonicalize()
{
    if [ -d "$1" ]; then
        (cd "$1" && pwd -P)
    else
        printf '%s' "$1"
    fi
}

if [ "$ALLOW_MISSING_BINARIES" = "auto" ]; then
    testdir_canon=$(canonicalize "$TESTDIR_ABS")
    build_canon=$(canonicalize "$REPO_ROOT/build")
    bin_canon=$(canonicalize "$REPO_ROOT/build/bin")
    if [ "$testdir_canon" = "$build_canon" ] \
        || [ "$testdir_canon" = "$bin_canon" ]; then
        ALLOW_MISSING_BINARIES=0
    else
        ALLOW_MISSING_BINARIES=1
    fi
fi

if [ ! -f "$TEST_LIST" ]; then
    echo "error: $TEST_LIST not found" >&2
    exit 1
fi

if [ ! -x "$ELFUSE" ] && [ "$LIST_ONLY" -eq 0 ]; then
    echo "error: $ELFUSE not found or not executable" >&2
    echo "  Build with: make elfuse" >&2
    exit 1
fi

if [ "$TAP" -eq 1 ] || [ ! -t 1 ]; then
    GREEN="" RED="" YELLOW="" RESET=""
else
    GREEN='\033[32m'
    RED='\033[31m'
    YELLOW='\033[1;33m'
    RESET='\033[0m'
fi

declare -a test_names=()
declare -a test_cmds=()
declare -a test_expected=()
declare -a test_stdout=()
declare -a test_sections=()
current_section="tests"

while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && [[ ! "$line" =~ ^\[section\] ]] && continue

    if [[ "$line" =~ ^\[section\][[:space:]]+(.+) ]]; then
        current_section="${BASH_REMATCH[1]}"
        continue
    fi

    expected=""
    stdout_pat=""
    if [[ "$line" =~ \#[^#]*expected_rc=([0-9]+) ]]; then
        expected="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ \#[^#]*stdout=([^[:space:]]+) ]]; then
        stdout_pat="${BASH_REMATCH[1]}"
    fi
    line="${line%%#*}"
    line="$(printf "%s" "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$line" ] && continue

    read -r binary _rest <<< "$line"
    name="$(basename "$binary")"

    test_names+=("$name")
    test_cmds+=("$line")
    test_expected+=("$expected")
    test_stdout+=("$stdout_pat")
    test_sections+=("$current_section")
done < "$TEST_LIST"

declare -a filtered_idx=()
if [ $# -gt 0 ]; then
    for arg in "$@"; do
        for i in "${!test_names[@]}"; do
            if [ "${test_names[$i]}" = "$arg" ]; then
                filtered_idx+=("$i")
            fi
        done
    done
    if [ ${#filtered_idx[@]} -eq 0 ]; then
        echo "error: no tests matched: $*" >&2
        exit 1
    fi
else

    # -f (name) and -s (section) are independent constraints; when both are set
    # a test must match both. Neither set selects everything.
    for i in "${!test_names[@]}"; do
        if [ -n "$FILTER" ] && ! printf "%s\n" "${test_names[$i]}" | grep -Eq "$FILTER"; then
            continue
        fi
        if [ -n "$SECTION" ] && ! printf "%s\n" "${test_sections[$i]}" | grep -Eq "$SECTION"; then
            continue
        fi
        filtered_idx+=("$i")
    done
    if [ ${#filtered_idx[@]} -eq 0 ] && {
        [ -n "$FILTER" ] || [ -n "$SECTION" ]
    }; then
        echo "error: no tests matched${FILTER:+ filter: $FILTER}${SECTION:+ section: $SECTION}" >&2
        exit 1
    fi
fi

if [ "$LIST_ONLY" -eq 1 ]; then
    prev_section=""
    for i in "${filtered_idx[@]}"; do
        if [ "${test_sections[$i]}" != "$prev_section" ]; then
            printf "%s\n" "${test_sections[$i]}"
            prev_section="${test_sections[$i]}"
        fi
        printf "  %s" "${test_names[$i]}"
        [ -n "${test_expected[$i]}" ] && printf " (expect rc=%s)" "${test_expected[$i]}"
        [ -n "${test_stdout[$i]}" ] && printf " (stdout=%s)" "${test_stdout[$i]}"
        printf "\n"
    done
    exit 0
fi

evaluate_result()
{
    local rc="$1"
    local expected="$2"
    local stdout_pat="$3"
    local output="$4"

    if [ "$rc" -eq 124 ]; then
        return 1
    fi

    # When the manifest declares expected_rc=N, only that exact rc passes.
    # Without this guard, a test that mistakenly exits 0 instead of its declared
    # non-zero code (e.g. test-complex with expected_rc=42) would be reported
    # PASS because rc=0 short-circuited the OR clause.
    if [ -n "$expected" ]; then
        if [ "$rc" -ne "$expected" ]; then
            return 1
        fi
    elif [ "$rc" -ne 0 ]; then
        return 1
    fi
    if [ -n "$stdout_pat" ] && ! grep -qE "$stdout_pat" <<< "$output"; then
        return 1
    fi
    return 0
}

# Run one test binary and record the outcome in rc and output.
#
# One function for the first attempt and the host-load retry both. Not tidiness:
# the two drifted the moment they were written apart, and the retry went in
# without the descriptor limit the first attempt applies, so a constrained test
# was re-run as a different test.
#
# ulimit runs in the subshell that produces output, and a failure to raise it
# exits that subshell with 125 rather than chaining into timeout. A && chain
# reports ulimit's own status, which the caller cannot tell from the binary's,
# and the binary never ran at all.
run_test_binary()
{
    local binary="$1" nofile="$2" sample="$3"
    shift 3

    hang_sample_arm "$binary" "$TIMEOUT" "$sample"
    if [ -n "$nofile" ]; then
        output=$(
            ulimit -n "$nofile" 2> /dev/null || exit 125
            exec timeout "$TIMEOUT" "$ELFUSE" "$binary" "$@" 2>&1
        )
        rc=$?
    else
        output=$(timeout "$TIMEOUT" "$ELFUSE" "$binary" "$@" 2>&1)
        rc=$?
    fi

    if [ "$rc" -eq 124 ]; then
        hang_sample_finish 1
    else
        hang_sample_finish 0
    fi
}

report_case()
{
    local state="$1"
    local name="$2"
    local detail="$3"

    case "$state" in
        ok) printf "%-45s [ ${GREEN}OK${RESET} ]%s\n" "$name" "$detail" ;;
        fail) printf "%-45s [ ${RED}FAIL${RESET} ]%s\n" "$name" "$detail" ;;
        skip) printf "%-45s [ ${YELLOW}SKIP${RESET} ]%s\n" "$name" "$detail" ;;

        # No bracketed verdict, because the test has not been decided yet and
        # every other state here is one the summary counts. The blanks are as
        # wide as the FAIL and SKIP tags, which is the closest a single width
        # gets: the verdicts do not share a column either (OK is 7 wide, FAIL
        # and SKIP 9).
        info) printf "%-45s %-8s%s\n" "$name" "" "$detail" ;;
    esac
}

print_failure_output()
{
    local output="$1"
    local prefix="$2"

    [ "$VERBOSE" -eq 1 ] && [ -n "$output" ] || return 0
    printf '%s\n' "$output" | sed "s/^/${prefix}/"
}

total=${#filtered_idx[@]}
pass=0
fail=0
skip=0
test_num=0

if [ "$TAP" -eq 1 ]; then
    echo "TAP version 14"
    echo "1..$total"
fi

prev_section=""

for i in "${filtered_idx[@]}"; do
    test_num=$((test_num + 1))
    name="${test_names[$i]}"
    cmd_line="${test_cmds[$i]}"
    expected="${test_expected[$i]}"
    stdout_pat="${test_stdout[$i]}"
    section="${test_sections[$i]}"

    read -r -a argv <<< "$cmd_line"
    binary="${argv[0]}"
    if [[ "$binary" != /* ]]; then
        binary="$TESTDIR_ABS/$binary"
    fi

    # bash 3.2 + set -u rejects "${argv[@]}" after 'unset argv[0]' has left the
    # array empty ("unbound variable"). The offset form "${argv[@]:1}" is
    # well-defined to produce zero elements when the array has only one slot, so
    # it works in every supported bash.
    args=()
    for arg in "${argv[@]:1}"; do
        arg="${arg//\$TESTDIR/$TESTDIR_ABS}"
        args+=("$arg")
    done

    if [ ! -f "$binary" ]; then
        if [ "$ALLOW_MISSING_BINARIES" -eq 1 ]; then
            if [ "$TAP" -eq 1 ]; then
                echo "ok $test_num - $name # SKIP binary not found"
            else
                if [ "$section" != "$prev_section" ]; then
                    printf "%s\n" "$section"
                    prev_section="$section"
                fi
                report_case skip "$name" ""
            fi
            skip=$((skip + 1))
            continue
        fi

        if [ "$TAP" -eq 1 ]; then
            echo "not ok $test_num - $name # missing binary: $binary"
        else
            if [ "$section" != "$prev_section" ]; then
                printf "%s\n" "$section"
                prev_section="$section"
            fi
            report_case fail "$name" " (missing binary)"
        fi
        fail=$((fail + 1))
        continue
    fi

    if [ "$TAP" -eq 0 ] && [ "$section" != "$prev_section" ]; then
        printf "%s\n" "$section"
        prev_section="$section"
    fi

    output=""

    # ${args[@]+...} guards the array expansion so a test with no extra
    # arguments (args=()) does not trip bash 3.2's set -u rejection of an empty
    # "${array[@]}". Host-limit annotations live in the manifest. Keep this
    # execution path generic so adding another constrained test does not require
    # a name-qualified branch here.
    test_host_busy_mark
    if host_nofile=$(elfuse_test_host_nofile "$TEST_LIST" "$name"); then
        run_test_binary "$binary" "$host_nofile" \
            "$TESTDIR_ABS/test-timeouts/$(basename "$binary")-hang.txt" \
            ${args[@]+"${args[@]}"}
    else
        output="invalid host_nofile test annotation"
        rc=125
    fi

    # A watchdog firing on a loaded machine reports the neighbours, not the
    # code. Re-run once, and only when the host really is busy, so an idle
    # machine still reports the timeout at once and pays nothing for this. Every
    # genuine hang the suite has caught reproduced on every attempt, so a second
    # timeout still fails.
    #
    # Its sample goes to a separate file. The first attempt's is the one taken
    # while the suite was in the state that produced the timeout, so it is the
    # one worth keeping.
    if [ "$rc" -eq 124 ] && test_host_busy_since_mark; then
        if [ "$TAP" -eq 1 ]; then
            echo "# $name timed out under host load; re-running"
        else
            report_case info "$name" "timed out under host load; re-running"
        fi
        run_test_binary "$binary" "$host_nofile" \
            "$TESTDIR_ABS/test-timeouts/$(basename "$binary")-hang-retry.txt" \
            ${args[@]+"${args[@]}"}
    fi

    if evaluate_result "$rc" "$expected" "$stdout_pat" "$output"; then
        passed=1
    else
        passed=0
    fi

    if [ "$TAP" -eq 1 ]; then
        if [ "$passed" -eq 1 ]; then
            echo "ok $test_num - $name"
            pass=$((pass + 1))
        elif [ "$rc" -eq 124 ]; then
            echo "not ok $test_num - $name # timeout after ${TIMEOUT}s"
            fail=$((fail + 1))
        else
            echo "not ok $test_num - $name # exit code $rc"
            print_failure_output "$output" "  # "
            fail=$((fail + 1))
        fi
    else
        if [ "$passed" -eq 1 ]; then
            if [ -n "$expected" ] && [ "$rc" -ne 0 ]; then
                report_case ok "$name" " (exit $rc)"
            else
                report_case ok "$name" ""
            fi
            pass=$((pass + 1))
        elif [ "$rc" -eq 124 ]; then
            report_case fail "$name" " (timeout after ${TIMEOUT}s)"
            fail=$((fail + 1))
        else
            report_case fail "$name" " (exit $rc)"
            print_failure_output "$output" "    "
            fail=$((fail + 1))
        fi
    fi
done

if [ "$TAP" -eq 0 ]; then
    if [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ]; then
        printf "  All %d tests passed\n" "$pass"
    else
        printf "  Results: %d passed, %d failed, %d skipped (of %d)\n" \
            "$pass" "$fail" "$skip" "$total"
    fi
fi

[ "$fail" -eq 0 ]
