#!/usr/bin/env bash

# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "${1:-}" = "--emit" ]; then
    awk 'BEGIN {
        print "match-begin"
        # Keep output larger than pipe capacity to expose early-match SIGPIPE.
        for (i = 0; i < 30000; i++)
            print "abcdefghijklmnopqrstuvwxyz"
        print "match-end"
    }'
    exit "$2"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export TEST_SAMPLE_TIMEOUTS=0
TEST_RUNNER=("$BASH")
BIN="$SCRIPT_DIR"

# shellcheck source=tests/lib/test-runner.sh
. "$SCRIPT_DIR/lib/test-runner.sh"

checks=0
failures=0

expect_result()
{
    local runner="$1" label="$2" pattern="$3" rc="$4" want="$5"
    local output
    checks=$((checks + 1))
    # Each subshell inherits zero pass and fail counts and discards updates.
    if output=$(
        if [ "$runner" = run_pipe ]; then
            run_pipe test-runner.sh "$pattern" input --emit "$rc"
        else
            run_check test-runner.sh "$pattern" --emit "$rc"
        fi
        [ "$pass" -eq "$want" ] && [ "$fail" -eq "$((1 - want))" ]
    ); then
        printf 'PASS: %s %s\n' "$runner" "$label"
    else
        printf 'FAIL: %s %s\n%s\n' "$runner" "$label" "$output" >&2
        failures=$((failures + 1))
    fi
}

for runner in run_check run_pipe; do
    expect_result "$runner" early-match '^match-begin$' 0 1
    expect_result "$runner" late-match '^match-end$' 0 1
    expect_result "$runner" missing-pattern '^absent$' 0 0
    expect_result "$runner" failed-command '^match-begin$' 7 0
done

printf 'test-runner: %s checks, %s failures\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
