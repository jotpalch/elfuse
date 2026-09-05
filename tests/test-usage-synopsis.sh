#!/usr/bin/env bash

# test-usage-synopsis.sh -- Pin the usage synopsis renderings against drift
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-usage-synopsis.sh <elfuse-binary>
#
# main() prints its usage synopsis at three sites: the --help block, the
# unknown-option error, and the missing-elf-path error. They were once three
# hand-maintained string literals and had drifted; the missing-elf-path copy
# predated the GDB stub and never learned [--gdb PORT] [--gdb-stop-on-entry], so
# the most common error path advertised an incomplete flag set. All three now
# expand ELFUSE_USAGE_BODY, which --help renders wrapped and the error paths
# render flat.
#
# Rather than sample the flag list, which is what let the old copies drift
# unnoticed, this compares the renderings against each other: a flag reaching
# one site and not another fails regardless of which flag it is. Asserted:
#
#   1. --help's wrapped synopsis, with its line breaks and indent collapsed
#      back to single spaces, is byte-identical to the flat form both error
#      paths print. This is the oracle the drift bug would have failed.
#   2. The two error paths print the same flat line as each other.
#   3. Every printed --help synopsis line fits 80 columns, and continuation
#      lines align under the first line's flags. log_error stamps a prefix on
#      the first line only, so the error paths must stay one line and are
#      checked for exactly that.
#
# A regression re-splits the sites into independent literals, or rewraps the
# synopsis past 80 columns, and this fails without needing to know the flags.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Labels here are sentences rather than tool names, so widen the column past the
# library default before report.sh reads it.
TEST_LABEL_WIDTH="${TEST_LABEL_WIDTH:-50}"
# shellcheck source=tests/lib/report.sh
. "$SCRIPT_DIR/lib/report.sh"

# report_pass / report_skip in tests/lib/report.sh increment these; only fail is
# read directly, by the exit status at the bottom.
# shellcheck disable=SC2034
pass=0
fail=0
# shellcheck disable=SC2034
skip=0

# Compare one rendering against another and report through the shared emitter,
# so this suite lines up with the rest of make check's output.
check()
{
    local label="$1" want="$2" got="$3"
    if [ "$want" = "$got" ]; then
        report_pass "$label"
    else
        report_fail "$label"
        printf '  want: %s\n' "$want" >&2
        printf '  got:  %s\n' "$got" >&2
    fi
}

# The synopsis block runs from the "usage:" line to the first blank line. awk
# reads to EOF rather than exiting there: an early exit closes the pipe while
# elfuse is still writing --help, and under pipefail that SIGPIPE fails the run.
# done latches at the first blank line so a later line starting with "usage: "
# cannot re-arm the block, which is what exiting used to guarantee.
help_block="$("$ELFUSE" --help |
    awk '/^usage: / && !done {f = 1} f && !NF {f = 0; done = 1} f {print}')"

# Collapsing runs of whitespace undoes the wrap without assuming how many lines
# it takes or where the breaks fall, so re-grouping the flags is not a failure
# while dropping or renaming one is.
help_flat="$(printf '%s\n' "$help_block" | tr '\n' ' ' | tr -s ' ')"
help_flat="${help_flat% }"

# Both error paths write through log_error, whose "HH:MM:SS ERROR file:line: "
# prefix is stripped by cutting at the "usage:" the synopsis starts with.
usage_line_of()
{
    sed -n 's/.*\(usage: elfuse .*\)$/\1/p'
}

# Both argument errors exit nonzero, which under `set -e -o pipefail` would
# abort the script before a single check ran; capture the status instead so a
# changed exit code is asserted rather than fatal.
no_args_err="$("$ELFUSE" 2>&1 || true)"
no_args_err="$(printf '%s\n' "$no_args_err" | usage_line_of)"
bad_flag_err="$("$ELFUSE" --no-such-flag 2>&1 || true)"
bad_flag_err="$(printf '%s\n' "$bad_flag_err" | usage_line_of)"

check "--help wrapped form unwraps to the flat form" "$help_flat" "$no_args_err"
check "both error paths print one flat synopsis" "$no_args_err" "$bad_flag_err"

# One line each: a wrapped string would print ragged under the log prefix.
check "missing-elf-path error is a single line" "1" \
    "$(printf '%s\n' "$no_args_err" | grep -c .)"
check "unknown-option error is a single line" "1" \
    "$(printf '%s\n' "$bad_flag_err" | grep -c .)"

# 80 columns is the width every --help reader is assumed to have; a longer line
# wraps at an arbitrary column and defeats the alignment below.
over80="$(printf '%s\n' "$help_block" | awk 'length($0) > 80' | wc -l | tr -d ' ')"
check "every --help synopsis line fits 80 columns" "0" "$over80"

# Continuation lines are indented to the column after "usage: elfuse ", so the
# flags form one block under the first line's.
indent="$(printf '%s' 'usage: elfuse ' | wc -c | tr -d ' ')"
misaligned="$(printf '%s\n' "$help_block" | awk -v n="$indent" \
    'NR > 1 && substr($0, 1, n) != sprintf("%*s", n, "")' | wc -l | tr -d ' ')"
check "continuation lines align under the flags" "0" "$misaligned"

# More than one line proves the wrap is real; a single-line --help synopsis is
# the regression that made the flags unscannable on an 80-column terminal.
lines="$(printf '%s\n' "$help_block" | grep -c .)"
check "--help wraps the synopsis over several lines" "yes" \
    "$([ "$lines" -gt 1 ] && echo yes || echo "no ($lines line)")"

report_summary
[ "$fail" -eq 0 ]
