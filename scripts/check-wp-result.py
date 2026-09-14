#!/usr/bin/env python3
"""Turn a Frama-C WP log into a pass/fail verdict for `make verify-*`.

Frama-C's own "Proved goals: N / M" line is not sufficient evidence on its
own, so this applies four independent gates before reporting success:

  1. The process exited 0. A crashed run can still have printed a summary.
  2. No "User Error" appeared, which means the input was rejected outright.
  3. At least --min-goals obligations were GENERATED. An emptied function body
     or a dropped contract proves 0 of 0, and that is not a proof.
  4. Every generated obligation was discharged.

Lives outside the makefile because the same logic written as a shell recipe
needs every `$` doubled and every line continued, which is how it grew past
80 columns and out of reach of any test.

Usage:
    check-wp-result.py --log FILE --status N --min-goals N --src FILE \
                       --unproved TEXT
"""

import argparse
import re
import sys

RED = "\033[0;31m"
GREEN = "\033[0;32m"
RESET = "\033[0m"

# An obligation WP could not discharge. The goal name carries a memory-model
# prefix that varies per proof and says nothing about which function is open,
# so strip it and report the bare name.
OPEN_GOAL = re.compile(
    r"^\[wp\] \[(Timeout|Stepout|Unknown|Failed)\] "
    r"(?:typed_caveat_|typed_|bytes_)?([A-Za-z0-9_]+)"
)

# Timeout and Stepout are the prover giving up on the clock or the step budget,
# not a counterexample. They say nothing about whether the goal holds, so they
# get their own advice below rather than the read-the-suffix key.
RESOURCE_VERDICTS = {"Timeout", "Stepout"}

PROVED_GOALS = re.compile(r"^\[wp\] Proved goals: *([0-9]+) / ([0-9]+)$")

# Everything up to and including a "User Error:" marker, so the message can be
# reprinted without its channel prefix. The gate itself is the looser substring
# "User Error": a report this cannot reformat must still fail the run.
USER_ERROR = re.compile(r"^.*User Error: *")

# A function WP took on faith: it generated a spec instead of analyzing a body.
# Frama-C words this two ways and the difference matters. "Neither code nor
# explicit exits and terminates" leaves a hand-written assigns in force;
# "Neither code nor specification" generates the frame too, which is the
# stronger assumption and was the one this pattern used to miss. log_impl came
# through that second wording, so every proof of a function that logs rested on
# an invented assigns \nothing that no report named.
ASSUMED = re.compile(
    r"Neither code nor (?:explicit|specification).* for function "
    r"([A-Za-z_][A-Za-z_0-9]*),"
)

# Printed verbatim under their respective banners. Kept as literal blocks
# rather than a run of print() calls so the alignment that makes them readable
# survives any reformatting.
MIN_GOALS_HINT = """\
           a gutted function body or a dropped contract proves trivially;
           raise VERIFY_*_MIN_GOALS when adding proved functions\
"""

RESOURCE_HINT = """\
           %d of the open obligations above are prover resource limits
           (%s), which say nothing about whether the goal holds. A loaded
           host is the usual cause; measure before concluding anything."""

# WP memoizes a verdict per goal, and a Timeout is memoized like any other, so
# one run on a loaded host leaves the target red on every later run including
# on an idle one. Nothing in the output says the verdict is a replay unless the
# prover line is read, which is why this names the way out.
CACHED_HINT = """\
           At least one came from the WP cache in .frama-c/ rather than from a
           prover run this time. The cache stores a timeout as if it were a
           result, so the verdict outlives the load that caused it. Re-run the
           target with FRAMAC_WP_CACHE=rebuild before reading anything into it."""

SUFFIX_KEY = """\
           Each open obligation named above is either a real defect or an
           ACSL contract too weak to justify the code. Read the suffix:
             <fn>_ensures[_N]           postcondition N does not hold
             <fn>_assigns_*             the function writes outside its frame
             <fn>_assert_rte_*          a runtime error is reachable (overflow,
                                        out-of-bounds, invalid dereference)
             <fn>_call_<g>_requires_*   a precondition of callee <g> is not met\
"""


def unproven(reason):
    """Print @reason under an UNPROVEN banner and return the failure status."""
    print("  %sUNPROVEN%s %s" % (RED, RESET, reason))
    return 1


def open_goals(lines):
    """Return [(verdict, goal, cached)] for every obligation WP left open."""
    found = []
    for line in lines:
        if match := OPEN_GOAL.match(line):
            found.append((match.group(1), match.group(2), "(Cached)" in line))
    return found


def report(log_path, lines, status, min_goals, src, unproved):
    """Verdict for one proof. Returns the process exit status."""
    opened = open_goals(lines)
    for verdict, goal, cached in opened:
        suffix = " [%s%s]" % (verdict, ", cached" if cached else "")
        print("          open: %s%s" % (goal, suffix))

    if status != 0:
        rc = unproven("frama-c exited %s; its own summary is not trusted" % status)
        print("           full output: %s" % log_path)
        return rc

    if any("User Error" in line for line in lines):
        unproven("frama-c rejected the input:")
        for error in sorted(
            {USER_ERROR.sub("", line) for line in lines if USER_ERROR.match(line)}
        ):
            print("           %s" % error)
        return 1

    counts = next((m for m in map(PROVED_GOALS.match, lines) if m), None)
    if not counts:
        rc = unproven("Frama-C emitted no result; it likely failed to run")
        print("           full output: %s" % log_path)
        return rc

    proved, total = int(counts.group(1)), int(counts.group(2))

    if total < min_goals:
        rc = unproven(
            "only %d obligations generated, expected at least %d" % (total, min_goals)
        )
        print(MIN_GOALS_HINT)
        return rc

    if proved != total:
        rc = unproven(
            "%d of %d proof obligations discharged, %d left open"
            % (proved, total, total - proved)
        )
        resource = [g for g in opened if g[0] in RESOURCE_VERDICTS]
        if resource:
            kinds = ", ".join(sorted({g[0] for g in resource}))
            print(RESOURCE_HINT % (len(resource), kinds))
            if any(g[2] for g in resource):
                print(CACHED_HINT)
        # Compared against the count WP reported, not against the lines that
        # parsed. An open obligation this could not classify still needs the
        # key, and measuring against @opened would let one parsed timeout
        # suppress the guidance for a second goal nobody read.
        if len(resource) < total - proved:
            print(SUFFIX_KEY)
        print("           Full prover output: %s" % log_path)
        return rc

    print(
        "  %sPROVED%s   %d of %d proof obligations discharged by alt-ergo/z3"
        % (GREEN, RESET, proved, total)
    )
    assumed = sorted({m.group(1) for m in map(ASSUMED.search, lines) if m})
    if assumed:
        print(
            "           assumed (spec generated, body not analyzed): %s"
            % "".join(name + " " for name in assumed)
        )
    print("           (holds for the ACSL contracts in %s;" % src)
    print("            %s, not proved)" % unproved)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, help="Frama-C output file")
    parser.add_argument(
        "--status", type=int, required=True, help="exit status of the frama-c run"
    )
    parser.add_argument(
        "--min-goals", type=int, required=True, help="floor on obligations generated"
    )
    parser.add_argument("--src", required=True, help="proved source file")
    parser.add_argument(
        "--unproved", required=True, help="what this proof does NOT cover"
    )
    args = parser.parse_args()

    with open(args.log, encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()

    return report(args.log, lines, args.status, args.min_goals, args.src, args.unproved)


if __name__ == "__main__":
    sys.exit(main())
