#!/usr/bin/env python3
"""Emit the verify_profiles JSON that frama-c-mcp loads and proves under.

The point of emitting it rather than writing it by hand is that it cannot then
drift from the command that decides. Every field here is the same make variable
the verify-<name> recipe consumes, so a profile and a "make verify-<name>" run
prove the same functions, over the same sources, under the same model.

Make expands the per-target variables and passes them in; this only assembles
JSON, which make cannot quote correctly on its own.
"""

import argparse
import json
import os
import shlex
import sys


def split_defines(raw, target):
    """Strip the -D that make carries and the schema refuses.

    shlex rather than str.split so -DMSG="two words" survives as one define
    instead of becoming two. A token that is not a -D is refused rather than
    passed through: the schema takes defines only, and a -U or a -include
    arriving here would be recorded as a macro named "-Ufoo".
    """
    try:
        toks = shlex.split(raw)
    except ValueError as exc:
        # shlex raises on an unbalanced quote. Uncaught it is a traceback out
        # of a make recipe, which names this file's internals rather than the
        # VERIFY_<T>_CPP_DEFS that produced it.
        sys.exit(f"target {target!r}: cannot split CPP_DEFS {raw!r}: {exc}")
    out = []
    for tok in toks:
        if not tok.startswith("-D"):
            sys.exit(f"target {target!r}: {tok!r} in CPP_DEFS is not a -D define")
        out.append(tok[2:])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--machdep", required=True)
    ap.add_argument("--provers", required=True)
    ap.add_argument("--timeout", required=True, type=int)
    ap.add_argument("--include-paths", required=True)
    ap.add_argument("--force-includes", required=True)
    ap.add_argument("--isystem-paths", default="")
    ap.add_argument(
        "--build-gates",
        default="",
        help="checks the verify-<name> recipe runs that a consumer of these "
        "profiles does not",
    )
    ap.add_argument(
        "--nostdinc",
        action="store_true",
        help="the recipe drops the default system include directories",
    )
    ap.add_argument(
        "--target",
        action="append",
        default=[],
        help="name|sources|functions|model|min_goals|cpp_defs",
    )
    args = ap.parse_args()

    include_paths = args.include_paths.split()
    force_includes = args.force_includes.split()
    isystem_paths = args.isystem_paths.split()
    build_gates = args.build_gates.split()

    # Refused rather than emitted empty, like the rest. -nostdinc with nowhere
    # to find a libc is not a configuration any recipe means, and a profile
    # claiming it would never match the load the recipe makes.
    if args.nostdinc and not isystem_paths:
        sys.exit("--nostdinc with no --isystem-paths; check FRAMAC_ISYSTEM_DIRS")

    # The emptiness test above cannot see the failure it was written for.
    # FRAMAC_ISYSTEM_DIRS is a shell substitution with a literal "/libc" glued
    # to it, so a frama-c that is missing or answers nothing yields the
    # non-empty, nonexistent "/libc" and the profile is emitted with exit 0.
    # Ask the filesystem instead, which is the only thing that distinguishes a
    # resolved share path from a stub of one.
    for path in isystem_paths:
        if not os.path.isdir(path):
            sys.exit(
                f"--isystem-paths {path!r} is not a directory; check "
                "FRAMAC_ISYSTEM_DIRS and whether $(FRAMAC) resolves"
            )
    provers = args.provers.replace(",", " ").split()

    # Refused for the reason the per-target fields below are. A profile with a
    # blank machdep, no provers, or a non-positive timeout still registers and
    # still loads sources, and is then refused at every run_wp and every stored
    # conclusion naming it, which reads as a broken target rather than as the
    # empty variable on the command line that emitted it. machdep gets the same
    # treatment as model and for the same reason: any value defaulted here
    # would be one the recipe does not pass.
    machdep = args.machdep.strip()
    if not machdep:
        sys.exit("no machdep; check FRAMAC_DATA_MODEL")
    if not provers:
        sys.exit("no provers; check FRAMAC_PROVERS")
    if args.timeout <= 0:
        sys.exit(f"timeout {args.timeout} is not positive; check FRAMAC_TIMEOUT")

    profiles = {}
    for spec in args.target:
        # Bounded so the last field absorbs any further separator. Defines are
        # last precisely because a -D value may legitimately contain one, as
        # -DFLAGS=(A|B) does; the fields before it cannot.
        parts = spec.split("|", 5)
        if len(parts) != 6:
            sys.exit(f"malformed --target: {spec!r}")
        name, sources, functions, model, min_goals, defines = parts
        if not name:
            sys.exit(f"--target with no name: {spec!r}")

        # Refused rather than emitted empty. The server needs both to check a
        # run or a conclusion against this target, and a profile carrying
        # neither would register a name that silently never matches. A target
        # whose _FCTS or _SRC went missing in mk/verify.mk fails here instead.
        source_list = sources.split()
        function_list = functions.split()
        if not source_list:
            sys.exit(f"target {name!r} has no sources; check VERIFY_*_SRC")
        if not function_list:
            sys.exit(f"target {name!r} has no functions; check VERIFY_*_FCTS")

        # Not defaulted. Any spelling chosen here would be one the recipe does
        # not pass, and the profile would then prove under a model the target
        # does not use.
        model_name = model.strip()
        if not model_name:
            sys.exit(f"target {name!r} has no model; check VERIFY_*_MODEL")

        # Refused rather than emitted absent: every target in mk/verify.mk
        # carries one, so a missing value means the block was edited wrong, and
        # a profile without it silently drops the check.
        try:
            floor = int(min_goals)
        except ValueError:
            sys.exit(f"target {name!r} has no min_goals; check VERIFY_*_MIN_GOALS")
        if floor <= 0:
            sys.exit(
                f"target {name!r} has min_goals {floor}; a floor of zero checks nothing"
            )

        profiles[name] = {
            "sources": source_list,
            "functions": function_list,
            # Stored stripped, matching the check above. The server compares
            # the model string against the one the receipt records, so a
            # trailing space in a VERIFY_*_MODEL assignment would make every
            # run under this profile fail to be evidence about its own target.
            "model": model_name,
            "machdep": machdep,
            "include_paths": include_paths,
            "defines": split_defines(defines, name),
            "force_includes": force_includes,
            "isystem_paths": isystem_paths,
            # The floor on obligations generated. "N of N discharged" is not
            # evidence on its own: an emptied body or a dropped contract
            # discharges 0 of 0, and this is the only check that catches it.
            "min_goals": floor,
            # Named, not exported: a consumer of these profiles runs Frama-C,
            # not the recipe, so these checks do not happen there.
            "build_gates": build_gates,
            # Recorded because it decides which declarations a file is compiled
            # against: without it the host's real headers shadow the modeled
            # libc and the same source is a different program.
            "nostdinc": args.nostdinc,
            "provers": provers,
            "timeout_seconds": args.timeout,
            # Every verify-<name> recipe passes -wp-rte. Recorded because it
            # decides which obligations exist at all, so a run without it
            # discharges a strictly smaller set than the target proves.
            "rte": True,
            "reproduce": f"make verify-{name}",
        }

    # An empty set emits valid JSON that the server then refuses whole, naming
    # neither this script nor the variable that came up empty. Fail where the
    # cause is still visible.
    if not profiles:
        sys.exit("no targets; check VERIFY_TARGETS in mk/verify.mk")

    json.dump(profiles, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
