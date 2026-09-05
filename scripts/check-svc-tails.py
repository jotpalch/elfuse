#!/usr/bin/env python3
"""Hold every HVC #5 return tail to the X7 ptrace test.

The host encodes a ptrace-stop request in X7 on the HVC #5 return and the shim
reads it in svc_hvc_restore_eret. A tail that reaches EL0 without passing
through that label drops a stop the host has already consumed, and the tracer
waits out its wait4 forever. Nothing in the compiler or the assembler notices,
because every spelling assembles.

Two live bugs had this exact shape, which is why this is a gate and not a
comment:

  exec_drop_frame never tested X7. That one is now deliberate (the host leaves
  X7 alone on the X8 == 2 tail, whose live registers are already the final EL0
  state) and is the single allowed exception below.

  tlbi_selective's defensive zero-count exit was "cbz x10, 1f", and 1f resolved
  to a numeric label sitting inside svc_restore_eret, past the test. A numeric
  local label is invisible to review in a way a named one is not, which is the
  second thing this checks.

The gate reads the dispatch region only: from the HVC #5 itself to the start of
svc_restore_eret. Every tail the host can select lives there. Numeric labels
inside that region are fine, and the selective-TLBI loop uses one; what is not
fine is a reference that resolves past the end of it.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHIM = ROOT / "src" / "core" / "shim.S"

REGION_START = re.compile(r"^\s*hvc\s+#5\b")
REGION_END = re.compile(r"^svc_restore_eret:")

LABEL = re.compile(r"^([A-Za-z_.][A-Za-z_0-9.]*):")
NUM_LABEL = re.compile(r"^(\d+):")
BRANCH = re.compile(r"^\s*(?:b|bl|b\.[a-z]+|cbz|cbnz|tbz|tbnz)\s+(.*)$")

# Transfers this script cannot follow: a register branch, and "ret", which
# leaves through X30 rather than through the tail. The shim has none today;
# one added here needs a different argument than "the branch targets look
# right".
INDIRECT = re.compile(r"^\s*(?:br|blr|ret)\b")

# Control leaves a tail only through one of these. Anything else as the last
# instruction before svc_restore_eret means the tail falls through into it,
# which reaches EL0 having skipped the X7 test just as surely as a branch would.
#
# "ret" is deliberately absent. It leaves through X30, which in this dispatch
# is a guest register restored from the saved frame, so it is neither a tail
# this gate can follow nor one that reaches the test.
TERMINAL = re.compile(r"^\s*(?:b|br|eret)\b(?!\.)")

# The gate label earns its name only while it still tests X7.
X7_TEST = re.compile(r"^\s*(?:cbz|cbnz)\s+x7\b")

GATE = "svc_hvc_restore_eret"
FORBIDDEN = "svc_restore_eret"

# The one tail allowed to skip the test, and why. Keep the reason with the name:
# an exception added later without one is the bug this gate exists to stop.
ALLOWED_SKIP = {
    "exec_drop_frame": "X8 == 2; the host takes that stop inline, never writes X7",
}


def branch_target(operands):
    """The label of a branch is its last comma-separated operand."""
    tail = operands.split(",")[-1].strip()
    return tail.split()[0] if tail else ""


def check(lines, path, counted=None):
    """Return a list of problem strings. Empty means the tails are sound.

    @counted, when a list, receives the number of tails reaching the test, so
    the caller does not walk the file again just to report it.
    """
    start = end = None
    for i, line in enumerate(lines):
        if start is None and REGION_START.match(line):
            start = i
        elif start is not None and REGION_END.match(line):
            end = i
            break
    if start is None:
        return [f"{path}: no 'hvc #5' found; the dispatch moved or was renamed"]
    if end is None:
        return [f"{path}: no '{FORBIDDEN}:' after the HVC #5; the tail moved"]

    named = {m.group(1): i for i, l in enumerate(lines) if (m := LABEL.match(l))}
    numeric = [
        (int(m.group(1)), i) for i, l in enumerate(lines) if (m := NUM_LABEL.match(l))
    ]

    problems = []

    # The whole gate rests on this label testing X7. Renaming or emptying it
    # would leave every tail branching somewhere that no longer checks.
    gate_at = named.get(GATE)
    if gate_at is None:
        problems.append(f"{path}: no '{GATE}:' label; the X7 tail is gone")
    elif not any(
        X7_TEST.match(lines[k])
        for k in range(gate_at + 1, min(gate_at + 6, len(lines)))
    ):
        problems.append(
            f"{path}:{gate_at + 1}: '{GATE}' no longer tests X7, so every tail "
            f"branching to it reaches EL0 unchecked"
        )

    # Fallthrough. The tail physically above svc_restore_eret reaches it with no
    # branch at all if its last instruction is not a transfer, and a branch walk
    # alone says nothing about that. Deleting one 'b svc_hvc_restore_eret' is the
    # whole of the mistake.
    last = None
    for i in range(start, end):
        body = LABEL.sub("", NUM_LABEL.sub("", lines[i])).strip()
        if not body or body.startswith(("/*", "*", "//", ".")):
            continue
        last, last_body = i, body
    if last is None:
        problems.append(f"{path}: the HVC #5 dispatch has no instructions")
    elif not TERMINAL.match(" " + last_body) and not INDIRECT.match(
        " " + last_body
    ):
        problems.append(
            f"{path}:{last + 1}: the last instruction of the HVC #5 dispatch is "
            f"'{last_body}', so control falls through into "
            f"{FORBIDDEN} without the X7 test. End the tail with an explicit "
            f"'b {GATE}'."
        )

    for i in range(start, end):
        if INDIRECT.match(lines[i]):
            problems.append(
                f"{path}:{i + 1}: register branch in the HVC #5 dispatch; this "
                f"gate cannot follow it, so the X7 test cannot be shown to be "
                f"reached."
            )

    # A numeric label on svc_restore_eret is what let a stray "1f" land past the
    # test. Numeric labels inside the dispatch are fine; the branch walk below
    # proves each reference resolves in the region rather than assuming it.
    for value, at in numeric:
        if at == end + 1:
            problems.append(
                f"{path}:{at + 1}: numeric label '{value}:' on {FORBIDDEN}. A "
                f"'{value}f' anywhere in the tail above resolves here and skips "
                f"the X7 test, which is how one live bug got in. Leave this "
                f"label named."
            )

    for i in range(start, end):
        m = BRANCH.match(lines[i])
        if not m:
            continue
        target = branch_target(m.group(1))
        if not target:
            continue
        where = f"{path}:{i + 1}"

        if target == FORBIDDEN:
            problems.append(
                f"{where}: branches to {FORBIDDEN}, skipping the X7 ptrace "
                f"test. Branch to {GATE} instead; it tests X7 and falls through "
                f"to {FORBIDDEN}."
            )
            continue

        if target == GATE:
            continue

        if target in ALLOWED_SKIP:
            # Only the X8 == 2 edge is exempt, not the label. An unconditional
            # branch here, or one not guarded by that compare, reaches a tail
            # that never restores the frame from a path where the host did
            # write X7.
            guarded = lines[i].strip().startswith("b.eq") and any(
                re.match(r"\s*cmp\s+x8,\s*#2\b", lines[j])
                for j in range(max(start, i - 4), i)
            )
            if not guarded:
                problems.append(
                    f"{where}: reaches '{target}' other than through the "
                    f"'cmp x8, #2' / 'b.eq' edge. That tail never restores the "
                    f"frame, so a path where the host wrote X7 must not get "
                    f"there."
                )
            continue

        if num := re.fullmatch(r"(\d+)([fb])", target):
            value, direction = int(num.group(1)), num.group(2)
            candidates = [at for v, at in numeric if v == value]
            if direction == "f":
                dest = min((at for at in candidates if at > i), default=None)
            else:
                dest = max((at for at in candidates if at < i), default=None)
            if dest is None:
                problems.append(f"{where}: '{target}' resolves to nothing")
            elif not start <= dest < end:
                problems.append(
                    f"{where}: '{target}' resolves to line {dest + 1}, outside "
                    f"the HVC #5 dispatch, so it leaves EL1 without the X7 "
                    f"test. Branch to {GATE} or to a named label in the tail."
                )
            continue

        at = named.get(target)
        if at is None:
            problems.append(f"{where}: unknown branch target '{target}'")
        elif not start <= at < end:
            problems.append(
                f"{where}: branches out of the HVC #5 dispatch to '{target}', "
                f"which does not test X7. Every tail must reach {GATE}; add "
                f"'{target}' to ALLOWED_SKIP in this script, with the reason, "
                f"if it is genuinely exempt."
            )

    if counted is not None:
        counted.append(
            sum(
                1
                for i in range(start, end)
                if (m := BRANCH.match(lines[i]))
                and branch_target(m.group(1)) == GATE
            )
        )

    return problems


def _shim(tail):
    """Wrap a dispatch tail in the minimum surrounding shape."""
    return (
        ["handle_svc_0:", "    hvc #5", "    cbz x8, svc_hvc_restore_eret"]
        + tail
        + [
            "svc_restore_eret:",
            "    RESTORE_GPRS_KEEP_X0",
            "    eret",
            "svc_hvc_restore_eret:",
            "    cbz x7, svc_restore_eret",
            "    b svc_restore_eret",
            "exec_drop_frame:",
            "    eret",
        ]
    )


CASES = [
    ("clean dispatch", _shim(["tlbi_full:", "    b svc_hvc_restore_eret"]), 0),
    (
        "tail branching straight to the restore",
        _shim(["tlbi_full:", "    b svc_restore_eret"]),
        1,
    ),
    (
        "numeric forward reference escaping the region",
        [
            "handle_svc_0:",
            "    hvc #5",
            "    cbz x10, 1f",
            "    b svc_hvc_restore_eret",
            "svc_restore_eret:",
            "1:",
            "    eret",
            "svc_hvc_restore_eret:",
            "    cbz x7, svc_restore_eret",
            "    eret",
        ],
        2,
    ),
    (
        "in-region loop label is not a finding",
        _shim(
            [
                "tlbi_selective:",
                "    cbz x10, svc_hvc_restore_eret",
                "3:  tlbi vae1is, x11",
                "    b.ne 3b",
                "    b svc_hvc_restore_eret",
            ]
        ),
        0,
    ),
    (
        "documented exception is allowed",
        _shim(
            [
                "tlbi_full:",
                "    cmp x8, #2",
                "    b.eq exec_drop_frame",
                "    b svc_hvc_restore_eret",
            ]
        ),
        0,
    ),
    (
        "tail falling through into the restore",
        [
            "handle_svc_0:",
            "    hvc #5",
            "    cbz x8, svc_hvc_restore_eret",
            "tlbi_full:",
            "    isb",
            "svc_restore_eret:",
            "    eret",
            "svc_hvc_restore_eret:",
            "    cbz x7, svc_restore_eret",
            "    eret",
        ],
        1,
    ),
    (
        "register branch cannot be cleared",
        _shim(["tlbi_full:", "    br x16"]),
        1,
    ),
    (
        "branch out to an unrelated handler",
        _shim(["tlbi_full:", "    b handle_brk"]) + ["handle_brk:", "    eret"],
        1,
    ),
    ("no dispatch at all", ["_start:", "    ret"], 1),
    (
        "tail leaving through ret",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret", "other:", "    ret"]),
        1,
    ),
    (
        "unconditional branch to the exempt tail",
        _shim(["tlbi_full:", "    b exec_drop_frame"]),
        1,
    ),
    (
        "the X8 == 2 edge is still allowed",
        _shim(
            [
                "tlbi_full:",
                "    cmp x8, #2",
                "    b.eq exec_drop_frame",
                "    b svc_hvc_restore_eret",
            ]
        ),
        0,
    ),
    (
        "gate label emptied of its X7 test",
        [
            "handle_svc_0:",
            "    hvc #5",
            "    cbz x8, svc_hvc_restore_eret",
            "    b svc_hvc_restore_eret",
            "svc_restore_eret:",
            "    eret",
            "svc_hvc_restore_eret:",
            "    b svc_restore_eret",
        ],
        1,
    ),
]


def self_test():
    print("  SVCTAIL self-test", flush=True)
    failures = 0
    for name, lines, expected in CASES:
        got = len(check(lines, "<case>"))
        if got != expected:
            print(f"  FAIL {name}: expected {expected} problem(s), got {got}")
            failures += 1
    if failures:
        print(f"  self-test: {failures} of {len(CASES)} cases failed")
        return 1
    print(f"  self-test: {len(CASES)} cases, all pass")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--self-test", action="store_true", help="run the checker's own cases"
    )
    if parser.parse_args().self_test:
        return self_test()

    counted = []
    problems = check(SHIM.read_text().splitlines(), str(SHIM), counted)
    print(f"  SVCTAIL {SHIM.relative_to(ROOT)}", flush=True)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            f"\n  {len(problems)} HVC #5 tail(s) can reach EL0 without the X7 "
            f"ptrace test.",
            file=sys.stderr,
        )
        return 1

    print(
        f"  {counted[0]} HVC #5 tail(s) reach the X7 test, "
        f"{len(ALLOWED_SKIP)} documented exception"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
