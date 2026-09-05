#!/usr/bin/env python3
"""Fail when a stub's rename-and-include_next trick would change a signature.

Two stubs take the modeled libc header whole and replace one name in it:
frama-c-stubs/sys/socket.h renames struct sockaddr_storage, and
frama-c-stubs/pthread.h renames pthread_setname_np. Both work only because the
modeled header names the thing exactly once, at its declaration. If a future
Frama-C grows a second use, in a prototype or another structure, the rename
follows it there too and quietly changes what that function takes or what that
field is, and nothing else in the tree would notice: the file still parses, the
proofs still discharge, and they are about a different program.

So the count is checked rather than assumed. One occurrence means the rename hit
the declaration and nothing else.

Skips rather than fails when Frama-C is absent, so a checkout without it can
still run the rest of the gates.

Usage:
    check-stub-shadow.py [--self-test]
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB_DIR = ROOT / "frama-c-stubs"

# The rename each shadow performs, and the modeled header it takes through
# include_next. Read from the stub itself rather than listed here: a stub that
# grows a second rename is covered without editing this file.
RENAME = re.compile(r"^#define\s+(\w+)\s+__fc_linux_\w+\s*$", re.M)
INCLUDE_NEXT = re.compile(r"^#include_next\s+<([^>]+)>\s*$", re.M)


def modeled_libc(framac):
    try:
        out = subprocess.run(
            [framac, "-print-share-path"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    path = pathlib.Path(out.stdout.strip()) / "libc"
    return path if path.is_dir() else None


def shadows():
    """(stub, renamed name, modeled header) for every rename-and-include_next."""
    for stub in sorted(STUB_DIR.rglob("*.h")):
        text = stub.read_text()
        target = INCLUDE_NEXT.search(text)
        if not target:
            continue
        for name in RENAME.findall(text):
            yield stub, name, target.group(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    # mk/verify.mk lets FRAMAC name the binary the proofs run under, and this
    # gate has to read that one's modeled libc. Probing a bare "frama-c" meant
    # an override sent the proofs to one installation and this check to another,
    # or to none: absent, it reports a clean skip, so the rename would go
    # unchecked with nothing saying so.
    ap.add_argument("--frama-c", default=os.environ.get("FRAMAC", "frama-c"))
    args = ap.parse_args()

    if args.self_test:
        # The regexes are the whole mechanism, so they are what the self-test
        # exercises: a rename is recognized, and a plain define is not.
        cases = [
            (
                "#define sockaddr_storage __fc_linux_sockaddr_storage\n",
                ["sockaddr_storage"],
            ),
            ("#define IPC_M 010000\n", []),
            (
                "#define pthread_setname_np __fc_linux_pthread_setname_np\n",
                ["pthread_setname_np"],
            ),
        ]
        for text, want in cases:
            got = RENAME.findall(text)
            if got != want:
                print(f"  self-test: {text.strip()!r} gave {got}, wanted {want}")
                return 1
        if INCLUDE_NEXT.findall("#include_next <sys/socket.h>\n") != ["sys/socket.h"]:
            print("  self-test: include_next not recognized")
            return 1
        print(f"  SHADOW   self-test: {len(cases) + 1} cases, all pass")
        return 0

    libc = modeled_libc(args.frama_c)
    if libc is None:
        print("  SHADOW   no frama-c; skipping (a run with it checks this)")
        return 0

    found = list(shadows())
    if not found:
        print(f"  no rename-and-include_next stubs under {STUB_DIR}")
        return 1

    bad = []
    for stub, name, header in found:
        modeled = libc / header
        if not modeled.is_file():
            bad.append((stub, name, header, None))
            continue
        # Whole-word, so sockaddr_storage does not count a match inside
        # __fc_linux_sockaddr_storage should one ever appear there.
        uses = len(re.findall(rf"\b{re.escape(name)}\b", modeled.read_text()))
        if uses != 1:
            bad.append((stub, name, header, uses))

    if bad:
        print("  a stub rename no longer hits exactly one declaration:")
        for stub, name, header, uses in bad:
            where = stub.relative_to(ROOT)
            if uses is None:
                print(f"    {where}: {header} is not in the modeled libc")
            else:
                print(f"    {where}: {name} appears {uses} times in {header}")
        print("  The rename follows every use, so a second one silently")
        print("  changes a signature the proofs then reason about. Reproduce")
        print("  the modeled header instead of renaming through it.")
        return 1

    print(f"  SHADOW   {len(found)} stub rename(s) hit exactly one declaration")
    return 0


if __name__ == "__main__":
    sys.exit(main())
