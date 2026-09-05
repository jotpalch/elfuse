#!/usr/bin/env python3
"""Fail when a stub constant disagrees with the macOS SDK it claims to copy.

frama-c-stubs/macos-libc.h supplies Darwin constants Frama-C's portable libc
omits, and its header says the values are the real ones rather than
placeholders. That claim was wrong the day it was written: ETOOMANYREFS was
given 62, which is Darwin's ELOOP, and both are arms of the same linux_errno()
switch. Nothing caught it, because nothing was checking.

The analyzer never links against the SDK, so a wrong value cannot break a
build. It quietly changes what the proofs reason about instead: two arms of a
walked switch sharing a value makes one of them look unreachable, and a proof
over that switch is then about a program nobody ships.

Skips rather than fails when no SDK is present, so a Linux checkout can still
run the rest of the gates. A macOS CI run has one.

Usage:
    check-stub-constants.py [--stub PATH]
"""

import argparse
import os
import pathlib
import re
import subprocess
import tempfile
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB_DIR = ROOT / "frama-c-stubs"

# Only object-like defines with an integer value. A macro with parameters or a
# non-numeric body is not a constant this can compare, and is reported as
# unchecked rather than silently passed.
# Any object-like define, not just the ones whose body is a bare literal. A
# body this cannot turn into an integer is not skipped: it goes to the compile
# probe below, because a constant the gate cannot read is exactly the one that
# drifts unnoticed. RLIM_INFINITY, RLIMIT_RSS and RUSAGE_CHILDREN were
# invisible here while the file's own comment claimed the SDK held them.
# Same line only: "\s" spans newlines, so a bodyless include guard would
# otherwise swallow the line after it and read as a constant. A body ending in
# a backslash is a multi-line macro, which is a derived value rather than a
# mirrored constant.
DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Z_][A-Z_0-9]*)[ \t]+([^\n\\]+?)[ \t]*$",
    re.M,
)

LITERAL = re.compile(r"^\(?\s*(-?)\s*(0[xX][0-9a-fA-F]+|\d+)\s*\)?$")


def c_int(token):
    """Value of a C integer literal, octal and a wrapping minus included.

    int(token, 0) is not this function: Python rejects a leading zero, and
    Darwin writes whole families that way. TIOCM_DTR is 0002 in sys/ioccom.h,
    so a gate using int(_, 0) does not report a mismatch on it, it raises
    ValueError and takes the build down with a traceback.
    """
    m = LITERAL.match(token.strip())
    if not m:
        raise ValueError(token)
    sign, text = (-1 if m.group(1) else 1), m.group(2).lower()
    if text.startswith("0x"):
        return sign * int(text, 16)
    if len(text) > 1 and text.startswith("0"):
        return sign * int(text, 8)
    return sign * int(text, 10)


def sdk_path():
    try:
        out = subprocess.run(
            ["xcrun", "--show-sdk-path"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    path = pathlib.Path(out.stdout.strip()) if out.returncode == 0 else None
    return path if path and (path / "usr" / "include").is_dir() else None


def sdk_mentions(search_dirs, names):
    """Names the SDK mentions at all, however it spells them.

    The value check below can only compare object-like defines. Hypervisor
    declares its constants as enumerators, so a grep for #define finds nothing
    and every one of them would read as a name the SDK does not have, which is
    the report reserved for a typo. Splitting the two questions keeps that
    report meaningful: a name the SDK mentions but does not #define is an
    enumerator this cannot value-check, while a name it never mentions is
    wrong whatever the spelling.
    """
    pattern = r"\b(" + "|".join(names) + r")\b"
    hit = subprocess.run(
        ["grep", "-rhoE", "--include=*.h", pattern, *[str(d) for d in search_dirs]],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout.split()
    return set(hit)


def sdk_values(include_dir, names):
    """{name: {values the SDK defines it as}} for every @names, in one pass.

    Searched across the whole include tree rather than named headers: the stub's
    comment says which header each constant comes from, and pinning that here
    would just be a second copy of the same claim to keep in step.

    One grep for all of them rather than one each. The tree is about 3,400 files
    and a scan costs roughly 0.75s, which a per-constant loop multiplied by the
    number of stub constants for no reason.
    """
    pattern = (
        r"^#define[ \t]+(" + "|".join(names) + r")[ \t]+(0[xX][0-9a-fA-F]+|[0-9]+)"
    )
    hit = subprocess.run(
        ["grep", "-rhoE", pattern, str(include_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout.splitlines()
    found = {name: set() for name in names}
    for line in hit:
        parts = line.split()
        if len(parts) >= 3 and parts[1] in found:
            found[parts[1]].add(c_int(parts[2]))
    return found


def sdk_enum_values(sdk, search_dirs, names, want_of, origin):
    """Value-check names the SDK declares as enumerators.

    sdk_values only sees object-like defines, so every Hypervisor constant used
    to reach the report as "mentioned, value not comparable" and no gate looked
    at what it equalled. HV_EXIT_REASON_CANCELED sat at 1 that way while the SDK
    enumerated it as 0, which put every analysis of the run loop's dispatch on
    the wrong branch.

    The compiler is the only thing that knows an enumerator's value, so ask it:
    include the SDK header that declares the name and let a _Static_assert
    compare. Nothing is run, only compiled, and a failure names the constant.

    Returns (disagree, unchecked): the names whose value differs, each with
    the stub's spelling of it, and the names no SDK header would compile so
    the question went unanswered.
    """
    fw_root = sdk / "System" / "Library" / "Frameworks"

    def include_for(header):
        """Framework headers must be reached the framework way.

        Including Hypervisor's hv_error.h by absolute path compiles but leaves
        the enumerators undeclared, because the umbrella header is what pulls
        in the platform guards they sit behind. The stub tree's own layout says
        which framework a name belongs to: frama-c-stubs/Hypervisor mirrors
        Hypervisor.framework.
        """
        parts = pathlib.Path(header).parts
        if "Frameworks" in parts:
            fw = parts[parts.index("Frameworks") + 1].removesuffix(".framework")
            return f"<{fw}/{fw}.h>"
        return f'"{header}"'

    def probe(header, name):
        """Ask the compiler what @name equals. Returns (decided, disagrees).

        Compares 32-bit bit patterns rather than values. The SDK enumerates
        HV_BAD_ARGUMENT as a signed int holding 0xFAE94003, so a stub spelling
        it as the unsigned 0xfae94003 is the same constant and must not read as
        a disagreement; a genuine difference like 0 against 1 still does.

        A compile that fails for any other reason is not evidence, so only the
        assertion's own diagnostic counts. Matching on the name would match the
        source line the compiler echoes back, which contains it either way.
        """
        want32 = want_of[name] & 0xFFFFFFFF
        body = [
            f"#include {include_for(header)}",
            f"_Static_assert((unsigned long long) (unsigned int) ({name})"
            f" == {want32}ULL, \"{name}\");",
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("\n".join(body) + "\n")
            path = f.name
        try:
            run = subprocess.run(
                ["cc", "-fsyntax-only", "-isysroot", str(sdk), "-F",
                 str(fw_root), path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if run.returncode == 0:
                return True, False
            if "static assertion failed" in run.stderr:
                return True, True
            return False, False
        finally:
            os.unlink(path)

    # One name at a time, trying each header that mentions it until one gives a
    # definitive answer. Picking the first grep hit and trusting it landed on
    # block.h, which mentions a name in passing and cannot be compiled alone.
    bad, unchecked = [], []
    for name in names:
        candidates = subprocess.run(
            ["grep", "-rlE", "--include=*.h", rf"\b{name}\b",
             *[str(d) for d in search_dirs]],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.split()
        for header in candidates:
            decided, disagrees = probe(header, name)
            if decided:
                if disagrees:
                    bad.append((name, want_of[name]))
                break
        else:
            # No header gave an answer. Reporting that as checked is how an
            # unverified enumerator would pass, which is the hole this whole
            # probe exists to close.
            unchecked.append(name)
    return bad, unchecked


def sdk_expr_values(sdk, search_dirs, exprs):
    """Check defines whose body is an expression rather than a literal.

    The SDK grep can only compare literals, so these used to fall out of the
    gate entirely: not reported as unchecked, simply absent. The compiler
    settles them. Including the SDK header and asserting its spelling of the
    name against the stub's body also checks a body that names another
    constant, since both sides then read the SDK.

    Returns (disagree, unchecked).
    """
    fw_root = sdk / "System" / "Library" / "Frameworks"
    bad, unchecked = [], []
    for name, raw in exprs:
        candidates = subprocess.run(
            ["grep", "-rlE", "--include=*.h", rf"\b{name}\b",
             *[str(d) for d in search_dirs]],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.split()
        decided = False
        for header in candidates:
            parts = pathlib.Path(header).parts
            if "Frameworks" in parts:
                fw = parts[parts.index("Frameworks") + 1].removesuffix(
                    ".framework"
                )
                inc = f"<{fw}/{fw}.h>"
            else:
                inc = f'"{header}"'
            body = [
                "#include <stdint.h>",
                f"#include {inc}",
                f'_Static_assert((long long) ({name}) == (long long) ({raw}),'
                f' "{name}");',
            ]
            with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
                f.write("\n".join(body) + "\n")
                path = f.name
            try:
                run = subprocess.run(
                    ["cc", "-fsyntax-only", "-isysroot", str(sdk), "-F",
                     str(fw_root), path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            finally:
                os.unlink(path)
            if run.returncode == 0:
                decided = True
                break
            if "static assertion failed" in run.stderr:
                bad.append((name, raw))
                decided = True
                break
        if not decided:
            unchecked.append((name, raw))
    return bad, unchecked


def stub_files(explicit):
    """Every header under frama-c-stubs, not just macos-libc.h.

    The constants moved out of that one file when the shadow headers arrived:
    sys/ipc.h and sys/msg.h carry Darwin values for the same reason and with
    the same consequence if one is wrong. Scanning the directory rather than a
    list means a new stub is covered the day it lands instead of the day
    somebody remembers to add it here.
    """
    if explicit:
        path = pathlib.Path(explicit)
        return [path] if path.is_file() else []
    return sorted(p for p in STUB_DIR.rglob("*.h"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stub", default=None)
    args = ap.parse_args()

    stubs = stub_files(args.stub)
    if not stubs:
        print(f"  no stub headers found under {STUB_DIR}")
        return 1

    sdk = sdk_path()
    if sdk is None:
        print("  STUBCONST no macOS SDK; skipping (a macOS run checks this)")
        return 0
    include_dir = sdk / "usr" / "include"
    # Only the frameworks the stub tree actually mirrors, named by its own
    # subdirectories: frama-c-stubs/Hypervisor means Hypervisor.framework. The
    # whole Frameworks tree is 6,266 headers and a grep over it costs half a
    # minute for one framework's worth of answers.
    #
    # Resolved rather than globbed, because a framework's Headers is a symlink
    # into Versions/A and grep -r does not descend a symlinked directory. That
    # silently found nothing for two of the Hypervisor names while finding the
    # others, which reads as "the SDK does not have this name" and is the one
    # report this gate must not get wrong.
    fw_root = sdk / "System" / "Library" / "Frameworks"
    frameworks = []
    for sub in sorted(p.name for p in STUB_DIR.iterdir() if p.is_dir()):
        headers = fw_root / f"{sub}.framework" / "Headers"
        if headers.is_dir():
            frameworks.append(headers.resolve())

    defines = []
    exprs = []
    origin = {}
    for stub in stubs:
        for name, raw in DEFINE.findall(stub.read_text()):
            origin[name] = stub.relative_to(ROOT)
            try:
                c_int(raw)
            except ValueError:
                # Not a literal, so the SDK grep cannot compare it. The
                # compiler can: assert the SDK's name against this body.
                exprs.append((name, raw))
                continue
            defines.append((name, raw))
    if not defines:
        print(f"  no integer defines found under {STUB_DIR}; the regex moved")
        return 1

    names = [name for name, _ in defines]
    found = sdk_values(include_dir, names)

    if exprs:
        bad_expr, unchecked_expr = sdk_expr_values(
            sdk, [include_dir, *frameworks], exprs
        )
        if bad_expr or unchecked_expr:
            print("  stub constants the SDK does not agree with:")
            for name, raw in bad_expr:
                print(f"    {origin[name]}: {name} is not {raw} in the SDK")
            for name, raw in unchecked_expr:
                print(f"    {origin[name]}: {name} could not be compiled")
            return 1

    # Only for the names the value scan came up empty on. Asking it about all of
    # them means grepping a 3,400-file tree for bare words, and one of those
    # words is NAME_MAX: the match list runs to tens of thousands of lines and
    # the gate went from under a second to half a minute for an answer it
    # already had.
    unresolved = [n for n in names if not found[n]]
    mentioned = (
        sdk_mentions([include_dir, *frameworks], unresolved) if unresolved else set()
    )
    wrong, missing, enum_only = [], [], []
    for name, raw in defines:
        want = c_int(raw)
        got = found[name]
        if not got:
            (enum_only if name in mentioned else missing).append(name)
        elif got != {want}:
            # One value that disagrees, or several headers disagreeing with each
            # other; either way there is nothing here that matches the stub.
            wrong.append((name, want, sorted(got)))

    # The enumerator half. Everything above compares object-like defines; these
    # need the compiler, so they are checked separately and folded into the same
    # report.
    if enum_only:
        want_of = {name: c_int(raw) for name, raw in defines}
        disagree, unchecked = sdk_enum_values(
            sdk, [include_dir, *frameworks], enum_only, want_of, origin
        )
        for name, want in disagree:
            wrong.append((name, want, ["differs; the SDK enumerates it"]))
            enum_only.remove(name)
        if unchecked:
            print("  no SDK header would compile for these, so their values")
            print("  went unchecked:")
            for name in sorted(unchecked):
                print(f"    {origin[name]}: {name}")
            print("  An unverified enumerator must not read as a verified one.")
            return 1

    if wrong:
        print("  stub constants disagree with the macOS SDK:")
        for name, want, got in wrong:
            print(f"    {origin[name]}: {name}: stub {want} ({hex(want)}), SDK {got}")
        print("  The analyzer never links, so this changes what the proofs")
        print("  reason about rather than what runs. Use the SDK value.")
        return 1

    if missing:
        print("  stub constants the SDK does not define uniquely:")
        for name in missing:
            print(f"    {origin[name]}: {name}")
        print("  Either the name is wrong or it is not an SDK constant; if it")
        print("  is deliberately synthetic, it does not belong in this file.")
        return 1

    checked = len(defines) - len(enum_only)
    note = ""
    if enum_only:
        note = (
            f"; {len(enum_only)} named by the SDK as enumerators, value checked by compiling against it"
        )
    print(
        f"  STUBCONST {checked} stub constant(s) in {len(stubs)} "
        f"header(s) match the macOS SDK{note}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
