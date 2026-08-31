"""Fail when a shared-memory access states no memory order.

The tree settled on C11 atomics: `.claude/skills/elfuse-conventions/SKILL.md`
bans the compiler `__atomic_*` and `__sync_*` builtins, and requires the
`_explicit` form of every C11 atomic operation so the order is written at the
site rather than defaulted.

Both rules exist for the same reason. A builtin takes a plain `T *`, so nothing
in the declaration says the object is shared, and the next reader adds a plain
access without seeing a reason not to. A bare `atomic_load(x)` is an atomic
operation, but a sequentially-consistent one by default, so it says no more
about the ordering the site needs than the plain operator does. Both were true
across this tree until the migration, and both went back to zero; this gate is
what keeps them there.

Deliberately NOT checked: plain-operator access to an `_Atomic` object. Finding
those needs the declarations resolved per translation unit, and the tree still
carries a large pre-existing set of them (`fd_entry_t.type` alone has dozens),
so a gate for it would fail on landing rather than hold a line.

`atomic_thread_fence` and `atomic_init` are exempt: the fence takes its order as
its only argument, and `atomic_init` has no order to state.

Usage:
    check-atomics.py [--self-test]
"""

import argparse
import pathlib
import re
import subprocess
import sys

# Builtins the conventions ban outright.
BUILTIN_RE = re.compile(r"\b(__atomic_\w+|__sync_\w+)\s*\(")

# A C11 atomic call whose name does not end in _explicit. The exempt names take
# no order argument at all.
EXEMPT = {
    "atomic_thread_fence",
    "atomic_signal_fence",
    "atomic_init",
    "atomic_is_lock_free",
}
IMPLICIT_RE = re.compile(
    r"\b(atomic_(?:load|store|exchange|compare_exchange_\w+|fetch_\w+|flag_\w+))\s*\("
)


def splice(text):
    """Translation phase 2: remove every backslash-newline, and record which
    physical line each surviving character came from.

    Splicing has to happen before anything looks for comment or string
    delimiters, because it can build one. A block comment ending as "*\\" then
    a newline then "/" closes at that "/", and a stripper that scans the
    physical text never sees the "*/", stays inside the comment, and masks the
    code after it. That direction is the dangerous one: the gate goes quiet on
    a real violation rather than shouting about a false one.

    Returns the spliced text and a parallel list giving the physical line of
    each character, so a match can still be reported where a reader will find
    it.
    """
    out, lines = [], []
    line = 1
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and text[i + 1] == "\n":
            line += 1
            i += 2
            continue
        out.append(c)
        lines.append(line)
        if c == "\n":
            line += 1
        i += 1
    return "".join(out), lines


def strip_comments(text):
    """Blank out comment and string bodies, one character out per character in.

    Length is preserved so an index into the result still indexes the input,
    which is what lets scan() map a match back to its physical line. Runs on
    spliced text, so a backslash can no longer be followed by a newline and an
    escape is always two real characters.
    """
    out = []
    i, n = 0, len(text)
    in_block = in_line = in_str = in_chr = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_block:
            if c == "*" and nxt == "/":
                in_block = False
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
        elif in_line:
            if c == "\n":
                in_line = False
                out.append("\n")
            else:
                out.append(" ")
        elif in_str or in_chr:
            closer = '"' if in_str else "'"
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == closer:
                in_str = in_chr = False
            out.append(" " if c != "\n" else "\n")
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
            continue
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
            continue
        elif c == '"':
            in_str = True
            out.append(" ")
        elif c == "'":
            in_chr = True
            out.append(" ")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def scan(text):
    """Yield (lineno, symbol, rule) for each violation in one file's text."""
    logical, lines = splice(text)
    masked = strip_comments(logical)
    assert len(masked) == len(logical), "strip_comments must preserve length"
    for m in BUILTIN_RE.finditer(masked):
        yield lines[m.start()], m.group(1), "builtin"
    for m in IMPLICIT_RE.finditer(masked):
        name = m.group(1)
        if name.endswith("_explicit") or name in EXEMPT:
            continue
        yield lines[m.start()], name, "implicit-order"


def self_test():
    cases = [
        ("__atomic_load_n(&x, __ATOMIC_RELAXED);", 1, "builtin"),
        ("__sync_synchronize();", 1, "builtin"),
        ("atomic_load(&x);", 1, "implicit-order"),
        ("atomic_fetch_add(&x, 1);", 1, "implicit-order"),
        ("atomic_compare_exchange_strong(&x, &e, d);", 1, "implicit-order"),
        ("atomic_load_explicit(&x, memory_order_relaxed);", 0, None),
        ("atomic_fetch_or_explicit(&x, 1, memory_order_release);", 0, None),
        ("atomic_thread_fence(memory_order_acquire);", 0, None),
        ("atomic_init(&x, 0);", 0, None),
        ("/* atomic_load(&x) in a comment */", 0, None),
        ("int atomic_loader(void);", 0, None),
        # Code after a closing */ on the same line is still code.
        ("/* note */ atomic_load(&x);", 1, "implicit-order"),
        # Interior lines of a block comment are not code.
        ("/* a\n * atomic_load(&x)\n */", 0, None),
        # ... and the gate resumes after the comment ends.
        ("/* a\n * b\n */ atomic_fetch_add(&x, 1);", 1, "implicit-order"),
        # A name inside a string literal is not a call.
        ('const char *s = "atomic_load(";', 0, None),
        # A real violation is still found after a string on the same line.
        ('log("x"); atomic_store(&x, 1);', 1, "implicit-order"),
    ]
    # Line-number cases, checked separately because they assert where a
    # violation lands rather than how many there are.
    line_cases = [
        # A spliced newline inside a literal must not shift what follows.
        ('const char *s = "a\\\nb";\natomic_load(&x);', 3),
        # Nor one inside a line comment, which the splice extends.
        ("// a \\\nstill comment\natomic_load(&x);", 3),
        # A block comment spanning lines keeps the count too.
        ("/* a\n b\n */\natomic_load(&x);", 4),
        # A terminator built by a splice really does end the comment, so the
        # call after it is code. Getting this wrong hides a violation.
        ("/* a *\\\n/ atomic_load(&x);", 2),
    ]
    failures = 0
    for src, want_n, want_rule in cases:
        got = list(scan(src))
        if len(got) != want_n or (want_n and got[0][2] != want_rule):
            print("  self-test FAIL: %r -> %r" % (src, got))
            failures += 1
    for src, want_line in line_cases:
        got = list(scan(src))
        if len(got) != 1 or got[0][0] != want_line:
            print(
                "  self-test FAIL (line): %r -> %r, wanted line %d"
                % (src, got, want_line)
            )
            failures += 1
    if failures:
        return 1
    print("  self-test: %d cases, all pass" % (len(cases) + len(line_cases)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    root = pathlib.Path(__file__).resolve().parent.parent
    files = subprocess.run(
        ["git", "ls-files", "src/*.c", "src/*.h"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    bad = []
    for rel in files:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, sym, rule in scan(text):
            bad.append((rel, lineno, sym, rule))

    if bad:
        print("  %d shared-memory access(es) with no stated order:" % len(bad))
        for rel, lineno, sym, rule in bad:
            hint = "banned builtin" if rule == "builtin" else "use the _explicit form"
            print("    %s:%d: %s (%s)" % (rel, lineno, sym, hint))
        print("  See .claude/skills/elfuse-conventions/SKILL.md")
        return 1

    print("  %d source file(s), every atomic states its memory order" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
