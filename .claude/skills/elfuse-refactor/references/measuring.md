# Measuring before judging

A count with no command behind it reads as a fact and rots into a wrong one.
Recompute rather than quote, including from this file. Every number below was
produced by the script beside it and is stale the moment the tree moves.

The tree is clang-formatted, which is the only reason these are honest: a
function definition is a signature at column 0 followed by a lone `{`, and its
body ends at the first lone `}`.

Say which numbers were measured and which were judged. Duplication findings are
judgment even with the script below behind them, so quote both locations and let
the reader check the call.

## Function size, and the trap in scanning it

`readability-function-size` is the one structural check that gates, so this is
the scan whose answer matters. It also has a trap: the exempting
`NOLINTNEXTLINE` sits above the comment block above a signature that may run
several lines, so a scan looking a fixed two lines above the brace misattributes
almost every one of them.

```python
import subprocess, sys

LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 400
rows = []
for f in subprocess.check_output(['git', 'ls-files', 'src/*.c']).decode().split():
    lines = open(f).read().split('\n')
    start = None
    for i, l in enumerate(lines):
        if l == '{' and start is None:
            start = i
        elif l == '}' and start is not None:
            n = i - start - 1
            if n > LIMIT:
                j = start - 1
                while j >= 0 and lines[j].strip() and not lines[j].startswith(
                        ('/*', ' *', ' */')):
                    j -= 1
                window = '\n'.join(lines[max(0, j - 12):start])
                nolint = 'NOLINTNEXTLINE(readability-function-size)' in window
                rows.append((n, f, start + 1, lines[j + 1].strip()[:48], nolint))
            start = None
for n, f, ln, sig, nolint in sorted(rows, reverse=True):
    print(f"{n:5d}  {'exempt' if nolint else '      '}  {f}:{ln}  {sig}")
```

It defaults to the 400-line ceiling the check gates on, so a clean run means
nothing needs attention. Pass a lower number to see the band underneath, which
is where the next function to cross it will come from; those are expected to be
unexempted and are not findings.

Measured at the time of writing, every function past the ceiling carried an
explicit exemption. A scan reporting unexempted bodies over the ceiling is
wrong before the tree is: check the scan, then `make lint`, then believe it.

This counts body lines between the braces. clang-tidy counts its own way, so
treat the number as a ranking rather than as the check's verdict.

## Duplication

Adding a dependency to score a cleanup is not worth it, but a sliding window of
normalized lines needs none and finds the blocks worth looking at.

```python
import collections, subprocess, sys

W = int(sys.argv[1]) if len(sys.argv) > 1 else 14
lines = []
for f in subprocess.check_output(['git', 'ls-files', 'src/*.c']).decode().split():
    for i, raw in enumerate(open(f), 1):
        s = raw.strip()
        if not s or s.startswith(('/*', '*', '//', '#')) or s in ('{', '}', '});'):
            continue
        lines.append((f, i, s))

seen = collections.defaultdict(list)
for i in range(len(lines) - W + 1):
    win = lines[i:i + W]
    if win[0][0] != win[-1][0]:
        continue
    seen['\n'.join(x[2] for x in win)].append((win[0][0], win[0][1]))

printed = []
for v in sorted((v for v in seen.values() if len(v) > 1), key=len, reverse=True):
    if any(len(p) == len(v) and all(pf == vf and abs(pl - vl) < 4
                                    for (pf, pl), (vf, vl) in zip(p, v))
           for p in printed):
        continue
    printed.append(v)
    print(f"{len(v)}x {W} lines: " + ', '.join(f'{f}:{l}' for f, l in v[:4]))
```

Two things about reading its output. Without the `printed` filter the same
finding reappears at each shifted offset, so one duplicated block reports as a
dozen; that filter is why the list is short enough to read. And the widest hit
in this tree is the unused-parameter run shared by the `sc_` wrappers in
`src/syscall/syscall.c`, which is a false alarm every time (see the skill).

Run it at a few widths. A block that survives at 25 lines is worth extracting
almost regardless of what it does; one that only appears at 12 usually is not.

## Nesting and file size

```sh
# statements at nesting depth 4 or deeper (4-space indent, so 20 columns in).
# The comma in \{20,\} is load-bearing: without it this matches exactly 20
# leading spaces and silently skips everything nested deeper.
grep -rn '^ \{20,\}[^ *]' --include='*.c' src

# file sizes
git ls-files 'src/*.c' | xargs wc -l | sort -rn | head -20
```

The nesting grep also catches wrapped continuation lines, so it is a lead rather
than a count.

## Reading the tree

Read a file with the editor's own file-reading tool before concluding its
content is malformed. A shell pager can be proxied through a summarizer that
elides list items and leaves markers behind, and the result reads as a corrupted
file rather than as a shortened view of a healthy one. Repairing that damage is
how a good file gets rewritten into a worse one.
