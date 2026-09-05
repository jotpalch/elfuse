# Sweeping the whole tree

Reviewing a diff and sweeping `src/` are different jobs. A diff has an author
and a reason; a sweep has neither, so it needs a fixed set of detectors and an
honest account of what each one cannot see. What follows is the set, and the
false positives each one produces here, which are worth knowing in advance
because every one of them costs a file read to dismiss.

State the scope in the result. A sweep that names the files it walked is
evidence; one that reports a verdict over `src/` without saying what it read
is a claim about every line in it that nobody made.

## The detectors

Run them over `src` with `--include='*.c'`, excluding `src/proved/`, whose
arithmetic is under contract already.

- Unsafe C string primitives: `strcpy`, `strcat`, `sprintf`, `gets`,
  `vsprintf`. Any hit is a finding; there is no accepted use in this tree.
- `alloca`, and array declarations whose size is a variable. A guest number
  must never size a stack object.
- `malloc`, `calloc` and `realloc` whose size argument is not a `sizeof`
  expression. Each hit is traced to the cap that bounds it, or it is a
  finding. This one is slow and is the highest-yield of the set.
- Additions inside a bounds test: `if (a + b > c)`. The wrap is the bug.
- Array subscripts named like syscall arguments: fd, signum, idx, slot, tid,
  clockid, nr.
- The same guest address read twice inside one function, which is the double
  fetch when the second read is the one used.
- A fallback that substitutes a constant for entropy.

## What each one gets wrong here

- The addition detector is mostly noise. Most hits combine values already
  bounded by `NAME_MAX` or by the destination size, and only the ones adding
  a length the other side chose can wrap. Read the provenance of both
  operands before writing anything down.
- The subscript detector answers a question about shape when the question is
  provenance. Most hits index a loop counter the code owns. It earns its
  place because the few that do take a guest number reach a host array.
- A grep for a discarded `guest_read` or `guest_write` return matches the
  continuation lines of multi-line conditions, and misses the case where the
  check is an accumulator on the previous line. Both directions are wrong, so
  confirm every hit against the file.

## What no sweep sees

The same three things grep never sees: indirection, where the dangerous call
sits behind a helper; absence, where the missing check has no text to match;
and logic, where each step is safe and the sequence is not. Those need the
rules in the skill body applied by reading, and they are why a clean sweep is
reported as a clean sweep rather than as a clean tree.
