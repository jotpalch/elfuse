# Writing a finding up

A finding is a claim that a specific guest action reaches a specific bad
outcome. It is worth writing only when the path can be stated end to end.
The schema below exists to stop a report degrading into a list of places the
reviewer felt uneasy about.

Three rules decide what becomes a finding at all:

- One root cause is one finding, with every sink listed. Two callers of the
  same unchecked helper are one entry. Splitting by call site inflates the
  count and hides that a single fix closes them all.
- A finding carries its fix. When the fix cannot be stated, the issue is not
  understood well enough to report, and the honest output is a question.
- Order by what one bad value reaches, not by how interesting the bug is.

## Per finding

- ID in the form WK-#, and a name giving the weakness in the entry point, in
  that order.
- Entry point: the syscall or format the guest drives, and which of its fields
  the guest chooses.
- Attack path: numbered steps from that entry point to the impact, tracing the
  chosen value from source to sink. One action per step, causally linked, no
  branching, with `path/to/file:line` and the exact value used at each step.
- Impact, named from the list the skill body opens with: host state read or
  written that the guest was never handed, sysroot escape, host memory
  corruption, host-resource exhaustion, or host privilege reached. When none
  of them fits, this is a robustness bug and saying so is the useful answer.
- Existing controls, and how far each one gets. This is where a report earns
  trust, because it is what the author of the code checks first.
- Residual severity after those controls. A path an existing control already
  closes is worth recording once and closing.
- The fix, at the layer that closes every listed sink.
- CWE id, Variant or Base. The Class-level ids name a category, not a bug.
- Confidence in the evidence, stated separately from impact. A high-impact
  guess and a low-impact certainty read differently and must not be merged.
- Locations: every sink as `path/to/file:line` or a line range.

CVSS vectors are optional and usually not worth the keystrokes here. When one
is given the score has to match the vector, since a mismatch discredits the
report faster than omitting both.

## Evidence

Verbatim excerpts, the smallest that carry the path, original comments
stripped and excess indentation removed. Mark the file at the top of each
block and elide non-relevant code. Annotate the flow inline, one sentence
each: the source where the guest value enters, each propagator that carries
it, each sanitizer it passes with what that check does not cover, and the sink
where it does the damage.

The sanitizer line is the one that gets skipped and the one that matters.
Naming the guard and stating precisely what it fails to cover is what
separates a finding from a reviewer who did not read the guard.

## Reproducer

One guest program or unit test that fails on the current source and passes
after the fix, at the cheapest level that exercises the boundary. Least
damaging form that still demonstrates the path: prove the read leaves its
bounds, do not demonstrate what could be done with it. `elfuse-verify` says
which lane it belongs in.

A finding without a reproducer is a hypothesis. That is a legitimate thing to
report, labeled as one.
