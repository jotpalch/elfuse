# Reducing prose

This reference decides what survives and which surface owns it. The sibling
`references/prose-register.md` decides how a survivor is written. Apply both
when a task changes more than a local sentence.

## The deletion pass

1. Read the names, types, control flow, tests, and neighboring documentation
   without relying on the prose.
2. Delete prose that only translates those surfaces into English.
3. Identify the facts that would be lost: rationale, invariants, boundaries,
   units, citations, and compatibility constraints.
4. Put each fact beside its narrowest stable owner. Shared contracts live once
   at the interface or type that owns them.
5. Rewrite each survivor as the shortest cause, constraint, or consequence
   that remains accurate.
6. Recompute numbers and guarantees, check citations, and run the
   surface-specific checks below.
7. Measure the reduction as evidence. No percentage can justify deleting a
   load-bearing fact.

Editing one sentence reopens its paragraph. A sentence left untouched inside a
rewritten block still reads as newly verified.

## Surface ownership

| Surface | Delete | Keep |
| --- | --- | --- |
| File or module header | A filename restatement, feature inventory, or execution tour | Legal text and one file-wide constraint with no narrower owner |
| Function or method docstring | A signature paraphrase, obvious return shape, or implementation sequence | A caller-visible contract, surprising side effect, or failure meaning |
| Inline or block comment | Statement narration, branch paraphrase, or implementation history | Rationale, invariant, boundary, unit, citation, or dangerous alternative |
| Test | Setup, action, and assertion narration | Why a fixture has an unusual shape or an obvious oracle is insufficient |
| JSONC, build, or workflow file | Generic purpose, visible syntax, schema inventory, or list count | Exclusion rationale, required-check behavior, or compatibility constraint |
| README | Repeated reference material | Navigation, entry points, and a concise capability statement |
| Usage document | Internal implementation detail | Copyable commands, inputs, outputs, and stable failure behavior |
| Domain reference | Repeated command catalogs and source-file inventories | Current contracts, ownership, architecture, and cross-component invariants |
| Commit body | Diff walkthrough, file inventory, moved source narration, or generic test log | Short what and why, the rejected obvious alternative, and claim-specific verification |
| PR or review text | A restated diff, walkthrough, status summary, or closing verdict | Intent, reproduction, correction, or measurement |
| Skill | A section summary, case-study transcript, or duplicated trigger | A routing branch, consequence, authority, and task-specific judgment |

Two copies of one fact eventually disagree. The second surface links to the
first instead of copying it.

## Checks before deletion

A Python docstring is runtime data. Search for consumers before deleting one:

```sh
git grep -n -E '__doc__|inspect\.getdoc|pydoc|help\(' -- '*.py'
```

Keep or replace it when argument parsing, help generation, introspection,
tests, or another runtime path consumes it.

Poor naming does not make narration valuable. Rename within the requested
scope when a better identifier makes the comment redundant. Retain a needed
explanation when the rename or restructuring would expand the task.

Legal notices, tool directives, generated-file notices, and externally
required annotations are outside this reduction rule. Vendored prose is not
rewritten as project style.

Documentation replaces copies with links and collapses adjacent sections that
state the same contract. Examples stay when they are copyable or distinguish
two behaviors. Preserve externally visible states, command syntax, error
semantics, and safety boundaries.

Deleting source narration does not move it into a commit body. Keep an obvious
alternative there only when its failure would attract a future rewrite.

## Calibration

These transformations distinguish deletion from shortening:

```text
# Cleanup takes 12 seconds, the runner adds 25, and transport adds 30.
rewrite: Keep supervisor cleanup below the channel deadline.

# Remove stale binds before recursive removal can enter the real device tree.
keep: the destructive alternative is invisible in the command itself
```

The result is allowed to be longer when the hidden contract is longer. The
test is what a reader loses after deletion, not how much text remains.
