---
name: elfuse-verify
description: How elfuse validates a change - choosing the lanes for the area you touched, the test matrix, make check, and the Frama-C proof targets declared in mk/verify.mk, including how to drive the frama-c MCP server on a stuck proof and how to read its proof_coverage report. Use when adding bounds math to src/proved/, writing or repairing ACSL contracts, running or debugging make verify / verify-mutants, asking how much of a target is actually proved, touching frama-c-stubs/, adding a test lane, or deciding what to run before calling work done.
---

# Validating an elfuse change

Two independent gates: the runtime tests and the proofs. A change to
attacker-facing bounds math needs both.

Independent in what they prove, not in what they consume. Run them one after
the other, never concurrently. `make verify` re-invokes itself parallel and
`verify-mutants` fans out too, while the runtime lanes are wall-clock
sensitive, so overlapping them makes the machine fail tests that a serial run
passes. Measured here: `make check` alongside the proof gate drove an 8-core
host to a load average of 43.8 against a busy threshold of 4.8, and
`test-thread-churn` timed out twice at 60 s and reported FAIL. The same binary
on the same tree at load 4.0 finishes in 0.34 s, three runs out of three.
Nothing was wrong with it. Neither mitigation saves you at that load, since
`test_host_is_busy` only skips the throughput guardrail and the runner only
re-runs once. A timing FAIL is worth nothing as evidence either way: it is not
a regression you can act on, and a serial re-run is the only thing that tells
you whether it was real.

The pure source scanners are the exception, and they are the cheap early
signal while something long is in flight: `check-lock-order`,
`check-eintr-contract`, `check-atomics`, `check-proof-targets`,
`check-stub-shadow` and `check-syscall-coverage` read the tree, cost seconds,
and fail long before a full lane would. Five of the six are on `make check`;
`check-stub-shadow` is a prerequisite of every `verify-*` target instead, so it
is not reached by `make check` alone. Running one directly with
`python3 scripts/<name>.py` costs nothing and needs no arguments.

Five of the six write nothing. `check-proof-targets` is the one that does:
it shells out to `make print-verify-targets` rather than reading
`mk/verify.mk`, and a sub-make evaluates the build-flavor guard while it reads
the makefiles. `print-%` goals are skipped by that guard for exactly this
reason (`mk/common.mk`), so the scanner is safe to run beside a build; if you
add a scanner that invokes make on some other goal, it is not.

## Choosing what to run

`docs/testing.md`, section "Validation Strategy By Change Type", is a table
from the area you touched to the minimum command set, and it is more specific
than any habit. Consult it first. It is where you learn that Rosetta work
wants `make test-rosetta-all`, that ptrace and debugger work want
`make test-gdbstub`, and that filename-codec work wants the soak lane on top
of `make check`.

The defaults below are what that table falls back to, not a substitute for it.

```
make check                       # unit tests, busybox, coverage gate, guardrail
bash tests/test-matrix.sh all    # the three modes
```

## Runtime

Modes and what a failure in each means:

- `elfuse-aarch64` - primary. Must stay green. A failure here is a regression.
- `qemu-aarch64` - ground truth via Alpine `aarch64-linux-musl` under
  `qemu-system-aarch64`. It answers "what does real Linux do", which is why
  `elfuse-debug` reaches for it on any behavioral divergence. TIMEOUTs are
  emulation speed, not regressions.
- `elfuse-x86_64` - the Rosetta path, with per-host-class baselines from
  `detect_x86_64_host_class`. Skips cleanly without the translator.

`tests/fetch-fixtures.sh` pulls Alpine packages, the `linux-virt` kernel, and
Rosetta fixtures on first run. musl is Alpine's only libc, so glibc-dynamic
lanes skip unless `GUEST_GLIBC_*` points at an external sysroot.

A fixture download that fails is not always a download failure. Some networks
answer plain HTTP with a page of their own, which arrives as a valid 200 and
only breaks at whatever tries to parse it: `make check` here failed at
`ar: Inappropriate file type or format` on a busybox `.deb` that was 2997 bytes
of HTML. The suite already knows this happens, which is what the `wget` lane's
"no unintercepted http to example.com from this host" skip is about. So when a
fixture step fails on a malformed archive, check what actually arrived before
believing the archive is at fault, and prefer an HTTPS source: `build/busybox`
now rewrites the mirror the Debian page lists to `deb.debian.org`, since the
per-country mirrors it offers are plain HTTP and not all of them answer HTTPS
at all.

### Writing a test lane

The runner is already hardened, and every one of these exists because a test
once passed without running anything. Do not work around them, and do not
loosen one to get a build green.

- `tests/lib/test-runner.sh::run` and `run_check` wrap every invocation in
  `timeout $TEST_TIMEOUT` (gtimeout fallback on macOS).
- `run_check` and `run_pipe` fail on non-zero exit before pattern evaluation.
  A test that greps for a string in the output of a crashed binary is not a
  test.
- `driver.sh::evaluate_result` requires `rc == expected_rc`.
- `ALLOW_MISSING_BINARIES` defaults to 0. A missing fixture is a failure, not
  a skip.

## Proofs

`src/proved/` is header-only arithmetic carrying ACSL contracts: the bounds
math of an attacker-facing parser or packer, split out of a `.c` and proved
with `-wp-rte`.

Every `src/proved/` header must have a matching `make verify-<name>` target,
but the reverse does not hold. A few targets prove a `.c` file directly, each
for a reason stated in the comment above it in `mk/verify.mk`; the general
one is that the loops in question could only have been described as
test-covered had they been split into a header.

`make print-verify-targets` is the current list. CI reads it to build its
matrix, so do not hardcode the set anywhere else, including here.

```
make verify           # every proof target, parallel by default
make verify-<name>    # one target
make verify-mutants   # assert each proof rejects a known-broken source
make print-verify-targets
make check-contracts  # rebuild with -DELFUSE_CONTRACT_ASSERT, then make check
```

`make verify` re-invokes itself with `-j$(VERIFY_JOBS)` unless you brought your
own `-j`. `VERIFY_JOBS=1` is how you ask for serial on both GNU make 4.x and
Apple's 3.81.

`verify-mutants` accepts `MUTANT_TARGET=<name>`, `MUTANT_JOBS=<n>`,
`MUTANT_SINCE=<rev>` for a changed-only run, and `MUTANT_ESCALATE=<seconds>`
(see the exhaustion section below).

Read past the "N mutations, N caught" line. It also prints the proved functions
that have no mutation yet, and that list, not the caught count, is the honest
measure of what the gate covers: all-caught alongside a handful of functions
nobody has tried to break says the gate is green and that those proofs have
never been asked whether they would reject a broken source. They are not
failures, and they are not covered either.

Recompute that list before quoting it, and read what it counts. It counts
distinct functions now; it used to count `(target, function)` pairs, so a
function proved by two targets showed up twice and read as uncovered under its
second target even though the first mutates it. That inflated the gap fourfold
the last time it was checked - twelve listings, three functions.

A function can also sit in a `_FCTS` list with no ACSL contract at all, proved
only for absence of runtime errors. Nothing there can reject a mutation, so
adding one is wasted effort until the function has a contract: that is the fix,
and it is usually two lines. Write the contract in the domain the code is in,
too. `futex_uaddr_is_aligned` would not discharge as `uaddr % 4 == 0` and does
as `(uaddr & 0x3) == 0`, because bridging modulo and bitmask on a 64-bit value
is what the prover times out on, not the property itself.

Adding a contract raises the obligation count, so raise
`VERIFY_<T>_MIN_GOALS` with it. That floor is a tripwire against an emptied
body or a dropped contract, which prove 0 of 0 and would otherwise pass; it is
meant to sit at the target's baseline. Two contracts added here left it 15 and
2 obligations low, and nothing failed to say so, because a floor is only ever
compared against from below.

Mutating a function that lives in an included header rather than in
`VERIFY_<T>_SRC` works: the runner stages the mutant in its own directory and
prepends it via `MUTANT_INCDIR`, where it shadows the real header. What a
target may mutate is its source plus the headers in its `VERIFY_<T>_SCAN`.

The staged path must mirror the original's path under `src/`, and
`MUTANT_INCDIR` must be the staging ROOT rather than the copy's parent, because
the spelling in the `#include` is what the preprocessor searches for. Deriving
it as the parent got `src/utils.h` right by luck and every nested header wrong:
`"proved/netlink.h"` resolved to `<parent>/proved/netlink.h`, missed, fell
through `-Isrc` to the real header, and the run proved unmutated code while
reporting a mutation nobody caught.

The unmutated baseline cannot catch that, and it is worth knowing why, because
the comment that claimed it could was wrong. The baseline stages a copy
identical to the file it shadows, so whether the preprocessor opens the shadow
or falls through, the program proved is the same and the run passes either way.
What does catch it is a probe: stage a copy carrying `#error`, require the run
to fail naming it, and read the LOG rather than make's stdout, since the recipe
redirects Frama-C there and a non-zero exit alone is also what a broken
override gives. It costs a parse, not a proof.

### A mutation is caught by exhaustion here, not by refutation

Worth knowing before tightening the gate on principle. An open goal means the
prover either reached a conclusion the mutant cannot satisfy (`[Unknown]`,
`[Failed]`) or ran out of budget (`[Timeout]`, `[Stepout]`), and only the first
is a refutation. In this tree the first never happens: across every mutation
log the tag is `[Timeout]`, and raising the budget eightfold to 240s on a host
at 0.3 to 0.6 runnable threads per CPU left all four `futexdeadline` mutations
exhausting exactly as they did at 30s. Alt-Ergo and Z3 do not refute these
goals, they grind. So refusing to count exhaustion does not make the gate
stricter, it makes "caught" unreachable and the gate permanently red.

What separates a broken contract from a merely hard one is the baseline, not
the tag: the unmutated source proves every goal, and the mutant, narrowed to
the mutated function, exhausts on that function's own goal. A goal that were
only hard would exhaust in the baseline too, and a failing baseline is fatal
rather than scored. The residual gap is a mutation that turns an easy true goal
into a hard true one: it exhausts at the short budget and would discharge at a
long one, and the tag alone cannot tell it from a rejection.

`--escalate SECONDS` closes that gap on demand. It re-runs every resource
verdict at the larger budget and reports MISSED for any mutation that then
proves, which is the honest verdict for one the proof does not reject. It is
off by default because it costs the escalated budget on precisely the goal that
already ran out of the short one, once per mutation, and every mutation in the
table is a resource verdict. Run it when a contract changes or when the claim
that these mutants are unprovable rather than slow is what is in question:

```
make verify-mutants MUTANT_TARGET=futexdeadline MUTANT_ESCALATE=240
```

Two things follow. Report the resource verdicts separately so the count never
reads as "these proofs refute their mutants", and say which budget produced
them. And do not diagnose them as load without measuring: a mutation run fans
out and becomes its own load source, so a split computed during a parallel run
will always disqualify itself. Serial (`MUTANT_JOBS=1`) on a quiet host is the
only measurement that means anything, and here it returned the same answer.

The mutation runs pass `-wp-cache none` for a related reason. WP's cache
defaults to `update` and stores a timeout as a stored verdict just like a
conclusion, so a replayed timeout would be a catch obtained with no prover run
at all. `make verify` keeps its cache, which is what makes a re-prove cheap;
only the mutation gate, where a fresh verdict is the whole point, turns it off.
That distinction is not academic: an `elf_place_segment` contract retried here
came back Timeout from the cache on a quiet host, and only defeating the cache
showed the real result.

`scripts/proof-scope.py` decides which targets a diff can reach, and
`.github/workflows/verify.yml` builds its jobs from it, so a target the branch
cannot affect gets no runner. It answers two questions: which targets to prove,
and, with `--mutation`, which mutation sets to re-run, the second being narrower
because a file that only schedules the run cannot change whether a target
rejects a broken source. Every "cannot tell" answer widens back to the whole
set, and a push to `main` always proves and mutates everything.

Three things follow when adding a target or a proof input. An input reached
through `-include` or an `-I` the scan does not use is invisible to the closure
and belongs in `HARNESS_FILES` (or under `STUB_PREFIX`). A file that only picks
what runs goes in `SCHEDULING_FILES`, and the self-test refuses it if it also
carries a prover budget or a make invocation. And `proof-scope.py --self-test`,
run by `.github/workflows/lint.yml`, is what tells you the lists are still
honest.

### Adding to src/proved/

Nothing lands there without a proof target -
`scripts/check-proof-targets.py` (a CI job in `.github/workflows/lint.yml`)
fails otherwise. Callers include the header as `proved/<name>.h`.

The routine:

1. Extract the arithmetic into `src/proved/<name>.h` with ACSL contracts.
2. Add the `VERIFY_<NAME>_SRC` / `VERIFY_<NAME>_MODEL` / `VERIFY_<NAME>_FCTS`
   variables in `mk/verify.mk` so the rule template instantiates
   `verify-<name>`. `typed` is the default choice for a model; see below.
3. `make verify-<name>` until it discharges with `-wp-rte`.
4. `make verify-mutants MUTANT_TARGET=<name>` - a proof that cannot reject a
   broken source proves nothing.

Supporting gates, all of which run per target:

- `scripts/check-acsl-coverage.py` - catches a contract assumed because its
  function was left out of `-wp-fct`.
- `scripts/check-char-signedness.py` (`make check-char-signedness`) - compiles
  each proved function under `-fsigned-char` and `-funsigned-char` at -O0 and
  requires identical code. The data model used for proving differs from arm64
  macOS on plain-char signedness; this is what keeps that sound.
- `scripts/check-stub-constants.py` (`make check-stub-constants`) - asserts
  every `frama-c-stubs/` constant matches the macOS SDK. The analyzer never
  links, so a wrong constant cannot fail a build, it silently changes what the
  proof reasons about.

### Choosing the next target

Parsability decides it before anything else does: a file Frama-C cannot parse
cannot be proved, however good a candidate it looks. Test that first, because
it costs one invocation and rules candidates out for free.

```
FC=$(command -v frama-c)
ARGS="-nostdinc -isystem $($FC -print-share-path)/libc -Iframa-c-stubs \
      -include prelude.h -include macos-libc.h -Isrc -Ibuild"
FILE=src/syscall/fs-stat.c
$FC -machdep gcc_x86_64 -cpp-extra-args="$ARGS" "$FILE"
```

`CPP_DEFS` is empty for every target but `verify-gva`, so leaving it out
matches what most targets are proved under. A failure names its own cause:
`'sys/attr.h' file not found` is the real modeling gap and ends the matter,
while `Cannot resolve variable X` is a missing declaration and is fixable
under `frama-c-stubs/`.

`parse_surface` does the same probe over a whole file list and groups the
failures by cause, which is the faster way to survey the tree. Give it the
flags above as `include_paths`, `isystem_paths`, `nostdinc` and
`force_includes`: a survey run without them measures a different program and
its blocked set fills with files that parse perfectly well. Measured with the
flags missing it reported 39 of 60 parsing against 46 of 60 true, and its
largest blocker group was a phantom.

Whatever the probe, read which header stopped a file and whose include it was.
A leaked include costs every file downstream of it and nothing to remove:
deleting one unused `sys/mount.h` from `runtime/procemu.h` took three files
straight into the parsing set.

Then rank what survives by whether it actually holds attacker-facing bounds
math. The shape that has worked every time is a self-contained codec or walk
over a guest-chosen blob: pure arithmetic, libc-only includes, an explicit
output-buffer bound, and no syscalls. A file whose header comment already says
it treats its input as untrusted and is free of project dependencies is
telling you it was written to be proved.

Two things that look like candidates and are not. A file whose length
arithmetic is all delegated to an already-proved header adds nothing but a
second harness. And a translation table with no arithmetic, however
attacker-reachable, has no obligations worth generating: `-wp-rte` on it
proves that a switch is a switch.

### Memory models, and what no model checks

Each target picks its own model via `VERIFY_<NAME>_MODEL` in `mk/verify.mk`,
and the comment above it says why. Pick the model the code needs, not the
model a neighbour target uses.

The general limit is worth understanding before trusting any of them: a
non-`typed` model buys reasoning power by assuming something the proof does
not check. `caveat`, used where `typed` cannot follow a byte-addressed buffer
whose entry stride is attacker-chosen, assumes formal pointer parameters do
not alias. The contracts state that with `\separated`, but the callers are not
in `-wp-fct`, so nothing verifies they honor it, and a future caller passing
the same address twice would invalidate the proof with no diagnostic.

That call-site gap is general, and it bites hardest for `proved/gva.h`:
`guest.c` cannot be given to Frama-C at all, so nothing verifies its call
sites honor the `requires` clauses. `make check-contracts` narrows it from the
runtime side by turning the expressible ones into runtime asserts, and is
deliberately separate from `make check` because those functions sit on the
`guest_read` / `guest_write` hot path.

### The frama-c MCP server, when it is available

`make verify-<name>` is a batch run: it either discharges or it does not, and
a failure tells you little about which obligation is stuck. If the `frama-c`
MCP server is connected, it drives the same Frama-C interactively, which turns
contract writing into a loop instead of a guess. Start with `self_check`,
because the optional pieces degrade independently, then reload the target's
sources plus `FRAMAC_STUB_DIR`, run WP one function at a time, and use
`get_wp_goals` and `context` to find which obligation is unproved rather than
rewriting a contract on suspicion. Retrying the unproved goals distinguishes
"not proved" from "not proved yet", so check that before rewriting a contract
that only needed a longer timeout. `create_sandbox` is the honest way to try a
strengthening without touching the real source.

Read the `self_check` result rather than the absence of an error: a degraded
server still answers, and the answer looks like a normal response.
`frama_c.status: ok` says only that the binary runs. The fields that decide
whether the interactive path works at all are `socket_spawn`, and
`wp.available` / `eva.available` under `capabilities`.

Do not read a failed `socket_spawn` as a missing `ast_utils` plugin without
checking. Its probes are time-bounded, so on a loaded host they time out and
report `error` or `unknown` for a plugin that is installed and works. Seen
here at load 75 on 8 cores: `socket_spawn` reported "the probe process exited
or never created one" and `ast_utils` came back `unknown`, while
`frama-c -load-module ast_utils_plugin -print-libc` succeeded immediately and
the plugin sat in Frama-C's plugin directory the whole time. `opam_switch_hint`
timing out in the same report is the tell. Confirm with that one-line load
before concluding anything, and re-run `self_check` on a quiet machine; only
if the plugin is genuinely absent is the install
`cd ast-utils && dune install` in the frama-c-mcp checkout.

`reload_project` does not take a raw preprocessor string. It takes structured
flags, and an unknown key is accepted and dropped rather than refused, so a
call carrying `cpp_extra_args` parses with none of them and then fails on a
header that is on the real include path. Mirror `FRAMAC_CPP_ARGS` field by
field instead; for this tree that is

```
include_paths:  ["frama-c-stubs", "src", "build"]
force_includes: ["prelude.h", "macos-libc.h"]
machdep:        "gcc_x86_64"
```

Those three lines are `FRAMAC_INCLUDE_DIRS`, `FRAMAC_FORCE_INCLUDES` and
`FRAMAC_DATA_MODEL` from `mk/verify.mk`, and they are reproduced here only to
show the shape; take the live values from `make print-verify-profiles` below
rather than from this block, which nothing gates.

`nostdinc` and `isystem_paths` are fields, and they are not optional detail on
this platform: without them the real macOS headers win over the modeled libc,
and a file whose parse depends on that shadowing loads as a different program.
Two measurements from when they could not be expressed, both worth knowing
because they are what a load under the wrong headers looks like.
`src/syscall/sys.c` parsed under the `mk/verify.mk` flags and failed without
them, on a `_Static_assert` over `struct rusage` that only holds against the
modeled header, which put it and six others in `parse_surface`'s blocked set:
39 of 60 reported against 46 of 60 true.

The flags are not the only way the two can differ, and the other way cost me a
wrong diagnosis. On `src/syscall/net.c` the server reported `recv_at`'s
`pointer_alignment` obligation unproved, surviving `retry_unproved` at double
the budget, which is its own strongest test for a goal that is unprovable
rather than slow. Under `mk/verify.mk` the same three functions discharge 6 of
6 and that obligation is never generated. I recorded that here as a header
artifact; it was not. The cause was RTE: the kernel's generator and WP's own
are different analyses, the kernel emits `pointer_alignment` assertions and
WP's does not, and the server was starting Frama-C with `-rte` where the recipe
passes `-wp-rte`. Fixed upstream, but the shape is worth keeping: a
`pointer_alignment` goal the build never generates is the signature of the
wrong RTE generator, not of a hard proof.

So the rule is not "distrust the server", it is "pass the flags". A profile
from `make print-verify-profiles` carries both, and `nostdinc` must be stated
for a profile to be proof evidence at all. When you load by hand instead, pass
`nostdinc` and `isystem_paths` yourself, or you are measuring another program.

Two rules about what any of that proves:

- The MCP's default WP model is not what every target uses. A goal that
  discharges under defaults says nothing about whether `make verify-<name>`
  passes. Always mirror the target's own `VERIFY_<NAME>_MODEL`.
- A prover budget is wall-clock, so on a saturated machine a goal can reach it
  whatever its difficulty. Read `wp_timeout_triage` before believing a timeout
  verdict: it carries `host_load_per_cpu` in its evidence and drops to
  `confidence: low` above one runnable thread per CPU, and again when the
  reading is `"unavailable"`, since an unread host is not a quiet one. Only a
  measured quiet host earns `confidence: high`.
- Re-running is not re-measuring, and this is the trap. WP's cache defaults to
  `update`, so it stores timeout verdicts too and replays them. Measured here:
  the same six functions, run under load (one-minute average 40 to 61 on 8
  cores) and again at load 3.3, produced the identical `proof_receipt` sha256,
  with every timeout goal carrying `from_cache: true`. The second run proved
  nothing and looked exactly like the first.

  The response says so now. `measurement` reports `replayed`, `unproved` and
  `unproved_replayed`, and `every_unproved_goal_was_replayed` is the one to
  read: when it is true the run attempted none of its own failures, and
  `wp_timeout_triage` drops to `confidence: low` saying so. Pass
  `cache: "None"` to prove everything in the run. It is the same distinction
  `proof_coverage` draws between `fresh_valid` and `cached_valid`, and it
  costs a re-prove, so spend it when a verdict is about to become a decision.
- `retry_unproved` settles slow against unprovable, and nothing else. It
  re-runs the timed-out goals at double the budget and reports which flip, so
  an empty `flipped` means more time is not the fix. It does not check that the
  program under it is the one you meant: on `src/syscall/net.c` a goal survived
  it and was still an artifact of the wrong header environment. Rule out the
  load, the cache, and the flags before reading it as a property of the code.
- The connected server is whatever binary is installed, which can lag the
  source tree. A behavior described here that the running server does not show
  means the installed binary predates it, not that the description is wrong;
  `self_check` reports the server version.
- The MCP is an accelerator, never the gate. A change lands on `make verify`
  plus `make verify-mutants`, run from the Makefile, because that is what CI
  runs and what a contributor without the server can reproduce. Never report a
  proof as done on MCP evidence alone, and never add a workflow step, script,
  or CI job that depends on the server being connected.

It also answers the coverage question rather than just the green/red one,
which is how you find a target that passes because it is proving less than you
thought. `proof_coverage` is the tool for that:

```
# denominator: every defined function of the loaded project
proof_coverage {}

# denominator: the function set that target declares
proof_coverage {verify_profile: "<target>", detail: "full"}
```

It measures stored conclusions, not the last run, so it reports nothing until
`store_function_conclusion` has filed a receipt from a `run_wp` on the real
project. With nothing loaded and nothing stored it answers `0 of 0`,
`incomplete`, and an empty function list rather than an error, which is easy to
skim as a clean report. Check the denominator before reading the percent.

Sandbox receipts are refused on purpose: a sandbox proves an extracted copy
whose uncontracted callees are stubs. Merge the annotations back, re-run WP on
the main project, and store that receipt.

Read a row's `reason` as the instruction, and treat an empty one as the only
thing that counts. Three of them come up here more than the others:

- `stale_source` after a single edit. A receipt hashes the whole loaded file
  set, not the one file its function lives in, so touching any source reds the
  entire report. Expect it; it is not a signal about the function you edited.
- `unverified_callee`, propagated through the call chain. Fix what
  `blocking_callees` names first.
- `proved_under_a_goal_filter`, meaning the run passed `prop` and left the
  unselected obligations unattempted. That is the "proving less than you
  thought" case caught by name.

One limit on the number, on top of the two rules above. It reads WP only, so
`complete` is a statement about proof obligations generated by the ACSL, RTE
and WP configuration that produced those receipts. A requirement no contract
states is not an uncovered row, it is absent from the denominator entirely, so
coverage cannot tell you the property table is complete.

### Calibrate the server before trusting a number from it

Run one already-green target through it and compare the obligation count with
what the matching `make verify-<name>` reports. Use `iov`: three functions, one
header, and a known answer of 40 of 40.

```
make verify-<name>                  # the answer, for name=iov
reload_project {verify_profiles: <make print-verify-profiles>,
                verify_profile: "iov"}
run_wp         {verify_profile: "iov", cache: "None"}
```

The counts must match exactly. Every wrong conclusion this file records came
from skipping that check, and each was invisible without it:

- The server refused 20 of the 21 targets outright with
  `invalid WP model 'typed'`, comparing the name case-sensitively where
  Frama-C does not care. A profile emitted faithfully from the recipe was
  rejected by the tool whose whole purpose is to run that recipe's proof.
- With that fixed it answered 42 obligations to the recipe's 40, both extras
  `pointer_alignment` on one function, because it started Frama-C with kernel
  `-rte` where the recipe passes `-wp-rte`. Those are different analyses and
  the larger one is not the target's.
- `caveat`, which one target is proved under, is accepted by Frama-C and named
  nowhere in `-wp-h`, so a list built from that help text called it invalid.

None of those announced themselves. Each produced a confident, well-formatted
answer about a program the build system does not prove, and `retry_unproved`
confirmed one of them. Two numbers side by side is the cheapest thing that
catches the whole class, and it costs one target.

### Making the MCP prove what the Makefile proves

`make print-verify-profiles` emits the `verify_profiles` JSON for all of
`mk/verify.mk`, one entry per target, carrying the sources, functions, model,
machdep, include paths, defines, provers, timeout and a `reproduce` command.
It comes from the same variables the `verify-<name>` recipe consumes, so a
profile and a Makefile run cannot disagree about what a target proves. Emit
it, never hand-write it: a hand-written function set is the drift the whole
mechanism exists to prevent.

That property is only as good as the sharing. The two lists the profile and the
recipe both need, include directories and force-includes, live in
`FRAMAC_INCLUDE_DIRS` and `FRAMAC_FORCE_INCLUDES`; `FRAMAC_CPP_ARGS` turns them
into `-I` and `-include` flags with `patsubst`, and the emitter passes them
through as the bare directories and headers the schema wants. Spelling either
list twice is the bug this arrangement exists to prevent, and it is not
hypothetical: they were duplicated at first, under a comment claiming they
could not drift. If you add an include path, add it there and check both sides
move:

```
make print-verify-profiles FRAMAC_INCLUDE_DIRS="... extra" | grep extra
make -n verify-align       FRAMAC_INCLUDE_DIRS="... extra" | grep -- -Iextra
```

The emitter refuses rather than emitting a profile that cannot be used: no
sources, no functions, an empty or blank model, no provers, a non-positive
timeout, a `CPP_DEFS` token that is not a `-D`, or no targets at all. Each
names the make variable to look at. That matters because the server's own
refusal comes much later and names none of them: a profile missing one required
field is accepted for loading and then rejected by every `run_wp` and every
`store_function_conclusion` that names it, which reads as a broken target
rather than as an empty variable on the command line that produced it.

That closes the loop between the two tools:

```
make print-verify-profiles                      # from the build system
reload_project {verify_profiles: <that JSON>, verify_profile: "<target>"}
run_wp         {verify_profile: "<target>"}
store_function_conclusion {function, status: "verified",
                           proof_receipt_sha256, verify_profile: "<target>"}
proof_coverage {verify_profile: "<target>", detail: "full"}
```

The JSON goes in as the object or as its text: the `verify_profiles` parameter
is untyped, so a client that stringifies it is not making a mistake, and the
server decodes either. Naming the profile is what makes each step mean the
target rather than the server's defaults. A run that deviated from the profile
is refused as that target's evidence rather than quietly accepted, and a
conclusion stored without one records what was proved but not what it settles.

Three things to know when feeding it in. The profile carries `nostdinc` and
`isystem_paths` alongside the include paths, all four from the same
`mk/verify.mk` variables the recipe uses, so the load the server makes is the
one the recipe makes. The model strings are the
Makefile's own spelling (`typed`, `caveat`, `Bytes`), which is the point:
normalizing them here would make the profile prove something the recipe does
not. And every profile carries `rte: true`, because every `verify-<name>`
recipe passes `-wp-rte`: that flag decides which obligations exist at all, so a
load without it gives a strictly smaller set. The server treats it as part of
the load identity, so a non-RTE load is refused as that target's evidence
rather than quietly accepted, and a profile that omits it can load sources but
cannot be proof evidence.

`rte: true` means WP's generator specifically, not Frama-C's kernel one. They
are different analyses over the same code and the kernel's is larger: it emits
`pointer_alignment` assertions WP's does not. The server used to start Frama-C
with kernel `-rte` here, which is how a profiled `iov` run answered 42
obligations to the recipe's 40 with both extras unproved. Worth knowing because
the field cannot express the difference, so the only way to see it is the
calibration above.

### frama-c-stubs/

Declarations the analyzer needs that the compiler or macOS supplies:
`Hypervisor/Hypervisor.h` and `macos-libc.h` for Darwin constants the modeled
libc omits, plus `prelude.h`, which declares nothing of its own and instead
force-includes the two headers Frama-C ships but never reaches on its own: its
gcc-builtins model, and its stdatomic.h for the `_Atomic` qualifier its front
end cannot parse and for the C11 atomics vocabulary the tree calls.

It sits outside `src/` on purpose so a real compile, which resolves through
`-Isrc`, cannot reach it. Only `FRAMAC_STUB_DIR` in `mk/verify.mk` does.
It is tracked in git because every proof target needs it to parse.

A missing declaration fails with "Cannot resolve variable" - that is how the
next one gets found. Only a minority of `src/`'s `.c` files parse today; the
rest stop on macOS headers Frama-C's libc genuinely does not model
(`sys/mount.h`, `sys/event.h`, `sys/sysctl.h`, `sys/xattr.h`, `sys/attr.h`,
`sys/spawn.h`). That is a real modeling gap. Do not paper over it with a fake
stub, and do not quote a parse count without recomputing it.

## Other checks

These are not part of `make check` and each answers a different question:

```
make lint                  # clang-tidy
make check-format          # formatting, and regenerates the dispatch header
make check-asan            # use-after-free, overflow, on the host side
make check-ubsan           # undefined behavior
make check-tsan            # data races, worth it for anything multi-vCPU
make infer-uninit          # uninitialized reads
```

## What done means

Green is a claim about named commands, so report it as one: which lanes ran,
what each said, and which ones did not run. The failure modes to avoid, all of
which have shipped before:

- A lane that could not run is named along with the risk that leaves. It is
  never rounded up into the passing set.
- The exit status a gate reports is the one to quote, and it is not always the
  one you are shown. A backgrounded `make check > log 2>&1; echo $?` reports
  the status of the whole command line, so a trailing `echo` makes a failing
  make look like a success: this happened three times in one session, twice
  hiding a real non-zero make. Read the status from inside the command, or read
  the log for `make: *** [target] Error N` and the suite's own `Results:` line.
  A single green summary line proves nothing on its own either, since `make`
  stops at the first failing step and the suites after it never print.
- A count, a latency, or a coverage figure is recomputed before it is quoted,
  including from this file and from `CLAUDE.md`, whose counts drift because
  nothing gates them. Measured in one session: 21 verify targets against its
  20, 32 file-scope locks against its 31, 17 files under `src/proved/` against
  the 15 it lists. The gates print the live number, so take it from
  `make print-verify-targets` and from what `check-lock-order` and
  `check-proof-targets` report. A number carried forward from a document reads
  as measured and is not.
- The `PROVED n of n` line is not in `build/verify-<name>.log`, which carries
  Frama-C's own `[wp] Proved goals: N / N` instead. It is check-wp-result.py's
  console output, colorized unconditionally, with the escape sitting between
  `PROVED` and the count. So a total summed from a `make verify` transcript
  with a naive `grep -oE 'PROVED +[0-9]+ of [0-9]+'` silently matches nothing
  and reports an empty sum rather than failing. Strip the escapes first
  (`sed 's/\x1b\[[0-9;]*m//g'`), or total the logs on `Proved goals` instead.
- A proof is done when `make verify` and `make verify-mutants` say so from the
  Makefile. MCP goals discharging is progress, not a verdict.
- A failure blamed on the environment earns one reproduction attempt under the
  condition blamed for it before it is written off. "Transient" and "the host
  was busy" are the two that hide real defects here, because a test harness
  racing its own pipeline and a probe that measures the wrong thing both fail
  only under load or only on some networks. Reproduce it, or say it went
  unexplained; do not report it as understood. Raising the reproduction rate on
  a failure that will not repeat on demand is `elfuse-debug`, under "When it
  only fails sometimes".

The throughput guardrail is the exception to that bullet: it is the one lane
where load genuinely decides the result. It runs near the end of `make check`,
so it measures on a machine `make check` has just loaded, and an UNMEASURED
verdict there says nothing about the change. Re-run `make test-bench-guardrail`
alone on an idle host and report what it says. UNMEASURED exits non-zero
exactly as a threshold violation does.

Establish the baseline before a multi-command session rather than after: this
tree is not green everywhere, and without the before-picture there is no way
to separate breakage you caused from breakage you inherited.

## Authoritative sources

This skill is a working summary. These are tracked and survive a fresh clone,
so prefer them when the two disagree:

- `docs/testing.md`, section "Validation Strategy By Change Type" - the change
  area to command mapping.
- `mk/verify.mk` - the per-target `_SRC` / `_MODEL` / `_FCTS` variables and
  the comment above each explaining its model choice.
- `tests/test-bench-guardrail.sh` - the comment above the unmeasured check,
  for why UNMEASURED and FAIL both exit non-zero.
