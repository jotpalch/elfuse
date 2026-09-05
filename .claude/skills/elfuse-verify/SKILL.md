---
name: elfuse-verify
description: How elfuse validates a change - choosing the lanes for the area you touched, the test matrix, make check, and the Frama-C proof targets declared in mk/verify.mk, including how to drive the frama-c MCP server on a stuck proof. Use when adding bounds math to src/proved/, writing or repairing ACSL contracts, running or debugging make verify / verify-mutants, touching frama-c-stubs/, adding a test lane, or deciding what to run before calling work done.
---

# Validating an elfuse change

Two independent gates: the runtime tests and the proofs. A change to
attacker-facing bounds math needs both.

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

`verify-mutants` accepts `MUTANT_TARGET=<name>`, `MUTANT_JOBS=<n>`, and
`MUTANT_SINCE=<rev>` for a changed-only run.

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

Two rules about what any of that proves:

- The MCP's default WP model is not what every target uses. A goal that
  discharges under defaults says nothing about whether `make verify-<name>`
  passes. Always mirror the target's own `VERIFY_<NAME>_MODEL`.
- The MCP is an accelerator, never the gate. A change lands on `make verify`
  plus `make verify-mutants`, run from the Makefile, because that is what CI
  runs and what a contributor without the server can reproduce. Never report a
  proof as done on MCP evidence alone, and never add a workflow step, script,
  or CI job that depends on the server being connected.

It also answers the coverage question rather than just the green/red one:
asking for goal counts shows how much of the property table has a verdict,
which is how you find a target that passes because it is proving less than you
thought.

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
- A count, a latency, or a coverage figure is recomputed before it is quoted,
  including from this file. A number carried forward from a document reads as
  measured and is not.
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
