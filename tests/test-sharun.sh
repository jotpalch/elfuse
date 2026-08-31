#!/usr/bin/env bash

# test-sharun.sh - Run sharun and its probe under elfuse
#
# Six arms, in increasing order of what they need from the host:
#   1  the prebuilt launcher, a static aarch64 ELF, so it runs anywhere elfuse
#      does
#   2  the x86_64 build of that same launcher through elfuse's Rosetta path, a
#      static-pie musl Rust binary, a shape no aarch64 lane exercises
#   3  the cross-built probe against the cross-glibc sysroot, which is the
#      loader coverage (DT_NEEDED, dlopen, $ORIGIN rpath) and skips without
#      that toolchain
#   4  the same probe inside a bundle, driven by the real launcher
#   5  the launcher regenerating the bundle's lib.path, which walks the tree
#      and writes to it from inside the guest
#   6  the bundle with its dlopen target removed, which must surface the
#      loader's errno rather than hang or crash
#
# The whole lane exits 77 in two places: when it cannot even reach arm 1, and
# when arm 1 passed but no dynamic-loader arm could run at all. The second is
# what stops a run that covered only the static launcher from reporting the same
# green as one that exercised the loader. Short of that, a developer without a
# bundle still gets the launcher and the loader covered on every run.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

elfuse_input="${1:-build/elfuse}"
case "$elfuse_input" in
    /*) elfuse="$elfuse_input" ;;
    *) elfuse="$(pwd)/$elfuse_input" ;;
esac
probe_dir="${2:-}"
case "$probe_dir" in
    '' | /*) ;;

    # Absolutized like elfuse above: the lane cd's nowhere itself, but it hands
    # this path to build-sharun-bundle.sh and reads it after the guest runs, so
    # a relative one silently breaks every arm when the lane is invoked from
    # anywhere but the repo root.
    *) probe_dir="$(pwd)/$probe_dir" ;;
esac
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

# CROSS_GLIBC_SYSROOT is exported by mk/toolchain.mk, so a make run already has
# it; the fallback asks the compiler the same question mk/toolchain.mk asks,
# which is what makes a hand run work. Spelling the path out here instead would
# reintroduce the literal that variable exists to remove, and would be wrong for
# a distro multiarch compiler whose sysroot is "/".
# "|| true" because the compiler need not exist: a host without the cross
# toolchain is the ordinary case this lane skips on, and without it the failed
# substitution takes errexit and the lane dies before it can report anything.
probe_sysroot="${CROSS_GLIBC_SYSROOT:-$(
    "${CROSS_COMPILE:-aarch64-linux-gnu-}gcc" -print-sysroot 2> /dev/null || true
)}"

# Exported, not just inherited: the fetch scripts run as subprocesses and read
# FIXTURES_DIR themselves, so without this a "make check FIXTURES_DIR=..." moved
# every other fixture and left these two caching under the repo default.
export FIXTURES_DIR="${FIXTURES_DIR:-$repo_root/externals/test-fixtures}"

# Before report.sh, which sources tests/lib/test-runner.sh, which defaults this
# to 10. Every arm here boots the hypervisor and runs a dynamically linked
# probe, so 10 is where a slow machine starts reporting timeouts as failures.
# Assigned rather than tested afterwards so "TEST_TIMEOUT=60 make check" still
# wins.
: "${TEST_TIMEOUT:=20}"

# shellcheck source=tests/lib/report.sh
. "$repo_root/tests/lib/report.sh"

# The lock is plain KEY=VALUE and every other consumer sources it. Re-reading
# individual keys with sed here would be a second parser for one format.
# shellcheck source=tests/sharun-fixture.lock
. "$repo_root/tests/sharun-fixture.lock"

[ -x "$elfuse" ] || {
    printf 'elfuse binary not found: %s\n' "$elfuse" >&2
    exit 1
}

# One answer to "is there a probe to run", so arms 3 and 4 ask it the same way.
# The probe itself, not the sysroot directory: make builds it only when the
# sysroot could compile and link it, so its presence is the tested fact, while a
# -d on a path this script guessed skips the two arms the lane exists for on any
# host whose sysroot is somewhere else.
#
# An empty probe_dir is a host without the cross toolchain, which is the skip
# this lane is built to degrade to. A probe_dir that was given but holds no
# usable probe is a broken build, and reporting that as "no cross-glibc sysroot"
# names a cause that is not the one in front of the reader, in the same green
# shape as a host that legitimately has no toolchain. Missing and present but
# not executable are the same answer here: a directory was named and there is
# nothing runnable in it.
if [ -n "$probe_dir" ] && [ ! -x "$probe_dir/probe" ]; then
    printf 'no runnable probe in the directory given: %s/probe\n' "$probe_dir" >&2
    printf 'the cross build produces it; "make test-sharun" builds it first\n' >&2
    exit 1
fi

# A probe with no sysroot to run it against. Only reachable by hand: a make run
# exports CROSS_GLIBC_SYSROOT, and the guard that builds the probe links against
# it. Loud rather than passing --sysroot '' to elfuse, which fails inside the
# guest as a loader error naming neither the empty sysroot nor the reason.
if [ -n "$probe_dir" ] && [ -z "$probe_sysroot" ]; then
    printf 'a probe was built but no cross-glibc sysroot is known; set\n' >&2
    printf 'CROSS_GLIBC_SYSROOT or run this through "make test-sharun"\n' >&2
    exit 1
fi

# timeout, not "$TIMEOUT": tests/lib/test-runner.sh, which report.sh sources,
# defines a timeout wrapper over the whole ladder it searches (TIMEOUT_BIN, then
# timeout, then gtimeout, then Homebrew's opt symlinks). report.sh's
# require_timeout looks only on PATH, so a host with coreutils installed but not
# linked skipped this entire lane while every other lane ran.
#
# One timeout for every guest invocation, applied in run_guest so no arm can
# choose its own. It was a literal at each call site, with nothing keeping them
# equal.
GUEST_TIMEOUT="$TEST_TIMEOUT"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# Resolve a launcher. The fetcher separates the two ways this goes wrong, and
# the difference matters: 77 means it could not be downloaded, which is a skip,
# while anything else means the cached copy failed its digest, which is a broken
# tree and has to be loud. Collapsing them would turn a corrupted cache into a
# green skip. Sets launcher_path and launcher_rc.
launcher_path=''
launcher_rc=0
resolve_launcher()
{
    set +e
    launcher_path="$("$repo_root/tests/fetch-sharun-bin.sh" "$1" \
        2> "$scratch/fetch-$1.err")"
    launcher_rc=$?
    set -e
    [ "$launcher_rc" -eq 0 ] || launcher_path=''
}

# Fetched here, not by a make prerequisite: a prerequisite that cannot be
# downloaded is fatal, and this lane runs inside "make check".
resolve_launcher aarch64
if [ "$launcher_rc" -ne 0 ]; then
    cat "$scratch/fetch-aarch64.err" >&2
    [ "$launcher_rc" -eq 77 ] && exit 77
    printf 'sharun launcher is present but unusable; the lane cannot continue\n' >&2
    exit 1
fi
sharun="$launcher_path"

# A literal, not a fixture file. The file it replaced synchronized nothing:
# tests/fixtures/sharun/probe.c prints this string from its own literal, so both
# still had to be edited together, and no other lane keeps expected output in
# tests/fixtures.
expected='sharun-probe-ok'
total=6

# Arms that actually exercised a dynamic loader, as opposed to skipping. Read
# once at the end to decide whether this run covered anything.
loader_arms_run=0

guest_rc=0
run_guest()
{
    local tag="$1"
    shift
    set +e
    timeout "$GUEST_TIMEOUT" "$@" > "$scratch/$tag.out" 2> "$scratch/$tag.err"
    guest_rc=$?

    # 124 is the cap firing, not the guest failing. Every arm here boots the
    # hypervisor, so a machine under load can push a correct run past the cap
    # and the arm would report rc=124 as though the probe were wrong. Re-run
    # once, and only when the host is actually busy: an idle machine reports the
    # timeout immediately and pays nothing, and a real hang reproduces on the
    # second attempt.
    #
    # Without the elapsed-time comparison tests/lib/test-runner.sh makes,
    # because there is nothing here for it to disambiguate. That runner has two
    # watchdogs and uses elapsed time to tell its own from the guest's; this
    # lane has one, the timeout on the line above, and the programs it runs are
    # the launcher and the probe, which exit 1 to 6 and never 124. A 124 here is
    # the cap and nothing else, so the only open question is whether load caused
    # it.
    if [ "$guest_rc" -eq 124 ] && test_host_is_busy; then
        printf 'timeout under host load, re-running: %s\n' "$tag" >&2
        timeout "$GUEST_TIMEOUT" "$@" > "$scratch/$tag.out" 2> "$scratch/$tag.err"
        guest_rc=$?
    fi
    set -e
}

# Run a guest command under elfuse and require rc 0 plus a marker on stdout.
# Named separately from tests/lib/test-runner.sh's run(): that resolves the
# binary as $BIN/$tool, and these arms live in three different directories.
#
# Every arm that runs a program and checks what it printed comes through here,
# arm 4 included. It was written out a second time there, and the two copies had
# already drifted in how they worded the same failure; one binary checked two
# ways is how a lane starts disagreeing with itself.
#
# The verdict comes back in marker_ok rather than the return status, matching
# guest_rc and launcher_rc above. A function that returns 1 would abort the lane
# under errexit at the call sites that do not test it.
marker_ok=0
expect_marker()
{
    local label="$1" marker="$2" tag="$3"
    shift 3
    run_guest "$tag" "$@"
    marker_ok=0

    # Read once and reused below. Read again for the diagnostic, an arm that
    # printed nothing and an arm that printed the wrong thing render the same
    # blank line, and those are the two cases a reader has to tell apart.
    local got=''
    got="$(cat "$scratch/$tag.out")"

    # Whole-stdout equality. A substring match would let extra output through in
    # one arm and fail in another, so two arms would disagree about one binary.
    if [ "$guest_rc" -eq 0 ] && [ "$got" = "$marker" ]; then
        report_pass "$label"
        marker_ok=1
        return 0
    fi

    # Which of the two failed. "rc=0" alone reads as a false alarm when the
    # process succeeded and only the output disagreed.
    if [ "$guest_rc" -ne 0 ]; then
        report_fail "$label: rc=$guest_rc"
    else
        report_fail "$label: output"
    fi

    # Name both sides. A wrong-output failure and a no-output failure print the
    # same thing otherwise, and the probe's stage codes are only readable next
    # to what it was supposed to say.
    printf 'expected stdout: %s\n' "$marker" >&2
    if [ -n "$got" ]; then
        printf 'actual stdout:   %s\n' "$got" >&2
    else
        printf 'actual stdout:   (nothing on stdout)\n' >&2
    fi
    sed 's/^/  stderr: /' "$scratch/$tag.err" >&2
    return 0
}

# Arm 1: the launcher. --version both pins the binary the lock file names and
# proves the Rust runtime got far enough to render output.
expect_marker 'sharun --version' "$SHARUN_VERSION_OUTPUT" version \
    "$elfuse" "$sharun" --version

# Arm 2: the same check through Rosetta. Skips when the translator is absent,
# the same gate tests/test-rosetta-statics.sh uses.
rosetta="${MATRIX_ROSETTA_TRANSLATOR:-/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"
if [ -n "${ELFUSE_NO_ROSETTA:-}" ]; then

    # Present on disk is not the same as willing to use it. This arm hands
    # elfuse an x86_64 binary, which the documented opt-out makes it refuse, so
    # without this the lane reports a red failure for a supported configuration.
    report_skip 'sharun x86_64 (Rosetta disabled)'
elif [ ! -x "$rosetta" ]; then
    report_skip 'sharun x86_64 (no Rosetta translator)'
else
    resolve_launcher x86_64
    if [ "$launcher_rc" -eq 77 ]; then
        report_skip 'sharun x86_64 (launcher unavailable)'
        cat "$scratch/fetch-x86_64.err" >&2
    elif [ "$launcher_rc" -ne 0 ]; then

        # Any non-77: a rotten pin, an HTTP error, or a digest that does not
        # match. Naming one of them here mislabels the other two.
        report_fail 'sharun x86_64 (launcher unusable)'
        cat "$scratch/fetch-x86_64.err" >&2
    else
        expect_marker 'sharun --version (x86_64 via Rosetta)' \
            "$SHARUN_VERSION_OUTPUT" version-x86 "$elfuse" "$launcher_path" \
            --version
    fi
fi

# Arm 3: the probe, standalone. SHARUN_FIXTURE_MARKER and SHARUN_DIR are what
# the bundle's .env and the launcher supply in arm 4; here the lane stands in
# for them, which is the only difference between the two probe runs.
if [ -z "$probe_dir" ]; then
    report_skip 'sharun probe (no cross-glibc sysroot)'
else
    loader_arms_run=$((loader_arms_run + 1))
    expect_marker 'sharun probe (dlopen, rpath, threads, fork)' \
        "$expected" probe env SHARUN_FIXTURE_MARKER=ok SHARUN_DIR=/sharun \
        "$elfuse" --sysroot "$probe_sysroot" "$probe_dir/probe"
fi

# Arms 5 and 6 only exist inside a bundle. Whenever arm 4 cannot run they still
# have to account for themselves, or the lane prints four lines and claims six.
skip_bundle_extras()
{
    report_skip "sharun --gen-lib-path ($1)"
    report_skip "sharun missing DSO ($1)"
}

# Stage a private copy of the bundle. Arms 5 and 6 both mutate what they run
# against, so they get their own: sharing one tree made a failure in arm 5 come
# back as an unrelated failure in arm 6. It also keeps an external
# SHARUN_FIXTURE_DIR read-only.
stage_bundle()
{
    local dest="$scratch/$1"
    rm -rf "$dest"
    mkdir -p "$dest"

    # -L, so a SHARUN_FIXTURE_DIR that is a symlink becomes a real tree here.
    # Without it the stage is itself a symlink back to the caller's bundle, and
    # the arms below delete through it into their source.
    #
    # A plain copy. An APFS clone (cp -c) saved about 7 ms per stage on a 3 MB
    # bundle, three times in a lane that boots the hypervisor six times, and
    # cost a Darwin test, an empty branch, and a recovery for the half-created
    # directory a failed clone leaves behind.
    cp -aL "$fixture" "$dest/sharun" || return 1
    printf '%s\n' "$dest"
}

# Arms 4, 5 and 6, all against one bundle. Every early return has already
# accounted for all three.
run_bundle_arms()
{
    local file missing='' sysroot

    # What these three arms need, which is the launcher plus this lane's probe
    # and its two DSOs. That is more than a generic sharun bundle carries, so
    # SHARUN_FIXTURE_DIR has to point at one built around this probe rather than
    # at any lib4bin output. manifest.txt is deliberately not required: only
    # tests/build-sharun-bundle.sh writes it, and the arms never read it.
    # Everything the arms open, including the two that are not programs: arms 4
    # and 6 read the marker out of .env, and arm 5 regenerates lib.path. Left
    # out, an external bundle missing either passed this check and failed later
    # as a wrong-output or missing-file error pointing at the arm rather than at
    # the bundle it was handed.
    for file in sharun bin/probe shared/bin/probe shared/lib/libprobe.so \
        shared/lib/libprobe-dlopen.so .env shared/lib/lib.path; do
        [ -e "$fixture/$file" ] || missing="$missing $fixture/$file"
    done
    if [ -n "$missing" ]; then
        printf 'sharun fixture is not a probe bundle; missing:%s\n' \
            "$missing" >&2
        report_fail 'sharun bundle (incomplete fixture)'
        skip_bundle_extras 'bundle unusable'
        return 0
    fi

    # Arm 4: the probe under the real launcher. Staging can fail (a full disk, a
    # bad fixture). Report it as the arm's failure rather than letting errexit
    # kill the lane with no summary.
    if ! sysroot="$(stage_bundle probe)"; then
        report_fail 'sharun bundle (could not stage)'
        skip_bundle_extras 'bundle unusable'
        return 0
    fi
    loader_arms_run=$((loader_arms_run + 1))
    expect_marker 'sharun bundle (launcher plus probe)' "$expected" bundle \
        "$elfuse" --sysroot "$sysroot" /sharun/bin/probe

    # Only this arm has a manifest, and only a failure wants it: it records
    # which launcher and glibc the bundle was assembled from, which is the first
    # question asked when the probe runs but says the wrong thing.
    if [ "$marker_ok" -eq 0 ] && [ -e "$fixture/manifest.txt" ]; then
        cat "$fixture/manifest.txt" >&2
    fi

    # Arm 5: the launcher rewriting the bundle from inside the guest.
    # --gen-lib-path walks shared/lib and writes lib.path back, so this is the
    # one arm where a sharun subcommand does directory reads and a file create
    # through elfuse rather than just exec'ing the loader.
    if ! sysroot="$(stage_bundle genlibpath)"; then
        report_fail 'sharun --gen-lib-path (could not stage)'
        report_skip 'sharun missing DSO (could not stage)'
        return 0
    fi
    rm -f "$sysroot/sharun/shared/lib/lib.path"

    # Not counted as a loader arm: --gen-lib-path is the static launcher reading
    # a directory and writing a file, with no dynamic loader involved. The
    # counter decides whether this run covered the loader at all, so an arm that
    # did not must not vote. Harmless today, since arm 4 always runs first, but
    # the counter's definition is what the exit-77 message claims.
    run_guest gen "$elfuse" --sysroot "$sysroot" /sharun/sharun --gen-lib-path

    # Content, not just size. The arm exists to show the launcher rewrites the
    # file correctly, and "not empty" would accept anything it happened to put
    # there. A bundle whose libraries all sit in shared/lib regenerates to the
    # single relative entry "+".
    if [ "$guest_rc" -eq 0 ] \
        && [ "$(cat "$sysroot/sharun/shared/lib/lib.path" 2> /dev/null)" = '+' ]; then
        report_pass 'sharun --gen-lib-path'
    else

        # Which of the two failed. The launcher exiting 0 and writing nothing
        # reads as a pass otherwise.
        if [ "$guest_rc" -ne 0 ]; then
            report_fail "sharun --gen-lib-path: rc=$guest_rc"
        elif [ ! -s "$sysroot/sharun/shared/lib/lib.path" ]; then
            report_fail 'sharun --gen-lib-path: no lib.path'
            ls -l "$sysroot/sharun/shared/lib/" >&2 2> /dev/null || true
        else

            # Present but not what the launcher should have written. Saying it
            # is missing and then listing a directory that contains it is worse
            # than saying nothing.
            report_fail 'sharun --gen-lib-path: wrong lib.path'
            printf 'wanted: +\n' >&2
            sed 's/^/  got: /' "$sysroot/sharun/shared/lib/lib.path" >&2
        fi
        sed 's/^/  stderr: /' "$scratch/gen.err" >&2
    fi

    # Arm 6: the negative path. With the dlopen target gone the probe must come
    # back with its own exit 3 and the loader's message, which is what proves
    # elfuse surfaces a failed dlopen instead of hanging or dying.
    if ! sysroot="$(stage_bundle missingdso)"; then
        report_fail 'sharun missing DSO (could not stage)'
        return 0
    fi
    rm -f "$sysroot/sharun/shared/lib/libprobe-dlopen.so"
    loader_arms_run=$((loader_arms_run + 1))
    run_guest miss "$elfuse" --sysroot "$sysroot" /sharun/bin/probe

    # The two halves report separately. "rc=3, want 3" is what this said when
    # the exit code was right and only the loader's message was missing, which
    # reads as a contradiction.
    if [ "$guest_rc" -ne 3 ]; then
        report_fail "sharun bundle (missing DSO): rc=$guest_rc, want 3"
        sed 's/^/  stderr: /' "$scratch/miss.err" >&2
    elif ! grep -q 'libprobe-dlopen.so' "$scratch/miss.err"; then
        report_fail 'sharun bundle (missing DSO): no dlerror'
        printf 'wanted libprobe-dlopen.so named on stderr\n' >&2
        sed 's/^/  stderr: /' "$scratch/miss.err" >&2
    else
        report_pass 'sharun bundle (missing DSO reports dlerror)'
    fi
}

# Arm 4: the same probe inside a bundle, driven by the real launcher. The bundle
# is assembled here from the prebuilt launcher, the probe already built for arm
# 3, and a prebuilt glibc. lib4bin would compute the probe's library closure
# with ldd and rewrite it with patchelf, which needs a Linux host; the closure
# is fixed and known, so the layout is written out directly instead.
#
# SHARUN_FIXTURE_DIR still points the arms at an unpacked bundle from elsewhere,
# which is how a real lib4bin bundle gets tested when someone has one.
fixture="${SHARUN_FIXTURE_DIR:-}"
if [ -n "$fixture" ]; then
    [ -d "$fixture" ] || {
        report_fail "sharun bundle: SHARUN_FIXTURE_DIR missing: $fixture"
        skip_bundle_extras 'no bundle'
        fixture=''
    }
elif [ -z "$probe_dir" ]; then
    report_skip 'sharun bundle (no probe to bundle)'
    skip_bundle_extras 'no bundle'
else
    set +e
    glibc_dir="$("$repo_root/tests/fetch-glibc.sh" 2> "$scratch/glibc-err")"
    glibc_rc=$?
    set -e
    if [ "$glibc_rc" -eq 77 ]; then

        # 77 is the whole condition, and tests/lib/fixture-cache.sh states what
        # it means. Enumerating the causes here went stale the day a missing
        # ar(1) became a loud failure, and a caller that lists them will sooner
        # or later list one the callee no longer reports that way.
        report_skip 'sharun bundle (no glibc package)'
        skip_bundle_extras 'no bundle'
        cat "$scratch/glibc-err" >&2
    elif [ "$glibc_rc" -ne 0 ]; then

        # The package arrived and was wrong, or the cached runtime is damaged.
        # Same rule as the launcher: present but broken has to be loud.
        report_fail 'sharun bundle (glibc runtime unusable)'
        skip_bundle_extras 'bundle unusable'
        cat "$scratch/glibc-err" >&2
    elif rm -rf "$scratch/local-bundle" \
        && bash "$repo_root/tests/build-sharun-bundle.sh" "$sharun" "$probe_dir" \
            "$glibc_dir" "$scratch/local-bundle" 2> "$scratch/build-err"; then
        fixture="$scratch/local-bundle"
    else

        # The inputs were all there and assembly still failed, which means the
        # tree is wrong (a probe that grew a dependency the bundle does not
        # carry, say). That is a failure, not a skip.
        report_fail 'sharun bundle (assembly failed)'
        skip_bundle_extras 'bundle unusable'
        cat "$scratch/build-err" >&2
        fixture=''
    fi
fi

# An if, not "[ -n ... ] && run_bundle_arms": that form returns nonzero when the
# fixture is empty, and errexit would then abort the lane before it printed its
# summary. Nothing to do with suppressing errexit inside the function: a
# then-branch does not suppress it, only a condition list does.
if [ -n "$fixture" ]; then
    run_bundle_arms
fi

# A run where every loader arm skipped proves nothing about the loader, which is
# the whole reason this lane exists, and it must not report the same status as
# one that covered it. It exits 77 rather than failing: the cross-glibc
# toolchain is optional, RUN_OPTIONAL_SKIP77 turns that into a visible SKIP, and
# failing here would red "make check" on every machine that simply does not have
# it. What this rules out is the third outcome, a silent green that covered
# nothing. Before the summary, not after. tests/test-matrix.sh scrapes the
# "Results:" line, and RUN_OPTIONAL_SKIP77 adds only a lane-level SKIP, so
# printing a passes-and-skips tally first and exiting 77 afterwards reads as a
# partial pass for a run that covered no loader at all.
if [ "$fail" -eq 0 ] && [ "$loader_arms_run" -eq 0 ]; then
    printf 'no dynamic-loader arm ran: this host has no cross-glibc sysroot and\n' >&2
    printf 'no bundle, so only the static launcher was covered\n' >&2
    report_summary "$total"
    exit 77
fi

report_summary "$total"

# Not "exit $fail": mk/tests.mk wraps this lane in RUN_OPTIONAL_SKIP77, which
# reads the exit status as a sentinel where 77 means skip. Handing it a failure
# count would report a green skip the day this lane grows 77 failing checks.
[ "$fail" -eq 0 ] || exit 1
