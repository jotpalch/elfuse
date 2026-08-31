#!/usr/bin/env bash

# build-sharun-bundle.sh - Assemble a sharun bundle without lib4bin
#
# lib4bin computes a binary's library closure with ldd and rewrites it with
# patchelf, which needs a Linux host. The probe's closure is known and fixed
# (libc, libm, libdl, libpthread, and its own two DSOs), so the layout can be
# written out directly and the bundle assembled anywhere, from the prebuilt
# launcher plus a prebuilt glibc.
#
# This is the only bundle builder: nothing in the tree shells out to lib4bin, so
# the lane has no Linux dependency and no published artifact to keep in step.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage="Usage: $0 <sharun-binary> <probe-dir> <glibc-dir> <out-dir>"
sharun="${1:?$usage}"
probe_dir="${2:?$usage}"
glibc_dir="${3:?$usage}"
out="${4:?$usage}"

# For GLIBC_CLOSURE, the one list of what the bundle's glibc holds.
# tests/fetch-glibc.sh copies those out of the package, this copies them in, and
# a list in each is how the two drift.
# shellcheck source=tests/sharun-fixture.lock
. "$(dirname "$0")/sharun-fixture.lock"

# readelf is a precondition of the DT_NEEDED gate at the end. Resolve it here so
# a missing cross toolchain fails before anything is created, rather than after
# a bundle has been assembled.
#
# One line rather than a copy of mk/toolchain.mk's search. The makefile always
# passes CROSS_COMPILE, so the ladder that used to be here only ran for a hand
# invocation, and it probed for -readelf where the makefile probes for -gcc: a
# toolchain with one and not the other made the two disagree. The guard below
# reports a bad hand-run just as well.
readelf="${CROSS_COMPILE:-aarch64-linux-gnu-}readelf"
command -v "$readelf" > /dev/null || {
    printf 'readelf not found: %s\n' "$readelf" >&2
    exit 1
}

for f in "$sharun" "$probe_dir/probe" "$probe_dir/libprobe.so" \
    "$probe_dir/libprobe-dlopen.so"; do
    [ -e "$f" ] || {
        printf 'sharun bundle input missing: %s\n' "$f" >&2
        exit 1
    }
done

# Never deletes: the output directory must not already exist. The only caller
# hands over a fresh path inside its own mktemp -d, and refusing to create the
# bundle on top of anything is a shorter and more honest contract than trying to
# decide which directories are safe to erase. A hand run passes a new path too.
[ -e "$out" ] && {
    printf 'bundle output already exists: %s\n' "$out" >&2
    exit 1
}

mkdir -p "$out/bin" "$out/shared/bin" "$out/shared/lib"
cp "$probe_dir/probe" "$out/shared/bin/probe"
cp "$probe_dir/libprobe.so" "$probe_dir/libprobe-dlopen.so" "$out/shared/lib/"

# Only the probe's own closure. Copying the whole package would drag in the nss
# and locale modules, which nothing here loads. Every one of them, not "copy it
# if it happens to be there": this reports a missing library against the glibc
# runtime it came from, which is the directory worth naming when one is absent.
for l in $GLIBC_CLOSURE; do
    [ -e "$glibc_dir/$l" ] || {
        printf 'glibc runtime is missing %s: %s\n' "$l" "$glibc_dir" >&2
        exit 1
    }
    cp -L "$glibc_dir/$l" "$out/shared/lib/$l"
done

# bin/probe is the launcher, not the program: sharun dispatches on argv[0] and
# runs shared/bin/<argv0> under the bundled loader. lib4bin hard-links the two;
# a copy is the same thing at this size.
cp "$sharun" "$out/sharun"
cp "$sharun" "$out/bin/probe"

# shared/bin/probe too, not just the two launcher copies. It is what the
# launcher execs, and leaving its mode to whatever cp carried over makes the
# bundle depend on how the probe was built rather than on what this writes.
chmod +x "$out/sharun" "$out/bin/probe" "$out/shared/bin/probe"

# lib.path is what sharun passes to the loader as --library-path, one directory
# per line, "+" meaning relative to the file's own directory. Written exactly as
# the launcher's own --gen-lib-path writes it, so the bundle and a regenerated
# one are byte-identical and tests/test-sharun.sh can assert one format.
printf '+\n' > "$out/shared/lib/lib.path"
printf 'SHARUN_FIXTURE_MARKER=ok\n' > "$out/.env"
{
    printf 'sharun=%s\n' "$sharun"
    printf 'glibc_dir=%s\n' "$glibc_dir"
    printf 'assembled_by=%s\n' "$0"
    printf 'assembled_on=%s\n' "$(uname -m)"
} > "$out/manifest.txt"

# The library list above is hardcoded, which is the one job lib4bin used to do
# by walking ldd. Nothing else would notice a fixture that grew a dependency:
# the bundle would simply lack it and the lane would fail with a loader error
# pointing at the wrong thing. readelf comes from the same cross toolchain that
# built the probe, so it is always present when this script runs.
#
# The DSOs are checked as well as the probe: a dependency added to either of
# them (libgcc_s.so.1 from a new builtin, say) is the same silent fall-behind.
# One readelf call takes all three, since the gate is a union over them.
#
# Command substitution, not process substitution into a while loop: there a
# readelf failure feeds the loop empty output, set -e never sees the producer's
# status, and the guard passes without having looked. Every ELF the bundle
# ships, not just the three this repo builds. The runtime libraries have their
# own DT_NEEDED, and reading only the probe's made the gate a check on the first
# level of the closure rather than the closure: a glibc whose libm grew a
# dependency would ship a bundle missing it and fail inside the guest, which is
# the error this gate exists to turn into a build failure.
needed="$("$readelf" -d "$out/shared/bin/probe" "$out"/shared/lib/*.so*)" || {
    printf 'readelf failed on the assembled bundle\n' >&2
    exit 1
}

# read, not "for lib in $(...)": an unquoted command substitution in a for list
# is word-split and glob-expanded, so a soname carrying whitespace or a bracket
# would be torn apart or matched against the filesystem. The colon is optional:
# GNU readelf prints "Shared library: [x]" and llvm-readelf omits it. Getting
# that wrong does not fail the gate, it empties it, which passes everything.
sonames="$(printf '%s\n' "$needed" \
    | sed -n 's/.*Shared library:*[[:space:]]*\[\(.*\)\]/\1/p' | sort -u)"

# The probe links at least libc, so extracting nothing means the pattern no
# longer matches this readelf's output rather than that the bundle is complete.
[ -n "$sonames" ] || {
    printf 'no DT_NEEDED entries parsed; readelf output format changed?\n' >&2
    "$readelf" -d "$out/shared/bin/probe" >&2
    exit 1
}

# Present is not the same as usable. The probe is linked against the toolchain's
# own glibc while the bundle ships the pinned Debian one, so a newer toolchain
# can leave the probe asking for symbol versions the bundled libc never defines.
# Every soname would still be present and the gate above would pass, and the
# failure would arrive inside the guest as a loader error naming a symbol rather
# than the skew that caused it.
#
# Highest versioned GLIBC_ tag on each side: .gnu.version_r across every ELF the
# cross toolchain built, against libc's .gnu.version_d, compared with sort -V.
# The DSOs as well as the probe, matching the DT_NEEDED gate above: a newer
# toolchain can leave one of them naming a symbol version the probe itself never
# asks for. Section-scoped, because libc carries both sections and what it needs
# says nothing about what it provides.
version_slice()
{
    awk -v s="$1" "index(\$0, \"section '\" s \"'\"){f=1;next} /section '/{f=0} f" \
        | sed -n 's/.*Name: GLIBC_\([0-9.]*\).*/\1/p' | sort -V -u | tail -1
}
want_glibc="$("$readelf" -V "$out/shared/bin/probe" \
    "$out/shared/lib/libprobe.so" "$out/shared/lib/libprobe-dlopen.so" \
    | version_slice .gnu.version_r)"
have_glibc="$("$readelf" -V "$out/shared/lib/libc.so.6" | version_slice .gnu.version_d)"

# Which readelf this is decides what an empty parse means. The section headings
# this reads are GNU readelf's; llvm-readelf lays -V out differently, and the
# soname gate above works with either, so a bundle assembled by hand with the
# llvm tools would fail here claiming the format changed when nothing had. GNU
# and nothing parsed is a real format change and stays fatal; anything else says
# what it skipped and why. Untested against llvm-readelf: none is installed
# here, so this is written from the two tools' documented output, not measured.
[ -n "$want_glibc" ] && [ -n "$have_glibc" ] || {
    if "$readelf" --version 2>&1 | grep -q GNU; then
        printf 'could not read GLIBC symbol versions; readelf output changed?\n' >&2
        exit 1
    fi
    printf 'skipping the glibc version check: %s is not GNU readelf\n' \
        "$readelf" >&2
    want_glibc=''
}
[ -z "$want_glibc" ] \
    || [ "$(printf '%s\n%s\n' "$want_glibc" "$have_glibc" | sort -V | tail -1)" \
        = "$have_glibc" ] || {
    printf 'glibc skew: the probe needs GLIBC_%s, the bundle ships GLIBC_%s\n' \
        "$want_glibc" "$have_glibc" >&2
    printf 'the cross toolchain is newer than GLIBC_VERSION in %s\n' \
        "$(dirname "$0")/sharun-fixture.lock" >&2
    exit 1
}

missing=''
while IFS= read -r lib; do
    [ -e "$out/shared/lib/$lib" ] || missing="$missing $lib"
done <<< "$sonames"
[ -z "$missing" ] || {
    printf 'bundle is missing DT_NEEDED entries:%s\n' "$missing" >&2
    printf 'add them to GLIBC_CLOSURE in %s\n' \
        "$(dirname "$0")/sharun-fixture.lock" >&2
    exit 1
}
