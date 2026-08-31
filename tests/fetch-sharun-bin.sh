#!/usr/bin/env bash

# fetch-sharun-bin.sh - Resolve a prebuilt sharun launcher for one architecture
#
# Usage: fetch-sharun-bin.sh aarch64|x86_64
#
# Prints the path to the launcher. Exits 77 when it cannot be fetched, so an
# unreachable network degrades the lane to a skip instead of failing the build.
# That is the whole reason this is a script and not a make rule: a make
# prerequisite that cannot be downloaded is fatal, and "make check" runs this
# lane.
#
# The binary is cached as "sharun" whatever the release calls it, because the
# launcher dispatches on argv[0] and looks for shared/bin/<argv0>. Under its
# release name it hunts for a bundle entry instead of serving --version.
# Upstream's own install line does the same rename.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

arch="${1:?Usage: $0 aarch64|x86_64}"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=tests/lib/fixture-cache.sh
. "$repo_root/tests/lib/fixture-cache.sh"
# shellcheck source=tests/sharun-fixture.lock
. "$repo_root/tests/sharun-fixture.lock"

case "$arch" in
    aarch64)
        asset="$SHARUN_BIN_NAME"
        want="$SHARUN_BIN_SHA256"
        ;;
    x86_64)
        asset="$SHARUN_BIN_X86_64"
        want="$SHARUN_BIN_X86_64_SHA256"
        ;;
    *)
        printf 'unknown sharun architecture: %s\n' "$arch" >&2
        exit 1
        ;;
esac

fixtures="${FIXTURES_DIR:-$repo_root/externals/test-fixtures}"

# One cache entry per architecture, so an unreachable x86_64 asset cannot cost
# the aarch64 arms their coverage.
dir="$fixtures/sharun/$SHARUN_VERSION/$arch"

# Called by fixture_cache_build with the staging directory last. Everything here
# writes only into that directory, so a failure leaves no partial cache.
fetch_launcher()
{
    local stage="$1"
    local out="$stage/sharun"

    fixture_cache_download \
        "https://github.com/VHSgunzo/sharun/releases/download/$SHARUN_VERSION/$asset" \
        "$out" "sharun launcher $SHARUN_VERSION $asset" || return $?
    fixture_cache_digest_ok "$out" "$want" 'sharun launcher' || return 1
    chmod +x "$out"
    return 0
}

# Checked on a cache hit, by fixture_cache_build, which runs this without
# holding its publish lock: verification reads the whole tree, and a lock held
# that long would break the assumption its stale-lock reaper rests on. Only the
# eviction that follows a failed check takes the lock, because that is a rename.
# fetch_launcher verifies before the file lands, but a hit skips the builder and
# the binary is then trusted by path, so this is the only thing that notices a
# cache corrupted after the fact; failing it evicts and rebuilds rather than
# reporting, because the cache is keyed by version and architecture, so every
# later run would fail identically until a human guessed which directory to
# delete. Here rather than in the caller so every architecture gets it from one
# rule: when the caller did it, the second architecture was added without one.
verify_launcher()
{
    fixture_cache_digest_ok "$1/sharun" "$want" 'cached sharun launcher'
}

# Propagate rather than flatten: 77 means it could not be fetched, anything else
# means what arrived was wrong. Collapsing them here turned a pinned-digest
# mismatch on a cold cache into a green skip.
fixture_cache_build "$dir" verify_launcher fetch_launcher || exit $?

# Separately from the digest, because it is not a property of the bytes: chmod
# runs only in the builder, which a cache hit skips, so a cached binary that
# lost its bit hashes correctly and would fail later at exec. Restored rather
# than reported: the bytes are already proven right, this directory belongs to
# this script, and one chmod is shorter than the message explaining why it will
# not do it. Tolerant of failure. This writes into the shared cache from outside
# the publish lock, so a peer that just failed its own verify can rename this
# directory away between the build returning and the chmod landing. That is a
# benign race over a tree already proven correct, and under errexit a hard chmod
# would turn it into "launcher present but unusable" and fail the lane.
chmod +x "$dir/sharun" 2> /dev/null || true
printf '%s\n' "$dir/sharun"
