#!/usr/bin/env bash

# fetch-glibc.sh - Resolve an aarch64 glibc runtime from a prebuilt .deb
#
# Prints a directory holding the aarch64 loader and shared objects. Nothing is
# compiled: the package is Debian's own build, pinned by digest, so this runs on
# a macOS host with no Linux and no cross-libc.
#
# The pin lives in tests/sharun-fixture.lock and points at snapshot.debian.org,
# whose file URLs are permanent. Distribution pools are not: Ubuntu's ports pool
# drops a package as soon as a point release supersedes it, which would rot this
# fetch within weeks.
#
# Override with GLIBC_DIR to point at a runtime you staged yourself.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=tests/lib/fixture-cache.sh
. "$repo_root/tests/lib/fixture-cache.sh"
# shellcheck source=tests/sharun-fixture.lock
. "$repo_root/tests/sharun-fixture.lock"

if [ -n "${GLIBC_DIR:-}" ]; then
    [ -d "$GLIBC_DIR" ] || {
        printf 'glibc directory missing: %s\n' "$GLIBC_DIR" >&2
        exit 1
    }
    printf '%s\n' "$GLIBC_DIR"
    exit 0
fi

fixtures="${FIXTURES_DIR:-$repo_root/externals/test-fixtures}"
runtime="$fixtures/glibc/$GLIBC_VERSION"

# Called by fixture_cache_build with the staging directory last. Everything here
# writes only into that directory, so a failure leaves no partial runtime.
extract_glibc()
{
    local stage="$1"
    local work="$stage/.work"

    # Required here, not at the top of the script: a warm cache never reaches
    # this function, and demanding ar in order to hand back an already extracted
    # runtime turned a good cache into a skip.
    #
    # 1, not 77: 77 means the network could not be reached, and a host that has
    # the network but no binutils has a broken build environment, which must be
    # loud rather than a green skip. build-sharun-bundle.sh treats a missing
    # readelf the same way. Checked before the download so a missing tool does
    # not cost a transfer first.
    command -v ar > /dev/null || {
        printf 'ar(1) not found; install binutils\n' >&2
        return 1
    }

    mkdir -p "$work"
    fixture_cache_download "$GLIBC_DEB_URL" "$work/libc6.deb" \
        "glibc package $GLIBC_DEB_URL" || return $?
    fixture_cache_digest_ok "$work/libc6.deb" "$GLIBC_DEB_SHA256" \
        'glibc package' || return 1

    # ar(1) writes into the current directory whatever its arguments say, so the
    # extraction runs in a subshell that has already cd'd into the work
    # directory rather than trusting it to honor an output path.
    (cd "$work" && ar x libc6.deb && tar -xf data.tar.*) || {
        printf 'glibc package extraction failed\n' >&2
        return 1
    }

    # Debian and Ubuntu disagree on whether the multiarch directory sits under
    # /lib or /usr/lib, and merged-usr moved it once already. Copy whatever the
    # package actually shipped rather than encoding one layout. A loop rather
    # than find -exec: find reports success even when the command it ran failed,
    # so an -exec copy that hits a full disk or a permission problem would
    # publish a partial runtime, and only three of its members are re-validated
    # afterwards.
    #
    # The list goes to a file and find's own status is checked, rather than the
    # loop reading a process substitution: there a find that dies mid-scan on an
    # unreadable directory feeds the loop what it managed to print and its
    # failure is never seen, and the partial tree is then digest-recorded and
    # published as a complete cache.
    local pattern=''
    for lib in $GLIBC_CLOSURE; do
        pattern="$pattern -o -name $lib"
    done
    # shellcheck disable=SC2086  # the pattern is a deliberate word list
    find -L "$work" -type f \( -false $pattern \) > "$work/.members" || {
        printf 'glibc extraction could not list package members\n' >&2
        return 1
    }

    local seen=' ' base=''
    while IFS= read -r member; do

        # Skip a basename already copied. -L follows the package's own symlinks,
        # so one real file reachable through both /lib and /usr/lib is listed
        # twice and copied over itself. Measured on this package against this
        # closure: 6 paths for 5 files, the loader being the one reachable both
        # ways. Harmless, since the second copy has the same contents, but it
        # hides the layout and does the work twice.
        base="$(basename "$member")"
        case "$seen" in
            *" $base "*) continue ;;
        esac
        seen="$seen$base "
        cp -L "$member" "$stage/" || {
            printf 'glibc extraction could not copy %s\n' "$member" >&2
            return 1
        }
    done < "$work/.members"
    rm -rf "$work"

    # Digests of what the bundle will consume, so a cache hit can be checked
    # rather than assumed. Sizes alone let a corrupted-but-same-length file
    # through, and the launcher cache is re-verified on every run; this was the
    # one path that trusted itself. *.so.* already matches
    # ld-linux-aarch64.so.1, so naming it again hashed it twice here and
    # verified it twice on every cache hit. Mandatory, not
    # "|| true": a manifest nobody notices missing is a check that silently
    # switches itself off, and the consumer below would then trust the tree.
    # shellcheck disable=SC2086  # one file per closure member, deliberately split
    (cd "$stage" && shasum -a 256 -- $GLIBC_CLOSURE) > "$stage/.sha256" || {
        printf 'could not record glibc digests: %s\n' "$stage" >&2
        return 1
    }
    [ -e "$stage/ld-linux-aarch64.so.1" ] || {
        printf 'glibc package carried no aarch64 loader\n' >&2
        return 1
    }
    return 0
}

# Checked on a cache hit, by fixture_cache_build, which runs this without
# holding its publish lock: verification reads the whole tree, and a lock held
# that long would break the assumption its stale-lock reaper rests on. Only the
# eviction that follows a failed check takes the lock, because that is a rename.
# extract_glibc validates what it wrote, but a hit returns before it runs and
# the runtime is then trusted by path, so this is the only thing that notices a
# cached tree truncated or emptied after the fact.
#
# A tree published before this script recorded digests has no manifest, and
# there is no telling a good one of those from a damaged one; it fails here like
# any other unverifiable tree and is rebuilt. That used to be a block of its own
# that evicted from outside the lock, which is the same job done twice.
#
# Captured, not streamed: this script returns the runtime path on stdout, so
# shasum's per-file lines would be read by the caller as part of the path. On
# failure the lines that matter go to stderr, which is where the reader needs
# the name of the file that did not match.
verify_glibc()
{
    local out=''

    [ -s "$1/.sha256" ] || {
        printf 'cached glibc runtime has no digest manifest\n' >&2
        return 1
    }
    out="$(cd "$1" && shasum -a 256 -c .sha256 2>&1)" || {
        printf 'cached glibc runtime failed its digests: %s\n' "$1" >&2
        printf '%s\n' "$out" | grep -v ': OK$' >&2
        return 1
    }

    # The member set as well as the members. Checking only what the manifest
    # lists means a file added to the runtime after publish is never noticed:
    # every listed entry still hashes, so the tree passes while holding
    # something this script never put there.
    local listed='' present=''

    # The pinned closure, not the manifest this tree happens to carry. Comparing
    # a cache against its own manifest only proves it is self-consistent: a tree
    # published when GLIBC_CLOSURE was smaller has listed == present and passes,
    # under the same GLIBC_VERSION that names the cache directory, while missing
    # a member the bundle now needs. The closure changed that way inside this
    # change, so it is not a hypothetical.
    # shellcheck disable=SC2086  # one word per closure member, deliberately split
    listed="$(printf '%s\n' $GLIBC_CLOSURE | sort)"

    # Dotfiles excluded, .sha256 among them. This runs on macOS, where opening
    # the cache directory in Finder drops a .DS_Store into it, and counting that
    # as drift would evict a healthy runtime and re-download the package on
    # every run after someone looked at the tree. What the check is for is a
    # library appearing beside the ones this script put there.
    present="$(cd "$1" && find . -maxdepth 1 ! -name . ! -name '.*' \
        -exec basename {} \; | sort)"

    [ "$listed" = "$present" ] || {
        printf 'cached glibc runtime does not match its manifest: %s\n' "$1" >&2
        diff <(printf '%s\n' "$listed") <(printf '%s\n' "$present") >&2 || true
        return 1
    }
    return 0
}

fixture_cache_build "$runtime" verify_glibc extract_glibc || exit $?

printf '%s\n' "$runtime"
