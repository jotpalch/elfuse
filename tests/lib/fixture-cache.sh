# fixture-cache.sh - Download a fixture into a shared cache exactly once
#
# Sourced, not executed. Two things live here: classifying a curl failure as
# "never reached the server" versus "answered and was wrong", and publishing a
# built tree into the cache without two concurrent builders corrupting it.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

# shellcheck shell=bash

# fixture_cache_download <url> <output> <what>
#
# Returns 0 on success, 77 when the transfer never reached the server, and 1
# when it reached it and got an error. That split matters: an unreachable
# network is a skip, but a 404 on a URL the lock file pins is a rotten pin, and
# reporting that as a skip hides exactly the drift the pin is there to catch.
# curl's transport failures are the resolve, connect, timeout and TLS-handshake
# codes; everything else means the far end answered.
fixture_cache_download()
{
    local url="$1" out="$2" what="$3" rc=0

    # --speed-limit/--speed-time rather than --max-time: a transfer that opens
    # and then stalls must fail, but a slow one that is still moving must not,
    # and a flat deadline cannot tell those apart. The builder holds the lock
    # for its whole run, so a wedged transfer would otherwise hold it forever.
    #
    # The connect timeout is short on purpose. It measures "did the far end
    # answer at all", never transfer speed, and --retry multiplies it: at 30
    # seconds an offline "make check" spent about two minutes reaching the skip
    # that the 77 exit exists to deliver quickly.
    curl --fail --location --retry 3 --retry-max-time 10 --silent --show-error \
        --connect-timeout 5 --speed-limit 1024 --speed-time 60 \
        --output "$out" "$url" || rc=$?
    [ "$rc" -eq 0 ] && return 0
    rc="$(_fixture_cache_classify "$rc" "$out")"

    # 77 is "never reached the server", the ordinary offline case, which the
    # lane turns into a skip. Anything else means the far end answered with
    # something wrong, and that has to be loud rather than degrade to a skip.
    # Said here, where the status is decided, so no caller has to pair a second
    # function with this one and none can word it differently.
    if [ "$rc" -eq 77 ]; then
        printf '%s unreachable, skipping\n' "$what" >&2
    else
        printf '%s download failed\n' "$what" >&2
    fi
    return "$rc"
}

_fixture_cache_classify()
{
    local rc="$1" out="$2"

    case "$rc" in
        5 | 6 | 7 | 35) echo 77 ;;
        18 | 28 | 52 | 56)

            # Timeouts and dropped connections. Each of these covers both a
            # transfer that never got going (a skip) and one the server began
            # and then abandoned (loud). The code cannot tell them apart, but
            # the output can: bytes on disk mean the far end answered and then
            # stopped, nothing on disk means it was never really reached.
            if [ -s "$out" ]; then echo 1; else echo 77; fi
            ;;
        *) echo 1 ;;
    esac
    return 0
}

# fixture_cache_digest_ok <file> <want> <what>
#
# True when the file is there and hashes to what the lock pins. Never 77: the
# bytes arrived and are not what was asked for, which is drift or tampering.
#
# The existence test is part of the check, not the caller's job. Without it
# shasum fails on its own under errexit and the mismatch message never prints,
# and that guard had been added to one of the three copies of this and not the
# others, which is the reason they are now one.
fixture_cache_digest_ok()
{
    local file="$1" want="$2" what="$3" have=''

    [ -s "$file" ] || {
        printf '%s is missing or empty: %s\n' "$what" "$file" >&2
        return 1
    }
    have="$(shasum -a 256 "$file" | awk '{print $1}')"
    [ "$want" = "$have" ] || {
        printf '%s digest mismatch: %s\nwanted %s\ngot    %s\n' \
            "$what" "$file" "$want" "$have" >&2
        return 1
    }
    return 0
}

# _fixture_cache_disarm <saved-traps>
#
# Drops the cleanup handler and puts back whatever the caller had. Called at
# every exit rather than once after the build: the lock wait and the publish
# rename come after the builder, and a kill in either of those windows used to
# leave the staging tree under the fixture cache with nothing to remove it.
_fixture_cache_disarm()
{
    trap - EXIT INT TERM
    [ -z "$1" ] || eval "$1"
    return 0
}

# _fixture_cache_inode <path>
#
# The inode number, or nothing. Two spellings because the flag that means "read
# this file" to BSD stat means "read the filesystem it sits on" to GNU stat,
# which answers with the same number for every path and so silently defeats the
# identity check below rather than failing it.
_fixture_cache_inode()
{
    if [ "$(uname -s)" = Darwin ]; then
        stat -f %i "$1" 2> /dev/null || true
    else
        stat -Lc %i "$1" 2> /dev/null || true
    fi
}

# _fixture_cache_lock_acquire <lock-dir>
#
# Blocks until this process owns the lock. Factored out of the publish path so
# eviction can hold the same lock rather than inventing a second exclusion
# scheme beside it: two mechanisms guarding one directory is how a cache ends up
# being torn down by one process while another is publishing into it.
_fixture_cache_lock_acquire()
{
    local lock="$1" waited=0 spent=0 lock_ino='' cur_ino='' now_ino=''

    # mkdir is the atomic claim, held across one rename. A lock older than the
    # grace period below cannot be a publish in progress.
    #
    # Which lock, though: removing whatever happens to sit at $lock lets two
    # waiters that time out together destroy each other. The first removes the
    # dead lock and acquires a fresh one; the second is already past its grace
    # period with no sleep left to take, so it deletes that fresh lock and
    # acquires as well. Both then believe they hold it, one loses its rename,
    # and the caller is told the build failed over a cache that is complete. So
    # this waits on a specific lock, identified by inode, and only removes that
    # one. A lock that changed hands is a live publisher and the wait starts
    # over against it.
    while ! mkdir "$lock" 2> /dev/null; do
        cur_ino="$(_fixture_cache_inode "$lock")"
        if [ -z "$lock_ino" ]; then
            lock_ino="$cur_ino"
        elif [ "$cur_ino" != "$lock_ino" ]; then
            lock_ino="$cur_ino"
            waited=0
        fi

        # Reaped only when the grace period has passed and this is still the
        # same lock, proven by inode. Falling back to "no inode means it
        # matches" made the test vacuously true and reaped whatever was there,
        # which is the two-waiter destruction described above, reintroduced by
        # the concession meant to keep the reaper portable. _fixture_cache_inode
        # handles both stat dialects, so an unreadable inode now means the lock
        # is gone rather than that this host cannot read one, and the next mkdir
        # takes it.
        if [ "$waited" -ge 50 ] && [ -n "$cur_ino" ] \
            && [ "$cur_ino" = "$lock_ino" ]; then

            # Read again here, not trusted from the top of the iteration. Two
            # waiters can both reach this test holding the same old inode; the
            # first reaps and takes a fresh lock, and the second would then
            # remove that live one, which is the destruction the inode is here
            # to stop. Re-reading narrows the window to the gap between this
            # line and the rm; it does not close it, because the shell has no
            # way to remove a directory by inode.
            now_ino="$(_fixture_cache_inode "$lock")"
            if [ "$now_ino" = "$lock_ino" ]; then
                printf 'fixture cache publish lock is stale; removing %s\n' \
                    "$lock" >&2
                rm -rf "$lock"
                lock_ino=''
                waited=0
            fi
            continue
        fi
        sleep 0.1
        waited=$((waited + 1))
        spent=$((spent + 1))

        # An absolute cap on top of the per-identity grace. The reaper only
        # fires for a lock whose inode this call can read and has been waiting
        # on, which is right, but stat also fails on a directory it lacks
        # permission to read, and then nothing would ever reap and this would
        # sleep forever. Sixty seconds is far past any real publish, so reaching
        # it means something is wrong that waiting will not fix.
        [ "$spent" -lt 600 ] || {
            printf 'gave up waiting for the fixture cache lock: %s\n' "$lock" >&2
            return 1
        }
    done
    return 0
}

# _fixture_cache_evict <final> <lock-dir>
#
# Removes a cached tree, taking the publish lock itself for the rename.
#
# A rename, then the delete outside the claim. The reaper above calls a lock
# older than five seconds abandoned, which is only true because the lock is held
# across a single same-filesystem rename; an rm -rf of a multi-megabyte tree
# under the same lock breaks that assumption, and a waiter would reap a live
# lock mid-eviction. The rename also makes the removal atomic to a reader: the
# tree is either wholly there or wholly gone, never a directory being emptied
# under someone reading it.
_fixture_cache_evict()
{
    local final="$1" lock="$2" doomed="$1.evicting.$$"

    # The claim covers the rename and nothing else. Holding it across the delete
    # is what the reaper above cannot survive: it calls a lock older than five
    # seconds abandoned, which is true of a rename and not of removing a
    # multi-megabyte tree on a loaded host, and a waiter would then reap a live
    # claim while this call still believes it holds it. Renaming first also
    # makes the removal atomic to a reader: the tree is wholly there or wholly
    # gone, never a directory being emptied underneath one.
    _fixture_cache_lock_acquire "$lock" || return 1

    # Tested under the claim, not before it. Two runs that fail the same cache
    # hit both come here; the first renames the tree away and the second finds
    # nothing to rename. That is the eviction it wanted, already done, so it
    # succeeds. Asking before taking the lock let both pass the test and made
    # the loser report a hard failure over work that had happened.
    if [ -d "$final" ] && ! mv "$final" "$doomed" 2> /dev/null; then
        rmdir "$lock" 2> /dev/null || true
        return 1
    fi
    rmdir "$lock" 2> /dev/null || true
    rm -rf "$doomed"
    return 0
}

# fixture_cache_build <final_dir> <verify_fn|-> <builder> [args...]
#
# Returns 0 when final_dir holds the fixture, whether this call built it or
# found it. A tree that is already there is handed to verify_fn first and
# rebuilt if it does not pass; "-" skips that. The check runs without the
# publish lock, which only the eviction that follows a failure takes:
# verification reads the whole tree, and holding the lock that long would break
# the assumption its stale-lock reaper rests on. Otherwise runs "builder
# [args...] <stage_dir>" with stage_dir created and empty, and publishes it. The
# builder's exit code is returned unchanged, so it can distinguish "could not
# fetch" (77, a skip) from "fetched something wrong" (anything else, loud).
#
# Builders run without holding anything. Every builder here produces the same
# pinned bytes, so two of them racing costs a duplicate download and nothing
# else, and the alternative (a lock held across a multi-megabyte transfer) has
# to answer what to do about a holder that was killed mid-download, which is
# where the complexity lives. Only the publish is serialized, and it is a single
# rename, so a lock still present after a few seconds is unambiguously abandoned
# rather than possibly-still-working.
_fixture_cache_stage=''

# Set when a cache hit failed its check and was evicted. Internal to
# fixture_cache_build, which reads it in one place: the guard that turns a
# builder's 77 into a loud failure when this call had already thrown a tree
# away. Not for callers, and the underscore says so. It was public once, and
# read by a fetch script, until the rule it fed moved in here; leaving the name
# and the comment behind advertised something no longer true, and every return
# path restores the value anyway, so a caller reading it would see what it held
# before the call.
_fixture_cache_rebuilt=0

# Cleans up, then dies of the signal it was given. A handler that only cleans up
# and returns leaves bash carrying on at the next command, so a Ctrl-C or a
# CI-sent SIGTERM during a download aborts curl and then resumes the build
# instead of ending it. Restoring the default and re-raising is what makes the
# process exit the way the sender asked.
_fixture_cache_on_signal()
{
    _fixture_cache_cleanup
    trap - "$1"

    # BASHPID, not $$: inside a subshell $$ still holds the PID of the shell
    # that started the script, so re-raising there signals the parent instead of
    # the process that took the signal.
    kill -"$1" "${BASHPID:-$$}"
}

_fixture_cache_cleanup()
{
    [ -z "$_fixture_cache_stage" ] || rm -rf "$_fixture_cache_stage"
    _fixture_cache_stage=''
    return 0
}

fixture_cache_build()
{
    local final="$1" verify="$2"
    shift 2
    local lock="$final.lock" rc=0

    # Saved before this call claims the global below, and restored on every
    # exit. _fixture_cache_stage is process-global, like the traps further down,
    # so a builder that itself calls fixture_cache_build would have the inner
    # call overwrite and then clear the outer one's stage: the outer publish
    # would then report failure and orphan its own staged tree.
    local prev_stage="$_fixture_cache_stage" prev_rebuilt="$_fixture_cache_rebuilt"

    # Cleared per call. It reports what this call did, and a caller that fetches
    # two fixtures would otherwise read the first one's eviction as the second
    # one's and turn an ordinary offline skip into a failure.
    _fixture_cache_rebuilt=0

    # A cache hit is checked before it is trusted, and checked under the lock,
    # so a tree that fails is evicted where no publisher can be mid-rename into
    # it. Callers used to do this after the call and then evict from outside,
    # which is a second mechanism guarding one directory: it could delete a
    # peer's fresh publish, or pull a launcher out from under an arm about to
    # exec it. "-" means the caller has nothing to check.
    if [ -d "$final" ]; then

        # Outside the lock. Verification reads the whole tree (a shasum of every
        # member), and the reaper above calls a lock older than five seconds
        # abandoned, which holds only while the lock covers a single rename. A
        # verify under the lock breaks exactly the assumption the reaper is
        # built on, and a loaded machine would then have a waiter tear down a
        # live claim. A read needs no exclusion: the worst a concurrent evict
        # can do is remove a tree this call was about to call good, and the
        # caller then fails on a missing path rather than trusting a bad one.
        if [ "$verify" = - ] || "$verify" "$final"; then
            _fixture_cache_rebuilt="$prev_rebuilt"
            return 0
        fi
        printf 'cached fixture failed its check; rebuilding: %s\n' "$final" >&2

        # The eviction takes the lock itself, for the rename alone.
        _fixture_cache_evict "$final" "$lock" || {
            _fixture_cache_rebuilt="$prev_rebuilt"
            return 1
        }

        # Told to the caller, because a rebuild that then cannot reach the
        # network returns 77 and the lane turns that into a green skip. A
        # corrupt cache is not an offline run and must not read like one.
        _fixture_cache_rebuilt=1
    fi
    mkdir -p "$(dirname "$final")" || {
        printf 'cannot create fixture cache directory: %s\n' \
            "$(dirname "$final")" >&2
        _fixture_cache_rebuilt="$prev_rebuilt"
        return 1
    }

    _fixture_cache_stage="$final.stage.$$"
    rm -rf "$_fixture_cache_stage"
    mkdir -p "$_fixture_cache_stage" || {

        # Restored here too. Leaving the global pointing at a stage this call
        # never created makes a nested caller's failure path clean up the inner
        # path and orphan the outer one's real tree.
        _fixture_cache_stage="$prev_stage"
        _fixture_cache_rebuilt="$prev_rebuilt"
        return 1
    }

    # Armed across the build, which is the only part that can be interrupted:
    # without it a builder killed mid-download abandons its staging tree under
    # the fixture cache, once per occurrence, forever. Saved and restored rather
    # than cleared, because trap state is process-global and a bare "trap -"
    # would take an EXIT handler the caller installed for its own reasons.
    local prev_traps
    prev_traps="$(trap -p EXIT INT TERM)"
    trap _fixture_cache_cleanup EXIT
    trap '_fixture_cache_on_signal INT' INT
    trap '_fixture_cache_on_signal TERM' TERM
    "$@" "$_fixture_cache_stage" || rc=$?
    if [ "$rc" -ne 0 ]; then
        _fixture_cache_cleanup
        _fixture_cache_stage="$prev_stage"
        _fixture_cache_disarm "$prev_traps"

        # Here rather than in each fetcher. 77 is "never reached the server",
        # which the lane turns into a skip, but this call threw away a tree that
        # failed its check before trying, so the cache is now gone and reporting
        # an ordinary offline run would hide the corruption that caused it. One
        # fetcher had this guard and the other did not, which is the whole
        # argument for it living where the eviction happens.
        if [ "$rc" -eq 77 ] && [ "$_fixture_cache_rebuilt" -eq 1 ]; then
            printf 'the cached fixture was unusable and could not be rebuilt: %s\n' \
                "$final" >&2
            _fixture_cache_rebuilt="$prev_rebuilt"
            return 1
        fi
        _fixture_cache_rebuilt="$prev_rebuilt"
        return "$rc"
    fi

    _fixture_cache_lock_acquire "$lock" || {
        _fixture_cache_cleanup
        _fixture_cache_stage="$prev_stage"
        _fixture_cache_rebuilt="$prev_rebuilt"
        _fixture_cache_disarm "$prev_traps"
        return 1
    }

    # Under the claim, so this cannot race a second publisher. Never mv onto an
    # existing directory: that puts the stage inside it and the cache answers
    # with final/final for good. A publish that lost simply drops its own work.
    if [ -d "$final" ] || [ -z "$_fixture_cache_stage" ]; then

        # Either another publisher won, or a signal handler already reclaimed
        # this stage. Renaming an empty name would land on the cwd.
        rc=1
        [ ! -d "$final" ] || rc=0
    else

        # Cleared only on success: clearing first would leave the cleanup below
        # with nothing to remove and the staging tree orphaned.
        if mv "$_fixture_cache_stage" "$final"; then
            _fixture_cache_stage=''
        else
            rc=1
        fi
    fi
    rmdir "$lock" 2> /dev/null || true

    # After the claim is released, not before. A publish that lost still holds a
    # fully built tree, and for the glibc runtime that is several megabytes; an
    # rm -rf of it under the lock is the same thing the reaper cannot survive,
    # which is why _fixture_cache_evict renames aside and deletes outside too.
    # Nothing races this: the stage is this call's own path. A no-op on the
    # winning path, where the rename already cleared the name.
    _fixture_cache_cleanup

    [ "$rc" -eq 0 ] && [ -d "$final" ] || {
        _fixture_cache_stage="$prev_stage"
        _fixture_cache_rebuilt="$prev_rebuilt"
        _fixture_cache_disarm "$prev_traps"
        return 1
    }

    # Restored on every exit, so a nested call hands the outer one its stage
    # back exactly as it found it.
    # Restored beside the stage and the traps, and for the same reason: a builder
    # that itself fetches a fixture would otherwise hand the outer call the inner
    # one's verdict, and an offline rebuild of a tree evicted out here would read
    # as an ordinary skip.
    _fixture_cache_stage="$prev_stage"
    _fixture_cache_rebuilt="$prev_rebuilt"
    _fixture_cache_disarm "$prev_traps"
    return 0
}
