#!/usr/bin/env bash

# Keep the USB loopback fixture out of the shipped binary by construction.
#
# USB_LOOPBACK_FIXTURE=1 swaps src/syscall/usbdev-fixture-stub.c for
# src/syscall/usbdev-fixture.c (the SRCS block in the top-level Makefile). That
# changes SRCS, not CFLAGS, and the stale-object guard in mk/common.mk is keyed
# on $(strip $(CFLAGS)) alone, so it has nothing to say about the switch: while
# both flavors linked to build/elfuse, building one and then asking for the
# other printed "Nothing to be done for 'elfuse'" and handed back whichever had
# been linked last. Measured before the split below, on the tree as it stood
# then: make clean; make elfuse; make USB_LOOPBACK_FIXTURE=1 elfuse; make elfuse
# left _usbdev_fixture_lock in build/elfuse until make clean. No byte counts
# here on purpose. That build needed both flavors to write one path, so it
# cannot be produced again to re-measure, and the pair this comment used to
# quote had gone stale against the tree twice over. The dated figures are in
# docs/internals.md; what reproduces today is what the check below asserts.
#
# What keeps them apart now is the path: mk/config.mk points ELFUSE_BIN at
# $(ELFUSE_LOOPBACK_BIN) when the fixture is asked for, so the two flavors never
# write the same file and the shipped one cannot be a stale copy of the other.
# That is one variable, in a file nothing stops a later change from
# re-simplifying, which is what this check is for. It asks make itself rather
# than reading the makefile, so a change that moves the decision elsewhere is
# still covered as long as the answer stays right.
#
# Cheap on purpose: two variable expansions, no compilation. The whole-tree
# reproduction above is what it stands in for.

set -e -u -o pipefail

MAKE_BIN="${MAKE:-make}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

plain="$("$MAKE_BIN" -C "$ROOT" -s --no-print-directory print-elfuse-bin)"
fixture="$("$MAKE_BIN" -C "$ROOT" -s --no-print-directory \
    USB_LOOPBACK_FIXTURE=1 print-elfuse-bin)"

if [ -z "$plain" ] || [ -z "$fixture" ]; then
    echo "check-usb-fixture-bin: print-elfuse-bin produced nothing" >&2
    exit 2
fi

if [ "$plain" = "$fixture" ]; then
    echo "Error: USB_LOOPBACK_FIXTURE=1 links to $fixture, the same path a" >&2
    echo "       plain build writes, so a fixture build leaves the shipped" >&2
    echo "       binary carrying the loopback model until a make clean." >&2
    echo "       Point ELFUSE_BIN at \$(ELFUSE_LOOPBACK_BIN) for that flavor" >&2
    echo "       (mk/config.mk), or make the choice invalidate the binary." >&2
    exit 1
fi
