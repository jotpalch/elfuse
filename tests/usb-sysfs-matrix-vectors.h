/*
 * Measured Linux answers for tests/test-usb-sysfs-matrix.c
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Recorded on Linux, not reasoned about: docker gcc:14 (aarch64, kernel 7.0)
 * over a real sysfs, with /dev/bus/other/f created, /dev/bus/usb/001/001
 * mknod'd as char 189:0, /dev/ttyACM0 mknod'd as char 166:0, a regular file at
 * /dev/ttyACM7, and a symlink at /dev/serial/by-id/usb-Rec_Device_0001-if00
 * pointing at ../../ttyACM0. See the header comment in the test for the exact
 * command; MATRIX_RECORD=1 prints this block.
 *
 * Columns, in order, with the path each names:
 *
 *   synth-dir   /sys/bus/usb/devices
 *               a directory the layer synthesizes
 *   back-sys    /sys/kernel
 *               a /sys name only the backing has
 *   back-dev    /dev/bus/other/f
 *               a /dev/bus name only the backing has
 *   subsys      <dev>/subsystem, discovered
 *               a subsystem symlink
 *   escape      /sys/class/../../etc/hostname
 *               a '..' chain out of the tree
 *   escape-syn  /sys/bus/usb/../../../etc/hostname
 *               the same, through the synthetic subtree
 *   usb-node    /dev/bus/usb/001/001
 *               a usbfs device node
 *   absent      /sys/no-such-name-here
 *               absent on both sides
 *   long-sys    a >63-byte spelling of an attribute, discovered
 *               longer than the virtual-path stamp a descriptor carries
 *   sys-root    /sys
 *               synthetic and backed at once
 *   dev-bus     /dev/bus
 *               synthetic and backed at once
 *   shadow      /dev/bus/usb/099/001
 *               a backing name planted inside a subtree this layer owns
 *   subsys-out  <dev>/subsystem/../pci, discovered
 *               a walk through the subsystem link and back out of the one
 *               subtree this layer owns
 *   dev-fold-out /dev/bus/usb/../other/f
 *               back-dev's file, spelled through the subtree this layer owns
 *   dev-fold-in /dev/bus/other/../usb/001/001
 *               usb-node's node, spelled through a bus this layer does not
 *               model
 *   sys-fold-in /sys/class/../bus/usb/devices
 *               synth-dir's directory, spelled through a /sys name the
 *               scratch tree also carries
 *   node-dotdot /dev/bus/usb/001/001/..
 *               usb-node's node followed by '..'
 *   dev-climb   /dev/bus/usb/001/../../..
 *               out of /dev/bus over the layer's directories
 *   dev-climb-f /dev/bus/other/f/../../../null
 *               the same, after back-dev's file
 *   tty-alias   /dev/ttyACM0
 *               a serial alias node this layer synthesizes
 *   tty-planted /dev/ttyACM7
 *               an alias-shaped name only the backing has
 *   tty-absent  /dev/ttyACM31
 *               an alias-shaped name absent on both sides
 *   tty-dot-node  /dev/ttyACM0/.
 *               tty-alias's node used as a directory
 *   tty-dotdot  /dev/ttyACM0/..
 *               the same node followed by '..'
 *   dev-dotdot  /dev/null/..
 *               a node this layer does not serve, followed by '..'
 *   dev-fold-file /dev/bus/other/f/../../usb/001/001
 *               dev-fold-in after back-dev's file
 *   dev-fold-absent /dev/bus/usb/xyz/../001/001
 *               dev-fold-in after a malformed usb name
 *   sys-fold-in2 /sys/devices/../bus/usb/devices
 *               sys-fold-in's directory, spelled through a /sys name only
 *               the backing has
 *   byid-link   /dev/serial/by-id/<leaf>, discovered
 *               a by-id symlink onto an alias node
 *   tty-fold    /dev/serial/by-id/../../ttyACM0
 *               tty-alias's node, spelled through a '..'
 *   byid-dotdot <leaf>/.., discovered
 *               byid-link's leaf followed by '..'
 *
 * cwd_stat and fcwd_stat ask the two *at rows' question of a cwd on the parent
 * rather than a descriptor: chdir and fchdir publish the cwd through different
 * code, and a relative lookup tests the cwd separately from a descriptor's
 * stamp.
 *
 * Two markers appear in the table.
 *
 * "-" is a cell the recording host cannot present, so no Linux value exists to
 * hold the guest to. They are the character-device columns (usb-node,
 * dev-fold-in, tty-alias, tty-fold and byid-link) under the four rows that have
 * to open the device: a mknod'd node with no driver behind it cannot be opened
 * there (the container's device cgroup answers EPERM, and an unbound minor
 * would answer ENODEV anyway), so open, open_nofollow, openat and epoll_ctl on
 * them were never measured. open_nofollow is measured for byid-link, because
 * ELOOP is decided on the link before anything is opened. Every other cell in
 * those columns is measured: they come from the directory entry rather than
 * from opening it. tests/test-usb-sysfs asserts the alias open contract
 * directly.
 *
 * "?" is a cell whose Linux value was measured and that elfuse knowingly does
 * not meet; the lane prints it as XFAIL instead of failing, and as XPASS once
 * it starts matching. They fall in two columns, escape-syn and sys-fold-in2,
 * and both are one fact seen from opposite ends: a folded /sys spelling that
 * crosses this layer's boundary cannot re-enter path translation, whichever way
 * it crosses.
 *
 * One more "?" is a single cell: fstat_type [byid-link], an O_PATH|O_NOFOLLOW
 * open of a by-id leaf, which Linux fstats as the link and this layer as the
 * node. A descriptor carries one 63-byte guest name and a by-id path can be
 * longer, so the name kept is the node's, which every ordinary open of the leaf
 * needs.
 *
 * escape-syn is a '..' chain that walks *through* the synthetic subtree and
 * back out cannot be resolved here. The lexical fold recognizes that the name
 * leaves /sys and hands it to the host walk, but the host walk has to traverse
 * /sys/bus/usb, which exists only inside this layer -- the lane's sysroot /sys
 * carries no `bus/usb`. The name therefore answers ENOENT where Linux resolves
 * it. This predates the synthetic USB tree in kind and reproduces identically
 * on the pre-merge build (377c134) with a sysroot whose /sys has no `bus`;
 * fixing it means having the folded spelling re-enter path translation, which
 * is a path-layer change rather than an ownership one. The neighbouring
 * `escape` column, whose chain transits only backing directories, is asserted
 * normally.
 *
 * sys-fold-in2 is the same fact walked the other way.
 * /sys/devices/../bus/usb/devices folds to a name this layer owns and does
 * serve, so ownership is decided correctly, but the resolve that follows joins
 * the unfolded suffix onto the scratch tree, which has no devices, so the
 * lookup fails and the layer reports its own authoritative ENOENT. Fifteen
 * entry points answer E2 where Linux resolves the name, and the five rows that
 * start from its parent cannot reach it either; statfs matches only because its
 * test is the lexical /sys prefix. sys-fold-in, through /sys/class, which the
 * scratch tree carries for the aliases, resolves and is asserted.
 *
 * The /dev half answers from its folded name, which stops at a '..' after a
 * node or a malformed usb name, asks the backing about a name of its own, and
 * pops a bus directory unasked, so /dev/bus/usb/099/../001/001 is served where
 * Linux answers ENOENT; the /sys half cannot, because usb_sys_resolve_suffix
 * has to see the '..' in their original positions to order them against the
 * subsystem symlinks. Making these cells green means having the folded spelling
 * re-enter path translation, the same path-layer change escape-syn needs.
 */

/* clang-format off */
/* Columns: synth-dir back-sys back-dev subsys escape escape-syn usb-node absent
 * long-sys sys-root dev-bus shadow subsys-out dev-fold-out dev-fold-in
 * sys-fold-in node-dotdot dev-climb dev-climb-f tty-alias tty-planted
 * tty-absent tty-dot-node tty-dotdot dev-dotdot dev-fold-file dev-fold-absent
 * sys-fold-in2 byid-link tty-fold byid-dotdot
 */

/* open               */ {"ok", "ok", "ok", "ok", "ok", "?ok", "-", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "-", "ok", "E20", "ok", "E20", "-", "ok", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "-", "-", "E20"},
/* open_nofollow      */ {"ok", "ok", "ok", "E40", "ok", "?ok", "-", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "-", "ok", "E20", "ok", "E20", "-", "ok", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "E40", "-", "E20"},
/* openat_dirfd       */ {"ok", "ok", "ok", "ok", "ok", "?ok", "-", "E2", "ok", "skip", "ok", "skip", "ok", "ok", "-", "ok", "skip", "ok", "skip", "-", "ok", "E2", "skip", "skip", "skip", "skip", "skip", "?ok", "-", "-", "skip"},
/* stat               */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "E20", "ok:d", "E20", "ok:c", "ok:f", "E2", "E20", "E20", "E20", "E20", "E2", "?ok:d", "ok:c", "ok:c", "E20"},
/* lstat              */ {"ok:d", "ok:d", "ok:f", "ok:l", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "E20", "ok:d", "E20", "ok:c", "ok:f", "E2", "E20", "E20", "E20", "E20", "E2", "?ok:d", "ok:l", "ok:c", "E20"},
/* fstatat_nofollow   */ {"ok:d", "ok:d", "ok:f", "ok:l", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "E20", "ok:d", "E20", "ok:c", "ok:f", "E2", "E20", "E20", "E20", "E20", "E2", "?ok:d", "ok:l", "ok:c", "E20"},
/* fstatat_dirfd      */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "skip", "ok:d", "skip", "ok:d", "ok:f", "ok:c", "ok:d", "skip", "ok:d", "skip", "ok:c", "ok:f", "E2", "skip", "skip", "skip", "skip", "skip", "?ok:d", "ok:c", "ok:c", "skip"},
/* statx              */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "E20", "ok:d", "E20", "ok:c", "ok:f", "E2", "E20", "E20", "E20", "E20", "E2", "?ok:d", "ok:c", "ok:c", "E20"},
/* access             */ {"ok", "ok", "ok", "ok", "ok", "?ok", "ok", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "ok", "ok", "E20", "ok", "E20", "ok", "ok", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "ok", "ok", "E20"},
/* faccessat_nofollow */ {"ok", "ok", "ok", "ok", "ok", "?ok", "ok", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "ok", "ok", "E20", "ok", "E20", "ok", "ok", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "ok", "ok", "E20"},
/* readlink           */ {"E22", "E22", "E22", "ok", "E22", "?E22", "E22", "E2", "E22", "E22", "E22", "E2", "E22", "E22", "E22", "E22", "E20", "E22", "E20", "E22", "E22", "E2", "E20", "E20", "E20", "E20", "E2", "?E22", "ok", "E22", "E20"},
/* readlinkat_dirfd   */ {"E22", "E22", "E22", "ok", "E22", "?E22", "E22", "E2", "E22", "skip", "E22", "skip", "E22", "E22", "E22", "E22", "skip", "E22", "skip", "E22", "E22", "E2", "skip", "skip", "skip", "skip", "skip", "?E22", "ok", "E22", "skip"},
/* getdents64         */ {"ok", "ok", "E20", "ok", "E20", "?E20", "E20", "E2", "E20", "ok", "ok", "E2", "ok", "E20", "E20", "ok", "E20", "ok", "E20", "E20", "E20", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "E20", "E20", "E20"},
/* statfs             */ {"sysfs", "sysfs", "other", "sysfs", "other", "?other", "other", "E2", "sysfs", "sysfs", "other", "E2", "sysfs", "other", "other", "sysfs", "E20", "other", "E20", "other", "other", "E2", "E20", "E20", "E20", "E20", "E2", "sysfs", "other", "other", "E20"},
/* fstatfs            */ {"sysfs", "sysfs", "other", "sysfs", "other", "?other", "other", "E2", "sysfs", "sysfs", "other", "E2", "sysfs", "other", "other", "sysfs", "E20", "other", "E20", "other", "other", "E2", "E20", "E20", "E20", "E20", "E2", "?sysfs", "other", "other", "E20"},
/* fstat_type         */ {"ok:d", "ok:d", "ok:f", "ok:l", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "E20", "ok:d", "E20", "ok:c", "ok:f", "E2", "E20", "E20", "E20", "E20", "E2", "?ok:d", "?ok:l", "ok:c", "E20"},
/* chdir              */ {"ok", "ok", "E20", "ok", "E20", "?E20", "E20", "E2", "E20", "ok", "ok", "E2", "ok", "E20", "E20", "ok", "E20", "ok", "E20", "E20", "E20", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "E20", "E20", "E20"},
/* fchdir             */ {"ok", "ok", "E20", "ok", "E20", "?E20", "E20", "E2", "E20", "ok", "ok", "E2", "ok", "E20", "E20", "ok", "E20", "ok", "E20", "E20", "E20", "E2", "E20", "E20", "E20", "E20", "E2", "?ok", "E20", "E20", "E20"},
/* cwd_stat           */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "skip", "ok:d", "skip", "ok:d", "ok:f", "ok:c", "ok:d", "skip", "ok:d", "skip", "ok:c", "ok:f", "E2", "skip", "skip", "skip", "skip", "skip", "?ok:d", "ok:c", "ok:c", "skip"},
/* fcwd_stat          */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "skip", "ok:d", "skip", "ok:d", "ok:f", "ok:c", "ok:d", "skip", "ok:d", "skip", "ok:c", "ok:f", "E2", "skip", "skip", "skip", "skip", "skip", "?ok:d", "ok:c", "ok:c", "skip"},
/* epoll_ctl          */ {"E1", "E1", "E1", "E1", "E1", "?E1", "-", "E2", "ok", "E1", "E1", "E2", "E1", "E1", "-", "E1", "E20", "E1", "E20", "-", "E1", "E2", "E20", "E20", "E20", "E20", "E2", "?E1", "-", "-", "E20"},
/* union_listing      */ {"n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "all", "all", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"},
    /* clang-format on */
