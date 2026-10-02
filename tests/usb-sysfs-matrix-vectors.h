/*
 * Measured Linux answers for tests/test-usb-sysfs-matrix.c
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Recorded on Linux, not reasoned about: docker gcc:14 (aarch64, kernel 6.x)
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
 *   back-sys    /sys/class
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
 *   sys-fold-in2 /sys/devices/../bus/usb/devices
 *               the same, spelled through a /sys name only the backing has
 *   tty-alias   /dev/ttyACM0
 *               a serial alias node this layer synthesizes
 *   tty-planted /dev/ttyACM7
 *               an alias-shaped name only the backing has
 *   tty-absent  /dev/ttyACM31
 *               an alias-shaped name absent on both sides
 *   byid-link   /dev/serial/by-id/<leaf>, discovered
 *               a by-id symlink onto an alias node
 *   tty-fold    /dev/serial/by-id/../../ttyACM0
 *               tty-alias's node, spelled through a '..'
 *   tty-dot-node  /dev/ttyACM0/.
 *               tty-alias's node used as a directory
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
 * would answer ENODEV anyway), so open, openat and epoll_ctl on them were never
 * measured. open_nofollow is measured for byid-link, because ELOOP is decided
 * on the link before anything is opened. Every other cell in those columns is
 * measured: they come from the directory entry rather than from opening it.
 * tests/test-usb-sysfs asserts the alias open contract directly.
 *
 * "?" is a cell whose Linux value was measured and that elfuse knowingly does
 * not meet; the lane prints it as XFAIL instead of failing, and XPASS when one
 * starts matching. Two columns, escape-syn and sys-fold-in2, are one fact seen
 * from opposite ends: a folded /sys spelling whose unfolded components are not
 * in the scratch tree cannot be resolved, whichever way it crosses the
 * boundary.
 *
 * One more "?" is a single cell: fstat_type [byid-link], an O_PATH|O_NOFOLLOW
 * open of a by-id leaf, which Linux fstats as the link and this layer as the
 * node. A descriptor carries one 63-byte guest name and a leaf runs to 242
 * bytes, so the name kept is the node's, which every ordinary open of the leaf
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
 * sys-fold-in2 is the /sys mirror of dev-fold-in.
 * /sys/devices/../bus/usb/devices folds to a name this layer serves, but the
 * resolve joins the unfolded suffix onto the scratch tree, which has no devices
 * directory, and answers its own ENOENT. statfs matches only because its test
 * is the lexical /sys prefix. The /sys half cannot fold before classify the way
 * the /dev half does, because usb_sys_resolve_suffix has to see each '..'
 * against the symlinks it follows.
 *
 * sys-fold-in is the same spelling through /sys/class, which the scratch tree
 * carries for the tty aliases, so its unfolded join resolves and its cells are
 * asserted.
 */

/* clang-format off */
/* synth-dir back-sys back-dev subsys escape escape-syn usb-node absent long-sys
 * sys-root dev-bus shadow subsys-out dev-fold-out dev-fold-in sys-fold-in
 * sys-fold-in2 tty-alias tty-planted tty-absent byid-link tty-fold tty-dot-node
 * open
 */ {"ok", "ok", "ok", "ok", "ok", "?ok", "-", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "-", "ok", "?ok", "-", "ok", "E2", "-", "-", "E20"},
/* open_nofollow      */ {"ok", "ok", "ok", "E40", "ok", "?ok", "-", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "-", "ok", "?ok", "-", "ok", "E2", "E40", "-", "E20"},
/* openat_dirfd       */ {"ok", "ok", "ok", "ok", "ok", "?ok", "-", "E2", "ok", "skip", "ok", "skip", "ok", "ok", "-", "ok", "?ok", "-", "ok", "E2", "-", "-", "skip"},
/* stat               */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:c", "ok:c", "E20"},
/* lstat              */ {"ok:d", "ok:d", "ok:f", "ok:l", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:l", "ok:c", "E20"},
/* fstatat_nofollow   */ {"ok:d", "ok:d", "ok:f", "ok:l", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:l", "ok:c", "E20"},
/* fstatat_dirfd      */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "skip", "ok:d", "skip", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:c", "ok:c", "skip"},
/* statx              */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:c", "ok:c", "E20"},
/* access             */ {"ok", "ok", "ok", "ok", "ok", "?ok", "ok", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "ok", "ok", "?ok", "ok", "ok", "E2", "ok", "ok", "E20"},
/* faccessat_nofollow */ {"ok", "ok", "ok", "ok", "ok", "?ok", "ok", "E2", "ok", "ok", "ok", "E2", "ok", "ok", "ok", "ok", "?ok", "ok", "ok", "E2", "ok", "ok", "E20"},
/* readlink           */ {"E22", "E22", "E22", "ok", "E22", "?E22", "E22", "E2", "E22", "E22", "E22", "E2", "E22", "E22", "E22", "E22", "?E22", "E22", "E22", "E2", "ok", "E22", "E20"},
/* readlinkat_dirfd   */ {"E22", "E22", "E22", "ok", "E22", "?E22", "E22", "E2", "E22", "skip", "E22", "skip", "E22", "E22", "E22", "E22", "?E22", "E22", "E22", "E2", "ok", "E22", "skip"},
/* getdents64         */ {"ok", "ok", "E20", "ok", "E20", "?E20", "E20", "E2", "E20", "ok", "ok", "E2", "ok", "E20", "E20", "ok", "?ok", "E20", "E20", "E2", "E20", "E20", "E20"},
/* statfs             */ {"sysfs", "sysfs", "other", "sysfs", "other", "?other", "other", "E2", "sysfs", "sysfs", "other", "E2", "sysfs", "other", "other", "sysfs", "sysfs", "other", "other", "E2", "other", "other", "E20"},
/* fstatfs            */ {"sysfs", "sysfs", "other", "sysfs", "other", "?other", "other", "E2", "sysfs", "sysfs", "other", "E2", "sysfs", "other", "other", "sysfs", "?sysfs", "other", "other", "E2", "other", "other", "E20"},
/* fstat_type         */ {"ok:d", "ok:d", "ok:f", "ok:l", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "ok:d", "ok:d", "E2", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "?ok:l", "ok:c", "E20"},
/* chdir              */ {"ok", "ok", "E20", "ok", "E20", "?E20", "E20", "E2", "E20", "ok", "ok", "E2", "ok", "E20", "E20", "ok", "?ok", "E20", "E20", "E2", "E20", "E20", "E20"},
/* fchdir             */ {"ok", "ok", "E20", "ok", "E20", "?E20", "E20", "E2", "E20", "ok", "ok", "E2", "ok", "E20", "E20", "ok", "?ok", "E20", "E20", "E2", "E20", "E20", "E20"},
/* cwd_stat           */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "skip", "ok:d", "skip", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:c", "ok:c", "skip"},
/* fcwd_stat          */ {"ok:d", "ok:d", "ok:f", "ok:d", "ok:f", "?ok:f", "ok:c", "E2", "ok:f", "skip", "ok:d", "skip", "ok:d", "ok:f", "ok:c", "ok:d", "?ok:d", "ok:c", "ok:f", "E2", "ok:c", "ok:c", "skip"},
/* epoll_ctl          */ {"E1", "E1", "E1", "E1", "E1", "?E1", "-", "E2", "ok", "E1", "E1", "E2", "E1", "E1", "-", "E1", "?E1", "-", "E1", "E2", "-", "-", "E20"},
/* union_listing      */ {"n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "all", "all", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"},
    /* clang-format on */
