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
 *               tty-alias's node, spelled through a '..' out of a directory
 *               this layer plants names in
 *   slash-dir   //dev/bus/usb/001
 *               a directory this layer synthesizes, spelled with the leading
 *               "//" Linux resolves as "/"
 *   dot-dir     /dev/./bus/usb/001
 *               the same directory, spelled with a "." component
 *   slash-node  //dev/bus/usb/001/001
 *               usb-node's node under the same leading "//"
 *   dot-node    /dev/./bus/usb/001/001
 *               usb-node's node under the same "." component
 *   fold2-dir   /.//dev/bus/usb/001
 *               slash-dir's directory with the two spellings interleaved
 *   fold2-node  /.//dev/bus/usb/001/001
 *               usb-node's node under the same interleaving
 *   fold2-sys   /.//sys/bus/usb/devices
 *               synth-dir's directory under the same interleaving
 *   fold3-dir   /././/dev/bus/usb/001
 *               slash-dir's directory one interleaving turn deeper
 *   subsys-out-slash  subsys-out spelled with a leading "//", discovered
 *               the walk through the subsystem link, spelled so the gate that
 *               resolves the link reads an unfolded name
 *   tty-dot-node  /dev/ttyACM0/.
 *               tty-alias's node with a trailing "." component, the spelling
 *               that asks every entry point what a device node used as a
 *               directory answers
 *
 * slash-dir through dot-node exist because folding was taught to the intercept
 * gates and to the USB layer but not to the consumers behind them, so
 * //dev/bus/usb/001 stat'd, opened and listed as the synthetic directory while
 * chdir on it reported ENOENT, statfs reported ENOENT, and a descriptor opened
 * through it carried no guest-path stamp at all -- getcwd then reported the
 * host scratch directory behind the tree and a relative open measured against
 * it created files there. A leading "." or "//" run never changes which object
 * a path names, whatever symlinks it crosses, so every cell in these columns is
 * the cell of the canonical spelling beside it; that is exactly what makes them
 * worth asserting. Leading is the whole claim: a trailing "." carries Linux's
 * directory requirement the way a trailing slash does, no column here spells
 * one, and the guest drops it -- a divergence these columns neither hold nor
 * repair.
 *
 * fold2-dir through fold3-dir are those four columns' blind spot, and it is the
 * one the fold itself had: a leading-run fold that runs one pass of "//" and
 * then one pass of "." leaves //dev behind for /.//dev, because stepping over
 * the "." uncovers a "//" the finished first pass can no longer see. Four
 * columns spelled with one or the other could not catch it, and the commit that
 * taught the gates to fold shipped exactly that loop: these spellings stat'd,
 * access'd and opened as ENOENT while statfs answered TMPFS_MAGIC and chdir put
 * the process inside the tree with getcwd reporting the folded name. The statfs
 * row is not what catches that -- statfs folds every component rather than the
 * leading run, so its cell is the canonical one either way. fstatfs is the row
 * that reddens, because the open it needs is one of the three that failed.
 * fold2-sys walks the /sys half, which parted the same way, and fold3-dir adds
 * a turn so a two-pass fold cannot pass by widening to three.
 *
 * subsys-out-slash is the one of these the gates' own fold cannot reach. It
 * names an object only the subsystem-link rewrite can find, and the gate that
 * sends a name through that rewrite reads a literal deeper than the first
 * component, so stepping over the leading run in front of it is not enough:
 * unfolded, the name arrived at the layer with the link unresolved and the
 * entry points behind it answered from the folds they each do for themselves.
 * What this column records is that failure where it is uniform rather than
 * where it splits: the walk ends on /sys/bus/pci, a bus only the sysroot has,
 * so an unresolved link leaves no entry point anything to find. Measured with
 * that gate's fold reverted, //sys/bus/usb/devices/<dev>/subsystem/../pci is
 * ENOENT at every entry point with a sysroot and without one, and seventeen of
 * these cells go red. fold2-sys spells a directory no synthetic link is walked
 * through, so that gate's literal matches it either way and its cells stay
 * green.
 *
 * The split lives on the neighboring spelling and no column holds it, because
 * holding it needs a name that ends inside the subtree this layer owns: with
 * the same fold reverted, //sys/bus/usb/devices/<dev>/subsystem/../usb is
 * served by stat, lstat, access, fstatat, open, fstat, fstatfs, chdir, fchdir
 * and getdents while statfs alone answers ENOENT -- ten entry points in, one
 * out, with a sysroot and without one. Same defect, one component further in;
 * the spelling recorded here is the one whose cells move in bulk.
 *
 * tty-dot-node is the alias node with a trailing "." after it, and it holds
 * chdir to what the entry points beside it answer for a device node used as a
 * directory. The chdir gate spelled its own prefix list, /sys and /dev/bus, and
 * the alias names sit directly under /dev, so chdir alone fell through to the
 * host and answered ENOENT where open, fchdir and getdents answered ENOTDIR --
 * and where /dev/bus/usb/001/001/. has answered ENOTDIR since before this
 * series. Thirteen of its cells are the inherited trailing-"." divergence
 * recorded as XFAIL, which is what leaves getdents64, chdir, fchdir and getcwd
 * as the cells it asserts; with the gate's literal put back, chdir and the
 * getcwd that follows it go red.
 *
 * cwd_stat and fcwd_stat are the cwd spellings of the two *at rows above. A
 * descriptor on the parent and a cwd on the parent are two different questions
 * -- one is answered by the guest name stamped on the descriptor, the other by
 * the test a relative lookup applies to the cwd -- so they are asked
 * separately, and the alias names are where the two parted. The cwd test
 * spelled a list of prefixes that the directories the aliases appear in are not
 * in, so chdir("/dev") then stat("ttyACM0") reported the placeholder file the
 * alias node sits on top of where /dev/ttyACM0 and openat(dirfd_of_dev,
 * "ttyACM0") reported the character device; with no sysroot to plant a
 * placeholder it answered ENOENT instead, which is the plain-hardware shape and
 * is held by tests/test-usb-sysfs rather than here. Six cells hold the split --
 * tty-alias, byid-link and tty-fold across both rows -- and they are the six
 * that go red with the alias arm taken back out of that test.
 *
 * fchdir is measured beside chdir rather than assumed to follow it, because the
 * two publish the cwd through different code: chdir has the directory's name
 * and fchdir has only a descriptor, so a repair that reaches one need not reach
 * the other. They agree here because neither publishes a virtual cwd for a
 * directory this layer plants names into rather than serves, which leaves both
 * with the guest spelling for the one test to read.
 *
 * Two markers appear in the table.
 *
 * "-" is a cell the recording host cannot present, so no Linux value exists to
 * hold the guest to. They are the character-device columns -- usb-node and its
 * slash-node, dot-node and fold2-node spellings, dev-fold-in, tty-alias,
 * tty-fold and byid-link -- under the four rows that have to open the device: a
 * mknod'd node with no driver behind it cannot be opened there (the container's
 * device cgroup answers EPERM, and an unbound minor would answer ENODEV
 * anyway), so open, openat and epoll_ctl on them were never measured.
 * open_nofollow is measured for byid-link, because ELOOP is decided on the link
 * before anything is opened. Every other cell in those columns is measured --
 * they come from the directory entry rather than from opening it. What the
 * guest cannot be held to here it is held to elsewhere: the fd-identity loop at
 * the end of the lane compares stat against open+fstat for every column that
 * opens, and tests/test-usb-sysfs asserts the alias open contract directly.
 *
 * "?" is a cell whose Linux value was measured and that elfuse knowingly does
 * not meet; the lane prints it as XFAIL instead of failing, and prints XPASS
 * when one starts matching, so a divergence cannot quietly stop being one. Two
 * columns, escape-syn and sys-fold-in2, are one fact seen from opposite ends: a
 * folded /sys spelling whose unfolded components are not in the scratch tree
 * cannot be resolved, whichever way it crosses the boundary.
 *
 * A third column, tty-dot-node, is the inherited trailing-"." divergence: the
 * component fold drops a trailing "." and with it Linux's directory
 * requirement, so a device node spelled that way is served where Linux answers
 * ENOTDIR. Thirteen of its cells carry it; it is the divergence
 * /dev/bus/usb/001/001/. carries on main, named in the header comment on
 * path_fold_dot_components. That is what leaves getdents64, chdir, fchdir and
 * getcwd as the cells it asserts, because each of them needs the name to be a
 * directory and so reaches the ENOTDIR from the other side.
 *
 * The last "?" is one cell rather than a column: fstat_type [byid-link], an
 * O_PATH|O_NOFOLLOW open of a by-id leaf followed by fstat, which Linux answers
 * with the link and this layer answers with the character device the link
 * names. A descriptor carries exactly one 63-byte guest name (the stamp), a
 * by-id leaf is up to 242 bytes, and the name that has to be right is the node:
 * it is what an ordinary open of the leaf must fstat as, and what fstatfs and
 * every relative walk read back. Keeping the link identity for the path-only
 * open as well would need a second name per descriptor. Recorded rather than
 * made length-dependent, which is what stamping whichever spelling happened to
 * fit would have been.
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
 * sys-fold-in2 is the same fact walked the other way, and it is the /sys mirror
 * of dev-fold-in. /sys/devices/../bus/usb/devices folds to a name this layer
 * owns and does serve, so ownership is decided correctly -- but the resolve
 * that follows joins the *unfolded* suffix onto the scratch tree, which has no
 * devices directory of its own, so the lookup fails and the layer reports its
 * own authoritative ENOENT. Twenty-one entry points answer E2 where Linux
 * resolves the name. statfs is the one cell that matches, and it matches
 * because its test is the lexical /sys prefix rather than a lookup.
 *
 * It is recorded rather than repaired because it is not this series' doing. The
 * /dev half could be repaired by folding before classify, because every
 * component of /dev this layer serves is a plain directory it materialized
 * itself; the /sys half cannot, because usb_sys_resolve_suffix has to see the
 * '..' in their original positions to order them against the symlinks. Making
 * these cells green means having the folded spelling re-enter path translation,
 * the same path-layer change escape-syn needs.
 *
 * sys-fold-in is the SAME spelling through a component the scratch tree does
 * carry, and it is green: /sys/class is a directory this layer materializes for
 * the tty aliases, so the unfolded join has something to walk. It was an XFAIL
 * when the tree had no class directory, and the alias layer turned eighteen of
 * its cells green without touching the resolver -- which is why sys-fold-in2
 * exists and why the harness prints XPASS. The distinction the two columns draw
 * is exactly the defect: whether the intermediate component happens to be one
 * of ours, not whether the name resolves on Linux. The listing side says the
 * same thing from the other end -- /sys/class/.. lists bus and /sys/devices/..
 * does not.
 */

/* clang-format off */
/*                                      synth-dir  back-sys  back-dev  subsys              escape    escape-syn  usb-node  absent  long-sys  sys-root  dev-bus   shadow   subsys-out          dev-fold-out  dev-fold-in  sys-fold-in                 sys-fold-in2                 tty-alias  tty-planted  tty-absent  byid-link  tty-fold  slash-dir  dot-dir   slash-node  dot-node    fold2-dir  fold2-node  fold2-sys  fold3-dir  subsys-out-slash  tty-dot-node */
/* open               */ {"ok",      "ok",     "ok",     "ok",               "ok",     "?ok",      "-",      "E2",   "ok",     "ok",     "ok",     "E2",    "ok",               "ok",         "-",         "ok",                       "?ok",                       "-",       "ok",        "E2",       "-",       "-",      "ok",      "ok",     "-",        "-",          "ok",      "-",        "ok",      "ok", "ok", "?E20"},
/* open_nofollow      */ {"ok",      "ok",     "ok",     "E40",              "ok",     "?ok",      "-",      "E2",   "ok",     "ok",     "ok",     "E2",    "ok",               "ok",         "-",         "ok",                       "?ok",                       "-",       "ok",        "E2",       "E40",     "-",      "ok",      "ok",     "-",        "-",          "ok",      "-",        "ok",      "ok", "ok", "?E20"},
/* openat_dirfd       */ {"ok",      "ok",     "ok",     "ok",               "ok",     "?ok",      "-",      "E2",   "ok",     "skip",   "ok",     "skip",  "ok",               "ok",         "-",         "ok",                       "?ok",                       "-",       "ok",        "E2",       "-",       "-",      "ok",      "ok",     "-",        "-",          "ok",      "-",        "ok",      "ok", "ok", "skip"},
/* stat               */ {"ok:d",    "ok:d",   "ok:f",   "ok:d",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",   "E2",    "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:c",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "?E20"},
/* lstat              */ {"ok:d",    "ok:d",   "ok:f",   "ok:l",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",   "E2",    "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:l",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "?E20"},
/* fstatat_nofollow   */ {"ok:d",    "ok:d",   "ok:f",   "ok:l",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",   "E2",    "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:l",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "?E20"},
/* fstatat_dirfd      */ {"ok:d",    "ok:d",   "ok:f",   "ok:d",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "skip",   "ok:d",   "skip",  "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:c",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "skip"},
/* statx              */ {"ok:d",    "ok:d",   "ok:f",   "ok:d",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",   "E2",    "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:c",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "?E20"},
/* access             */ {"ok",      "ok",     "ok",     "ok",               "ok",     "?ok",      "ok",     "E2",   "ok",     "ok",     "ok",     "E2",    "ok",               "ok",         "ok",        "ok",                       "?ok",                       "ok",      "ok",        "E2",       "ok",      "ok",     "ok",      "ok",     "ok",       "ok",         "ok",      "ok",       "ok",      "ok", "ok", "?E20"},
/* faccessat_nofollow */ {"ok",      "ok",     "ok",     "ok",               "ok",     "?ok",      "ok",     "E2",   "ok",     "ok",     "ok",     "E2",    "ok",               "ok",         "ok",        "ok",                       "?ok",                       "ok",      "ok",        "E2",       "ok",      "ok",     "ok",      "ok",     "ok",       "ok",         "ok",      "ok",       "ok",      "ok", "ok", "?E20"},
/* readlink           */ {"E22",     "E22",    "E22",    "ok",               "E22",    "?E22",     "E22",    "E2",   "E22",    "E22",    "E22",    "E2",    "E22",              "E22",        "E22",       "E22",                      "?E22",                      "E22",     "E22",       "E2",       "ok",      "E22",    "E22",     "E22",    "E22",      "E22",        "E22",     "E22",      "E22",     "E22", "E22", "?E20"},
/* readlinkat_dirfd   */ {"E22",     "E22",    "E22",    "ok",               "E22",    "?E22",     "E22",    "E2",   "E22",    "skip",   "E22",    "skip",  "E22",              "E22",        "E22",       "E22",                      "?E22",                      "E22",     "E22",       "E2",       "ok",      "E22",    "E22",     "E22",    "E22",      "E22",        "E22",     "E22",      "E22",     "E22", "E22", "skip"},
/* getdents64         */ {"ok",      "ok",     "E20",    "ok",               "E20",    "?E20",     "E20",    "E2",   "E20",    "ok",     "ok",     "E2",    "ok",               "E20",        "E20",       "ok",                       "?ok",                       "E20",     "E20",       "E2",       "E20",     "E20",    "ok",      "ok",     "E20",      "E20",        "ok",      "E20",      "ok",      "ok", "ok", "E20"},
/* statfs             */ {"sysfs",   "sysfs",  "other",  "sysfs",            "other",  "?other",   "other",  "E2",   "sysfs",  "sysfs",  "other",  "E2",    "sysfs",            "other",      "other",     "sysfs",                    "sysfs",                     "other",   "other",     "E2",       "other",   "other",  "other",   "other",  "other",    "other",      "other",   "other",    "sysfs",   "other", "sysfs", "?E20"},
/* fstatfs            */ {"sysfs",   "sysfs",  "other",  "sysfs",            "other",  "?other",   "other",  "E2",   "sysfs",  "sysfs",  "other",  "E2",    "sysfs",            "other",      "other",     "sysfs",                    "?sysfs",                    "other",   "other",     "E2",       "other",   "other",  "other",   "other",  "other",    "other",      "other",   "other",    "sysfs",   "other", "sysfs", "?E20"},
/* fstat_type         */ {"ok:d",    "ok:d",   "ok:f",   "ok:l",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",   "E2",    "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "?ok:l",   "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "?E20"},
/* chdir              */ {"ok",      "ok",     "E20",    "ok",               "E20",    "?E20",     "E20",    "E2",   "E20",    "ok",     "ok",     "E2",    "ok",               "E20",        "E20",       "ok",                       "?ok",                       "E20",     "E20",       "E2",       "E20",     "E20",    "ok",      "ok",     "E20",      "E20",        "ok",      "E20",      "ok",      "ok", "ok", "E20"},
/* fchdir             */ {"ok",      "ok",     "E20",    "ok",               "E20",    "?E20",     "E20",    "E2",   "E20",    "ok",     "ok",     "E2",    "ok",               "E20",        "E20",       "ok",                       "?ok",                       "E20",     "E20",       "E2",       "E20",     "E20",    "ok",      "ok",     "E20",      "E20",        "ok",      "E20",      "ok",      "ok", "ok", "E20"},
/* getcwd             */ {"self",    "self",   "E20",    "at:/sys/bus/usb",  "E20",    "?E20",     "E20",    "E2",   "E20",    "self",   "self",   "E2",    "at:/sys/bus/pci",  "E20",        "E20",       "at:/sys/bus/usb/devices",  "?at:/sys/bus/usb/devices",  "E20",     "E20",       "E2",       "E20",     "E20",    "self",    "self",   "E20",      "E20",        "self",    "E20",      "self",    "self", "at:/sys/bus/pci", "E20"},
/* cwd_stat           */ {"ok:d",    "ok:d",   "ok:f",   "ok:d",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "skip",   "ok:d",   "skip",  "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:c",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "skip"},
/* fcwd_stat          */ {"ok:d",    "ok:d",   "ok:f",   "ok:d",             "ok:f",   "?ok:f",    "ok:c",   "E2",   "ok:f",   "skip",   "ok:d",   "skip",  "ok:d",             "ok:f",       "ok:c",      "ok:d",                     "?ok:d",                     "ok:c",    "ok:f",      "E2",       "ok:c",    "ok:c",   "ok:d",    "ok:d",   "ok:c",     "ok:c",       "ok:d",    "ok:c",     "ok:d",    "ok:d", "ok:d", "skip"},
/* epoll_ctl          */ {"E1",      "E1",     "E1",     "E1",               "E1",     "?E1",      "-",      "E2",   "ok",     "E1",     "E1",     "E2",    "E1",               "E1",         "-",         "E1",                       "?E1",                       "-",       "E1",        "E2",       "-",       "-",      "E1",      "E1",     "-",        "-",          "E1",      "-",        "E1",      "E1", "E1", "?E20"},
/* union_listing      */ {"n/a",     "n/a",    "n/a",    "n/a",              "n/a",    "n/a",      "n/a",    "n/a",  "n/a",    "all",    "all",    "n/a",   "n/a",              "n/a",        "n/a",       "n/a",                      "n/a",                       "n/a",     "n/a",       "n/a",      "n/a",     "n/a",    "n/a",     "n/a",    "n/a",      "n/a",        "n/a",     "n/a",      "n/a",     "n/a", "n/a", "n/a"},
    /* clang-format on */
