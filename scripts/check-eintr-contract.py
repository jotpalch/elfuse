"""Fail when a syscall path can hand the guest EINTR without saying whether the
dispatcher may restart it.

The dispatcher restarts an interrupted SVC when the only thing that broke the
wait was an execve handed to the thread group leader (see syscall_restart_arm
in src/syscall/proc.h). Restarting re-executes the syscall with the guest's
original arguments, which is right for a wait that consumed nothing and wrong
for one that did: a relative timeout starts again from zero, and a request
already on the wire is sent twice. Both failure modes were shipped and then
found by review rather than by a test, twice, which is why this is a gate
rather than a convention.

Nothing in C makes that decision visible. A new interruptible wait is
restartable by default simply because the epilogue arms on any EINTR, so the
author of the next one has to know a rule that is not written down anywhere the
compiler can see. This script writes it down: every function that can hand the
guest EINTR is classified here, and the classification is checked against the
source rather than trusted.

Three classifications:

  forbids     The function calls syscall_restart_forbid(). Verified against the
              body, so the claim cannot go stale while the call is deleted.
  restartable Re-executing the syscall is harmless: the wait reports EINTR
              before transferring anything, consuming a deadline, or leaving
              host state behind. Needs a reason.
  not-a-wait  The EINTR does not come from a blocking wait at all (a teardown
              refusal, or handoff bookkeeping). Needs a reason.

Adding an interruptible wait therefore fails the build until its restart
behaviour is stated. Deleting one fails it too, so the inventory cannot rot
into a list of functions that no longer exist.

The unit is the function that decides, not the syscall that returns. A handler
forwarding a wait helper's result carries no EINTR expression of its own and is
not listed; the helper it called is, because that is where the wait happens and
where the decision belongs. Moving the annotation to syscall entry points would
name hundreds of forwarders and put the classification a long way from the code
it describes.

What this does not do is check every branch. It asks whether a function makes
a restart decision, not whether each of its EINTR exits makes the right one, so
a function with several exits that loses the call on one of them still passes.
Catching that needs the reasoning a reviewer does; this only guarantees that
the reasoning happened once and is written down.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"

# Sites that hand EINTR to the guest, keyed by "path::function".
#
# Keyed by function rather than by line so ordinary edits above a site do not
# churn this table. The value is (classification, reason).
INVENTORY = {
    # Waits that consumed a guest-supplied deadline, or sent something.
    "syscall/time.c::interruptible_sleep_ns": (
        "forbids",
        "Relative sleeps have spent part of the interval; TIMER_ABSTIME "
        "re-derives the same instant and stays restartable.",
    ),
    "syscall/poll.c::sys_ppoll": (
        "forbids",
        "A finite poll has spent part of the guest's timeout.",
    ),
    "syscall/poll.c::sys_pselect6": (
        "forbids",
        "A finite select has spent part of the guest's timeout.",
    ),
    "syscall/poll.c::sys_epoll_pwait": (
        "forbids",
        "A finite epoll wait has spent part of the guest's timeout, and ready "
        "events outrank leader work because kqueue consumes the edge.",
    ),
    "runtime/futex.c::futex_os_sync_wait": (
        "forbids",
        "The address-wait path plain FUTEX_WAIT takes; its deadline is " "relative.",
    ),
    "runtime/futex.c::futex_wait": (
        "forbids",
        "Relative FUTEX_WAIT has spent part of its timeout; FUTEX_WAIT_BITSET "
        "is absolute and stays restartable.",
    ),
    "syscall/signal.c::signal_rt_sigtimedwait": (
        "forbids",
        "The timeout is spent in 1 ms chunks before this reports EINTR.",
    ),
    "syscall/io.c::tty_drain_interruptible": (
        "forbids",
        "The kernel returns a plain -EINTR from the TCSBRK/TCSBRKP/TIOCSBRK "
        "drain (tty_io.c, no ERESTARTSYS), and part of the output has already "
        "drained, so a restart would wait the interval again.",
    ),
    "syscall/fuse.c::fuse_request_locked": (
        "forbids",
        "FUSE_INTERRUPT is on the wire and the request is detached, so a "
        "restart would re-issue the operation under a fresh unique.",
    ),
    # Waits that report EINTR before doing anything the guest can observe.
    "syscall/io.c::io_retry_backoff": (
        "restartable",
        "Polled retry helper; reports before the operation it guards runs.",
    ),
    "syscall/io.c::io_wait_fd_or_interrupted": (
        "restartable",
        "Reports readiness or EINTR before any transfer; the caller has not "
        "touched the fd yet.",
    ),
    "syscall/fs.c::open_nonblocking_writer": (
        "restartable",
        "FIFO open retry; nothing is opened until it succeeds.",
    ),
    "syscall/inotify.c::inotify_read": (
        "restartable",
        "Reached only when kevent returned no event, so nothing is consumed.",
    ),
    "syscall/fuse.c::fuse_dev_read": (
        "restartable",
        "The queue is empty by the loop condition; no request is dequeued.",
    ),
    "syscall/proc.c::sys_wait4": (
        "restartable",
        "Every reapable outcome returns earlier; no child is removed and no "
        "status or rusage is written.",
    ),
    "syscall/proc.c::sys_waitid": (
        "restartable",
        "Same shape as sys_wait4: the reap and WNOHANG answers precede this.",
    ),
    "runtime/futex.c::futex_lock_pi": (
        "restartable",
        "The deadline is absolute and futex_unlock_pi zeroes the word rather "
        "than transferring ownership, so a restart re-CASes.",
    ),
    "runtime/futex.c::sys_futex_waitv": (
        "restartable",
        "The deadline is converted to an absolute instant at entry, so a "
        "restart re-derives the same one.",
    ),
    # Not blocking waits.
    "syscall/signal.c::signal_rt_sigsuspend": (
        "not-a-wait",
        "Returns the EINTR sigsuspend is defined to return; the mask is "
        "restored on the way out.",
    ),
    "syscall/exec.c::exec_handoff_to_leader": (
        "not-a-wait",
        "Handoff bookkeeping: the requester is being reaped, or the slot never "
        "reported back.",
    ),
    "syscall/mem.c::hvf_apply_file_overlay": (
        "not-a-wait",
        "Refuses the overlay because an execve is reaping this thread.",
    ),
    "syscall/mem.c::hvf_remove_file_overlay": (
        "not-a-wait",
        "Refuses the unmap window because an execve is reaping this thread.",
    ),
    "syscall/mem.c::sys_mmap_high_va": (
        "not-a-wait",
        "Refuses the overlay because an execve is reaping this thread.",
    ),
    "runtime/forkipc.c::sys_clone": (
        "not-a-wait",
        "Refuses the fork because an execve is reaping this thread.",
    ),
    "syscall/syscall.c::syscall_dispatch": (
        "not-a-wait",
        "Tests a handler's EINTR result to decide the restart; produces none "
        "of its own.",
    ),
}

# Anything on these lines is the mechanism itself, not a site that reports to a
# guest.
SELF = {"syscall/syscall.c::syscall_restart_forbid"}

EINTR_RE = re.compile(r"(return\s+-LINUX_EINTR|=\s*-LINUX_EINTR|errno\s*=\s*EINTR)\b")
FUNC_START_RE = re.compile(r"^(\w[\w \t\*]*?)\b(\w+)\s*\([^;]*$")


def functions(path):
    """Yield (name, first_line, last_line) for each top-level function."""
    lines = path.read_text(errors="ignore").split("\n")
    name = None
    pending = None
    depth = 0
    start = None
    for i, line in enumerate(lines, 1):
        if start is None:
            m = FUNC_START_RE.match(line)
            if m and not line.lstrip().startswith(
                ("if", "for", "while", "switch", "return", "#", "}")
            ):
                pending = m.group(2)
            if line.startswith("{") and pending:
                name, start, depth = pending, i, 1
                continue
            if line.rstrip().endswith("{") and pending and not line.startswith(" "):
                name, start, depth = pending, i, line.count("{") - line.count("}")
                continue
        else:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                yield name, start, i
                name, start, pending = None, None, None


def scan():
    """Return {key: has_forbid} for every function that can report EINTR."""
    found = {}
    for path in sorted(SRC.rglob("*.c")):
        rel = path.relative_to(SRC).as_posix()
        text = path.read_text(errors="ignore").split("\n")
        for name, first, last in functions(path):
            body = "\n".join(text[first - 1 : last])
            if not EINTR_RE.search(body):
                continue
            key = f"{rel}::{name}"
            found[key] = "syscall_restart_forbid()" in body
    return found


def main():
    found = scan()
    for key in SELF:
        found.pop(key, None)

    problems = []

    for key, has_forbid in sorted(found.items()):
        entry = INVENTORY.get(key)
        if entry is None:
            problems.append(
                f"unclassified: {key} can report EINTR to the guest.\n"
                f"    Decide whether the dispatcher may restart it and add it to\n"
                f"    INVENTORY in {pathlib.Path(__file__).name}. A wait that has\n"
                f"    consumed a relative timeout, transferred data, or sent a\n"
                f"    request must call syscall_restart_forbid() and be recorded\n"
                f"    as 'forbids'."
            )
            continue
        kind, reason = entry
        if kind == "forbids" and not has_forbid:
            problems.append(
                f"stale claim: {key} is recorded as 'forbids' but its body has\n"
                f"    no syscall_restart_forbid() call."
            )
        if kind != "forbids" and has_forbid:
            problems.append(
                f"stale claim: {key} calls syscall_restart_forbid() but is\n"
                f"    recorded as '{kind}'."
            )
        if not reason.strip():
            problems.append(f"missing reason: {key}")

    for key in sorted(set(INVENTORY) - set(found)):
        problems.append(
            f"stale entry: {key} is in INVENTORY but no longer reports EINTR.\n"
            f"    Remove it."
        )

    if problems:
        print("EINTR restart contract check failed:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        return 1

    forbids = sum(1 for k in INVENTORY if INVENTORY[k][0] == "forbids")
    print(
        f"  {len(found)} function(s) can report EINTR; all classified "
        f"({forbids} forbid the SVC restart)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
