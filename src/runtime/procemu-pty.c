/*
 * Pseudoterminal master side-table
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split out of runtime/procemu.c, which had grown to 4769 lines covering /proc,
 * /sys, /dev, and this. The seam is real rather than convenient: every
 * reference to the keepalive table and its shared segments lived inside one
 * contiguous run, and the rest of procemu.c reaches it only through the
 * proc_pty_* entry points already declared in runtime/procemu.h.
 *
 * What the table is for, and why it exists at all, is documented on
 * pty_keepalive_table below.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "utils.h"

#include "debug/log.h"
#include "runtime/procemu.h"
#include "runtime/procemu-internal.h"

#include "syscall/fd.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"

/* Pseudoterminal master side-table.
 *
 * Bridges two host vs guest mismatches in one place:
 *
 * 1. The macOS /dev/ptmx master is not itself a tty. TIOCSWINSZ / TIOCGWINSZ
 *    on the bare master return ENOTTY until something has opened the
 *    corresponding slave once, and the stored winsize gets cleared whenever
 *    the slave refcount drops to zero (verified empirically on macOS 15).
 *    Linux ptmx masters are tty fds in their own right, so guests assume those
 *    ioctls work without an open slave. To bridge the gap, every /dev/ptmx
 *    open eagerly opens one slave host fd that elfuse holds for the lifetime
 *    of the master and never exposes to the guest.
 *
 * 2. macOS slaves live at /dev/ttysNNN; Linux glibc looks for /dev/pts/N where
 *    N comes from TIOCGPTN. Guest opens of /dev/pts/N route back to the
 *    macOS path captured from ptsname(3) at /dev/ptmx open time, not a
 *    re-formatted guess, so format changes in macOS (or unusual minor
 *    encodings) cannot strand the guest with the wrong slave.
 *
 * Entries are keyed by the host master fd because that is what fd_cleanup_entry
 * has when the guest closes a master. Capacity matches the macOS default UNIX98
 * slave count; overflow leaves the entry empty and the guest gets the pre-fix
 * degraded behavior for that one pair instead of an open failure.
 *
 * Fork-restored entries may outlive their master for one /dev/pts/N open. A
 * foot / sshd / posix-compliant child closes the master fd after fork before
 * opening the slave (the child has no use for the master); without retaining
 * the path mapping past close, the subsequent /dev/pts/N open in the child
 * loses its translation and fails with ENOENT even though the parent still
 * holds the master and the macOS slave node is openable. Those stale entries
 * keep the received slave fd, which pins the macOS tty so the mapping cannot
 * come to name an unrelated minor, and give it up once a translated open has
 * failed. Ordinary local master closes clear the mapping immediately.
 */
#define PTY_KEEPALIVE_MAX 256

/* macOS caps shm names (PSHMNAMLEN) at 31 bytes including the leading slash. */
#define PTY_SHM_NAME_MAX 32
#define PTY_KEEPALIVE_FREE (-1)

/* Parse the N out of "/dev/pts/N".
 *
 * Returns false for the directory itself, a missing or non-numeric tail, or
 * trailing garbage.
 *
 * Deliberately stricter than strtoul, which would take leading whitespace, a
 * "+" sign and leading zeros. devpts dentries are decimal and canonical, so
 * Linux answers ENOENT for "/dev/pts/016" even while slave 16 is open, and
 * accepting the alias here would let one live slave answer under many names --
 * for its stat, its statfs identity, and for whether chmod and chown are
 * intercepted at all.
 */
bool pty_slave_num_from_path(const char *path, uint32_t *out)
{
    if (!path || strncmp(path, "/dev/pts/", 9) != 0)
        return false;
    const char *digits = path + 9;
    if (!*digits)
        return false;
    /* "0" is the only name that may start with a zero. */
    if (digits[0] == '0' && digits[1] != '\0')
        return false;

    unsigned long n = 0;
    for (const char *d = digits; *d; d++) {
        if (*d < '0' || *d > '9')
            return false;
        if (n > (UINT32_MAX - (unsigned long) (*d - '0')) / 10)
            return false;
        n = n * 10 + (unsigned long) (*d - '0');
    }
    if (out)
        *out = (uint32_t) n;
    return true;
}

/* PTY_SLAVE_PATH_MAX lives in procemu.h so this table and the fork-IPC payload
 * (proc_pty_ipc_entry_t) cannot drift apart. Cross-process slave accounting for
 * one pty.
 *
 * The per-process counters below cannot answer the hangup question on their
 * own, because a guest fork is a posix_spawn of a fresh elfuse process (see
 * forkipc.c): the child gets its own keepalive table, so the slave a shell
 * opens after the fork is invisible to the parent that owns the master and
 * polls it. That is the whole terminal case -- foot holds the master and never
 * opens a slave in that process -- so the master would never report a hangup.
 *
 * Anonymous shared memory cannot cross posix_spawn either, so this lives in a
 * shm segment named after the host slave path, which is unique per host pty and
 * which both sides already know: the parent from its own open, the child from
 * the slave_path in the fork-IPC keepalive payload. No new IPC is needed.
 *
 * Counters are atomic rather than mutex-guarded on purpose: a process that dies
 * holding a process-shared mutex would wedge every other process on this pty,
 * and macOS has no robust mutexes. slave_count and seen are read together as
 * one predicate by pty_slot_hung_up_locked, and they are written by other
 * processes, so the two are sequentially consistent rather than relaxed.
 * seq_cst puts every access to the pair in one total order, which is what makes
 * "seen is set, so the count that goes with it is visible" hold: a reader that
 * observes seen after a sibling set it also observes that sibling's increment.
 * Under relaxed the two locations order independently and a reader can pair a
 * fresh seen with a stale count, reporting HUP on a pty another process just
 * opened a slave on.
 *
 * pty_keepalive_lock does not close this: it is per-process, and the writers
 * that matter are in other processes. refs is different and stays relaxed on
 * the way up, since the acquire fence on the drop to zero is what orders it.
 */
typedef struct {
    _Atomic int32_t refs;        /* elfuse processes holding a keepalive */
    _Atomic int32_t slave_count; /* guest-held slaves across all of them */
    _Atomic int32_t seen;        /* a guest slave existed at least once */
} pty_shared_t;

static struct {
    int master_host_fd;
    int slave_host_fd;
    uint32_t linux_pts_num;
    bool stale_open_once;

    /* Slaves the guest has open, and whether it ever had one. Both are needed:
     * a count of zero means hung up only after the first open.
     *
     * These stay per-process and are the fallback when the shared segment is
     * unavailable (shm_open denied, for instance), which degrades to the
     * same-process-only behavior rather than failing. guest_slave_count doubles
     * as this process's contribution to shared->slave_count, so detaching can
     * subtract it and stay balanced even when the guest exits without running
     * per-fd cleanup.
     */
    int guest_slave_count;
    bool guest_slave_seen;
    pty_shared_t *shared;
    char slave_path[PTY_SLAVE_PATH_MAX];
} pty_keepalive_table[PTY_KEEPALIVE_MAX];

/* Guest-held slave fds, so a master can report the hangup Linux gives once the
 * last slave closes.
 *
 * elfuse keeps one slave open for the master's whole life (see the side-table
 * header above), which is what stops macOS from ever hanging the master up: it
 * only does so when *every* slave fd is gone. A guest terminal waiting for that
 * hangup to learn its shell exited therefore waits forever, which is what
 * happens to foot. Counting the slaves the guest itself holds lets sys_poll and
 * sys_read answer for the pty layer instead of the host, without giving up the
 * keepalive the tty ioctls need.
 *
 * The count only means anything once the guest has opened a slave at least
 * once; before that a master with no slave is ordinary, not hung up.
 */
#define PTY_GUEST_SLAVE_MAX (PTY_KEEPALIVE_MAX * 4)
static struct {
    int slave_host_fd; /* PTY_KEEPALIVE_FREE when the slot is unused */
    uint32_t linux_pts_num;
} pty_guest_slave_table[PTY_GUEST_SLAVE_MAX];
static pthread_mutex_t pty_keepalive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t pty_keepalive_once = PTHREAD_ONCE_INIT;

/* Derive the shm name for a pty from its host slave path. The basename is
 * unique per host pty ("ttys004"), which is what makes the segment findable
 * from a spawned child holding nothing but the path. macOS caps shm names at 31
 * bytes including the leading slash, so the prefix is kept short. Pty
 * accounting trace.
 *
 * Writes to the file named by ELFUSE_PTY_LOG when set, in addition to the
 * normal DEBUG log. The file matters because this subsystem spans processes:
 * the parent holding the master and the child holding the slave are different
 * elfuse instances, launched by a GUI app whose stderr goes nowhere reachable,
 * so a shared append-only file with a pid tag is the only way to see both
 * halves of a hangup decision in one place.
 */
__attribute__((format(printf, 1, 2))) static void pty_diag(const char *fmt, ...)
{
    static _Atomic int diag_fd = -2; /* -2 unopened, -1 disabled */
    int fd = atomic_load_explicit(&diag_fd, memory_order_acquire);
    if (fd == -2) {
        const char *path = getenv("ELFUSE_PTY_LOG");
        int opened = -1;
        if (path && path[0])
            opened =
                open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        int expected = -2;
        if (!atomic_compare_exchange_strong_explicit(
                &diag_fd, &expected, opened, memory_order_release,
                memory_order_acquire)) {
            if (opened >= 0)
                close(opened);
            fd = atomic_load_explicit(&diag_fd, memory_order_acquire);
        } else {
            fd = opened;
        }
    }
    if (fd < 0)
        return;

    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;

    char line[600];
    int m = snprintf(line, sizeof(line), "[pid %d] %s\n", (int) getpid(), msg);
    if (m > 0)
        (void) !write(fd, line, (size_t) m);
}

static bool pty_shared_name(const char *slave_path, char *out, size_t out_sz)
{
    if (!slave_path || slave_path[0] == '\0')
        return false;
    const char *base = strrchr(slave_path, '/');
    base = base ? base + 1 : slave_path;
    if (base[0] == '\0')
        return false;

    /* Reject anything that is not a plain name so the path cannot inject a
     * separator into the shm namespace.
     */
    for (const char *p = base; *p; p++) {
        if (!isalnum((unsigned char) *p) && *p != '_' && *p != '-')
            return false;
    }
    int n = snprintf(out, out_sz, "/elfuse.pty.%s", base);
    return n > 0 && (size_t) n < out_sz;
}

/* Map this pty's shared counters, creating the segment when absent.
 *
 * fresh discards any segment left behind by a previous master on the same host
 * pty: the path is only recycled once the host tty is fully released, so a
 * surviving segment is stale state from a process that died without detaching.
 * The fork-restore path passes false, since joining the parent's live segment
 * is the entire point there.
 *
 * Returns NULL when the segment is unavailable; callers fall back to the
 * per-process counters.
 */
static pty_shared_t *pty_shared_attach(const char *slave_path, bool fresh)
{
    char name[PTY_SHM_NAME_MAX];
    if (!pty_shared_name(slave_path, name, sizeof(name)))
        return NULL;
    if (fresh)
        shm_unlink(name);

    bool created = true;
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0 && errno == EEXIST) {
        created = false;
        fd = shm_open(name, O_RDWR, 0600);
    }
    if (fd < 0)
        return NULL;

    if (created && ftruncate(fd, sizeof(pty_shared_t)) < 0) {
        close(fd);
        shm_unlink(name);
        return NULL;
    }
    if (!created) {
        /* The creator sizes the segment just after shm_open, so a joiner that
         * lands in that gap would map a zero-length object and take SIGBUS on
         * first touch. Bail to the per-process fallback instead of waiting:
         * this runs under fd_lock (proc_pty_master_adopt registers with both
         * pty_keepalive_lock and fd_lock held), where sleeping would stall
         * every fd operation in the process.
         */
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size < (off_t) sizeof(pty_shared_t)) {
            close(fd);
            return NULL;
        }
    }

    void *map = mmap(NULL, sizeof(pty_shared_t), PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED)
        return NULL;

    pty_shared_t *sh = map;
    atomic_fetch_add_explicit(&sh->refs, 1, memory_order_relaxed);
    return sh;
}

/* Drop this process's reference, handing back any slaves it still had counted,
 * and unlink the segment once the last process lets go.
 */
static void pty_shared_detach(pty_shared_t *sh,
                              const char *slave_path,
                              int local_slave_count)
{
    if (!sh)
        return;
    if (local_slave_count > 0) {
        pty_diag("pty: detach returns %d slave(s) path=%s", local_slave_count,
                 slave_path ? slave_path : "?");
        atomic_fetch_sub_explicit(&sh->slave_count, local_slave_count,
                                  memory_order_seq_cst);
    }

    /* Release on the drop, acquire before the unlink: the process that takes
     * the count to zero must see every other participant's writes to the
     * segment before it removes the name.
     */
    if (atomic_fetch_sub_explicit(&sh->refs, 1, memory_order_release) == 1) {
        atomic_thread_fence(memory_order_acquire);
        char name[PTY_SHM_NAME_MAX];
        if (pty_shared_name(slave_path, name, sizeof(name)))
            shm_unlink(name);
    }
    munmap(sh, sizeof(*sh));
}

/* Sentinel-init. Other fields stay BSS-zero; without sentinels a host fd 0
 * close would match slot 0 and close the wrong fd inside elfuse.
 */
static void pty_keepalive_init(void)
{
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        pty_keepalive_table[i].master_host_fd = PTY_KEEPALIVE_FREE;
        pty_keepalive_table[i].guest_slave_count = 0;
        pty_keepalive_table[i].guest_slave_seen = false;
        pty_keepalive_table[i].slave_host_fd = PTY_KEEPALIVE_FREE;
    }
}

static void pty_keepalive_lock_acquire(void)
{
    pthread_once(&pty_keepalive_once, pty_keepalive_init);
    pthread_mutex_lock(&pty_keepalive_lock);
}

/* Find a slot by master_host_fd; -1 if none. Caller holds the lock. */
static int pty_keepalive_find_master_locked(int master_host_fd)
{
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++)
        if (pty_keepalive_table[i].master_host_fd == master_host_fd)
            return i;
    return -1;
}

/* Whether row i describes pty minor pts. A fully cleared row keeps neither a
 * path nor a minor, so the path test is what stops it matching minor 0.
 */
static bool pty_row_is_pts_locked(int i, uint32_t pts)
{
    return pty_keepalive_table[i].linux_pts_num == pts &&
           pty_keepalive_table[i].slave_path[0] != '\0';
}

/* The one row that carries a pty's slave accounting: whichever row already
 * holds a count, else the first row for that minor. Aliased masters (dup,
 * SCM_RIGHTS adopt, fork restore) each get a row of their own, but the slaves
 * belong to the pty rather than to any one master fd, so every counting path
 * has to agree on a single home.
 *
 * except_slot excludes a row from the answer, which the master-close path needs
 * to find an heir for a row that still holds the count it is giving up.
 */
static int pty_account_row_locked(uint32_t pts, int except_slot)
{
    int seen = -1, first = -1;
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (i == except_slot || !pty_row_is_pts_locked(i, pts))
            continue;
        if (pty_keepalive_table[i].guest_slave_count > 0)
            return i;

        /* Below a live count, a row that has seen a slave outranks one that
         * never did. Without that, an alias registered at a lower index takes
         * the home from a row whose count has fallen to zero, and the
         * no-segment hangup test reads guest_slave_seen off the wrong row and
         * never reports the hangup.
         */
        if (seen < 0 && pty_keepalive_table[i].guest_slave_seen)
            seen = i;
        if (first < 0)
            first = i;
    }
    return seen >= 0 ? seen : first;
}

/* Record on the pty's shared segment that it has had a slave, through whichever
 * row still maps it. Every row for a minor attaches the same segment by
 * slave_path, so the heir taking over the accounting need not be the row that
 * holds the mapping, and pty_slot_hung_up_locked reads the segment rather than
 * any one row's copy.
 */
static void pty_shared_mark_seen_locked(uint32_t pts)
{
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_row_is_pts_locked(i, pts) && pty_keepalive_table[i].shared) {
            atomic_store_explicit(&pty_keepalive_table[i].shared->seen, 1,
                                  memory_order_seq_cst);
            return;
        }
    }
}

/* Defined below, next to the one-shot open it serves. */
static int pty_keepalive_retire_stale_locked(int slot);

static int pty_keepalive_clear_slot_locked(int slot)
{
    int slave = pty_keepalive_table[slot].slave_host_fd;

    /* Slaves the guest still holds outlive this master. Hand the accounting to
     * another row for the same pty when one exists; otherwise keep this row as
     * the pty's master-less home. Returning the count to the segment here would
     * report a hangup with those slaves open.
     */
    if (pty_keepalive_table[slot].guest_slave_count > 0) {
        int heir = pty_account_row_locked(
            pty_keepalive_table[slot].linux_pts_num, slot);

        /* An heir that maps no segment cannot take over a count that was
         * contributed to one: its releases would not reach the segment the
         * other processes read.
         */
        if (heir >= 0 && pty_keepalive_table[slot].shared &&
            !pty_keepalive_table[heir].shared)
            heir = -1;

        if (heir < 0) {
            /* Nobody to take it, so this row stays as the pty's master-less
             * home until its last slave closes.
             */
            pty_keepalive_table[slot].master_host_fd = PTY_KEEPALIVE_FREE;
            return pty_keepalive_retire_stale_locked(slot);
        }

        /* A count that was never in a segment becomes one that is, so the
         * segment has to learn about it here. Otherwise each of those slaves
         * decrements on close a total it was never added to, and the count goes
         * negative under the other processes reading it.
         */
        if (!pty_keepalive_table[slot].shared &&
            pty_keepalive_table[heir].shared) {
            atomic_fetch_add_explicit(
                &pty_keepalive_table[heir].shared->slave_count,
                pty_keepalive_table[slot].guest_slave_count,
                memory_order_seq_cst);
        }
        pty_shared_mark_seen_locked(pty_keepalive_table[slot].linux_pts_num);

        pty_keepalive_table[heir].guest_slave_count +=
            pty_keepalive_table[slot].guest_slave_count;
        pty_keepalive_table[heir].guest_slave_seen = true;
        pty_keepalive_table[slot].guest_slave_count = 0;
    } else if (pty_keepalive_table[slot].guest_slave_seen) {
        /* No count left, but the fact that this pty ever had a slave is what
         * the no-segment hangup test reads. Hand it on so an alias does not
         * answer "never had one" for a pty that has already hung up.
         */
        int heir = pty_account_row_locked(
            pty_keepalive_table[slot].linux_pts_num, slot);
        if (heir >= 0)
            pty_keepalive_table[heir].guest_slave_seen = true;

        /* Not conditional on the heir mapping the segment: the row that does
         * may be a third alias, and the hangup test reads the segment rather
         * than any row's local copy.
         */
        pty_shared_mark_seen_locked(pty_keepalive_table[slot].linux_pts_num);
    }
    pty_shared_detach(pty_keepalive_table[slot].shared,
                      pty_keepalive_table[slot].slave_path,
                      pty_keepalive_table[slot].guest_slave_count);
    pty_keepalive_table[slot].shared = NULL;
    pty_keepalive_table[slot].master_host_fd = PTY_KEEPALIVE_FREE;
    pty_keepalive_table[slot].guest_slave_count = 0;
    pty_keepalive_table[slot].guest_slave_seen = false;
    pty_keepalive_table[slot].slave_host_fd = PTY_KEEPALIVE_FREE;
    pty_keepalive_table[slot].linux_pts_num = 0;
    pty_keepalive_table[slot].stale_open_once = false;
    pty_keepalive_table[slot].slave_path[0] = '\0';
    return slave;
}

/* Consume a stale entry's one-shot open without giving up its accounting.
 *
 * pty_open_slave retires the entry as soon as it has translated the
 * close-before-open sequence, but the caller only records the guest slave
 * afterwards. Clearing the slot outright detached the shared segment first, so
 * that slave was credited to nobody and the master -- still held by the parent
 * -- never learned the shell had one. What has to be consumed is the one-shot
 * marker and the retained fd; the path, pts number and shared mapping stay so
 * the slot remains the pty's accounting home, master-less, exactly as the
 * record and release paths already expect.
 *
 * Returns the retained slave fd for the caller to close, or -1.
 */
static int pty_keepalive_retire_stale_locked(int slot)
{
    int slave = pty_keepalive_table[slot].slave_host_fd;
    pty_keepalive_table[slot].slave_host_fd = PTY_KEEPALIVE_FREE;
    pty_keepalive_table[slot].stale_open_once = false;
    return slave;
}

static uint32_t pty_extract_pts_num(const char *slave_path)
{
    /* macOS canonical slave paths are /dev/ttysNNN with a decimal tail. Read
     * the longest decimal suffix and return it as the Linux pts number used by
     * guest /dev/pts/N.
     *
     * Returns UINT32_MAX on parse failure so callers can reject ambiguous names
     * rather than silently aliasing.
     */
    if (!slave_path)
        return UINT32_MAX;
    const char *p = slave_path + strlen(slave_path);
    while (p > slave_path && isdigit((unsigned char) p[-1]))
        p--;
    if (!*p || !isdigit((unsigned char) *p))
        return UINT32_MAX;
    char *endp;
    unsigned long n = strtoul(p, &endp, 10);
    if (endp == p || *endp != '\0' || n > UINT32_MAX)
        return UINT32_MAX;
    return (uint32_t) n;
}

/* Result codes for the locked register helper. */
#define PTY_REG_INSERTED 0 /* new entry installed */
#define PTY_REG_EXISTS 1   /* a matching entry already existed */
#define PTY_REG_FULL (-1)  /* table out of free slots */

/* Caller-holds-lock variant.
 *
 * Returns one of PTY_REG_* and, on PTY_REG_EXISTS, writes the existing entry's
 * pts number to *existing_pts_num. The lock-held variant exists so
 * proc_pty_master_adopt can atomically pair fd-table slot validation with
 * keepalive insertion under fd_lock + pty_keepalive_lock, eliminating the race
 * window where a sibling close+recycle between validate and register would
 * attach the keepalive to the wrong file.
 */
static int pty_keepalive_register_locked(int master_host_fd,
                                         int slave_host_fd,
                                         uint32_t linux_pts_num,
                                         const char *slave_path,
                                         bool stale_open_once,
                                         bool fresh_segment,
                                         uint32_t *existing_pts_num)
{
    int empty_slot = -1;
    int stale_path_slot = -1;
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd == master_host_fd) {
            if (existing_pts_num)
                *existing_pts_num = pty_keepalive_table[i].linux_pts_num;
            return PTY_REG_EXISTS;
        }
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE)
            continue;

        /* Prefer a stale-path slot with the same pts number: the macOS minor
         * deterministically maps to the same slave_path string, so reusing
         * keeps lookups path-correct and bounds the table at one slot per live
         * minor instead of accumulating a new entry on every reopen.
         */
        if (pty_keepalive_table[i].slave_path[0] != '\0' &&
            pty_keepalive_table[i].linux_pts_num == linux_pts_num) {
            stale_path_slot = i;
        } else if (empty_slot < 0 &&
                   pty_keepalive_table[i].slave_path[0] == '\0') {
            empty_slot = i;
        }
    }
    int slot = (stale_path_slot >= 0) ? stale_path_slot : empty_slot;
    if (slot < 0) {
        /* Out of empty slots and no stale-path match: evict the lowest-index
         * stale-path entry so the live registration cannot starve. Live entries
         * are never evicted. The eviction policy is approximately LRU: empty
         * slots fill from low indices, so the lowest-index stale slot tends to
         * be the oldest closed. A theoretical race exists with the
         * close-before-open child pattern (a child stales slot K under
         * pty_keepalive_lock and races into open("/dev/pts/N") just as another
         * thread evicts slot K to register a different minor) but needs the
         * keepalive table to be full -- live and stale entries both count --
         * with the staling thread's slot being the lowest-index stale. Well
         * outside the foot / sshd workload that motivated this code.
         */
        for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
            if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE &&
                pty_keepalive_table[i].slave_path[0] != '\0') {
                slot = i;
                break;
            }
        }
        if (slot < 0)
            return PTY_REG_FULL;
    }

    /* Reusing a row for a different pty hands its mapping back before the
     * fields below are overwritten, or the reference and any slaves it still
     * counted would be stranded in the segment.
     *
     * A row being reused for the minor it already describes keeps that pty's
     * accounting: the slaves counted on it are still open. A freshly allocated
     * host pty is the exception -- the minor only comes back once every fd on
     * it is gone, so a leftover count there is dead state.
     */
    bool same_pty = !fresh_segment &&
                    pty_keepalive_table[slot].slave_path[0] != '\0' &&
                    pty_keepalive_table[slot].linux_pts_num == linux_pts_num;
    if (!same_pty) {
        pty_shared_detach(pty_keepalive_table[slot].shared,
                          pty_keepalive_table[slot].slave_path,
                          pty_keepalive_table[slot].guest_slave_count);
        pty_keepalive_table[slot].shared = NULL;
        pty_keepalive_table[slot].guest_slave_count = 0;
        pty_keepalive_table[slot].guest_slave_seen = false;
    }

    pty_keepalive_table[slot].master_host_fd = master_host_fd;
    if (pty_keepalive_table[slot].slave_host_fd >= 0 &&
        pty_keepalive_table[slot].slave_host_fd != slave_host_fd)
        close(pty_keepalive_table[slot].slave_host_fd);
    pty_keepalive_table[slot].slave_host_fd = slave_host_fd;
    pty_keepalive_table[slot].linux_pts_num = linux_pts_num;
    pty_keepalive_table[slot].stale_open_once = stale_open_once;
    if (slave_path)
        str_copy_trunc(pty_keepalive_table[slot].slave_path, slave_path,
                       PTY_SLAVE_PATH_MAX);
    else
        pty_keepalive_table[slot].slave_path[0] = '\0';

    /* Only a pty the host just handed us gets a new segment. Every other
     * registration -- a dup of a live master, an SCM_RIGHTS adopt, a
     * fork-restore -- is one more reference to a pty that other processes may
     * already be accounting for, and must join their segment. Discarding it
     * would split the aliases onto separate counters, so slaves opened through
     * one would be invisible to the other and the hangup would be lost.
     */
    if (!pty_keepalive_table[slot].shared) {
        pty_keepalive_table[slot].shared = pty_shared_attach(
            pty_keepalive_table[slot].slave_path, fresh_segment);

        /* A count kept across the reuse above was accumulated while this row
         * had no segment, so the segment it has just joined knows nothing about
         * it. Without this, each of those slaves decrements on close a total it
         * was never added to, the shared count goes negative, and
         * pty_slot_hung_up_locked reports a hangup with the slaves still open.
         * Same compensation pty_keepalive_clear_slot_locked makes when it hands
         * a segment-less count to an heir that maps one.
         *
         * Only reachable through the same_pty path: every other route zeroed
         * the count just above, and a fresh_segment registration is by
         * definition not one of them.
         */
        if (pty_keepalive_table[slot].shared &&
            pty_keepalive_table[slot].guest_slave_count > 0) {
            atomic_fetch_add_explicit(
                &pty_keepalive_table[slot].shared->slave_count,
                pty_keepalive_table[slot].guest_slave_count,
                memory_order_seq_cst);
            atomic_store_explicit(&pty_keepalive_table[slot].shared->seen, 1,
                                  memory_order_seq_cst);
        }
    }
    return PTY_REG_INSERTED;
}

/* Lock-acquiring convenience wrapper used by the open-time and fork-restore
 * paths where atomicity with fd_table is not required.
 *
 * Returns the PTY_REG_* status. It used to report through errno instead, which
 * the insert path could not do honestly: pty_shared_attach reaches an existing
 * segment by letting an O_EXCL create fail with EEXIST and reopening, and
 * nothing after that clears errno. A successful insert during fork restore
 * therefore returned with errno still EEXIST, and the caller read that as "a
 * duplicate, drop the slave" and closed an fd the table had already recorded.
 */
static int pty_keepalive_register(int master_host_fd,
                                  int slave_host_fd,
                                  uint32_t linux_pts_num,
                                  const char *slave_path,
                                  bool stale_open_once,
                                  bool fresh_segment)
{
    pty_keepalive_lock_acquire();
    int rc = pty_keepalive_register_locked(
        master_host_fd, slave_host_fd, linux_pts_num, slave_path,
        stale_open_once, fresh_segment, NULL);
    pthread_mutex_unlock(&pty_keepalive_lock);
    return rc;
}

uint32_t proc_pty_master_pts_num(int master_host_fd)
{
    if (master_host_fd < 0)
        return UINT32_MAX;
    pty_keepalive_lock_acquire();
    int slot = pty_keepalive_find_master_locked(master_host_fd);
    uint32_t pts_num =
        (slot < 0) ? UINT32_MAX : pty_keepalive_table[slot].linux_pts_num;
    pthread_mutex_unlock(&pty_keepalive_lock);
    return pts_num;
}

/* Re-validate that fd_table[guest_fd] still refers to (host_fd, generation).
 * Returns true when both match the snapshot, false otherwise (slot closed or
 * recycled). Used by proc_pty_master_adopt to bracket every host-fd-number
 * access against the closing-and-reuse race.
 */
static bool pty_fd_still_canonical(int guest_fd,
                                   int canonical_host_fd,
                                   uint64_t canonical_gen)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return false;
    return snap.host_fd == canonical_host_fd &&
           snap.generation == canonical_gen;
}

uint32_t proc_pty_master_adopt(int guest_fd)
{
    /* Step 1: atomically snapshot (host_fd, generation) and dup the canonical
     * fd in a single fd_lock window. fd_snapshot_and_dup pins the file object
     * behind the canonical host fd, so even if a sibling closes the guest fd
     * and the host fd number is recycled by an unrelated open, host syscalls
     * against the probe still operate on the right tty. The generation captured
     * here is the witness for the subsequent table lookup and register
     * validations.
     */
    fd_entry_t snap;
    int probe = fd_snapshot_and_dup(guest_fd, &snap);
    if (probe < 0)
        return UINT32_MAX;
    int canonical_host_fd = snap.host_fd;
    uint64_t canonical_gen = snap.generation;

    /* Fast path: a keepalive was already registered for this canonical fd
     * (typical case for /dev/ptmx opens that went through pty_open_master). The
     * keepalive table is keyed by host fd number, so re-validate the slot
     * identity before trusting the returned pts_num. If the fd has been
     * recycled to a different file (generation mismatch), the existing entry
     * belongs to that file, not the pinned probe, and the slow path below must
     * register a fresh entry for the pinned probe.
     */
    uint32_t existing = proc_pty_master_pts_num(canonical_host_fd);
    if (existing != UINT32_MAX &&
        pty_fd_still_canonical(guest_fd, canonical_host_fd, canonical_gen)) {
        close(probe);
        return existing;
    }

    /* Step 2: confirm the file really is a /dev/ptmx master. ptsname(3) returns
     * NULL/ENOTTY on non-pty descriptors, so a stray TIOCGPTN against a regular
     * file is rejected without any side effect.
     */
    char slave_path[PTY_SLAVE_PATH_MAX];
    uint32_t pts_num = UINT32_MAX;
    int slave;
    if (ptsname_r(probe, slave_path, sizeof(slave_path)) != 0)
        goto out;
    pts_num = pty_extract_pts_num(slave_path);
    if (pts_num == UINT32_MAX)
        goto out;

    /* unlockpt(3) is harmless if the sender already unlocked. EINVAL means
     * already unlocked; anything else means the slave will not open and we give
     * up cleanly.
     */
    if (unlockpt(probe) < 0 && errno != EINVAL) {
        pts_num = UINT32_MAX;
        goto out;
    }
    slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        pts_num = UINT32_MAX;
        goto out;
    }

    /* Step 3: re-validate AND publish under the joint pty_keepalive_lock +
     * fd_lock window. Lock order is pty_keepalive_lock first;
     * duplicate_guest_fd uses the same order when bracketing
     * fd_snapshot_and_dup + proc_pty_dup_keepalive_locked, so the two paths
     * cannot deadlock. With both held, no sibling can flip the fd_table slot
     * between the validation read and the keepalive insert, so the keepalive
     * cannot attach to a recycled canonical host fd.
     */
    pty_keepalive_lock_acquire();
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_CLOSED ||
        fd_table[guest_fd].host_fd != canonical_host_fd ||
        fd_table[guest_fd].generation != canonical_gen) {
        pthread_mutex_unlock(&fd_lock);
        pthread_mutex_unlock(&pty_keepalive_lock);
        close(slave);
        pts_num = UINT32_MAX;
        goto out;
    }
    uint32_t existing_pts = UINT32_MAX;

    /* Adopting a master elfuse did not open: the pty already exists and other
     * processes may hold its segment, so join rather than replace.
     */
    int rc =
        pty_keepalive_register_locked(canonical_host_fd, slave, pts_num,
                                      slave_path, false, false, &existing_pts);
    pthread_mutex_unlock(&fd_lock);
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (rc == PTY_REG_FULL) {
        close(slave);
        pts_num = UINT32_MAX;
    } else if (rc == PTY_REG_EXISTS) {
        /* Another adopter registered first; their slave keeps the tty alive.
         * The pts_num came from the locked scan above, so it is the value the
         * winning entry holds and is not subject to a lookup-after-recycle
         * race.
         */
        close(slave);
        pts_num = existing_pts;
    }

out:
    close(probe);
    return pts_num;
}

/* Look up the captured macOS slave path for a Linux pts number.
 *
 * Returns 0 and writes the path on hit, -1 with errno=ENOENT on miss. Used by
 * the /dev/pts/N open and stat intercepts so they hit the exact path returned
 * by ptsname(3) rather than a guessed /dev/ttys%03lu reformat that breaks if
 * macOS changes its naming scheme or uses an unexpected minor encoding.
 */
int pty_lookup_slave_path(uint32_t linux_pts_num, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) {
        errno = EINVAL;
        return -1;
    }
    int hit = -1;
    pty_keepalive_lock_acquire();

    /* Prefer a live entry (master still open in this process) over a stale path
     * entry. Both encode the same slave_path for a given minor on macOS, so the
     * preference only matters if a future change ever lets the two diverge -
     * live wins by breaking out of the scan on first match.
     */
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].linux_pts_num != linux_pts_num)
            continue;
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE) {
            hit = i;
            break;
        }
        if (!pty_keepalive_table[i].stale_open_once ||
            pty_keepalive_table[i].slave_host_fd < 0)
            continue;
        if (hit < 0)
            hit = i;
    }
    if (hit < 0) {
        pthread_mutex_unlock(&pty_keepalive_lock);
        errno = ENOENT;
        return -1;
    }
    size_t len = strlen(pty_keepalive_table[hit].slave_path);
    if (len >= out_sz) {
        pthread_mutex_unlock(&pty_keepalive_lock);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, pty_keepalive_table[hit].slave_path, len + 1);
    pthread_mutex_unlock(&pty_keepalive_lock);
    return 0;
}

bool proc_pty_slave_stat(const char *path, struct stat *out)
{
    if (!path || strncmp(path, "/dev/pts/", 9) != 0 || !path[9])
        return false;
    struct stat st;
    if (proc_intercept_stat(path, out ? out : &st) != 0)
        return false;
    return true;
}

/* The guest-slave table is zero-initialized, so mark every slot free the first
 * time it is touched: fd 0 is a legitimate host descriptor and must not read as
 * an occupied slot.
 */
static void pty_guest_slave_table_init_once(void)
{
    static bool done;
    if (done)
        return;
    for (int i = 0; i < PTY_GUEST_SLAVE_MAX; i++)
        pty_guest_slave_table[i].slave_host_fd = PTY_KEEPALIVE_FREE;
    done = true;
}

/* Retire a recorded slave fd and credit its master. Caller holds the lock.
 * Returns any retained keepalive slave fd the caller must close.
 */
static int pty_guest_slave_release_locked(int slave_host_fd)
{
    for (int i = 0; i < PTY_GUEST_SLAVE_MAX; i++) {
        if (pty_guest_slave_table[i].slave_host_fd != slave_host_fd)
            continue;
        uint32_t pts_num = pty_guest_slave_table[i].linux_pts_num;
        pty_guest_slave_table[i].slave_host_fd = PTY_KEEPALIVE_FREE;
        int k = pty_account_row_locked(pts_num, -1);
        if (k >= 0 && pty_keepalive_table[k].guest_slave_count > 0) {
            pty_keepalive_table[k].guest_slave_count--;
            pty_diag("pty: -slave pts=%u hostfd=%d local=%d shared=%d", pts_num,
                     slave_host_fd, pty_keepalive_table[k].guest_slave_count,
                     pty_keepalive_table[k].shared
                         ? atomic_load_explicit(
                               &pty_keepalive_table[k].shared->slave_count,
                               memory_order_seq_cst) -
                               1
                         : -1);
            if (pty_keepalive_table[k].shared)
                atomic_fetch_sub_explicit(
                    &pty_keepalive_table[k].shared->slave_count, 1,
                    memory_order_seq_cst);

            /* A master-less home with nothing left to account for can go now
             * rather than at process teardown.
             */
            if (pty_keepalive_table[k].guest_slave_count == 0 &&
                pty_keepalive_table[k].master_host_fd == PTY_KEEPALIVE_FREE)
                return pty_keepalive_clear_slot_locked(k);
        }
        break;
    }
    return -1;
}

/* Put a slave fd on this process's books and credit its master. Caller holds
 * the lock.
 *
 * bump_shared is false only for a slave inherited through fork: the parent
 * already added it to the shared count on the child's behalf (see
 * proc_pty_fork_parent_note_inherited), so counting it again here would double
 * it. The local count still rises either way, since it is this process's
 * contribution and what its closes and its detach subtract.
 */
static void pty_guest_slave_record_locked(int slave_host_fd,
                                          uint32_t linux_pts_num,
                                          bool bump_shared)
{
    for (int i = 0; i < PTY_GUEST_SLAVE_MAX; i++) {
        if (pty_guest_slave_table[i].slave_host_fd != PTY_KEEPALIVE_FREE)
            continue;
        pty_guest_slave_table[i].slave_host_fd = slave_host_fd;
        pty_guest_slave_table[i].linux_pts_num = linux_pts_num;

        /* The accounting home, not merely the first row for this pty. A slot
         * whose master has already closed still owns the count: a fork-restored
         * child routinely drops its copy of the master and only then opens
         * /dev/pts/N, and requiring a live master here left that slave credited
         * to nobody, so the parent still holding the master never learned the
         * shell had one.
         */
        int k = pty_account_row_locked(linux_pts_num, -1);
        if (k >= 0) {
            pty_keepalive_table[k].guest_slave_count++;
            pty_keepalive_table[k].guest_slave_seen = true;
            pty_diag(
                "pty: +slave pts=%u hostfd=%d bump_shared=%d local=%d "
                "shared=%d",
                linux_pts_num, slave_host_fd, (int) bump_shared,
                pty_keepalive_table[k].guest_slave_count,
                pty_keepalive_table[k].shared
                    ? atomic_load_explicit(
                          &pty_keepalive_table[k].shared->slave_count,
                          memory_order_seq_cst) +
                          (bump_shared ? 1 : 0)
                    : -1);
            if (pty_keepalive_table[k].shared) {
                if (bump_shared)
                    atomic_fetch_add_explicit(
                        &pty_keepalive_table[k].shared->slave_count, 1,
                        memory_order_seq_cst);
                atomic_store_explicit(&pty_keepalive_table[k].shared->seen, 1,
                                      memory_order_seq_cst);
            }
        }
        break;
    }
}

static void pty_note_guest_slave(int slave_host_fd,
                                 uint32_t linux_pts_num,
                                 bool bump_shared)
{
    if (slave_host_fd < 0)
        return;
    pty_keepalive_lock_acquire();
    pty_guest_slave_table_init_once();

    /* Drop any entry left over for this host fd number first. The open is
     * recorded before the guest fd is installed, so a failed fd_alloc closes
     * the host fd without passing through the close hooks; retiring the stale
     * slot on reuse keeps that from inflating an unrelated pty's count.
     */
    int slave = pty_guest_slave_release_locked(slave_host_fd);
    pty_guest_slave_record_locked(slave_host_fd, linux_pts_num, bump_shared);
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (slave >= 0)
        close(slave);
}

void proc_pty_note_guest_slave(int slave_host_fd, uint32_t linux_pts_num)
{
    pty_note_guest_slave(slave_host_fd, linux_pts_num, true);
}

void proc_pty_fork_parent_note_inherited(void)
{
    /* fork duplicates every slave fd the guest holds, so the child's copies are
     * live the instant fork returns. Count them here, in the parent, while the
     * guest is still inside clone: leaving it to the child's own init loses the
     * race against a parent that closes its copy immediately, which is exactly
     * what openpty(3)-style terminal startup does. The pty would look hung up
     * in that window and the terminal would see its shell die at startup.
     */
    pty_keepalive_lock_acquire();

    /* The sentinel init is what makes an unused slot readable as free. Without
     * it a table still in its BSS-zero state reads as PTY_GUEST_SLAVE_MAX
     * occupied slots holding host fd 0, and every one of them would be counted
     * as an inherited slave -- which is what a parent that never opened a slave
     * itself does on its very first fork.
     */
    pty_guest_slave_table_init_once();
    for (int i = 0; i < PTY_GUEST_SLAVE_MAX; i++) {
        if (pty_guest_slave_table[i].slave_host_fd == PTY_KEEPALIVE_FREE)
            continue;
        uint32_t pts_num = pty_guest_slave_table[i].linux_pts_num;

        /* The accounting home, not the first row with a live master. Picking
         * differently here would credit the child's inherited slave to one row
         * while pty_guest_slave_release_locked takes it back off another, and
         * the two rows need not share a segment.
         */
        int k = pty_account_row_locked(pts_num, -1);
        if (k >= 0 && pty_keepalive_table[k].shared)
            atomic_fetch_add_explicit(
                &pty_keepalive_table[k].shared->slave_count, 1,
                memory_order_seq_cst);
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
}

void proc_pty_dup_guest_slave_locked(int src_slave_host_fd,
                                     int dst_slave_host_fd)
{
    if (src_slave_host_fd < 0 || dst_slave_host_fd < 0)
        return;
    pty_guest_slave_table_init_once();

    uint32_t pts_num = UINT32_MAX;
    for (int i = 0; i < PTY_GUEST_SLAVE_MAX; i++) {
        if (pty_guest_slave_table[i].slave_host_fd == src_slave_host_fd) {
            pts_num = pty_guest_slave_table[i].linux_pts_num;
            break;
        }
    }
    if (pts_num == UINT32_MAX)
        return; /* not a tracked slave; nothing to mirror */

    /* The dup is a live reference to the same slave, so it has to be counted
     * like the open that produced the source. Only open() used to register, so
     * a terminal that dup2()s its slave onto stdin/stdout/stderr and closes the
     * original left the count at zero with three references still open -- the
     * master then reported a hangup with the shell still running.
     */
    int slave = pty_guest_slave_release_locked(dst_slave_host_fd);
    pty_guest_slave_record_locked(dst_slave_host_fd, pts_num, true);
    if (slave >= 0)
        close(slave);
}

void proc_pty_release_process_slaves(void)
{
    /* Hand back every slave this process still holds, at process teardown.
     *
     * Per-fd cleanup cannot be relied on for this: a shell exiting normally
     * never closes its stdio, the kernel does, so the slaves backing fds 0/1/2
     * leave no close hook behind. Without this the shared count keeps a
     * departed shell's slaves forever and the master never reports the hangup
     * its terminal is waiting on -- the "window stays open after exit" case.
     *
     * A process killed outright still cannot run this, and leaks its
     * contribution. That is bounded: the host pty is only recycled once every
     * fd on it is gone, and the next master to claim that path starts a fresh
     * segment (see pty_shared_attach), so the stale count is discarded rather
     * than inherited.
     */
    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (!pty_keepalive_table[i].shared)
            continue;
        pty_shared_detach(pty_keepalive_table[i].shared,
                          pty_keepalive_table[i].slave_path,
                          pty_keepalive_table[i].guest_slave_count);
        pty_keepalive_table[i].shared = NULL;
        pty_keepalive_table[i].guest_slave_count = 0;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
}

void proc_pty_adopt_inherited_slaves(void)
{
    /* A guest fork hands the child every slave fd the parent had open, but the
     * table that maps a host fd back to its pty is per-process and does not
     * travel, so those inherited slaves were counted by nobody. The parent then
     * closes its own copy -- exactly what openpty(3)-style startup does -- the
     * count falls to zero while the child's shell still holds a live slave, and
     * the master reports a hangup the instant the terminal window appears.
     *
     * Recover the mapping from the host instead of shipping more state: a pty
     * slave is a char device whose rdev matches the slave path recorded in the
     * keepalive entry, which the child has just restored. Runs in the forked
     * child's single-threaded init, after the fd table and the keepalives.
     */
    struct {
        uint32_t pts_num;
        dev_t rdev;
        int skip_slave_fd;
        int skip_master_fd;
    } ptys[PTY_KEEPALIVE_MAX];
    int npty = 0;

    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX && npty < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE)
            continue;
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        struct stat st;
        if (stat(pty_keepalive_table[i].slave_path, &st) != 0 ||
            !S_ISCHR(st.st_mode))
            continue;
        ptys[npty].pts_num = pty_keepalive_table[i].linux_pts_num;
        ptys[npty].rdev = st.st_rdev;
        ptys[npty].skip_slave_fd = pty_keepalive_table[i].slave_host_fd;
        ptys[npty].skip_master_fd = pty_keepalive_table[i].master_host_fd;
        npty++;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (npty == 0)
        return;

    /* Snapshot the host fds before matching: proc_pty_note_guest_slave takes
     * pty_keepalive_lock, which sorts before fd_lock, so neither lock can be
     * held while calling it.
     */
    int host_fds[FD_TABLE_SIZE];
    int nfd = 0;
    pthread_mutex_lock(&fd_lock);
    for (int gfd = 0; gfd < FD_TABLE_SIZE; gfd++) {
        if (fd_table[gfd].type == FD_CLOSED || fd_table[gfd].host_fd < 0)
            continue;
        host_fds[nfd++] = fd_table[gfd].host_fd;
    }
    pthread_mutex_unlock(&fd_lock);

    for (int i = 0; i < nfd; i++) {
        struct stat st;
        if (fstat(host_fds[i], &st) != 0 || !S_ISCHR(st.st_mode))
            continue;
        for (int p = 0; p < npty; p++) {
            if (st.st_rdev != ptys[p].rdev)
                continue;

            /* elfuse's own keepalive slave is not a guest slave, and the master
             * never matches the slave's rdev but is cheap to exclude.
             */
            if (host_fds[i] == ptys[p].skip_slave_fd ||
                host_fds[i] == ptys[p].skip_master_fd)
                break;

            /* Local books only: the parent already counted these copies into
             * the shared total before fork returned.
             */
            pty_note_guest_slave(host_fds[i], ptys[p].pts_num, false);
            break;
        }
    }
}

void proc_pty_slave_fd_closed(int host_fd)
{
    if (host_fd < 0)
        return;
    pty_keepalive_lock_acquire();
    pty_guest_slave_table_init_once();
    int slave = pty_guest_slave_release_locked(host_fd);
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (slave >= 0)
        close(slave);
}

void proc_pty_forget_host_fd(int host_fd)
{
    proc_pty_close_keepalive(host_fd);
    proc_pty_slave_fd_closed(host_fd);
}

/* Whether this slot's pty has no guest slave left. Reads the shared segment
 * when one is mapped, so a slave held by another process in the fork family
 * counts; falls back to the per-process view when it is not. Caller holds
 * pty_keepalive_lock.
 */
static bool pty_slot_hung_up_locked(int slot)
{
    pty_shared_t *sh = pty_keepalive_table[slot].shared;
    bool hung_up;
    if (sh) {
        hung_up =
            atomic_load_explicit(&sh->seen, memory_order_seq_cst) != 0 &&
            atomic_load_explicit(&sh->slave_count, memory_order_seq_cst) <= 0;
    } else {
        /* No segment, so the counters are this process's own -- and they live
         * on the pty's accounting home, which for an aliased master is not this
         * row. Reading them here is what the shared case gets for free.
         */
        int home =
            pty_account_row_locked(pty_keepalive_table[slot].linux_pts_num, -1);
        if (home < 0)
            home = slot;
        hung_up = pty_keepalive_table[home].guest_slave_seen &&
                  pty_keepalive_table[home].guest_slave_count == 0;
    }

    /* Only on the way to reporting one: the negative answer is the steady state
     * and every poll would log it. This subsystem spans processes, so without a
     * record of which side saw what a wrong verdict is very hard to place after
     * the fact.
     */
    if (hung_up)
        pty_diag(
            "pty: HANGUP pts=%u seen=%d shared=%d local=%d/%d path=%s",
            pty_keepalive_table[slot].linux_pts_num,
            sh ? atomic_load_explicit(&sh->seen, memory_order_seq_cst) : -1,
            sh ? atomic_load_explicit(&sh->slave_count, memory_order_seq_cst)
               : -1,
            (int) pty_keepalive_table[slot].guest_slave_seen,
            pty_keepalive_table[slot].guest_slave_count,
            pty_keepalive_table[slot].slave_path);
    return hung_up;
}

bool proc_pty_master_hung_up(int guest_fd, uint64_t expect_generation)
{
    /* Keyed on the guest fd rather than a host one: the caller brings a
     * generation to check, and only the guest fd leads back to the table entry
     * carrying it. A host fd number alone cannot tell a live master from one a
     * sibling closed and an unrelated open recycled.
     */
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return false;

    /* The caller resolved this guest fd earlier; re-resolving it here reopens
     * the close-and-reuse window. Reject a slot that has been recycled since,
     * so the hangup is never charged to an unrelated file.
     */
    if (snap.generation != expect_generation)
        return false;
    int master_host_fd = snap.host_fd;
    if (master_host_fd < 0)
        return false;
    bool hung_up = false;
    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd != master_host_fd)
            continue;
        hung_up = pty_slot_hung_up_locked(i);
        break;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    return hung_up;
}

int pty_open_slave(uint32_t linux_pts_num, int linux_flags)
{
    int oflags = translate_open_flags(linux_flags) &
                 (O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    char host_path[PTY_SLAVE_PATH_MAX];
    int stale_hit = -1;
    int retained_slaves[PTY_KEEPALIVE_MAX];
    int nretained = 0;
    int fd;

    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].linux_pts_num != linux_pts_num)
            continue;
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE) {
            size_t len = strlen(pty_keepalive_table[i].slave_path);
            if (len >= sizeof(host_path)) {
                pthread_mutex_unlock(&pty_keepalive_lock);
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(host_path, pty_keepalive_table[i].slave_path, len + 1);
            pthread_mutex_unlock(&pty_keepalive_lock);
            return open(host_path, oflags);
        }
        if (stale_hit < 0 && pty_keepalive_table[i].stale_open_once &&
            pty_keepalive_table[i].slave_host_fd >= 0)
            stale_hit = i;
    }

    if (stale_hit < 0) {
        pthread_mutex_unlock(&pty_keepalive_lock);
        errno = ENOENT;
        return -1;
    }

    /* The retained slave fd pins the macOS tty while this translates the
     * close-before-open sequence, so the cached path cannot resolve to a reused
     * unrelated minor. The mapping is consumed only when the open failed:
     * keeping it while the pin is still doing its job is what lets the child
     * open its slave more than once, and stat it, and see it in /dev/pts.
     * Retiring on success made the entry one-shot, so a second open, a stat of
     * the child's own pts path, or a readdir after the first open answered
     * ENOENT while the child still held a live slave on that pty.
     */
    size_t len = strlen(pty_keepalive_table[stale_hit].slave_path);
    if (len >= sizeof(host_path)) {
        int retained_slave = pty_keepalive_retire_stale_locked(stale_hit);
        pthread_mutex_unlock(&pty_keepalive_lock);
        if (retained_slave >= 0)
            close(retained_slave);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(host_path, pty_keepalive_table[stale_hit].slave_path, len + 1);
    fd = open(host_path, oflags);
    int saved = errno;
    for (int i = 0; fd < 0 && i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE)
            continue;
        if (!pty_keepalive_table[i].stale_open_once)
            continue;
        if (strncmp(pty_keepalive_table[i].slave_path, host_path,
                    PTY_SLAVE_PATH_MAX) != 0)
            continue;
        int retained_slave = pty_keepalive_retire_stale_locked(i);
        if (retained_slave >= 0 && nretained < PTY_KEEPALIVE_MAX)
            retained_slaves[nretained++] = retained_slave;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    for (int i = 0; i < nretained; i++)
        close(retained_slaves[i]);
    errno = saved;
    return fd;
}

int pty_open_pts_dir(int linux_flags)
{
    char dir[80];
    uint32_t pts_nums[PTY_KEEPALIVE_MAX];
    int pts_count = 0;
    int n = snprintf(dir, sizeof(dir), "/tmp/elfuse-pts-XXXXXX");
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!mkdtemp(dir))
        return -1;

    pty_keepalive_lock_acquire();

    /* Enumerate live masters and fork-child stale entries. A stale entry holds
     * its slave fd for as long as it is listed here, so it cannot name a reused
     * unrelated tty while it appears in readdir.
     */
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE &&
            (!pty_keepalive_table[i].stale_open_once ||
             pty_keepalive_table[i].slave_host_fd < 0))
            continue;

        /* Aliased masters give one minor several rows, so the same number can
         * come up more than once. A duplicate only re-creates the placeholder
         * file it already made, which readdir reports once either way.
         */
        pts_nums[pts_count++] = pty_keepalive_table[i].linux_pts_num;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);

    for (int i = 0; i < pts_count; i++) {
        char entry[160];
        int en = snprintf(entry, sizeof(entry), "%s/%u", dir, pts_nums[i]);
        if (en <= 0 || (size_t) en >= sizeof(entry))
            continue;
        int tfd = open(entry, O_CREAT | O_WRONLY, 0444);
        if (tfd >= 0)
            close(tfd);
    }

    proc_scratch_register(dir);

    int fd = proc_open_dir_fd(dir, linux_flags);
    if (fd < 0) {
        int saved = errno;
        proc_scratch_remove_one(dir);
        errno = saved;
    }
    return fd;
}

void proc_pty_lock_for_dup(void)
{
    pty_keepalive_lock_acquire();
}

void proc_pty_unlock_for_dup(void)
{
    pthread_mutex_unlock(&pty_keepalive_lock);
}

void proc_pty_dup_keepalive_locked(int src_master_host_fd,
                                   int dst_master_host_fd)
{
    /* Caller-holds-lock variant; see header for the dup race this guards. */
    if (src_master_host_fd < 0 || dst_master_host_fd < 0)
        return;

    int slot = pty_keepalive_find_master_locked(src_master_host_fd);
    if (slot < 0)
        return;
    int dst_slave = dup(pty_keepalive_table[slot].slave_host_fd);
    if (dst_slave < 0)
        return;
    uint32_t src_pts_num = pty_keepalive_table[slot].linux_pts_num;
    char src_slave_path[PTY_SLAVE_PATH_MAX];
    memcpy(src_slave_path, pty_keepalive_table[slot].slave_path,
           PTY_SLAVE_PATH_MAX);

    /* dup(2) clears FD_CLOEXEC; the keepalive must not survive exec into a
     * guest child that has no map back to it.
     */
    if (fd_set_cloexec(dst_slave) < 0) {
        close(dst_slave);
        return;
    }
    int rc = pty_keepalive_register_locked(dst_master_host_fd, dst_slave,
                                           src_pts_num, src_slave_path, false,
                                           /*fresh_segment=*/false, NULL);
    if (rc != PTY_REG_INSERTED) {
        /* Table full or duplicate entry for dst_master_host_fd; drop the
         * redundant slave. Duplicate is unexpected: dst is a freshly-duped host
         * fd that should not already be in the table unless a prior close
         * skipped proc_pty_close_keepalive.
         */
        close(dst_slave);
    }
}

void proc_pty_close_keepalive(int master_host_fd)
{
    /* fd_cleanup_entry calls this for every guest fd close, not just pty
     * masters; pty_keepalive_lock_acquire guarantees sentinel-init first.
     */
    if (master_host_fd < 0)
        return;

    int slave = -1;
    pty_keepalive_lock_acquire();
    int slot = pty_keepalive_find_master_locked(master_host_fd);
    if (slot >= 0) {
        if (pty_keepalive_table[slot].stale_open_once) {
            /* Fork-restored child entry: retain the slave fd and path so
             * /dev/pts/N stays openable after close(master). pty_open_slave
             * gives them up only once an open has failed. Only the master goes
             * away here. Any slave fd this process still holds stays open and
             * keeps counting: closing the master does not close the slaves, and
             * a terminal's child routinely drops its copy of the master while
             * holding the slave as its stdio. Retiring the count here would
             * report a hangup with the shell still running. The slaves
             * decrement themselves as they close.
             */
            pty_keepalive_table[slot].master_host_fd = PTY_KEEPALIVE_FREE;
        } else {
            slave = pty_keepalive_clear_slot_locked(slot);
        }
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (slave >= 0)
        close(slave);
}

static void proc_pty_expire_stale_by_path(const char *slave_path)
{
    if (!slave_path || slave_path[0] == '\0')
        return;

    int stale_slaves[PTY_KEEPALIVE_MAX];
    int nslaves = 0;
    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE)
            continue;
        if (!pty_keepalive_table[i].stale_open_once)
            continue;
        if (strncmp(pty_keepalive_table[i].slave_path, slave_path,
                    PTY_SLAVE_PATH_MAX) != 0)
            continue;
        int slave = pty_keepalive_clear_slot_locked(i);
        if (slave >= 0 && nslaves < PTY_KEEPALIVE_MAX)
            stale_slaves[nslaves++] = slave;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    for (int i = 0; i < nslaves; i++)
        close(stale_slaves[i]);
}

static int pty_keepalive_register_recycled(int master_host_fd,
                                           int slave_host_fd,
                                           uint32_t linux_pts_num,
                                           const char *slave_path,
                                           bool stale_open_once,
                                           bool fresh_segment)
{
    proc_pty_expire_stale_by_path(slave_path);
    return pty_keepalive_register(master_host_fd, slave_host_fd, linux_pts_num,
                                  slave_path, stale_open_once, fresh_segment);
}

int proc_pty_snapshot_keepalive(proc_pty_ipc_entry_t *out_entries,
                                int *out_slave_fds,
                                int max_entries)
{
    if (!out_entries || !out_slave_fds || max_entries <= 0)
        return 0;

    int n = 0;
    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX && n < max_entries; i++) {
        if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE)
            continue;

        /* dup under the lock so the slave fd cannot be closed and the host fd
         * number recycled before SCM_RIGHTS reads it. The caller closes the dup
         * after the send completes.
         */
        int duped = dup(pty_keepalive_table[i].slave_host_fd);
        if (duped < 0)
            continue;

        out_entries[n].master_host_fd = pty_keepalive_table[i].master_host_fd;
        out_entries[n].linux_pts_num = pty_keepalive_table[i].linux_pts_num;
        _Static_assert(sizeof(out_entries[n].slave_path) == PTY_SLAVE_PATH_MAX,
                       "ipc slave_path size must match keepalive table");
        memcpy(out_entries[n].slave_path, pty_keepalive_table[i].slave_path,
               PTY_SLAVE_PATH_MAX);
        out_slave_fds[n] = duped;
        n++;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    return n;
}

void proc_pty_restore_keepalive(int master_host_fd,
                                int slave_host_fd,
                                uint32_t linux_pts_num,
                                const char *slave_path)
{
    /* fork-IPC hand-off. SCM_RIGHTS drops FD_CLOEXEC; set it here so the
     * keepalive does not survive exec. Any failure drops the slave fd.
     */
    if (master_host_fd < 0)
        goto drop;

    if (slave_host_fd >= 0 && fd_set_cloexec(slave_host_fd) < 0)
        goto drop;

    /* Trust the parent's linux_pts_num verbatim instead of re-parsing
     * slave_path. The wire-format string is bounded to PTY_SLAVE_PATH_MAX - 1
     * bytes; if a future macOS canonical form ever exceeded that, the parent
     * would have truncated and reparsing here would yield the wrong number.
     *
     * Anything but PTY_REG_INSERTED means the child's fd_table-restore path
     * replayed master_host_fd over a prior recv-keepalive entry, so the slave
     * handed in here is redundant; drop it rather than leak it.
     */
    if (pty_keepalive_register_recycled(
            master_host_fd, slave_host_fd, linux_pts_num, slave_path, true,
            /*fresh_segment=*/false) != PTY_REG_INSERTED)
        goto drop;
    return;

drop:
    if (slave_host_fd >= 0)
        close(slave_host_fd);
}

/* Open /dev/ptmx, unlock the slave, and instantiate a keepalive slave fd so the
 * master's tty ioctls work before the guest opens the slave itself.
 * Returns the master host fd on success, -1 with errno set on failure.
 */
int pty_open_master(int linux_flags)
{
    /* /dev/ptmx is a character device; O_CREAT / O_TRUNC / O_EXCL make no sense
     * here. Strip them and only honor accmode + descriptor flags so the host
     * open(2) never sees a variadic-mode-required combination without a mode
     * arg.
     */
    int oflags = translate_open_flags(linux_flags) &
                 (O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    int master = open("/dev/ptmx", oflags);
    if (master < 0)
        return -1;

    /* grantpt(3) is a no-op on a unix98 pty mount, but call it for clarity and
     * to match what posix_openpt(3)'s callers expect to have happened.
     */
    char slave_path[PTY_SLAVE_PATH_MAX];
    if (grantpt(master) < 0 || unlockpt(master) < 0 ||
        ptsname_r(master, slave_path, sizeof(slave_path)) != 0) {
        close_keep_errno(master);
        return -1;
    }

    /* Establish the (linux_pts_num, slave_path) mapping that /dev/pts/N opens
     * and stats resolve through. If table or slave-fd registration fails after
     * the master is open, report EMFILE rather than silently returning a master
     * fd whose pts number cannot be opened back through /dev/pts/N. The caller
     * can close other pty pairs and retry instead of dealing with a half-broken
     * descriptor.
     */
    uint32_t linux_pts_num = pty_extract_pts_num(slave_path);
    if (linux_pts_num == UINT32_MAX) {
        close(master);
        errno = ENOTTY;
        return -1;
    }
    int slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        close_keep_errno(master);
        return -1;
    }

    /* The host just allocated this pty, so nothing live can be using a segment
     * under its name; any leftover is state a process died holding.
     */
    int reg = pty_keepalive_register_recycled(master, slave, linux_pts_num,
                                              slave_path, false,
                                              /*fresh_segment=*/true);
    if (reg == PTY_REG_FULL) {
        close(slave);
        close(master);
        errno = EMFILE;
        return -1;
    }

    /* Defense-in-depth: the freshly-opened master fd should not already have a
     * keepalive (would indicate a stale entry from a prior close that did not
     * run proc_pty_close_keepalive). Drop the redundant slave so it does not
     * leak.
     */
    if (reg == PTY_REG_EXISTS)
        close(slave);
    return master;
}
