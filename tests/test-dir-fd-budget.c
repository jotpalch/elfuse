/*
 * A guest directory fd must cost exactly one host descriptor
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse sizes the host descriptor budget as FD_TABLE_SIZE guest fds plus
 * HOST_FD_RESERVE for its own plumbing (src/elfuse-limits.h), which assumes one
 * host descriptor per guest fd. Directories used to break that assumption:
 * fd_alloc_opened_host() dup'd the descriptor so fdopendir() could adopt one
 * copy while the fd table kept the other, and the duplicate lived as long as
 * the guest fd. A guest that opened directories therefore ran out at half the
 * table it was promised, and the overflow came out of the reserve, so the first
 * casualty was elfuse's own fork IPC rather than the open that caused it.
 *
 * The stream now adopts the slot's own descriptor and owns it (see
 * dir_stream_open / dir_stream_t in src/syscall/fs.c), so both tests below
 * measure the same thing from two directions: how many directories fit, and
 * whether dup'ing them fits too.
 *
 * A dup costs nothing at all, which is the stronger form of the same invariant.
 * dup(2) gives the alias the source's open file description, so the alias
 * shares the source's stream -- one descriptor, one listing position, one union
 * state, given back when the last of the two guest fds closes. The bound
 * asserted below is therefore a ceiling the dup half can only come in under,
 * and it is left as a ceiling on purpose: what must never happen is a dup
 * costing more, and pinning it at exactly zero would make this test fail for a
 * future dup that legitimately needed a descriptor of its own.
 *
 * Runs with host_nofile=elfuse-minimum, which is the point: with the host limit
 * at exactly what elfuse asks for, the doubling has nowhere to hide. Before the
 * fix the first test reached 636 of a promised 1021.
 *
 * Syscalls exercised: openat(56), dup(23), getdents64(61), lseek(62),
 *                     fcntl(25), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Every threshold below is derived from the guest's own RLIMIT_NOFILE, read at
 * runtime, rather than written down. Under elfuse that limit is seeded from
 * FD_TABLE_SIZE and the host budget is that plus HOST_FD_RESERVE, so a change
 * to either constant moves these with it; a written-down 1000 would keep
 * compiling and quietly stop discriminating the moment the table grew. Reading
 * the limit rather than including src/elfuse-limits.h is also what lets the
 * same binary mean something in the reference lane, where the host-side
 * constants describe nothing.
 *
 * A few descriptors are already spoken for -- stdio, whatever the harness holds
 * -- so the ceiling is approached, not hit exactly. SLACK is the room left for
 * them.
 */
#define SLACK 24

static int nofile_limit(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
        return -1;
    return rl.rlim_cur > INT_MAX ? INT_MAX : (int) rl.rlim_cur;
}

/* Directory opens should stop on the guest table, the way a plain file does.
 * The doubling stopped at roughly half of it.
 */
static int expect_at_least(int limit)
{
    return limit - SLACK;
}

/* Enough open+dup pairs that a directory costing two descriptors would need
 * more than the whole host budget (4 * pairs > limit + HOST_FD_RESERVE), while
 * the 2 * pairs guest fds still fit under the limit. A shared alias spends no
 * descriptor of its own, so the pairs cost half of this; the count is what a
 * regression to a descriptor per alias would fail at, not what today's cost
 * predicts.
 */
static int dup_pairs(int limit)
{
    return limit / 2 - SLACK;
}

static char fixture_dir[] = "/tmp/elfuse-dir-budget-XXXXXX";
static char fixture_file[256];

static int open_fixture_dir(void)
{
    return open(fixture_dir, O_RDONLY | O_DIRECTORY);
}

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

/* A stream that never reports its end would spin the walk below forever and
 * reach the driver as a timeout rather than as a failure. The fixture holds
 * three entries; this ceiling is about a broken stream, not about contents.
 */
#define MAX_ENTRIES 4096

/* Read the whole stream through raw getdents64 and report whether the fixture
 * file was read back. False covers an unreadable stream as well as an absent
 * entry -- a failed lseek, a getdents64 error, a malformed record -- which is
 * why the callers word their failures as not having read the entry rather than
 * as the entry being gone. Deliberately spends no second descriptor -- these
 * checks run while the guest fd table is deep into the budget the test just
 * measured, and an fdopendir()/dup() here would fail with EMFILE for reasons
 * that have nothing to do with what is under test.
 *
 * Every record is bounds-checked before any of it is read. The buffer is what a
 * change to directory-stream ownership could plausibly corrupt, so this walk
 * treats a malformed reclen as a failure to report rather than as something to
 * step over -- and reading a name that does not terminate inside its own record
 * would run strcmp off the end of buf.
 */
static bool dir_lists_fixture(int fd)
{
    if (lseek(fd, 0, SEEK_SET) < 0)
        return false;

    char buf[4096];
    int seen = 0;
    for (;;) {
        long n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (n <= 0)
            return false;
        const long header = (long) offsetof(linux_dirent64_t, d_name);
        for (long off = 0; off < n;) {
            /* The header has to fit before anything in it can be read. A
             * malformed reclen walks off toward n rather than landing on it,
             * and reading d_reclen out of a record that is not all there is
             * itself the over-read this walk exists to avoid.
             */
            if (n - off < header)
                return false;
            linux_dirent64_t *de = (linux_dirent64_t *) (buf + off);
            long reclen = de->d_reclen;
            if (reclen <= header || reclen > n - off)
                return false;
            if (!memchr(de->d_name, '\0', (size_t) (reclen - header)))
                return false;
            if (!strcmp(de->d_name, "marker"))
                return true;
            if (++seen > MAX_ENTRIES)
                return false;
            off += reclen;
        }
    }
}

static void close_all(int *fds, int n)
{
    for (int i = 0; i < n; i++)
        if (fds[i] >= 0)
            close(fds[i]);
}

/* Sized from the limit at startup rather than declared, so the arrays cannot
 * become the thing the open loop stops on.
 */
static int *fds;
static int *dups;

int main(void)
{
    printf("test-dir-fd-budget: one host descriptor per directory fd\n\n");

    int limit = nofile_limit();
    if (limit <= SLACK * 4) {
        fprintf(stderr,
                "guest RLIMIT_NOFILE is %d, too low to measure a "
                "descriptor budget\n",
                limit);
        return 2;
    }
    const int want_open = expect_at_least(limit);
    const int want_pairs = dup_pairs(limit);
    const int slots = limit + SLACK;
    printf("  RLIMIT_NOFILE %d: expecting >= %d directories, %d dup pairs\n\n",
           limit, want_open, want_pairs);

    fds = calloc((size_t) slots, sizeof(*fds));
    dups = calloc((size_t) want_pairs, sizeof(*dups));
    if (!fds || !dups) {
        fprintf(stderr, "out of memory sizing the fd arrays\n");
        return 2;
    }

    if (!mkdtemp(fixture_dir)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    snprintf(fixture_file, sizeof(fixture_file), "%s/marker", fixture_dir);
    int marker = open(fixture_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (marker < 0) {
        /* mkdtemp made a directory nobody else will ever name, so this is the
         * only chance to take it back.
         */
        fprintf(stderr, "create marker: %s\n", strerror(errno));
        rmdir(fixture_dir);
        return 1;
    }
    close(marker);

    TEST("directory fds reach the guest table");
    int opened = 0;
    for (; opened < slots; opened++) {
        fds[opened] = open_fixture_dir();
        if (fds[opened] < 0)
            break;
    }
    if (opened >= want_open) {
        PASS();
    } else {
        printf("FAIL: stopped at %d, expected >= %d (errno=%d)\n", opened,
               want_open, errno);
        fails++;
    }

    TEST("a directory fd still reads after that");
    if (opened > 0 && dir_lists_fixture(fds[0]))
        PASS();
    else
        FAIL("fixture entry missing from a surviving directory fd");
    close_all(fds, opened);

    TEST("dup'ing directory fds costs no more than one each");
    int paired = 0;
    for (; paired < want_pairs; paired++) {
        fds[paired] = open_fixture_dir();
        if (fds[paired] < 0)
            break;
        dups[paired] = dup(fds[paired]);
        if (dups[paired] < 0) {
            /* Report the dup's errno, not the close's: the descriptor
             * exhaustion this test exists to catch is what dup answered, and
             * close is allowed to overwrite errno even when it succeeds.
             */
            int saved_errno = errno;
            close(fds[paired]);
            errno = saved_errno;
            break;
        }
    }
    if (paired == want_pairs) {
        PASS();
    } else {
        printf("FAIL: only %d of %d pairs (errno=%d)\n", paired, want_pairs,
               errno);
        fails++;
    }

    close_all(fds, paired);
    close_all(dups, paired);

    /* The two fds share one stream over one descriptor, held by a reference
     * count, so closing either must not give the descriptor back while the
     * other still names it. Checked by using the survivor as a directory rather
     * than by reading it: the shared position means the source's own reads
     * would have consumed the listing, and what is under test here is the
     * descriptor's lifetime, not the listing. tests/test-dir-union-alias covers
     * the sharing itself.
     */
    TEST("a dup outlives the fd it came from");
    bool dup_ok = false;
    int source = open_fixture_dir();
    if (source >= 0) {
        int alias = dup(source);
        if (alias >= 0) {
            close(source);
            int through_alias = openat(alias, "marker", O_RDONLY);
            dup_ok = through_alias >= 0;
            if (through_alias >= 0)
                close(through_alias);
            close(alias);
        } else {
            close(source);
        }
    }
    EXPECT_TRUE(dup_ok,
                "the surviving dup stopped working as a directory "
                "after the original closed");

    /* fdopendir sets FD_CLOEXEC on the descriptor it adopts, which is now the
     * guest fd's own. The guest's close-on-exec flag lives in elfuse's fd
     * table, not on the host descriptor, so an open without O_CLOEXEC must
     * still read back clear.
     */
    TEST("opening a directory does not set close-on-exec");
    int plain = open_fixture_dir();
    if (plain < 0) {
        FAIL("could not open the fixture directory");
    } else {
        int fd_flags = fcntl(plain, F_GETFD);
        if (fd_flags < 0)
            FAIL("F_GETFD on the directory fd failed");
        else
            EXPECT_TRUE((fd_flags & FD_CLOEXEC) == 0,
                        "directory fd came back with FD_CLOEXEC set");
        close(plain);
    }

    unlink(fixture_file);
    rmdir(fixture_dir);

    SUMMARY("test-dir-fd-budget");
    return fails ? 1 : 0;
}
