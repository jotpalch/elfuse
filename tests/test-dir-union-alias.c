/*
 * An aliased directory fd shares one listing position and one union
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dup(2) gives the alias the source's open file description, so the two guest
 * fds share one directory position: whatever one of them reads, the other does
 * not read again. Linux is unambiguous here -- measured in docker (gcc:14): an
 * unread source dup'd and then drained through the alias yields the whole
 * listing on the alias and nothing at all on the source.
 *
 * elfuse gave the alias a stream of its own over a duplicated descriptor. On a
 * plain directory that made the alias come back empty, because the duplicate
 * shares the file offset and the source's stream had already read the host
 * directory to its end. On a *union* directory -- a /sys name the USB layer
 * serves but does not own, whose listing is the synthetic entries followed by
 * the backing's -- it did something worse than empty: the alias's fresh stream
 * carried a fresh, undrained union state, so it skipped the synthetic half it
 * had no position for and then drained and emitted the backing half a second
 * time. The alias returned a plausible listing that was neither the whole one
 * nor the remainder.
 *
 * Every route to an alias is walked, because they are four spellings of one
 * operation and only one of them was ever exercised: dup, dup2, F_DUPFD and
 * F_DUPFD_CLOEXEC. Closing one alias mid-listing is walked too -- the shared
 * stream must outlive it and the survivor must deliver the remainder -- since
 * sharing an object is what makes premature release possible.
 *
 * fork(2) is the fifth route. The child receives the descriptor over
 * SCM_RIGHTS, so on Linux the position is shared for real: measured in docker
 * (gcc 14.4, Linux 6.19 aarch64) over this same sequence on a 403-name
 * directory, an unread fd forked and drained by the child gives the child all
 * 403 names and the parent 0, and the parent-drains-first order gives the
 * parent all 403 and the child 0. macOS shares the position too, but only as
 * far as the block boundary: fdopendir() reads one host block ahead into the
 * stream's own memory and leaves the description there, so the names already
 * buffered go to whoever buffered them and the rest of the directory is still
 * in the description for the other side to read. Over the 403-name plain
 * fixture below elfuse answers the unread fork with 354 names on the child and
 * 49 on the parent -- 49 being the block the parent's own open had already
 * taken -- a real split at a place Linux would not have split, and one that
 * adds up to the same 403.
 *
 * So what is asserted is the property, not an order and not a split: across the
 * pair, every name of the directory appears exactly once, and the pair's total
 * is the directory's. That is what Linux satisfies in every state, it is what a
 * shared position means, and it fails both ways -- on a name emitted twice and
 * on a name lost -- which is what the defect did on the two halves of the union
 * at once. The fork routes failed it for a second reason: a fork-restored fd
 * was given a fresh, undrained union state over a primary it also re-read, so
 * the child drained the backing and emitted names the parent still held.
 *
 * One fork state is not asserted, because this cannot deliver it: a parent that
 * closes its copy of the fd before the backing has been drained takes the
 * backing half with it, and the child answers with its primary alone. That row
 * is measured and printed as an XFAIL carrying both values -- Linux's and this
 * build's -- rather than left out of the lane; see case_fork_cross_close for
 * why it is recorded in both directions and what the two rows separate.
 *
 * Both fixtures are several hundred names wide, and that is load-bearing. An
 * earlier revision of this lane staged three names a side, and scored 22 of 22
 * on a build that loses a whole host block: at three names the whole listing
 * fits inside the one block the open reads ahead, so a stream that never
 * touches its primary has nothing left to lose. Measured on the fixtures this
 * lane stages, an unread fork: the 403-name plain directory comes back 403
 * across the pair here and 352 on that build -- 51 names gone, with no error --
 * and the 405-name union comes back 405 here and 809, with 404 of its names
 * delivered twice, on the build whose child drains the backing again. Those two
 * builds score 20 of 22 and 10 of 22 against this lane, and 22 of 22 against
 * the three-name one.
 *
 * Syscalls exercised: openat(56), dup(23), dup3(24), fcntl(25), clone(220),
 * getdents64(61), close(57)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Cases that neither passed nor failed: a measured divergence from Linux this
 * build knowingly keeps, printed with both values. Counted so the summary says
 * one is there instead of leaving a row that only reads as absent.
 */
static int xfails = 0;

/* The union root: a /sys the USB layer synthesizes and the sysroot also has.
 * Staged several hundred names wide on the sysroot side, so the backing half is
 * what dominates the listing and delivering it twice is unmissable.
 */
#define UNION_DIR "/sys"

/* A sysroot directory with nothing synthetic in it: the plain-directory case,
 * where the same sharing must hold for the same reason. Staged just as wide,
 * because this is the side where a lost host block shows and the union side is
 * where a repeated backing shows -- the two builds this lane separates are each
 * broken on only one of them.
 *
 * It sits outside /sys deliberately. A directory under /sys is only plain until
 * some later commit decides to synthesize a name in it, and this lane's whole
 * plain half then stops measuring what it says it measures: a stream whose
 * primary is synthetic hands a forked child nothing, so the fixture can no
 * longer split at a host block boundary and the row that needs the split
 * reports the fixture rather than the build. Outside /sys nothing in this layer
 * can claim it.
 */
#define PLAIN_DIR "/plain-alias"

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

/* Both fixtures are several hundred names wide on purpose -- see the header
 * comment -- so the capacity here has to clear that with room to spare, and has
 * to hold a listing delivered twice without silently clipping it back to the
 * right size. NAME_CAP is 64 because that is what one 64-byte getdents64 buffer
 * can carry in a single record, which is the widest name partial_read below can
 * ever be handed.
 */
#define MAX_NAMES 1024
#define NAME_CAP 64
#define MAX_CALLS 256

/* The listing must be wider than one host directory block, or the whole class
 * of defect this lane exists for is invisible. Measured on this fixture (macOS
 * 15.6, APFS, elfuse over a 403-name sysroot directory): the open reads 49 of
 * the 403 names ahead, so a stream that skips its primary loses 51 names and a
 * three-name fixture loses none. The floor is set below the fixture's width
 * rather than at it, so adding a name to the staging does not fail the lane,
 * and far above one block, so removing the width does.
 */
#define MIN_REFERENCE_NAMES 300

typedef struct {
    char name[MAX_NAMES][NAME_CAP];
    int count;
    bool overflow;
} names_t;

static void names_add(names_t *ns, const char *name)
{
    if (ns->count >= MAX_NAMES) {
        ns->overflow = true;
        return;
    }
    snprintf(ns->name[ns->count++], NAME_CAP, "%s", name);
}

static int names_count_of(const names_t *ns, const char *name)
{
    int n = 0;
    for (int i = 0; i < ns->count; i++)
        if (!strcmp(ns->name[i], name))
            n++;
    return n;
}

/* Append one getdents64 call's worth of names. The buffer is the size handed to
 * the syscall, and every record is bounds-checked before its name is read.
 *
 * Returns the call's return value.
 */
static long drain_call(int fd, size_t bufsz, names_t *ns, bool *malformed)
{
    char buf[4096];
    if (bufsz > sizeof(buf)) {
        *malformed = true;
        return -1;
    }
    errno = 0;
    long n = syscall(SYS_getdents64, fd, buf, bufsz);
    if (n <= 0)
        return n;
    const long header = (long) offsetof(linux_dirent64_t, d_name);
    for (long off = 0; off < n;) {
        if (n - off < header) {
            *malformed = true;
            return n;
        }
        linux_dirent64_t *de = (linux_dirent64_t *) (buf + off);
        long reclen = de->d_reclen;
        if (reclen <= header || reclen > n - off) {
            *malformed = true;
            return n;
        }
        if (!memchr(de->d_name, '\0', (size_t) (reclen - header))) {
            *malformed = true;
            return n;
        }
        names_add(ns, de->d_name);
        off += reclen;
    }
    return n;
}

/* Read fd to the end, appending every name. */
static bool drain(int fd, names_t *ns)
{
    bool malformed = false;
    for (int calls = 0; calls <= MAX_CALLS; calls++) {
        long n = drain_call(fd, 4096, ns, &malformed);
        if (malformed)
            return false;
        if (n < 0)
            return false;
        if (n == 0)
            return true;
    }
    return false;
}

/* Every name of @want appears exactly once in @got, and @got holds nothing
 * else. Order is never consulted.
 *
 * The total across the pair is checked first and reported whether or not it is
 * the thing that broke, because it is the one number that catches both halves
 * of the defect at once and the one number a narrow fixture cannot show: a
 * listing that loses a host block and a listing that delivers the backing twice
 * are both a wrong total, and at three names neither is. The per-name counts
 * follow, and say which names, so a total that is right by cancellation -- a
 * name lost and another duplicated -- is still caught.
 *
 * At several hundred names a single offending name is not a useful report, so
 * the counts are summarized and one example of each kind is named.
 */
static bool same_names_once(const names_t *want,
                            const names_t *got,
                            char *why,
                            size_t whysz)
{
    if (want->overflow || got->overflow) {
        snprintf(why, whysz, "listing larger than the test's capacity");
        return false;
    }

    int lost = 0, twice = 0, foreign = 0;
    const char *lost_eg = NULL, *twice_eg = NULL, *foreign_eg = NULL;
    for (int i = 0; i < want->count; i++) {
        int n = names_count_of(got, want->name[i]);
        if (n == 0) {
            lost++;
            if (!lost_eg)
                lost_eg = want->name[i];
        } else if (n > 1) {
            twice++;
            if (!twice_eg)
                twice_eg = want->name[i];
        }
    }
    for (int i = 0; i < got->count; i++) {
        if (names_count_of(want, got->name[i]) == 0) {
            foreign++;
            if (!foreign_eg)
                foreign_eg = got->name[i];
        }
    }

    if (!lost && !twice && !foreign && got->count == want->count)
        return true;

    snprintf(why, whysz,
             "%d names across the pair, want %d: %d lost (%s), %d delivered "
             "more than once (%s), %d not in the directory at all (%s)",
             got->count, want->count, lost, lost_eg ? lost_eg : "-", twice,
             twice_eg ? twice_eg : "-", foreign, foreign_eg ? foreign_eg : "-");
    return false;
}

/* The listing a single untouched fd delivers: the reference every case below is
 * compared against.
 */
static bool reference(const char *dir, names_t *ns)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return false;
    bool ok = drain(fd, ns);
    close(fd);
    return ok;
}

/* The routes an alias can arrive by. Each is the same operation -- a second
 * guest fd on one open file description -- and the lane walks all of them
 * because only dup() was ever walked before.
 */
typedef enum {
    ROUTE_DUP,
    ROUTE_DUP2,
    ROUTE_DUPFD,
    ROUTE_DUPFD_CLOEXEC,
    ROUTE_FORK,
} route_t;

/* Slots dup2/F_DUPFD are aimed at, chosen high enough that the harness's own
 * descriptors cannot be sitting in them.
 */
#define DUP2_SLOT 40
#define DUPFD_FLOOR 50

static int make_alias(route_t route, int src)
{
    switch (route) {
    case ROUTE_DUP:
        return dup(src);
    case ROUTE_DUP2:
        return dup2(src, DUP2_SLOT);
    case ROUTE_DUPFD:
        return fcntl(src, F_DUPFD, DUPFD_FLOOR);
    case ROUTE_DUPFD_CLOEXEC:
        return fcntl(src, F_DUPFD_CLOEXEC, DUPFD_FLOOR);
    default:
        errno = EINVAL;
        return -1;
    }
}

/* Read one small call off @src so the source has consumed part of the listing
 * and no more. A 64-byte buffer holds a name of up to 44 bytes; nothing in the
 * fixture is close to that, so a short call here is a real partial read rather
 * than the entry-too-large refusal.
 *
 * Returns false when the partial read delivered nothing to continue from.
 */
static bool partial_read(int src, names_t *ns)
{
    bool malformed = false;
    int before = ns->count;
    long first = drain_call(src, 64, ns, &malformed);
    return !malformed && first > 0 && ns->count > before;
}

/* The child half of the fork route: drain the inherited fd and report the names
 * back one per line, then a status line the parent reads as the walk's verdict.
 *
 * Written with write(2) rather than stdio because the child leaves through
 * _exit and an unflushed buffer would report an empty listing as a real one.
 */
static void fork_child_report(int src, int out, int gate)
    __attribute__((noreturn));
static void fork_child_report(int src, int out, int gate)
{
    /* When a gate is given, the case being walked is one whose state the parent
     * establishes after the fork, so the child must not read before it is told.
     * A byte on the gate is that permission; a closed gate (EOF) means the
     * parent gave up, and the child reads anyway rather than hanging.
     */
    if (gate >= 0) {
        char go;
        read(gate, &go, 1);
        close(gate);
    }

    names_t got = {0};
    bool ok = drain(src, &got);
    for (int i = 0; i < got.count; i++) {
        dprintf(out, "%s\n", got.name[i]);
    }
    dprintf(out, "%s\n", ok && !got.overflow ? "#ok" : "#broke");
    _exit(0);
}

/* Collect the child's report into @ns.
 *
 * Returns false if the child's own walk did not end on a well-formed stream, or
 * said nothing at all.
 */
static bool fork_collect(int in, names_t *ns)
{
    FILE *f = fdopen(in, "r");
    if (!f) {
        close(in);
        return false;
    }
    char line[NAME_CAP + 8];
    bool verdict = false, spoke = false;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (!strcmp(line, "#ok")) {
            verdict = true;
            spoke = true;
            continue;
        }
        if (!strcmp(line, "#broke")) {
            spoke = true;
            continue;
        }
        names_add(ns, line);
    }
    fclose(f);
    return spoke && verdict;
}

/* One case: put @src in the state @half_read asks for, alias it by @route, and
 * check that the pair together delivers the directory once.
 *
 * The two sides are drained in a fixed order -- alias (or child) first, then
 * source -- because a shared position makes the order irrelevant to what the
 * pair delivers, which is the whole claim.
 */
static void case_alias(const char *dir,
                       route_t route,
                       bool half_read,
                       const char *what)
{
    TEST(what);
    names_t ref = {0};
    if (!reference(dir, &ref)) {
        FAIL("could not read the reference listing");
        return;
    }
    if (ref.count < MIN_REFERENCE_NAMES) {
        fprintf(stderr, "  %d names, want at least %d\n", ref.count,
                MIN_REFERENCE_NAMES);
        FAIL("the fixture is too narrow to show a lost host block");
        return;
    }

    int src = open(dir, O_RDONLY | O_DIRECTORY);
    if (src < 0) {
        FAIL("could not open the directory");
        return;
    }

    names_t got = {0};
    if (half_read && !partial_read(src, &got)) {
        close(src);
        FAIL("the partial read delivered nothing to continue from");
        return;
    }

    bool ok;
    if (route == ROUTE_FORK) {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            close(src);
            FAIL("could not open the pipe the child reports over");
            return;
        }
        pid_t child = fork();
        if (child < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            close(src);
            FAIL("could not fork");
            return;
        }
        if (child == 0) {
            close(pipefd[0]);
            fork_child_report(src, pipefd[1], -1);
        }
        close(pipefd[1]);
        bool child_ok = fork_collect(pipefd[0], &got);
        int status = 0;
        waitpid(child, &status, 0);
        ok = child_ok && drain(src, &got);
        close(src);
    } else {
        int alias = make_alias(route, src);
        if (alias < 0) {
            close(src);
            FAIL("could not alias the directory fd");
            return;
        }
        ok = drain(alias, &got) && drain(src, &got);
        close(alias);
        close(src);
    }

    if (!ok) {
        FAIL("a walk over the pair did not end on a well-formed stream");
        return;
    }

    char why[192];
    if (same_names_once(&ref, &got, why, sizeof(why))) {
        PASS();
    } else {
        fprintf(stderr, "  %s\n", why);
        FAIL("the pair did not deliver the directory exactly once");
    }
}

/* Closing one alias must not disturb the other. The two guest fds share one
 * refcounted stream, so a close that took the stream down with it would leave
 * the survivor walking freed memory -- or, if the close simply dropped the
 * union state, restart the survivor's listing. What is asserted is the same
 * property: the survivor delivers the remainder and the pair adds up once.
 */
static void case_cross_close(const char *dir, const char *what)
{
    TEST(what);
    names_t ref = {0};
    if (!reference(dir, &ref)) {
        FAIL("could not read the reference listing");
        return;
    }
    if (ref.count < MIN_REFERENCE_NAMES) {
        fprintf(stderr, "  %d names, want at least %d\n", ref.count,
                MIN_REFERENCE_NAMES);
        FAIL("the fixture is too narrow to show a lost host block");
        return;
    }

    int src = open(dir, O_RDONLY | O_DIRECTORY);
    if (src < 0) {
        FAIL("could not open the directory");
        return;
    }
    int alias = dup(src);
    if (alias < 0) {
        close(src);
        FAIL("could not dup the directory fd");
        return;
    }

    names_t got = {0};
    if (!partial_read(alias, &got)) {
        close(alias);
        close(src);
        FAIL("the alias's partial read delivered nothing to continue from");
        return;
    }
    close(alias); /* the alias goes away mid-listing */

    bool ok = drain(src, &got);
    close(src);
    if (!ok) {
        FAIL("the source did not survive the alias's close");
        return;
    }

    char why[192];
    if (same_names_once(&ref, &got, why, sizeof(why))) {
        PASS();
    } else {
        fprintf(stderr, "  %s\n", why);
        FAIL("the surviving fd did not continue the shared listing");
    }
}

/* The one state this cannot deliver whole, recorded rather than asserted.
 *
 * A child whose parent closes its copy of the fd before either side has drained
 * the backing answers with its primary alone: the backing half belongs to the
 * parent's stream (see dir_stream_open_inherited in src/syscall/internal.h) and
 * that stream is gone, while the block the parent's own open() read ahead went
 * with it. Linux keeps position and listing in the open file description, so
 * the close costs the child nothing and it reads the directory whole.
 *
 * It is reported the way tests/usb-sysfs-matrix-vectors.h reports its
 * escape-syn column: the measured Linux value is carried here as data and
 * printed as an XFAIL beside what elfuse answers, rather than deleted from the
 * lane. So a change in either direction shows up as a diff in the lane's output
 * -- a child that started draining its own backing would move the elfuse number
 * up, a widening loss would move it down -- while neither counts as a pass nor
 * turns the lane red. The value elfuse gives today is carried too, and a
 * departure from it is called out on the same line; nothing else in this lane
 * holds that side.
 *
 * Both rows are load-bearing, because neither number alone separates the three
 * answers. Measured here by putting each of the other two back at the one site
 * that chooses between them, dir_stream_open_inherited: with the child allowed
 * to drain a backing of its own -- what 54cd91e does -- the plain row still
 * reads 354 and the union row moves to 404; with the child's stream handed back
 * already at the end of its listing -- what 27ee83a does -- the union row still
 * reads 0 and the plain row moves to 0. So the pair, plain 354 with union 0, is
 * this build's answer and neither other's, and the two rows together pin the
 * middle course between delivering the backing twice and delivering nothing.
 *
 * Linux side measured in docker (gcc 14.4, Linux 6.19 aarch64) over this same
 * sequence on directories staged with this lane's two widths: the child gets
 * all 403 names of the plain fixture and all 405 of the union's. elfuse side
 * measured on macOS 15.6, APFS.
 */
static void case_fork_cross_close(const char *dir,
                                  int linux_names,
                                  int recorded,
                                  const char *what)
{
    TEST(what);
    names_t ref = {0};
    if (!reference(dir, &ref)) {
        FAIL("could not read the reference listing");
        return;
    }
    if (ref.count < MIN_REFERENCE_NAMES) {
        fprintf(stderr, "  %d names, want at least %d\n", ref.count,
                MIN_REFERENCE_NAMES);
        FAIL("the fixture is too narrow to show a lost host block");
        return;
    }

    int src = open(dir, O_RDONLY | O_DIRECTORY);
    if (src < 0) {
        FAIL("could not open the directory");
        return;
    }
    int pipefd[2], gate[2];
    if (pipe(pipefd) < 0) {
        close(src);
        FAIL("could not open the pipe the child reports over");
        return;
    }
    if (pipe(gate) < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        close(src);
        FAIL("could not open the gate the child waits on");
        return;
    }
    pid_t child = fork();
    if (child < 0) {
        close(gate[0]);
        close(gate[1]);
        close(pipefd[0]);
        close(pipefd[1]);
        close(src);
        FAIL("could not fork");
        return;
    }
    if (child == 0) {
        close(pipefd[0]);
        close(gate[1]);
        fork_child_report(src, pipefd[1], gate[0]);
    }
    close(pipefd[1]);
    close(gate[0]);

    /* The state being measured: the parent's copy is gone before the child has
     * read anything, and the gate is what makes that an order rather than a
     * race.
     */
    close(src);
    ssize_t told = write(gate[1], "g", 1);
    close(gate[1]);

    names_t got = {0};
    bool child_ok = fork_collect(pipefd[0], &got);
    int status = 0;
    waitpid(child, &status, 0);
    if (told != 1 || !child_ok || got.overflow) {
        FAIL("the child's walk did not end on a well-formed stream");
        return;
    }

    xfails++;
    printf("XFAIL: Linux %d, elfuse %d%s\n", linux_names, got.count,
           got.count == recorded ? "" : " -- the recorded value moved");
    if (got.count != recorded)
        fprintf(stderr, "  recorded %d, now %d\n", recorded, got.count);
}

/* Two aliases inside the child, which is the dimension every case above misses:
 * they all put the second fd on one side of the fork or the other, and this one
 * carries a pair of aliases across it together.
 *
 * The parent opens the directory and dups it, so both descriptors name one open
 * file description before the fork. The child inherits both. Nothing about
 * elfuse's fork rebuild makes that pair share a wrapper on its own -- each
 * inherited descriptor arrives over SCM_RIGHTS on its own, and building a
 * stream for each gives the child two locks, two DIR* read-ahead buffers and
 * two positions over one description -- so the child's second alias came back
 * holding names the first had never delivered, and the first had ended at a
 * clean 0 before them.
 *
 * What is asserted is the alias property, not a count: after the child has
 * drained the first alias to its end, the second delivers nothing, and no name
 * arrives twice. Both halves hold on Linux for any pair of fds on one
 * description, so neither needs measuring; the count the child reaches is the
 * inherited-stream loss the fork cross-close row already records, and is
 * deliberately not asserted here.
 *
 * The plain fixture only. The union fixture's child answers with nothing at all
 * (see case_fork_cross_close), so both halves would hold vacuously there.
 */
static void case_child_aliases(const char *dir, const char *what)
{
    TEST(what);
    int src = open(dir, O_RDONLY | O_DIRECTORY);
    if (src < 0) {
        FAIL("could not open the directory");
        return;
    }
    int alias = dup(src);
    if (alias < 0) {
        close(src);
        FAIL("could not dup the directory fd");
        return;
    }
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        close(alias);
        close(src);
        FAIL("could not open the pipe the child reports over");
        return;
    }
    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        close(alias);
        close(src);
        FAIL("could not fork");
        return;
    }
    if (child == 0) {
        close(pipefd[0]);

        /* First alias to its end, then the second. The marker between them is
         * what lets the parent tell which side a name came from; a name after
         * it is a name the first alias's end-of-listing had already denied.
         */
        names_t first = {0}, second = {0};
        bool ok = drain(src, &first);
        ok = drain(alias, &second) && ok;
        for (int i = 0; i < first.count; i++)
            dprintf(pipefd[1], "%s\n", first.name[i]);
        dprintf(pipefd[1], "#split\n");
        for (int i = 0; i < second.count; i++)
            dprintf(pipefd[1], "%s\n", second.name[i]);
        dprintf(pipefd[1], "%s\n",
                ok && !first.overflow && !second.overflow ? "#ok" : "#broke");
        _exit(0);
    }
    close(pipefd[1]);

    /* The parent's copies go away: it never reads, and holding them would leave
     * the child's answer depending on when they closed.
     */
    close(alias);
    close(src);

    names_t first = {0}, second = {0};
    FILE *f = fdopen(pipefd[0], "r");
    if (!f) {
        close(pipefd[0]);
        FAIL("could not read the child's report");
        return;
    }
    char line[NAME_CAP + 8];
    bool split = false, verdict = false, spoke = false;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (!strcmp(line, "#split")) {
            split = true;
            continue;
        }
        if (!strcmp(line, "#ok")) {
            verdict = true;
            spoke = true;
            continue;
        }
        if (!strcmp(line, "#broke")) {
            spoke = true;
            continue;
        }
        names_add(split ? &second : &first, line);
    }
    fclose(f);
    int status = 0;
    waitpid(child, &status, 0);

    if (!spoke || !verdict || !split || first.overflow || second.overflow) {
        FAIL("the child's walk over the pair did not end well-formed");
        return;
    }
    if (first.count < MIN_REFERENCE_NAMES) {
        fprintf(stderr, "  the child's first alias delivered %d names\n",
                first.count);
        FAIL("the fixture is too narrow to split at a host block boundary");
        return;
    }

    const char *twice = NULL;
    for (int i = 0; i < second.count && !twice; i++)
        if (names_count_of(&first, second.name[i]))
            twice = second.name[i];
    if (second.count) {
        fprintf(stderr,
                "  the first alias ended at 0 with %d names, then the second "
                "delivered %d more (%s%s)\n",
                first.count, second.count, second.name[0],
                twice ? ", and repeated one" : "");
        FAIL("the child's two aliases split one listing between them");
    } else {
        PASS();
    }
}

typedef struct {
    route_t route;
    const char *name;
} route_desc_t;

static const route_desc_t routes[] = {
    {ROUTE_DUP, "dup"},       {ROUTE_DUP2, "dup2"},
    {ROUTE_DUPFD, "F_DUPFD"}, {ROUTE_DUPFD_CLOEXEC, "F_DUPFD_CLOEXEC"},
    {ROUTE_FORK, "fork"},
};

static void run_dir(const char *dir,
                    const char *kind,
                    int linux_names,
                    int recorded)
{
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        char what[64];
        snprintf(what, sizeof(what), "%s %s unread", kind, routes[i].name);
        case_alias(dir, routes[i].route, false, what);
        snprintf(what, sizeof(what), "%s %s part-read", kind, routes[i].name);
        case_alias(dir, routes[i].route, true, what);
    }
    char what[64];
    snprintf(what, sizeof(what), "%s cross-close", kind);
    case_cross_close(dir, what);
    snprintf(what, sizeof(what), "%s fork cross-close", kind);
    case_fork_cross_close(dir, linux_names, recorded, what);
}

int main(void)
{
    printf(
        "test-dir-union-alias: an alias shares one position and one union\n\n");

    /* The two numbers each row carries: what Linux answers, and what this build
     * answers. Both measured -- see case_fork_cross_close.
     */
    run_dir(PLAIN_DIR, "plain", 403, 354);
    run_dir(UNION_DIR, "union", 405, 0);
    case_child_aliases(PLAIN_DIR, "plain two aliases inside the child");

    SUMMARY("test-dir-union-alias");
    if (xfails)
        printf(
            "%d expected failure%s printed above, neither passed nor "
            "failed\n",
            xfails, xfails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}
