/*
 * Relative and dirfd-relative names in a sysroot
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A guest names the same file two ways: absolutely, and relative to its working
 * directory or to a directory descriptor. Both must reach the same file. That
 * is not automatic here, because a name whose spelling the volume cannot hold
 * is stored escaped, so the translation has to run whichever way the guest
 * spelled it, and for a relative name there is no leading component to key on,
 * only the descriptor it is resolved against.
 *
 * This matters well beyond a shell doing cd: fts, find, git and rsync walk
 * trees with openat(dirfd, name) throughout, and never build an absolute path
 * at all.
 *
 * Code under test: src/syscall/casefold-walk.c and the byte-exact resolver
 * beside it in src/syscall/proc-state.c, both reached from src/syscall/path.c's
 * path_translate_at, for the case where the guest path does not begin with '/'.
 * A regression shows up as the same guest name resolving to two different files
 * depending on how it was spelled, so a create through one spelling is
 * invisible through the other, and an O_EXCL create of a name that already
 * exists succeeds instead of reporting EEXIST.
 *
 * Run under --sysroot.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define DIR_V "/name-relative"

/* Every fixture name needs escaping, so a spelling that skips the translation
 * lands somewhere different and the mismatch is visible.
 */
#define NAME_A "Alpha.One"
#define NAME_B "Beta.Two"
#define NAME_C "Gamma.Three"

/* Outside the sysroot the guest is looking at the real host filesystem, where
 * elfuse owns nothing and must store names exactly as given. An absolute path
 * that falls through already does; a relative one has to agree, or the same
 * file has two spellings depending on how it was named and elfuse leaves
 * escaped names in directories that are not its own.
 *
 * argv[1] is a directory outside the sysroot, staged by the recipe, which also
 * checks the on-disk half afterwards.
 */
static void section_outside_sysroot(const char *host_dir)
{
    char abs[PATH_MAX];

    /* Visible, so a manual run without the recipe's host fixture reads as fewer
     * tests run, not as the section passing.
     */
    if (!host_dir || !host_dir[0]) {
        printf("  (outside-sysroot section skipped: no host dir given)\n");
        return;
    }

    TEST("chdir to a directory outside the sysroot");
    EXPECT_TRUE(chdir(host_dir) == 0, "chdir");

    TEST("create a mixed-case name there through a relative path");
    EXPECT_TRUE(file_write_at(AT_FDCWD, "Outside.Rel", "rel") == 0, "create");

    TEST("create a mixed-case name there through an absolute path");
    snprintf(abs, sizeof(abs), "%s/Outside.Abs", host_dir);
    EXPECT_TRUE(file_write_at(AT_FDCWD, abs, "abs") == 0, "create");

    /* Both spellings must reach both files: nothing was translated, so a
     * relative and an absolute name of the same file are the same name.
     */
    TEST("the relative-created name opens absolutely");
    snprintf(abs, sizeof(abs), "%s/Outside.Rel", host_dir);
    EXPECT_TRUE(file_content_at_is(AT_FDCWD, abs, "rel") == 0, "content");

    TEST("the absolute-created name opens relatively");
    EXPECT_TRUE(file_content_at_is(AT_FDCWD, "Outside.Abs", "abs") == 0,
                "content");

    TEST("chdir back to the sysroot root");
    EXPECT_TRUE(chdir("/") == 0, "chdir");
}

/* openat2(RESOLVE_NO_SYMLINKS) is answered by a second walker, which refuses
 * the open if any component is a symlink. That walker resolves the whole path
 * itself, so it has to spell each component the way the volume stores it,
 * exactly as the translation above does. Two walkers that disagree give a guest
 * two different answers for one path: here the file resolves through openat but
 * not through openat2, which reports ENOENT for a file that is plainly there.
 *
 * Every fixture name needs escaping, so a walker still using the guest spelling
 * finds nothing and the disagreement is visible rather than incidental.
 */
static void section_openat2_no_symlinks(int dirfd)
{
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_SYMLINKS};
    long fd;

    TEST("openat2 RESOLVE_NO_SYMLINKS opens through an escaped component");
    errno = 0;
    fd = syscall(SYS_openat2, dirfd, "Walk.Dir/Leaf.File", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        PASS();
    } else {
        FAIL("a walker other than the translation missed the escaped name");
    }

    /* The refusal itself must still work, or the fix would have bought the open
     * by disabling the check it exists for.
     */

    /* RESOLVE_NO_XDEV is answered by a third walker, which probes each
     * component to see whether a symlink moves the path onto another mount. It
     * probes by name too, so it has the same requirement. Only detection
     * matters here, not where the link points, so the target need not resolve.
     */
    TEST("openat2 RESOLVE_NO_XDEV sees a symlink under an escaped name");
    {
        struct open_how xdev = {
            .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
        long x;

        errno = 0;
        x = syscall(SYS_openat2, dirfd, "Cross.Link/self", &xdev, sizeof(xdev));
        if (x >= 0) {
            close((int) x);
            FAIL("a mount crossing through an escaped symlink went unnoticed");
        } else {
            EXPECT_ERRNO((int) x, EXDEV, "should report a mount crossing");
        }
    }

    TEST("openat2 RESOLVE_NO_SYMLINKS still refuses a symlink component");
    errno = 0;
    fd = syscall(SYS_openat2, dirfd, "Walk.Link/leaf", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("a symlink component was traversed");
    } else {
        EXPECT_ERRNO((int) fd, ELOOP, "should refuse the symlink");
    }

    /* The walker sees host spellings, and an escape is longer than the name it
     * stands for: past the guest limit once the name passes 125 bytes. A walker
     * sized to the guest limit refuses those components with ENAMETOOLONG for a
     * file openat opens without complaint, which is the two-answers
     * disagreement again, in a length rather than a spelling.
     */
    TEST("openat2 RESOLVE_NO_SYMLINKS opens a 126-byte escaped name");
    {
        char longname[256];

        memset(longname, 'Q', 126);
        longname[126] = '\0';
        if (file_write_at(dirfd, longname, "long") != 0) {
            FAIL("create");
        } else {
            errno = 0;
            fd = syscall(SYS_openat2, dirfd, longname, &how, sizeof(how));
            if (fd >= 0) {
                close((int) fd);
                PASS();
            } else {
                FAIL("a walker refused a name Linux allows");
            }
        }

        TEST("openat2 RESOLVE_NO_SYMLINKS opens a 255-byte escaped name");
        memset(longname, 'Q', 255);
        longname[255] = '\0';
        if (file_write_at(dirfd, longname, "long") != 0) {
            FAIL("create");
        } else {
            errno = 0;
            fd = syscall(SYS_openat2, dirfd, longname, &how, sizeof(how));
            if (fd >= 0) {
                close((int) fd);
                PASS();
            } else {
                FAIL("a walker refused a name Linux allows");
            }
        }
    }
}

/* A trailing separator asserts the target is a directory, so "file/" owes
 * ENOTDIR (POSIX 4.13, path_resolution(7)). The component walk skips
 * separators, so by the time a host path is built the assertion is gone unless
 * something puts it back, and it goes missing for an escaped name and a
 * fold-stable one alike, so both are checked. A regression reads as open("f/")
 * succeeding on a regular file, which no Linux program expects and which turns
 * a caller's directory check into a silent success.
 */
static void section_trailing_slash(void)
{
    char path[PATH_MAX];
    int fd;

    TEST("stage a file and a directory whose names need escaping");
    EXPECT_TRUE(file_write_at(AT_FDCWD, DIR_V "/Slash.File", "f") == 0 &&
                    (mkdir(DIR_V "/Slash.Dir", 0755) == 0 || errno == EEXIST) &&
                    file_write_at(AT_FDCWD, DIR_V "/slashfile", "g") == 0,
                "stage");

    TEST("open of an escaped file with a trailing slash is ENOTDIR");
    snprintf(path, sizeof(path), "%s/Slash.File/", DIR_V);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        FAIL("a regular file opened as a directory");
    } else {
        EXPECT_ERRNO(fd, ENOTDIR, "should be ENOTDIR");
    }

    TEST("stat of an escaped file with a trailing slash is ENOTDIR");
    {
        struct stat st;
        snprintf(path, sizeof(path), "%s/Slash.File/", DIR_V);
        EXPECT_ERRNO(stat(path, &st), ENOTDIR, "should be ENOTDIR");
    }

    /* The same for a name stored literally, so the fix is not one that only
     * works where an escape happens to be built.
     */
    TEST("open of a fold-stable file with a trailing slash is ENOTDIR");
    snprintf(path, sizeof(path), "%s/slashfile/", DIR_V);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        FAIL("a regular file opened as a directory");
    } else {
        EXPECT_ERRNO(fd, ENOTDIR, "should be ENOTDIR");
    }

    /* And the assertion must not reject what it is supposed to allow. */
    TEST("a directory with a trailing slash still resolves");
    {
        struct stat st;
        snprintf(path, sizeof(path), "%s/Slash.Dir/", DIR_V);
        EXPECT_TRUE(stat(path, &st) == 0 && S_ISDIR(st.st_mode), "should open");
    }

    TEST("the root with a trailing slash still resolves");
    {
        struct stat st;
        EXPECT_TRUE(stat("/", &st) == 0 && S_ISDIR(st.st_mode), "root");
    }
}

/* Resolution stops at the first component that is not a directory, and every
 * operation naming something below it owes ENOTDIR (path_resolution(7)). The
 * trailing-slash section above pins the same rule where the non-directory is
 * the final component; here it is an ancestor, which is the form that decides
 * whether the sysroot has answered at all. Reporting ENOENT instead sends the
 * lookup on to the host, where an unrelated file sharing the literal path
 * answers in the sysroot's place, so the wrong errno and a wrong file are the
 * same regression. A fold-stable name and an escaped one are both checked,
 * because the two take different spellings on disk and the rule has to survive
 * either.
 */
static void section_below_non_directory_at(void);

static void section_below_non_directory(void)
{
    char path[PATH_MAX];
    struct stat st;

    TEST("stage regular files to resolve below");
    EXPECT_TRUE(file_write_at(AT_FDCWD, DIR_V "/notdirfile", "f") == 0 &&
                    file_write_at(AT_FDCWD, DIR_V "/Not.Dir.File", "g") == 0,
                "stage");

    TEST("stat below a fold-stable regular file is ENOTDIR");
    snprintf(path, sizeof(path), "%s/notdirfile/below", DIR_V);
    EXPECT_ERRNO(stat(path, &st), ENOTDIR, "should be ENOTDIR");

    TEST("lstat below a fold-stable regular file is ENOTDIR");
    EXPECT_ERRNO(lstat(path, &st), ENOTDIR, "should be ENOTDIR");

    TEST("open below a fold-stable regular file is ENOTDIR");
    EXPECT_ERRNO(open(path, O_RDONLY), ENOTDIR, "should be ENOTDIR");

    TEST("stat below an escaped regular file is ENOTDIR");
    snprintf(path, sizeof(path), "%s/Not.Dir.File/below", DIR_V);
    EXPECT_ERRNO(stat(path, &st), ENOTDIR, "should be ENOTDIR");

    TEST("open below an escaped regular file is ENOTDIR");
    EXPECT_ERRNO(open(path, O_RDONLY), ENOTDIR, "should be ENOTDIR");

    /* Two components below, so the rule cannot depend on the leaf's parent
     * being the offending entry.
     */
    TEST("stat two components below a regular file is ENOTDIR");
    snprintf(path, sizeof(path), "%s/notdirfile/a/b", DIR_V);
    EXPECT_ERRNO(stat(path, &st), ENOTDIR, "should be ENOTDIR");

    /* The rule must not swallow a plain absent path, which still owes ENOENT.
     * The two answers come from different findings -- ENOTDIR from a component
     * that exists and is not a directory, ENOENT from one that does not exist
     * at all -- so a resolver that cannot report which of the two it stopped on
     * gives one answer for the other. Every case below was measured on Linux
     * 6.19 (docker gcc:14) rather than reasoned from the rule.
     *
     * The absent arm is the one that fails dangerously, because the wrong errno
     * is not the whole of it. A walk that gives up on an absent component and
     * reports no spelling for where it stopped leaves the caller deciding from
     * an unset one, and the syscall then answers for a path the guest never
     * named: this suite caught it succeeding, and describing the sysroot root,
     * for a name nothing holds. errno is cleared first for that reason -- a
     * call that returns 0 leaves the previous assertion's errno behind, and the
     * failure then reads as the wrong errno rather than as no failure at all.
     */
    TEST("an absent path below a real directory is still ENOENT");
    snprintf(path, sizeof(path), "%s/absent-dir/below", DIR_V);
    errno = 0;
    EXPECT_ERRNO(stat(path, &st), ENOENT, "should be ENOENT");

    TEST("open of an absent path below a real directory is ENOENT");
    errno = 0;
    EXPECT_ERRNO(open(path, O_RDONLY), ENOENT, "should be ENOENT");

    TEST("the absent component named on its own is ENOENT");
    snprintf(path, sizeof(path), "%s/absent-dir", DIR_V);
    errno = 0;
    EXPECT_ERRNO(stat(path, &st), ENOENT, "should be ENOENT");

    /* A trailing slash turns the leaf into a directory reference, which is what
     * flips the answer to ENOTDIR when the leaf exists as a file. It must not
     * flip anything when nothing on the path exists.
     */
    TEST("an absent path with a trailing slash is ENOENT");
    snprintf(path, sizeof(path), "%s/absent-dir/below/", DIR_V);
    errno = 0;
    EXPECT_ERRNO(stat(path, &st), ENOENT, "should be ENOENT");

    TEST("two absent components deep is still ENOENT");
    snprintf(path, sizeof(path), "%s/absent-dir/absent-two/below", DIR_V);
    errno = 0;
    EXPECT_ERRNO(stat(path, &st), ENOENT, "should be ENOENT");

    section_below_non_directory_at();
}

/* The same split addressed through a descriptor rather than a path. Linux
 * refuses a relative name against an O_PATH descriptor on a regular file with
 * ENOTDIR before it looks the name up, while a descriptor on a real directory
 * still owes ENOENT for a name that directory does not hold -- so neither
 * answer can be derived from the other, and a rule that decides the first one
 * early must not reach the second. Measured on Linux 6.19 alongside the path
 * cases above.
 */
static void section_below_non_directory_at(void)
{
    struct stat st;
    int filefd, dirfd;

    TEST("O_PATH opens the regular file itself");
    filefd = open(DIR_V "/notdirfile", O_PATH);
    EXPECT_TRUE(filefd >= 0, "O_PATH open");

    TEST("openat below an O_PATH regular file is ENOTDIR");
    errno = 0;
    EXPECT_ERRNO(openat(filefd, "below", O_RDONLY), ENOTDIR,
                 "should be ENOTDIR");

    TEST("fstatat below an O_PATH regular file is ENOTDIR");
    errno = 0;
    EXPECT_ERRNO(fstatat(filefd, "below", &st, 0), ENOTDIR,
                 "should be ENOTDIR");

    /* AT_EMPTY_PATH names the descriptor itself, not a child, so the rule above
     * must not reach it.
     */
    TEST("fstatat of the O_PATH file itself still reports the file");
    EXPECT_TRUE(
        fstatat(filefd, "", &st, AT_EMPTY_PATH) == 0 && S_ISREG(st.st_mode),
        "AT_EMPTY_PATH");
    close(filefd);

    TEST("O_PATH opens the real directory");
    dirfd = open(DIR_V, O_PATH);
    EXPECT_TRUE(dirfd >= 0, "O_PATH open");

    TEST("an absent name under an O_PATH directory is ENOENT");
    errno = 0;
    EXPECT_ERRNO(fstatat(dirfd, "absent-dir/below", &st, 0), ENOENT,
                 "should be ENOENT");

    TEST("openat an absent name under an O_PATH directory is ENOENT");
    errno = 0;
    EXPECT_ERRNO(openat(dirfd, "absent-dir/below", O_RDONLY), ENOENT,
                 "should be ENOENT");
    close(dirfd);
}

int main(int argc, char **argv)
{
    char abs[PATH_MAX];
    int dirfd;

    TEST("fixture mkdir");
    EXPECT_TRUE(mkdir(DIR_V, 0755) == 0 || errno == EEXIST, "mkdir");

    /* Created absolutely, reopened relatively. */
    snprintf(abs, sizeof(abs), "%s/%s", DIR_V, NAME_A);
    TEST("create through an absolute path");
    EXPECT_TRUE(file_write_at(AT_FDCWD, abs, "abs") == 0, "create");

    TEST("chdir into the directory");
    EXPECT_TRUE(chdir(DIR_V) == 0, "chdir");

    TEST("the same file opens through a cwd-relative name");
    EXPECT_TRUE(file_content_at_is(AT_FDCWD, NAME_A, "abs") == 0,
                "relative spelling reached a different file");

    /* An O_EXCL create of a name that already exists must fail, whichever way
     * it is spelled. If the relative spelling skips the translation it lands on
     * a free slot and succeeds, leaving two entries for one guest name.
     */
    TEST("O_EXCL through a relative name reports EEXIST");
    EXPECT_ERRNO(openat(AT_FDCWD, NAME_A, O_CREAT | O_EXCL | O_WRONLY, 0644),
                 EEXIST, "should already exist");

    /* Created relatively, reopened absolutely. */
    TEST("create through a cwd-relative name");
    EXPECT_TRUE(file_write_at(AT_FDCWD, NAME_B, "rel") == 0, "create");

    snprintf(abs, sizeof(abs), "%s/%s", DIR_V, NAME_B);
    TEST("the same file opens through an absolute path");
    EXPECT_TRUE(file_content_at_is(AT_FDCWD, abs, "rel") == 0,
                "absolute spelling reached a different file");

    /* The directory holds one entry per guest name and no more: a spelling that
     * skipped translation would show up here as a second entry.
     */
    TEST("two names, two entries");
    EXPECT_EQ(dir_entry_count("."), 2, "entry count");

    /* The same through a real directory descriptor, which is how a tree walker
     * reaches every name it touches.
     */
    TEST("open a dirfd on the sysroot directory");
    EXPECT_TRUE(
        chdir("/") == 0 && (dirfd = open(DIR_V, O_RDONLY | O_DIRECTORY)) >= 0,
        "open dirfd");

    TEST("create through a dirfd");
    EXPECT_TRUE(file_write_at(dirfd, NAME_C, "dfd") == 0, "create");

    snprintf(abs, sizeof(abs), "%s/%s", DIR_V, NAME_C);
    TEST("the dirfd-created file opens absolutely");
    EXPECT_TRUE(file_content_at_is(AT_FDCWD, abs, "dfd") == 0,
                "dirfd spelling reached a different file");

    TEST("the absolute-created file opens through the dirfd");
    EXPECT_TRUE(file_content_at_is(dirfd, NAME_A, "abs") == 0,
                "dirfd lookup reached a different file");

    TEST("three names, three entries");
    EXPECT_EQ(dir_entry_count(DIR_V), 3, "entry count");

    /* Metadata and mutation must agree with the lookups above. */
    {
        struct stat st;
        TEST("fstatat through the dirfd");
        EXPECT_TRUE(fstatat(dirfd, NAME_A, &st, 0) == 0, "fstatat");
    }

    TEST("renameat through the dirfd");
    EXPECT_TRUE(renameat(dirfd, NAME_C, dirfd, "Delta.Four") == 0, "renameat");
    TEST("the renamed file opens absolutely under its new name");
    snprintf(abs, sizeof(abs), "%s/Delta.Four", DIR_V);
    EXPECT_TRUE(file_content_at_is(AT_FDCWD, abs, "dfd") == 0,
                "renamed content");

    TEST("mkdirat through the dirfd");
    EXPECT_TRUE(mkdirat(dirfd, "Sub.Dir", 0755) == 0, "mkdirat");
    TEST("the new directory is visible absolutely");
    {
        struct stat st;
        snprintf(abs, sizeof(abs), "%s/Sub.Dir", DIR_V);
        EXPECT_TRUE(stat(abs, &st) == 0 && S_ISDIR(st.st_mode), "stat dir");
    }

    TEST("unlinkat through the dirfd removes the file the absolute name saw");
    EXPECT_TRUE(unlinkat(dirfd, "Delta.Four", 0) == 0, "unlinkat");
    snprintf(abs, sizeof(abs), "%s/Delta.Four", DIR_V);
    TEST("and it is gone absolutely");
    EXPECT_ERRNO(open(abs, O_RDONLY), ENOENT, "should be gone");

    /* Fixtures for the second walker: a directory whose name needs escaping
     * holding a file whose name does too, and a symlink (itself needing
     * escaping) to a second directory.
     *
     * That second directory and its file are deliberately all-lowercase, so
     * they are stored under their own spelling. A symlink records the target
     * the guest gave it, and nothing rewrites those bytes, so a link pointing
     * at a name that is stored escaped cannot be followed by the host at all.
     * Pointing it at a fold-stable name keeps this case about the walker's
     * spelling of the link, which is what is under test, instead of about the
     * link's own target.
     */
    TEST("stage fixtures for the openat2 walker");
    {
        int sub = -1, plain = -1;
        EXPECT_TRUE(
            mkdirat(dirfd, "Walk.Dir", 0755) == 0 &&
                (sub = openat(dirfd, "Walk.Dir", O_RDONLY | O_DIRECTORY)) >=
                    0 &&
                file_write_at(sub, "Leaf.File", "leaf") == 0 &&
                mkdirat(dirfd, "walkdir", 0755) == 0 &&
                (plain = openat(dirfd, "walkdir", O_RDONLY | O_DIRECTORY)) >=
                    0 &&
                file_write_at(plain, "leaf", "plain") == 0 &&
                symlinkat("walkdir", dirfd, "Walk.Link") == 0 &&
                symlinkat("/proc", dirfd, "Cross.Link") == 0,
            "stage");
        if (sub >= 0)
            close(sub);
        if (plain >= 0)
            close(plain);
    }

    section_openat2_no_symlinks(dirfd);
    section_trailing_slash();
    section_below_non_directory();

    close(dirfd);

    section_outside_sysroot(argc > 1 ? argv[1] : NULL);

    SUMMARY("test-sysroot-name-relative");
    return fails > 0 ? 1 : 0;
}
