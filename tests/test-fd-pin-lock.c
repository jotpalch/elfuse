/*
 * Test that concurrent fd syscalls do not drop the process's record locks
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression coverage for host-fd lifetime pinning. A multi-threaded guest used
 * to run every fd syscall against a private dup of the host descriptor, closed
 * on return. POSIX record locks are released when the process closes any
 * descriptor for the inode (fcntl(2), "Record locking"), so that close threw
 * away the F_SETLK the very same call had just taken: the lock lasted only
 * until the syscall returned. Pinning holds the table's own descriptor instead
 * of duplicating it, so nothing closes and the lock survives.
 *
 * The sibling thread is load-bearing twice over. It keeps the guest off the
 * single-active fast path, which never dup'd and so never had the bug, and its
 * own fd syscalls each take and drop a pin on the very descriptor holding the
 * lock, which is the case that has to stay quiet.
 *
 * Both fork orders are covered. A child forked before the lock isolates the
 * pin; a child forked after it covers the same defect one layer down, in the
 * fork path itself. Sending the fd table over SCM_RIGHTS used to dup every
 * descriptor and close the dup once the send completed, and that close dropped
 * every record lock the guest held, so a fork silently unlocked the parent.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#define LOCK_BYTE 4096

static pthread_barrier_t barrier;
static int lock_fd = -1;
static atomic_int sibling_stop;
static atomic_int sibling_calls;
static atomic_int sibling_failed;

static int set_lock(int fd, short type)
{
    struct flock fl = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = LOCK_BYTE,
        .l_len = 1,
    };
    return fcntl(fd, F_SETLK, &fl);
}

/* Runs fd syscalls against the locked descriptor for as long as the main thread
 * holds the lock. Each one acquires and releases a pin on it.
 *
 * Loops until told to stop rather than a fixed count, so the checks the main
 * thread runs in between are concurrent with it by construction. A counted loop
 * can drain before the main thread reaches its first check, which leaves the
 * check measuring nothing and passing anyway.
 */
static void *sibling(void *arg)
{
    (void) arg;
    pthread_barrier_wait(&barrier);
    while (!atomic_load(&sibling_stop)) {
        /* Both reach the host descriptor and so take a pin on it. F_GETFD does
         * not: elfuse answers the close-on-exec bit from the fd table without
         * touching the host fd, so it would leave half this loop inert.
         *
         * A failure here is recorded rather than just ending the loop. Exiting
         * quietly would let every check the main thread runs pass while the
         * sibling contributed nothing, which is the one way this test can go
         * green without having tested concurrency at all.
         */
        if (fcntl(lock_fd, F_GETFL) < 0) {
            atomic_store(&sibling_failed, errno);
            break;
        }
        struct stat st;
        if (fstat(lock_fd, &st) < 0) {
            atomic_store(&sibling_failed, errno);
            break;
        }
        atomic_fetch_add(&sibling_calls, 1);
    }
    return NULL;
}

/* Asks the child to try the same lock and report whether it got it.
 *
 * Returns 1 if the child took the lock (meaning this process no longer holds
 * it), 0 if it was correctly refused, -1 if the exchange itself failed.
 */
static int child_can_lock(int go_wr, int rep_rd)
{
    /* Every negative return is marked, not just one: the caller compares
     * against 1 or 0, so an unmarked -1 reads as a child that was refused.
     */
    int taken = -1;
    if (write(go_wr, "x", 1) != 1 ||
        read(rep_rd, &taken, sizeof(taken)) != (ssize_t) sizeof(taken)) {
        printf("[child unreachable] ");
        return -1;
    }
    if (taken < 0)
        printf("[child never tried] ");
    return taken;
}

int main(void)
{
    int passes = 0, fails = 0;

    /* Unique per invocation: record locks are held per (process, inode), so a
     * fixed name shares one lock space with every concurrent run.
     */
    char path[] = "/tmp/elfuse-test-fd-pin-lock.XXXXXX";

    lock_fd = mkstemp(path);
    if (lock_fd < 0) {
        perror("mkstemp");
        return 1;
    }

    int go[2], report[2];
    if (pipe(go) < 0 || pipe(report) < 0) {
        perror("pipe");
        close(lock_fd);
        unlink(path);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(lock_fd);
        unlink(path);
        return 1;
    }
    if (child == 0) {
        close(go[1]);
        close(report[0]);
        int cfd = open(path, O_RDWR);
        char b;
        while (read(go[0], &b, 1) == 1) {
            /* -1, not 0, when the child never got to try. A refusal and a
             * failed open both leave the lock untaken, and reporting them the
             * same way lets every "the child was refused" check pass on a child
             * that did nothing.
             */
            int taken = cfd < 0 ? -1 : (set_lock(cfd, F_WRLCK) == 0 ? 1 : 0);
            if (taken == 1)
                set_lock(cfd, F_UNLCK);
            if (write(report[1], &taken, sizeof(taken)) !=
                (ssize_t) sizeof(taken))
                break;
        }
        _exit(0);
    }
    close(go[0]);
    close(report[1]);

    atomic_store(&sibling_stop, 0);
    atomic_store(&sibling_calls, 0);
    atomic_store(&sibling_failed, 0);
    pthread_barrier_init(&barrier, NULL, 2);
    pthread_t th;
    if (pthread_create(&th, NULL, sibling, NULL) != 0) {
        perror("pthread_create");
        close(go[1]);
        close(report[0]);
        waitpid(child, NULL, 0);
        pthread_barrier_destroy(&barrier);
        close(lock_fd);
        unlink(path);
        return 1;
    }

    /* Releases the sibling, which runs until the second barrier below. Every
     * check between the two happens with a second thread live, so the guest is
     * off the single-active path throughout.
     */
    pthread_barrier_wait(&barrier);

    while (atomic_load(&sibling_calls) == 0 &&
           atomic_load(&sibling_failed) == 0)
        sched_yield();

    TEST("the sibling began fd syscalls");
    EXPECT_TRUE(atomic_load(&sibling_failed) == 0,
                "sibling made no successful fd calls");

    TEST("the region starts unlocked");
    EXPECT_EQ(child_can_lock(go[1], report[0]), 1,
              "child could not take a free lock");

    TEST("F_SETLK on a multi-threaded guest");
    EXPECT_EQ(set_lock(lock_fd, F_WRLCK), 0, "F_SETLK F_WRLCK rejected");

    TEST("the lock outlives the syscall that took it");
    EXPECT_EQ(child_can_lock(go[1], report[0]), 0,
              "a second process took the lock this one still holds");

    /* The sibling has been running fd syscalls against lock_fd since the first
     * barrier, concurrently with every check above. Stop it and ask again.
     */
    atomic_store(&sibling_stop, 1);
    pthread_join(th, NULL);

    TEST("the sibling actually ran fd syscalls");
    EXPECT_TRUE(
        atomic_load(&sibling_failed) == 0 && atomic_load(&sibling_calls) > 0,
        "sibling made no successful fd calls");

    TEST("the lock survives a sibling's fd syscalls");
    EXPECT_EQ(child_can_lock(go[1], report[0]), 0,
              "a sibling's fd syscalls released this process's lock");

    /* Fork with the lock already held. The state transfer must not close any
     * descriptor for this file in the parent, or the lock dies here.
     */
    TEST("the lock survives a fork");
    int post[2];
    if (pipe(post) < 0) {
        EXPECT_TRUE(0, "pipe failed");
    } else {
        pid_t late = fork();
        if (late == 0) {
            close(post[0]);
            int cfd = open(path, O_RDWR);

            /* -1, not 0, when the child never got to try: see child_can_lock. A
             * failed open must not read as a refusal here either.
             */
            int taken = cfd < 0 ? -1 : (set_lock(cfd, F_WRLCK) == 0 ? 1 : 0);
            ssize_t ignored = write(post[1], &taken, sizeof(taken));
            (void) ignored;
            _exit(0);
        }
        close(post[1]);
        int taken = -1;
        ssize_t n = read(post[0], &taken, sizeof(taken));
        close(post[0]);
        if (late > 0)
            waitpid(late, NULL, 0);
        EXPECT_TRUE(n == (ssize_t) sizeof(taken) && taken == 0,
                    "forking released this process's lock");
    }

    TEST("F_UNLCK releases it");
    EXPECT_EQ(set_lock(lock_fd, F_UNLCK), 0, "F_UNLCK rejected");
    EXPECT_EQ(child_can_lock(go[1], report[0]), 1,
              "child still refused the lock after F_UNLCK");

    close(go[1]);
    close(report[0]);
    waitpid(child, NULL, 0);

    pthread_barrier_destroy(&barrier);
    close(lock_fd);
    unlink(path);

    SUMMARY("test-fd-pin-lock");
    return fails == 0 ? 0 : 1;
}
