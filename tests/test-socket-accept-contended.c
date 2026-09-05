/*
 * Two threads blocking on accept for one listener
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse owns O_NONBLOCK on the sockets it opens, including listeners, and
 * emulates the guest's blocking semantics on top: wait for readiness, then
 * accept. A sibling that takes the connection the wait reported leaves the host
 * accept answering EAGAIN, and a guest that asked to block must not see it --
 * on Linux the flag is not set at all and the accept simply waits again.
 *
 * This is the accept-shaped instance of a race the recv paths already retry. It
 * reached the guest because socket ownership was added without giving accept
 * the same retry: measured, one spurious EAGAIN in every run of three before
 * the retry and none after.
 *
 * Passes on real Linux, where a blocking accept has no EAGAIN to report.
 *
 * Syscalls exercised: socket(198), bind(200), listen(201), accept4(242),
 *                     connect(203), close(57), unlink(35), clone(220)
 */

#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define ROUNDS 200

/* Generous next to the tens of milliseconds this loop needs when it works, and
 * well under the harness timeout so a stall is reported here rather than as a
 * bare timeout. Measured under elfuse a round of the wait costs about 1.3 ms
 * rather than the nominal 1, so this is roughly 13 seconds of real time against
 * the harness's 60.
 */
#define ACCEPT_DEADLINE_MS 10000

static int lfd;
static atomic_int eagains, accepted, stop;

static void *acceptor(void *arg)
{
    (void) arg;
    while (!atomic_load(&stop)) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) {
            if (errno == EAGAIN)
                atomic_fetch_add(&eagains, 1);
            return NULL;
        }
        atomic_fetch_add(&accepted, 1);
        close(c);
    }
    return NULL;
}

int main(void)
{
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;

    /* A private directory per run: the fixed name it replaces was shared with
     * every concurrent run, and the unlink() before bind() removed whichever
     * listener got there first.
     */
    char sock_dir[] = "/tmp/elfuse-accept-contended-XXXXXX";
    if (!mkdtemp(sock_dir)) {
        FAIL("mkdtemp failed");
        SUMMARY("test-socket-accept-contended");
        return 1;
    }
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s/s", sock_dir);

    lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0 || bind(lfd, (struct sockaddr *) &sa, sizeof(sa)) != 0 ||
        listen(lfd, 64) != 0) {
        FAIL("listener setup failed");
        goto fail;
    }

    int wake_fds[2];
    for (int i = 0; i < 2; i++) {
        wake_fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
        if (wake_fds[i] < 0) {
            while (i > 0)
                close(wake_fds[--i]);
            close(lfd);
            FAIL("wake socket setup failed");
            goto fail;
        }
    }

    pthread_t a, b;
    if (pthread_create(&a, NULL, acceptor, NULL) != 0 ||
        pthread_create(&b, NULL, acceptor, NULL) != 0) {
        FAIL("pthread_create failed");
        goto fail;
    }

    /* Count what the client actually got onto the listener. The assertion below
     * is about the acceptors, so it has to measure them against the connections
     * that were made rather than against the number this loop intended to make.
     */
    int made = 0;
    for (int i = 0; i < ROUNDS; i++) {
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (c < 0) {
            FAIL("client socket failed");
            break;
        }
        if (connect(c, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
            FAIL("client connect failed");
            close(c);
            break;
        }
        made++;
        close(c);
    }

    /* Bounded, and it fails rather than stalls. An unbounded wait turns any
     * connection that never arrives -- a dropped round, a saturated backlog --
     * into a 60 second harness timeout that says nothing about which side went
     * wrong. This is the same rule the sibling eventfd test follows for a
     * failed post.
     */
    int waited_ms = 0;
    while (atomic_load(&accepted) < made && !atomic_load(&eagains) &&
           waited_ms < ACCEPT_DEADLINE_MS) {
        usleep(1000);
        waited_ms++;
    }

    /* Whether every connection reached an acceptor has to be settled here.
     * Reading the counter after the join cannot tell: the two wake connections
     * below are accepted as well, so a run that lost one still finishes at the
     * target and the shortfall would go unreported.
     *
     * Measured against made rather than ROUNDS so this says something in every
     * run. A client loop that broke early has already reported itself, and the
     * acceptors are not at fault for connections nobody sent -- but the ones
     * that were sent still have to arrive, and asserting on ROUNDS there would
     * either blame the wrong side or, if the whole check is skipped, pass
     * without having looked at anything.
     *
     * The eagains term is the one place this deliberately stays quiet, and it
     * is worth being explicit since the rest of this comment argues against
     * exactly that. An acceptor that saw EAGAIN returns, so connections after
     * it are lost as a consequence rather than as a second fault, and the
     * assertion above already names the cause. Reporting both would double a
     * single failure, not describe two.
     */
    bool short_of_made =
        !atomic_load(&eagains) && atomic_load(&accepted) < made;

    /* Release whichever acceptors are still parked. */
    atomic_store(&stop, 1);
    for (int i = 0; i < 2; i++) {
        if (connect(wake_fds[i], (struct sockaddr *) &sa, sizeof(sa)) != 0)
            FAIL("wake client connect failed");
        close(wake_fds[i]);
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    unlink(sa.sun_path);
    rmdir(sock_dir);

    TEST("a blocking accept never reports EAGAIN to the guest");
    EXPECT_TRUE(atomic_load(&eagains) == 0,
                "a sibling taking the connection turned a blocking accept "
                "into EAGAIN");

    TEST("every connection made reaches an acceptor");
    EXPECT_TRUE(!short_of_made,
                "a connection that was made never reached an acceptor");

    close(lfd);
    SUMMARY("test-socket-accept-contended");
    return fails ? 1 : 0;

fail:
    unlink(sa.sun_path);
    rmdir(sock_dir);
    SUMMARY("test-socket-accept-contended");
    return 1;
}
