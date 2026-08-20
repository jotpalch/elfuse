/*
 * NETLINK_KOBJECT_UEVENT silent-socket contract: the surface libusb_init()'s
 * netlink hotplug monitor needs (linux_netlink.c:102-133).
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Asserts, in the order libusb performs them:
 *   socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,
 *          NETLINK_KOBJECT_UEVENT) succeeds,
 *   bind(nl_groups=1) succeeds (and nl_groups=2, nusb's udev group),
 *   setsockopt(SOL_SOCKET, SO_PASSCRED, 1) succeeds and reads back 1,
 *   getsockopt(SO_RCVBUF/SO_TYPE) report sane values,
 *   a drained socket is not readable: non-blocking recv reports EAGAIN and
 *   poll() times out,
 *   send() to the kernel-side netlink address (nl_pid 0) either fails with
 *   EPERM (elfuse refuses guests the authority to fabricate uevents) or is
 *   swallowed whole (a real Linux kernel's netlink_unicast() to the uevent
 *   handler returns the payload length; the handler's own CAP_SYS_ADMIN
 *   refusal only travels back as an NLMSG_ERROR ack, and a payload shorter
 *   than NLMSG_HDRLEN is skipped silently),
 *   and a NETLINK_ROUTE socket still opens, so the uevent path did not
 *   disturb the rtnetlink emulation.
 *
 * The assertions hold for the elfuse emulation and for a real Linux kernel with
 * no hotplug activity during the run (the test matrix runs this binary under
 * qemu-aarch64 too). Genuine uevents arriving mid-run are tolerated by draining
 * before every readability check.
 */

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>

static int pass, fail;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("PASS: %s\n", (msg));                                       \
            pass++;                                                            \
        } else {                                                               \
            printf("FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
            fail++;                                                            \
        }                                                                      \
    } while (0)

/* Read until the socket is empty so a genuine uevent arriving on a real Linux
 * kernel cannot fail the emptiness assertions below.
 */
static void drain(int fd)
{
    char buf[4096];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) >= 0)
        ;
}

int main(void)
{
    /* The exact socket() call libusb's netlink monitor makes. */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    NETLINK_KOBJECT_UEVENT);
    CHECK(fd >= 0, "socket(NETLINK_KOBJECT_UEVENT)");
    if (fd < 0)
        return 1;

    struct sockaddr_nl snl = {.nl_family = AF_NETLINK, .nl_groups = 1};
    CHECK(bind(fd, (struct sockaddr *) &snl, sizeof(snl)) == 0,
          "bind(nl_groups=1)");

    int one = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) == 0,
          "setsockopt(SO_PASSCRED, 1)");

    int val = -1;
    socklen_t len = sizeof(val);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, &len) == 0 &&
              val == 1 && len == sizeof(int),
          "getsockopt(SO_PASSCRED) == 1");

    val = 0;
    len = sizeof(val);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len) == 0 && val > 0,
          "getsockopt(SO_RCVBUF) > 0");

    val = 0;
    len = sizeof(val);
    CHECK(
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &len) == 0 && val == SOCK_RAW,
        "getsockopt(SO_TYPE) == SOCK_RAW");

    /* No uevent is ever synthesized: an empty socket reports EAGAIN... */
    drain(fd);
    char buf[4096];
    ssize_t r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    CHECK(r == -1 && errno == EAGAIN, "recv(MSG_DONTWAIT) empty -> EAGAIN");

    /* ...and poll() times out. Retried through drain() so a real hotplug event
     * during the run cannot fail the assertion.
     */
    int quiet = 0;
    for (int i = 0; i < 4 && !quiet; i++) {
        drain(fd);
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        quiet = poll(&pfd, 1, 200) == 0;
    }
    CHECK(quiet, "poll(200ms) times out on silent socket");

    /* Guests cannot fabricate uevents. elfuse refuses the send outright with
     * EPERM (uevent_net_rcv_skb's answer for a sender without CAP_SYS_ADMIN). A
     * real Linux kernel never surfaces that refusal through sendto():
     * netlink_unicast() to a kernel socket with .input set returns skb->len
     * unconditionally, the handler's -EPERM only comes back as an NLMSG_ERROR
     * ack, and this 14-byte payload is under NLMSG_HDRLEN so netlink_rcv_skb()
     * skips it without even an ack. So: success returning the payload length is
     * the real-kernel outcome, and any failure must be the EPERM refusal.
     */
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t s = sendto(fd, "add@/devices/x", 14, 0, (struct sockaddr *) &kernel,
                       sizeof(kernel));
    CHECK(s == -1 ? errno == EPERM : s == 14,
          "sendto() refused (EPERM) or swallowed by a real Linux kernel");

    /* nusb's watch_devices() binds group 2 (udevd's multicast group). */
    int fd2 =
        socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    struct sockaddr_nl snl2 = {.nl_family = AF_NETLINK, .nl_groups = 2};
    CHECK(fd2 >= 0 && bind(fd2, (struct sockaddr *) &snl2, sizeof(snl2)) == 0,
          "second socket, bind(nl_groups=2)");
    if (fd2 >= 0)
        close(fd2);

    /* The rtnetlink emulation must be undisturbed by the uevent path. */
    int rt = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rt >= 0, "socket(NETLINK_ROUTE) still works");
    if (rt >= 0)
        close(rt);

    /* An unemulated netlink family is still refused. elfuse reports
     * EAFNOSUPPORT; a real Linux kernel reports EPROTONOSUPPORT for an
     * unregistered family. Either way the caller learns the family is absent.
     */
    int bogus = socket(AF_NETLINK, SOCK_RAW, 99);
    CHECK(bogus == -1 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT),
          "socket(protocol=99) refused");
    if (bogus >= 0)
        close(bogus);

    close(fd);
    printf("%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
