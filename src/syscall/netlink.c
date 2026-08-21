/*
 * AF_NETLINK emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Emulates Linux NETLINK_ROUTE sockets so that glibc's getifaddrs() works.
 * macOS has no AF_NETLINK; netlink emulation synthesizes responses by querying
 * the host via getifaddrs(3) and formatting into Linux netlink message headers
 * (struct nlmsghdr, struct ifinfomsg, struct ifaddrmsg, etc.).
 *
 * Supported operations:
 *   socket(AF_NETLINK, SOCK_RAW|SOCK_DGRAM, NETLINK_ROUTE) -> synthetic fd
 *   bind() -> always succeeds
 *   sendmsg(RTM_GETLINK) -> builds interface list from host getifaddrs
 *   sendmsg(RTM_GETADDR) -> builds address list from host getifaddrs
 *   recvmsg() / read() -> returns buffered response data
 *
 * NETLINK_KOBJECT_UEVENT sockets are also accepted, as a silent socket: no
 * uevent is ever synthesized, so the fd never becomes readable, a non-blocking
 * receive reports EAGAIN, and poll() times out. That is exactly the Linux
 * kernel's behavior on a machine with no hotplug activity, and it is enough for
 * libusb_init()'s netlink hotplug monitor (socket + bind(nl_groups=1) +
 * setsockopt(SO_PASSCRED) + a poll loop) to come up. Sends on a uevent socket
 * report -EPERM, matching uevent_net_rcv() for a sender without CAP_SYS_ADMIN
 * (elfuse guests are not privileged over the host's device model). SOL_SOCKET
 * options on any netlink fd are emulated per-fd in
 * netlink_setsockopt/netlink_getsockopt below.
 *
 * Other protocols return -EAFNOSUPPORT at socket() time.
 */

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/io.h" /* io_wait_fd_or_interrupted */
#include "syscall/net.h"
#include "proved/netlink.h"
#include "utils.h"
#include <poll.h>

#ifndef LINUX_MSG_DONTWAIT
#define LINUX_MSG_DONTWAIT 0x40
#endif

static void netlink_close(int guest_fd);

/* Linux netlink message structures. These structures are defined manually to
 * match the Linux ABI exactly, since macOS has no <linux/netlink.h>. The two
 * headers the walks step over, nlmsghdr_t and rtattr_t, live in
 * proved/netlink.h with NLMSG_HDRLEN, RTA_HDRLEN and the arithmetic
 * verify-netlink proves against them. The reply builders below round with the
 * same netlink_align_up as the walks, so the two cannot round differently.
 */

/* Netlink message types */
#define NLMSG_DONE 3
#define NLMSG_ERROR 2

/* RTM_* types (from linux/rtnetlink.h) */
#define RTM_GETLINK 18
#define RTM_GETADDR 22
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20

/* NLM_F_* flags. Only NLM_F_MULTI is set on synthesized replies; the dump-style
 * request flags (NLM_F_ROOT|NLM_F_MATCH) are recognized in the request but
 * never echoed back, so they have no constants here.
 */
#define NLM_F_MULTI 0x02

/* Interface info message (struct ifinfomsg) */
typedef struct {
    uint8_t ifi_family, __ifi_pad;
    uint16_t ifi_type;   /* ARPHRD_* */
    int32_t ifi_index;   /* Interface index */
    uint32_t ifi_flags;  /* IFF_* flags */
    uint32_t ifi_change; /* IFF_* change mask */
} ifinfomsg_t;

/* Interface address message (struct ifaddrmsg) */
typedef struct {
    uint8_t ifa_family;    /* Address family */
    uint8_t ifa_prefixlen; /* Prefix length */
    uint8_t ifa_flags;     /* Address flags */
    uint8_t ifa_scope;     /* Address scope */
    uint32_t ifa_index;    /* Interface index */
} ifaddrmsg_t;

/* IFLA_* attribute types */
#define IFLA_IFNAME 3
#define IFLA_MTU 4

/* IFA_* attribute types */
#define IFA_ADDRESS 1
#define IFA_LOCAL 2

/* ARPHRD values */
#define ARPHRD_ETHER 1
#define ARPHRD_LOOPBACK 772

/* sockaddr_nl (Linux netlink socket address) */
typedef struct {
    uint16_t nl_family; /* AF_NETLINK */
    uint16_t nl_pad;
    uint32_t nl_pid;    /* Port ID */
    uint32_t nl_groups; /* Multicast groups mask */
} sockaddr_nl_t;

/* Per-socket state. */

#define MAX_NETLINK_FDS 16
#define NETLINK_BUF_SIZE 8192

/* Ceiling on one staged request. Linux bounds a send by sk_sndbuf and reports
 * EMSGSIZE past it; this is that refusal against a fixed buffer. The largest
 * request nl_process_request() reads is an RTM_GETLINK carrying an IFLA_IFNAME
 * filter, an nlmsghdr and an ifinfomsg and an attribute holding IFNAMSIZ.
 */
#define NETLINK_REQ_MAX 512

typedef struct {
    bool in_use;
    int guest_fd;                  /* Guest fd number */
    uint8_t buf[NETLINK_BUF_SIZE]; /* Response buffer */
    size_t buf_len;                /* Bytes written into buf */
    size_t buf_pos;                /* Current read position */
    uint32_t seq;                  /* Sequence number from last request */
    uint32_t pid;                  /* Bound PID (from bind or auto-assigned) */
    int pipe_wr;                   /* Host pipe write descriptor */
    int pipe_rd;                   /* Host pipe read descriptor */
    int proto;                     /* NETLINK_ROUTE or NETLINK_KOBJECT_UEVENT */
    int sock_type;                 /* SOCK_RAW or SOCK_DGRAM (SO_TYPE) */
    /* Emulated SOL_SOCKET option state. There is no host socket behind a
     * netlink fd, so these are pure per-fd caches for getsockopt round-trips.
     * rcvbuf/sndbuf hold the Linux-doubled value getsockopt reports.
     */
    int opt_passcred;
    int opt_rcvbuf;
    int opt_sndbuf;
} netlink_state_t;

/* Linux net.core.rmem_default/wmem_default on a stock kernel: what
 * getsockopt(SO_RCVBUF/SO_SNDBUF) reports before the guest ever sets one.
 */
#define NETLINK_DEFAULT_BUFSIZE 212992

/* Floor for a doubled SO_RCVBUF/SO_SNDBUF, standing in for Linux's
 * SOCK_MIN_RCVBUF/SOCK_MIN_SNDBUF (truesize-derived, ~2.2KB).
 */
#define NETLINK_MIN_BUFSIZE 2048

static netlink_state_t nl_state[MAX_NETLINK_FDS];
static pthread_mutex_t nl_lock = PTHREAD_MUTEX_INITIALIZER;

#define NL_FOR_EACH(s) \
    for (netlink_state_t *s = nl_state; s < nl_state + MAX_NETLINK_FDS; s++)

/* Helpers. */

static netlink_state_t *nl_find(int guest_fd)
{
    NL_FOR_EACH (s)
        if (s->in_use && s->guest_fd == guest_fd)
            return s;
    return NULL;
}

static netlink_state_t *nl_alloc(int guest_fd)
{
    NL_FOR_EACH (s) {
        if (s->in_use)
            continue;
        memset(s, 0, sizeof(*s));
        s->in_use = true;
        s->guest_fd = guest_fd;
        s->pipe_wr = -1;
        s->pipe_rd = -1;
        s->pid = (uint32_t) getpid();
        return s;
    }
    return NULL;
}

static void netlink_signal_readable(netlink_state_t *ns)
{
    if (ns->pipe_wr != -1) {
        uint8_t dummy = 1;
        (void) write(ns->pipe_wr, &dummy, 1);
    }
}

static void netlink_clear_readable(netlink_state_t *ns)
{
    int host_fd = ns->pipe_rd;
    if (host_fd < 0)
        return;

    uint8_t dummy[128];
    while (read(host_fd, dummy, sizeof(dummy)) > 0) {
        /* Drain non-blocking pipe */
    }
}

/* Append a netlink attribute to the buffer.
 *
 * Returns bytes written. The payload precondition is memcpy's own predicate
 * from Frama-C's string.h, not a hand-written \valid_read. datalen may be 0,
 * and an empty \valid_read range says nothing at all about the pointer, while
 * memcpy still demands \object_pointer on it. Restating the predicate is what
 * keeps the two in step.
 */
/*@
  requires \valid(buf + (0 .. max - 1));
  requires valid_read_or_empty(data, datalen);
  requires \separated(buf + (0 .. max - 1), (char *) data + (0 .. datalen - 1));
  assigns buf[0 .. max - 1];
  ensures \result <= max;
 */
static size_t nl_put_attr(uint8_t *buf,
                          size_t max,
                          uint16_t type,
                          const void *data,
                          uint16_t datalen)
{
    /* Proved in src/proved/netlink.h: on success total is RTA_HDRLEN + datalen
     * and fits the 16-bit wire field, and aligned is at most max. The cast to
     * rta_len is therefore lossless and both writes below land inside max.
     */
    uint64_t total, aligned;
    if (!netlink_attr_extent(datalen, max, &total, &aligned))
        return 0;
    rtattr_t rta = {.rta_len = (uint16_t) total, .rta_type = type};
    memcpy(buf, &rta, sizeof(rta));
    memcpy(buf + RTA_HDRLEN, data, datalen);
    /* Zero padding */
    if (aligned > total)
        memset(buf + total, 0, (size_t) (aligned - total));
    return (size_t) aligned;
}

/* Build RTM_GETLINK response from host getifaddrs(). A non-empty name_filter or
 * non-zero index_filter restricts the reply to one matching link.
 */
static int nl_build_getlink(netlink_state_t *ns,
                            const char *name_filter,
                            uint32_t index_filter)
{
    struct ifaddrs *ifalist, *ifa;
    if (getifaddrs(&ifalist) < 0)
        return -1;

    uint8_t *buf = ns->buf;
    size_t off = 0, max = NETLINK_BUF_SIZE;

    /* Track which interfaces netlink emulation has already emitted (by index).
     * getifaddrs returns one entry per address, but RTM_GETLINK wants one
     * message per interface.
     */
    uint32_t seen[64];
    int nseen = 0;

    for (ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        unsigned int idx = if_nametoindex(ifa->ifa_name);
        if (idx == 0)
            continue;

        if (name_filter[0] && strcmp(ifa->ifa_name, name_filter) != 0)
            continue;
        if (index_filter != 0 && idx != index_filter)
            continue;

        /* Check if already seen */
        bool found = false;
        for (int i = 0; i < nseen; i++) {
            if (seen[i] == idx) {
                found = true;
                break;
            }
        }
        if (found)
            continue;
        if (nseen < 64)
            seen[nseen++] = idx;

        /* Build message: nlmsghdr + ifinfomsg + attributes. Check minimum space
         * before advancing off.
         */
        size_t min_msg = NLMSG_HDRLEN + netlink_align_up(sizeof(ifinfomsg_t));
        if (off + min_msg > max)
            break;
        size_t msg_start = off;
        off += NLMSG_HDRLEN;

        ifinfomsg_t ifi = {0};
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type =
            (!strcmp(ifa->ifa_name, "lo0")) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        ifi.ifi_index = (int32_t) idx;
        ifi.ifi_flags = ifa->ifa_flags;
        memcpy(buf + off, &ifi, sizeof(ifi));
        off += netlink_align_up(sizeof(ifi));

        /* IFLA_IFNAME */
        size_t namelen = strlen(ifa->ifa_name) + 1;
        size_t n = nl_put_attr(buf + off, max - off, IFLA_IFNAME, ifa->ifa_name,
                               (uint16_t) namelen);
        off += n;

        /* IFLA_MTU: use a reasonable default */
        uint32_t mtu = (ifi.ifi_type == ARPHRD_LOOPBACK) ? 65536 : 1500;
        n = nl_put_attr(buf + off, max - off, IFLA_MTU, &mtu, 4);
        off += n;

        /* Backfill nlmsghdr now that nlmsg_len is known (header is reserved at
         * msg_start; attributes were written after it).
         */
        nlmsghdr_t hdr = {
            .nlmsg_len = (uint32_t) (off - msg_start),
            .nlmsg_type = RTM_NEWLINK,
            .nlmsg_flags = NLM_F_MULTI,
            .nlmsg_seq = ns->seq,
            .nlmsg_pid = ns->pid,
        };
        memcpy(buf + msg_start, &hdr, sizeof(hdr));
    }

    freeifaddrs(ifalist);

    /* Append NLMSG_DONE */
    if (off + NLMSG_HDRLEN <= max) {
        nlmsghdr_t done = {
            .nlmsg_len = NLMSG_HDRLEN,
            .nlmsg_type = NLMSG_DONE,
            .nlmsg_flags = NLM_F_MULTI,
            .nlmsg_seq = ns->seq,
            .nlmsg_pid = ns->pid,
        };
        memcpy(buf + off, &done, sizeof(done));
        off += NLMSG_HDRLEN;
    }

    ns->buf_len = off;
    ns->buf_pos = 0;
    return 0;
}

/* Build RTM_GETADDR response from host getifaddrs(). */
static int nl_build_getaddr(netlink_state_t *ns)
{
    struct ifaddrs *ifalist, *ifa;
    if (getifaddrs(&ifalist) < 0)
        return -1;

    uint8_t *buf = ns->buf;
    size_t off = 0, max = NETLINK_BUF_SIZE;

    for (ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;

        unsigned int idx = if_nametoindex(ifa->ifa_name);
        if (idx == 0)
            continue;

        size_t min_msg = NLMSG_HDRLEN + netlink_align_up(sizeof(ifaddrmsg_t));
        if (off + min_msg > max)
            break;
        size_t msg_start = off;
        off += NLMSG_HDRLEN;

        /* Compute prefix length from netmask */
        uint8_t prefixlen = 0;
        if (ifa->ifa_netmask) {
            if (family == AF_INET) {
                uint32_t mask = ntohl(
                    ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr);
                while (mask & 0x80000000U) {
                    prefixlen++;
                    mask <<= 1;
                }
            } else {
                struct in6_addr *m =
                    &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
                for (int i = 0; i < 16; i++) {
                    uint8_t byte = m->s6_addr[i];
                    while (byte & 0x80) {
                        prefixlen++;
                        byte <<= 1;
                    }
                    if (byte != 0)
                        break;
                }
            }
        }

        int linux_family = (family == AF_INET) ? LINUX_AF_INET : LINUX_AF_INET6;

        ifaddrmsg_t iam = {0};
        iam.ifa_family = (uint8_t) linux_family;
        iam.ifa_prefixlen = prefixlen;
        iam.ifa_scope = 0; /* RT_SCOPE_UNIVERSE */
        iam.ifa_index = (uint32_t) idx;
        memcpy(buf + off, &iam, sizeof(iam));
        off += netlink_align_up(sizeof(iam));

        /* IFA_ADDRESS attribute */
        if (family == AF_INET) {
            struct in_addr *addr =
                &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            off += nl_put_attr(buf + off, max - off, IFA_ADDRESS, addr, 4);
            /* IFA_LOCAL (same for point-to-point) */
            off += nl_put_attr(buf + off, max - off, IFA_LOCAL, addr, 4);
        } else {
            struct in6_addr *addr =
                &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            off += nl_put_attr(buf + off, max - off, IFA_ADDRESS, addr, 16);
        }

        nlmsghdr_t hdr = {
            .nlmsg_len = (uint32_t) (off - msg_start),
            .nlmsg_type = RTM_NEWADDR,
            .nlmsg_flags = NLM_F_MULTI,
            .nlmsg_seq = ns->seq,
            .nlmsg_pid = ns->pid,
        };
        memcpy(buf + msg_start, &hdr, sizeof(hdr));
    }

    freeifaddrs(ifalist);

    /* NLMSG_DONE */
    if (off + NLMSG_HDRLEN <= max) {
        nlmsghdr_t done = {
            .nlmsg_len = NLMSG_HDRLEN,
            .nlmsg_type = NLMSG_DONE,
            .nlmsg_flags = NLM_F_MULTI,
            .nlmsg_seq = ns->seq,
            .nlmsg_pid = ns->pid,
        };
        memcpy(buf + off, &done, sizeof(done));
        off += NLMSG_HDRLEN;
    }

    ns->buf_len = off;
    ns->buf_pos = 0;
    return 0;
}

/* Public API. */

void netlink_init(void)
{
    memset(nl_state, 0, sizeof(nl_state));
    fd_register_cleanup(FD_NETLINK, netlink_close);
}

int64_t netlink_socket(int protocol, int type)
{
    /* NETLINK_ROUTE gets the rtnetlink dump emulation; NETLINK_KOBJECT_UEVENT
     * gets a silent socket (see the file header). Everything else is refused
     * the way a Linux kernel without that netlink family would refuse it.
     */
    if (protocol != NETLINK_ROUTE && protocol != NETLINK_KOBJECT_UEVENT)
        return -LINUX_EAFNOSUPPORT;

    /* Allocate a pipe fd pair: the read end serves as the "socket" that
     * poll/epoll can wait on. Netlink emulation writes to the write end when
     * response data is buffered.
     */
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return -LINUX_EMFILE;

    if (fd_set_nonblock(pipefd[0]) < 0 || fd_set_nonblock(pipefd[1]) < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    int gfd = fd_alloc(FD_NETLINK, pipefd[0], netlink_close);
    if (gfd < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    netlink_state_t *ns = nl_alloc(gfd);
    if (!ns) {
        fd_mark_closed(gfd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_ENOMEM;
    }

    ns->pipe_wr = pipefd[1];
    ns->pipe_rd = pipefd[0];
    ns->proto = protocol;
    ns->sock_type = type & 0xF; /* strip SOCK_NONBLOCK/SOCK_CLOEXEC */

    /* Linux opens a netlink socket O_RDWR; carry SOCK_NONBLOCK into linux_flags
     * so a non-blocking receive on an empty socket reports EAGAIN instead of
     * parking the caller. libusb's uevent monitor opens with
     * SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC and relies on exactly that.
     */
    fd_publish_linux_flags(
        gfd, LINUX_O_RDWR |
                 ((type & LINUX_SOCK_NONBLOCK) ? LINUX_O_NONBLOCK : 0) |
                 ((type & LINUX_SOCK_CLOEXEC) ? LINUX_O_CLOEXEC : 0));

    return gfd;
}

int64_t netlink_bind(int guest_fd,
                     guest_t *g,
                     uint64_t addr_gva,
                     uint32_t addrlen)
{
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns)
        return -LINUX_EBADF;

    /* Parse sockaddr_nl if provided to get nl_pid */
    if (addr_gva && addrlen >= sizeof(sockaddr_nl_t)) {
        sockaddr_nl_t snl;
        if (guest_read_small(g, addr_gva, &snl, sizeof(snl)) == 0) {
            if (snl.nl_pid != 0)
                ns->pid = snl.nl_pid;
        }
    }

    return 0;
}

/* Double a requested SO_RCVBUF/SO_SNDBUF the way __sock_set_rcvbuf() does, so a
 * getsockopt round-trip reports what a Linux kernel would.
 */
static int nl_bufsize_store(int value)
{
    if (value < 0)
        value = 0;
    int doubled = (value > INT_MAX / 2) ? INT_MAX : value * 2;
    return (doubled < NETLINK_MIN_BUFSIZE) ? NETLINK_MIN_BUFSIZE : doubled;
}

int64_t netlink_setsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint32_t optlen)
{
    /* SOL_NETLINK (NETLINK_ADD_MEMBERSHIP and friends) is out of scope: no
     * emulated protocol delivers multicast events, so there is no membership to
     * track. No consumer in scope sets them (libusb/nusb join groups via
     * bind()); refuse the level the way sock_setsockopt refuses an unknown one
     * rather than pretending a membership took effect.
     */
    if (level != LINUX_SOL_SOCKET)
        return -LINUX_ENOPROTOOPT;

    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    /* Every option cached below carries an int; sock_setsockopt refuses a
     * shorter buffer with EINVAL before looking at the option.
     */
    if (optlen < sizeof(int)) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EINVAL;
    }
    int value = 0;
    if (guest_read_small(g, optval_gva, &value, sizeof(value)) < 0) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EFAULT;
    }

    switch (optname) {
    case LINUX_SO_PASSCRED:
        ns->opt_passcred = !!value;
        break;
    case LINUX_SO_RCVBUF:
        ns->opt_rcvbuf = nl_bufsize_store(value);
        break;
    case LINUX_SO_SNDBUF:
        ns->opt_sndbuf = nl_bufsize_store(value);
        break;
    default:
        /* Generic SOL_SOCKET toggles (SO_REUSEADDR, SO_KEEPALIVE, timeouts,
         * ...) succeed on any Linux socket. None of them can change what a
         * silent emulated socket observably does, so accept and discard.
         */
        break;
    }

    pthread_mutex_unlock(&nl_lock);
    return 0;
}

int64_t netlink_getsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint64_t optlen_gva)
{
    if (level != LINUX_SOL_SOCKET)
        return -LINUX_ENOPROTOOPT;

    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    int value;
    switch (optname) {
    case LINUX_SO_PASSCRED:
        value = ns->opt_passcred;
        break;
    case LINUX_SO_RCVBUF:
        value = ns->opt_rcvbuf ? ns->opt_rcvbuf : NETLINK_DEFAULT_BUFSIZE;
        break;
    case LINUX_SO_SNDBUF:
        value = ns->opt_sndbuf ? ns->opt_sndbuf : NETLINK_DEFAULT_BUFSIZE;
        break;
    case LINUX_SO_TYPE:
        value = ns->sock_type;
        break;
    case LINUX_SO_PROTOCOL:
        value = ns->proto;
        break;
    case LINUX_SO_DOMAIN:
        value = LINUX_AF_NETLINK;
        break;
    case LINUX_SO_ERROR:
    case LINUX_SO_ACCEPTCONN:
        value = 0;
        break;
    default:
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_ENOPROTOOPT;
    }
    pthread_mutex_unlock(&nl_lock);

    int32_t guest_optlen;
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0)
        return -LINUX_EFAULT;

    /* sock_getsockopt(): a negative optlen is -EINVAL, never a write. */
    if (guest_optlen < 0)
        return -LINUX_EINVAL;

    uint32_t write_len = sizeof(value);
    if (write_len > (uint32_t) guest_optlen)
        write_len = guest_optlen;
    if (write_len > 0 &&
        guest_write_small(g, optval_gva, &value, write_len) < 0)
        return -LINUX_EFAULT;

    /* Linux sock_getsockopt() writes back min(len, sizeof(int)): a short optlen
     * must not grow to claim bytes that were never written.
     */
    uint32_t actual_len = write_len;
    if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Extract the LinkByName/LinkByIndex filter (ifi_index plus an optional
 * IFLA_IFNAME) from a RTM_GETLINK request. Empty name / zero index = no filter.
 */
/*@
  requires \valid_read(req + (0 .. reqlen - 1));
  requires \valid(name_out + (0 .. name_cap - 1));
  requires \valid(index_out);
  requires name_cap > 0;
  requires reqlen <= NETLINK_LEN_MAX;
  requires \separated(name_out + (0 .. name_cap - 1),
                      req + (0 .. reqlen - 1),
                      index_out);
  assigns name_out[0 .. name_cap - 1], *index_out;
 */
static void nl_parse_link_filter(const uint8_t *req,
                                 size_t reqlen,
                                 char *name_out,
                                 size_t name_cap,
                                 uint32_t *index_out)
{
    name_out[0] = '\0';
    *index_out = 0;

    if (reqlen < NLMSG_HDRLEN + sizeof(ifinfomsg_t))
        return;

    ifinfomsg_t ifi;
    memcpy(&ifi, req + NLMSG_HDRLEN, sizeof(ifi));
    if (ifi.ifi_index > 0)
        *index_out = (uint32_t) ifi.ifi_index;

    uint32_t nlmsg_len;
    memcpy(&nlmsg_len, req, sizeof(nlmsg_len));
    size_t total = (nlmsg_len < reqlen) ? nlmsg_len : reqlen;

    size_t off = NLMSG_HDRLEN + netlink_align_up(sizeof(ifinfomsg_t));

    /* The invariant bounds off itself, not just off relative to total. Without
     * it the C loop test "off + RTA_HDRLEN <= total" is not known to be free of
     * unsigned wrap, and every goal under the loop inherits that doubt.
     */
    /*@
      loop invariant off <= reqlen + NETLINK_ALIGNTO;
      loop assigns off, name_out[0 .. name_cap - 1];
      loop variant total - off;
     */
    while (off + RTA_HDRLEN <= total) {
        rtattr_t rta;
        memcpy(&rta, req + off, sizeof(rta));

        /* Proved in src/proved/netlink.h: on success the payload at off +
         * RTA_HDRLEN for data_len bytes lies inside total, and next_off is
         * strictly past off.
         */
        uint64_t data_len, next_off;
        if (!netlink_rta_bounds(off, total, rta.rta_len, &data_len, &next_off))
            break;
        if (rta.rta_type == IFLA_IFNAME) {
            size_t dlen = (size_t) data_len;
            size_t i = 0;
            /*@
              loop invariant i < name_cap;
              loop assigns i, name_out[0 .. name_cap - 1];
              loop variant dlen - i;
             */
            for (; i < dlen && i + 1 < name_cap && req[off + RTA_HDRLEN + i];
                 i++)
                name_out[i] = (char) req[off + RTA_HDRLEN + i];
            name_out[i] = '\0';
        }
        off = (size_t) next_off;
    }
}

/* Build the reply for one rtnetlink request (already copied into req). Mutates
 * ns->buf/seq.
 *
 * Returns 0 on success (including a built NLMSG_ERROR reply for unsupported
 * types), or a negative LINUX_E* on a build failure. Caller holds nl_lock. req
 * is guaranteed to be at least NLMSG_HDRLEN bytes.
 */
static int nl_process_request(netlink_state_t *ns,
                              const uint8_t *req,
                              size_t reqlen)
{
    nlmsghdr_t req_hdr;
    memcpy(&req_hdr, req, sizeof(req_hdr));
    ns->seq = req_hdr.nlmsg_seq;

    int ret;
    switch (req_hdr.nlmsg_type) {
    case RTM_GETLINK: {
        char name[64];
        uint32_t index;
        nl_parse_link_filter(req, reqlen, name, sizeof(name), &index);
        ret = nl_build_getlink(ns, name, index);
        break;
    }
    case RTM_GETADDR:
        ret = nl_build_getaddr(ns);
        break;
    default:
        /* Unsupported request: return NLMSG_ERROR with EOPNOTSUPP */
        if (NLMSG_HDRLEN + 4 <= NETLINK_BUF_SIZE) {
            size_t off = 0;
            nlmsghdr_t err_hdr = {
                .nlmsg_len = NLMSG_HDRLEN + 4,
                .nlmsg_type = NLMSG_ERROR,
                .nlmsg_seq = ns->seq,
                .nlmsg_pid = ns->pid,
            };
            memcpy(ns->buf + off, &err_hdr, sizeof(err_hdr));
            off += NLMSG_HDRLEN;
            int32_t errcode = -95; /* -EOPNOTSUPP */
            memcpy(ns->buf + off, &errcode, 4);
            ns->buf_len = off + 4;
            ns->buf_pos = 0;
        }
        return 0;
    }

    return (ret < 0) ? -LINUX_EIO : 0;
}

/* A staged guest iovec vector, on the caller's stack for the common count. */
typedef struct {
    linux_iovec_t stack[SYSCALL_IOV_STACK_MAX];
    linux_iovec_t *iov;
    linux_iovec_t *heap; /* non-NULL only when iov was heap-allocated */
} nl_iov_buf_t;

/* Stage the iovcnt guest iovec entries at iov_gva into buf.
 *
 * Both directions want the entries themselves rather than the resolved host
 * pointers host_iov_prepare() builds, since one netlink request and one
 * response each span the whole vector and are staged through ns->buf.
 *
 * Returns 0, or a negative Linux errno. Pair every return with nl_iov_free().
 * iovcnt is bounded by the caller, whose spelling decides what an empty vector
 * means.
 */
static int64_t nl_iov_stage(guest_t *g,
                            uint64_t iov_gva,
                            int iovcnt,
                            nl_iov_buf_t *buf)
{
    buf->iov = buf->stack;
    buf->heap = NULL;
    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        buf->heap = malloc((size_t) iovcnt * sizeof(*buf->heap));
        if (!buf->heap)
            return -LINUX_ENOMEM;
        buf->iov = buf->heap;
    }

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        uint64_t entry_gva = iov_gva + (uint64_t) i * sizeof(*buf->iov);
        if (guest_read_small(g, entry_gva, &buf->iov[i], sizeof(*buf->iov)) < 0)
            return -LINUX_EFAULT;
        if (!iov_total_add(total, buf->iov[i].iov_len, &total))
            return -LINUX_EINVAL;
    }
    return 0;
}

static void nl_iov_free(nl_iov_buf_t *buf)
{
    free(buf->heap);
    buf->heap = NULL;
}

/* Bound msg_iovlen, which is uint64_t on Linux, before the int narrowing, so a
 * 64-bit value whose low 32 bits fall inside the cap cannot slip past it.
 * sys_sendmsg and sys_recvmsg refuse the same count the same way.
 */
static int64_t nl_msg_iovcnt(const linux_msghdr_t *mhdr, int *iovcnt)
{
    if (mhdr->msg_iovlen > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;
    *iovcnt = (int) mhdr->msg_iovlen;
    return 0;
}

/* The send half of sendmsg(2), sendto(2), write(2) and writev(2) on a netlink
 * socket.
 *
 * One request spans the whole iovec, so it is gathered before it is parsed. A
 * gathered length between one byte and one nlmsghdr transfers and does nothing:
 * the loop in netlink_rcv_skb() is entered only from nlmsg_total_size(0) bytes
 * up, and the send reports the byte count rather than an error. Measured
 * against Linux 6.18 under qemu-aarch64.
 */
static int64_t netlink_send_iov(int guest_fd,
                                guest_t *g,
                                const linux_iovec_t *iov,
                                int iovcnt)
{
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    int64_t result;

    /* A uevent socket is receive-only here. Linux's uevent_net_rcv() refuses a
     * sender without CAP_SYS_ADMIN with -EPERM, and elfuse guests have no
     * authority to fabricate uevents, so every send is that refusal.
     */
    if (ns->proto == NETLINK_KOBJECT_UEVENT) {
        result = -LINUX_EPERM;
        goto out;
    }

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > UINT64_MAX - total) {
            result = -LINUX_EINVAL;
            goto out;
        }
        total += iov[i].iov_len;
    }

    /* Linux's netlink_sendmsg() refuses an empty message before it builds an
     * skb, which is what a sendmsg or a write of nothing reports. No entries at
     * all sums to nothing too. The writev spelling never arrives here empty:
     * do_readv_writev() returns on a zero total above the socket, and
     * netlink_writev() carries that rule.
     */
    if (total == 0) {
        result = -LINUX_ENODATA;
        goto out;
    }

    /* Ahead of the read, the order netlink_sendmsg() checks its length in: an
     * oversized send is refused whatever its buffers hold.
     */
    if (total > NETLINK_REQ_MAX) {
        result = -LINUX_EMSGSIZE;
        goto out;
    }

    if (total < (uint64_t) NLMSG_HDRLEN) {
        result = (int64_t) total;
        goto out;
    }

    /* Every entry is read, so total is the byte count that was validated and
     * parsed, and an unmapped entry anywhere in the vector is EFAULT rather
     * than a report of bytes nothing looked at. An entry of no length reads
     * nothing and validates nothing, which is what Linux does with it.
     *
     * A total of NLMSG_HDRLEN or more rules out an empty vector, so the loop
     * always runs. req is zeroed anyway: cppcheck reads the loop as skippable
     * and calls the parse below an uninitialized read.
     */
    uint8_t req[NETLINK_REQ_MAX] = {0};
    size_t rlen = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (guest_read(g, iov[i].iov_base, req + rlen,
                       (size_t) iov[i].iov_len) < 0) {
            result = -LINUX_EFAULT;
            goto out;
        }
        rlen += (size_t) iov[i].iov_len;
    }

    bool was_empty = ns->buf_pos >= ns->buf_len;
    int ret = nl_process_request(ns, req, rlen);
    if (ret == 0) {
        if (was_empty && ns->buf_pos < ns->buf_len)
            netlink_signal_readable(ns);
    }
    result = (ret < 0) ? ret : (int64_t) total;

out:
    pthread_mutex_unlock(&nl_lock);
    return result;
}

int64_t netlink_send(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t len)
{
    linux_iovec_t one = {.iov_base = buf_gva, .iov_len = len};
    return netlink_send_iov(guest_fd, g, &one, 1);
}

int64_t netlink_writev(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt)
{
    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    nl_iov_buf_t buf;
    int64_t ret = nl_iov_stage(g, iov_gva, iovcnt, &buf);
    if (ret == 0) {
        uint64_t total = 0;
        for (int i = 0; i < iovcnt; i++)
            total += buf.iov[i].iov_len; /* nl_iov_stage bounds the sum */

        /* A vectored write carrying nothing stops in do_readv_writev() before
         * the socket is reached, so it reports 0 where write(2) of nothing
         * reports ENODATA. Measured against Linux 6.18 under qemu-aarch64.
         */
        ret = total == 0 ? 0 : netlink_send_iov(guest_fd, g, buf.iov, iovcnt);
    }
    nl_iov_free(&buf);
    return ret;
}

int64_t netlink_sendmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags)
{
    (void) flags;
    linux_msghdr_t mhdr;
    if (guest_read_small(g, msg_gva, &mhdr, sizeof(mhdr)) < 0)
        return -LINUX_EFAULT;

    int iovcnt;
    int64_t ret = nl_msg_iovcnt(&mhdr, &iovcnt);
    if (ret < 0)
        return ret;

    /* ___sys_sendmsg() carries an empty vector down to the socket rather than
     * answering it, so netlink_send_iov() decides this one too.
     */
    nl_iov_buf_t buf;
    ret = nl_iov_stage(g, mhdr.msg_iov, iovcnt, &buf);
    if (ret == 0)
        ret = netlink_send_iov(guest_fd, g, buf.iov, iovcnt);
    nl_iov_free(&buf);
    return ret;
}

/* Block until the netlink receive buffer has data. Called with nl_lock held.
 *
 * On success returns 0 with nl_lock still held and ns valid. On EAGAIN, EINTR,
 * EIO, or if the socket was closed underneath the poll, releases nl_lock and
 * returns the negative Linux errno. flags carries MSG_DONTWAIT; pass 0 for
 * read(2), which only honors O_NONBLOCK.
 */
static int64_t nl_wait_readable_locked(netlink_state_t *ns,
                                       int guest_fd,
                                       int flags)
{
    while (ns->buf_pos >= ns->buf_len) {
        bool nonblock = (flags & LINUX_MSG_DONTWAIT) ||
                        (fd_table[guest_fd].linux_flags & LINUX_O_NONBLOCK);
        if (nonblock) {
            pthread_mutex_unlock(&nl_lock);
            return -LINUX_EAGAIN;
        }

        int rd_fd = ns->pipe_rd;
        pthread_mutex_unlock(&nl_lock);

        /* Bounded + interrupt-aware: an untimed poll() here has no re-check
         * point, so a worker parked on an AF_NETLINK socket with no incoming
         * messages is invisible to thread_join_workers' poll cap and touches
         * guest memory on an eventual delayed return, well after guest_destroy
         * may have unmapped it.
         */
        int64_t wait_rc = io_wait_fd_or_interrupted(rd_fd, POLLIN);
        if (wait_rc < 0)
            return wait_rc;

        pthread_mutex_lock(&nl_lock);
        netlink_state_t *current_ns = nl_find(guest_fd);
        if (!current_ns || current_ns != ns) {
            pthread_mutex_unlock(&nl_lock);
            return -LINUX_EBADF;
        }
    }
    return 0;
}

/* Return the byte length of the longest run of complete netlink messages that
 * starts at ns->buf_pos and fits within to_copy. Falls back to to_copy when not
 * even one whole message fits (MSG_TRUNC semantics). Called with nl_lock held.
 */
/*@
  requires \valid_read(ns);
  requires ns->buf_pos <= ns->buf_len;
  requires ns->buf_len <= NETLINK_BUF_SIZE;
  requires to_copy <= ns->buf_len - ns->buf_pos;
  assigns \nothing;
  ensures \result <= to_copy;
 */
static size_t nl_complete_span(const netlink_state_t *ns, size_t to_copy)
{
    size_t msg_end = 0, pos = ns->buf_pos;
    /*@
      loop invariant ns->buf_pos <= pos <= ns->buf_len;
      loop invariant msg_end <= to_copy;
      loop assigns pos, msg_end;
      loop variant ns->buf_len - pos;
     */
    while (pos < ns->buf_len && (pos - ns->buf_pos + NLMSG_HDRLEN) <= to_copy) {
        /* memcpy rather than a cast: pos is not guaranteed to sit on a message
         * boundary (see the header), so ns->buf + pos need not be suitably
         * aligned for nlmsghdr_t.
         */
        nlmsghdr_t hdr;
        memcpy(&hdr, ns->buf + pos, sizeof(hdr));

        /* Proved in src/proved/netlink.h: on success span is strictly positive,
         * so this loop advances for any header at all. Before the widening this
         * loop could spin forever on a guest-chosen length; see the header.
         */
        uint64_t span;
        if (!netlink_msg_span(hdr.nlmsg_len, &span))
            break;
        size_t msg_bytes = pos - ns->buf_pos + (size_t) span;
        if (msg_bytes > to_copy)
            break;
        pos += (size_t) span;
        msg_end = pos - ns->buf_pos;
    }
    return msg_end == 0 ? to_copy : msg_end;
}

/* Write the kernel-side sockaddr_nl (nl_pid 0) and its length to the guest at
 * the given addresses. Called with nl_lock held.
 */
static void nl_write_kernel_src(guest_t *g,
                                uint64_t addr_gva,
                                uint64_t namelen_gva)
{
    sockaddr_nl_t snl = {
        .nl_family = LINUX_AF_NETLINK,
        .nl_pid = 0, /* from kernel */
    };
    guest_write_small(g, addr_gva, &snl, sizeof(snl));
    uint32_t namelen = sizeof(sockaddr_nl_t);
    guest_write_small(g, namelen_gva, &namelen, sizeof(namelen));
}

/* The receive half of recvmsg(2), recvfrom(2), read(2) and readv(2) on a
 * netlink socket: drain whole messages, filling every entry in turn.
 *
 * One response spans the whole iovec, so a first entry too small for it does
 * not cap the transfer. nl_complete_span() bounds every spelling alike, so none
 * of them hands out a message split across two calls.
 *
 * Returns the byte count, or a negative Linux errno. Takes nl_lock and releases
 * it before returning. flags carries MSG_DONTWAIT; pass 0 for read(2), which
 * only honors O_NONBLOCK.
 */
static int64_t netlink_recv_iov(int guest_fd,
                                guest_t *g,
                                const linux_iovec_t *iov,
                                int iovcnt,
                                int flags)
{
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > UINT64_MAX - total) {
            pthread_mutex_unlock(&nl_lock);
            return -LINUX_EINVAL;
        }
        total += iov[i].iov_len;
    }

    if (total == 0) {
        pthread_mutex_unlock(&nl_lock);
        return 0;
    }

    int64_t werr = nl_wait_readable_locked(ns, guest_fd, flags);
    if (werr < 0)
        return werr;

    size_t avail = ns->buf_len - ns->buf_pos;
    size_t to_copy = (avail < total) ? avail : (size_t) total;
    size_t msg_end = nl_complete_span(ns, to_copy);

    size_t done = 0;
    for (int i = 0; i < iovcnt && done < msg_end; i++) {
        size_t remain = msg_end - done;
        size_t chunk =
            (iov[i].iov_len < remain) ? (size_t) iov[i].iov_len : remain;
        if (chunk == 0)
            continue;

        /* The count is what landed, not whole entries: guest memory is copied
         * chunk by chunk and a chunk that faults still places the bytes ahead
         * of it, which is what copy_to_iter() counts.
         */
        size_t moved = guest_write_partial(g, iov[i].iov_base,
                                           ns->buf + ns->buf_pos, chunk);
        ns->buf_pos += moved;
        done += moved;
        if (moved < chunk) {
            pthread_mutex_unlock(&nl_lock);

            /* Bytes already placed are transferred; reporting EFAULT over them
             * would lose them, since buf_pos has moved past.
             */
            return done ? (int64_t) done : -LINUX_EFAULT;
        }
    }

    if (ns->buf_pos >= ns->buf_len)
        netlink_clear_readable(ns);

    pthread_mutex_unlock(&nl_lock);
    return (int64_t) done;
}

/* recvfrom(2) on a netlink socket: write back a kernel sockaddr_nl (nl_pid 0)
 * when src is requested.
 */
int64_t netlink_recv(int guest_fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva)
{
    linux_iovec_t one = {.iov_base = buf_gva, .iov_len = len};
    int64_t ret = netlink_recv_iov(guest_fd, g, &one, 1, flags);
    if (ret >= 0 && src_gva && addrlen_gva)
        nl_write_kernel_src(g, src_gva, addrlen_gva);
    return ret;
}

/* getsockname(2) on a netlink socket: returns the bound/auto-assigned pid. */
int64_t netlink_getsockname(int guest_fd,
                            guest_t *g,
                            uint64_t addr_gva,
                            uint64_t addrlen_gva)
{
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }
    uint32_t pid = ns->pid;
    pthread_mutex_unlock(&nl_lock);

    uint32_t cap = 0;
    if (guest_read_small(g, addrlen_gva, &cap, sizeof(cap)) < 0)
        return -LINUX_EFAULT;

    sockaddr_nl_t snl = {
        .nl_family = LINUX_AF_NETLINK,
        .nl_pid = pid,
    };
    size_t n = (cap < sizeof(snl)) ? cap : sizeof(snl);
    if (n > 0 && guest_write(g, addr_gva, &snl, n) < 0)
        return -LINUX_EFAULT;

    uint32_t actual = sizeof(snl);
    if (guest_write_small(g, addrlen_gva, &actual, sizeof(actual)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t netlink_recvmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags)
{
    linux_msghdr_t mhdr;
    if (guest_read_small(g, msg_gva, &mhdr, sizeof(mhdr)) < 0)
        return -LINUX_EFAULT;

    int iovcnt;
    int64_t ret = nl_msg_iovcnt(&mhdr, &iovcnt);
    if (ret < 0)
        return ret;

    nl_iov_buf_t buf;
    ret = nl_iov_stage(g, mhdr.msg_iov, iovcnt, &buf);
    if (ret == 0)
        ret = netlink_recv_iov(guest_fd, g, buf.iov, iovcnt, flags);
    nl_iov_free(&buf);
    if (ret < 0)
        return ret;

    if (mhdr.msg_name && mhdr.msg_namelen >= sizeof(sockaddr_nl_t))
        nl_write_kernel_src(g, mhdr.msg_name,
                            msg_gva + offsetof(linux_msghdr_t, msg_namelen));

    int32_t zero_flags = 0;
    guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_flags),
                      &zero_flags, sizeof(zero_flags));
    uint64_t zero_controllen = 0;
    guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                      &zero_controllen, sizeof(zero_controllen));
    return ret;
}

int64_t netlink_readv(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt)
{
    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    nl_iov_buf_t buf;
    int64_t ret = nl_iov_stage(g, iov_gva, iovcnt, &buf);
    if (ret == 0)
        ret = netlink_recv_iov(guest_fd, g, buf.iov, iovcnt, 0);
    nl_iov_free(&buf);
    return ret;
}

int64_t netlink_read(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    linux_iovec_t one = {.iov_base = buf_gva, .iov_len = count};
    return netlink_recv_iov(guest_fd, g, &one, 1, 0);
}

static void netlink_close(int guest_fd)
{
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return;
    }
    if (ns->pipe_wr != -1) {
        close(ns->pipe_wr);
        ns->pipe_wr = -1;
    }
    ns->pipe_rd = -1;
    ns->in_use = false;
    pthread_mutex_unlock(&nl_lock);
}
