/*
 * Socket/networking syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Translates Linux socket syscalls into macOS equivalents, handling the
 * differences in address family constants, sockaddr layout (sa_len byte),
 * socket option constants, and flag encoding (SOCK_NONBLOCK/SOCK_CLOEXEC packed
 * into the type argument).
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"
#include "syscall/linux-wire.h" /* linux_iovec_t */

/* Linux address families. */
#define LINUX_AF_UNSPEC 0
#define LINUX_AF_UNIX 1
#define LINUX_AF_INET 2
#define LINUX_AF_INET6 10
#define LINUX_AF_NETLINK 16

/* Linux Netlink protocol families. */
#define NETLINK_ROUTE 0
#define NETLINK_KOBJECT_UEVENT 15

/* Linux socket types + flags. */
#define LINUX_SOCK_STREAM 1
#define LINUX_SOCK_DGRAM 2
#define LINUX_SOCK_SEQPACKET 5
#define LINUX_SOCK_NONBLOCK 0x800
#define LINUX_SOCK_CLOEXEC 0x80000

/* Linux SOL_SOCKET option level. */
#define LINUX_SOL_SOCKET 1

/* Linux cmsg types for AF_UNIX. */
#define LINUX_SCM_CREDENTIALS 2

/* Linux ucred structure (12 bytes on aarch64). */
typedef struct {
    int32_t pid;
    uint32_t uid, gid;
} linux_ucred_t;

/* Linux SOL_SOCKET option names (differ from macOS!) */
#define LINUX_SO_DEBUG 1
#define LINUX_SO_REUSEADDR 2
#define LINUX_SO_TYPE 3
#define LINUX_SO_ERROR 4
#define LINUX_SO_DONTROUTE 5
#define LINUX_SO_BROADCAST 6
#define LINUX_SO_SNDBUF 7
#define LINUX_SO_RCVBUF 8
#define LINUX_SO_KEEPALIVE 9
#define LINUX_SO_OOBINLINE 10
#define LINUX_SO_LINGER 13
#define LINUX_SO_RCVTIMEO 20
#define LINUX_SO_SNDTIMEO 21
#define LINUX_SO_PASSCRED 16
#define LINUX_SO_PEERCRED 17
#define LINUX_SO_ACCEPTCONN 30
#define LINUX_SO_REUSEPORT 15
#define LINUX_SO_RCVLOWAT 18
#define LINUX_SO_SNDLOWAT 19
#define LINUX_SO_PROTOCOL 38
#define LINUX_SO_DOMAIN 39

/* Linux TCP level options. */
#define LINUX_IPPROTO_TCP 6
#define LINUX_TCP_NODELAY 1
#define LINUX_TCP_KEEPIDLE 4 /* -> macOS TCP_KEEPALIVE */
#define LINUX_TCP_KEEPINTVL 5
#define LINUX_TCP_KEEPCNT 6

/* Linux IP/IPv6 level options. */
#define LINUX_IPPROTO_IP 0
#define LINUX_IPPROTO_IPV6 41
#define LINUX_IP_TOS 1
#define LINUX_IP_TTL 2
#define LINUX_IP_HDRINCL 3
#define LINUX_IP_PKTINFO 8
#define LINUX_IP_MTU_DISCOVER 10
#define LINUX_IP_RECVERR 11
#define LINUX_IP_RECVTTL 12
#define LINUX_IP_RECVTOS 13
#define LINUX_IPV6_V6ONLY 26

/* Linux msghdr (aarch64). */
typedef struct {
    uint64_t msg_name; /* Guest pointer to sockaddr */
    uint32_t msg_namelen, _pad0;
    uint64_t msg_iov; /* Guest pointer to iovec array */
    uint64_t msg_iovlen;
    uint64_t msg_control; /* Guest pointer to ancillary data */
    uint64_t msg_controllen;
    int32_t msg_flags, _pad1;
} linux_msghdr_t;

/* Linux mmsghdr (for sendmmsg/recvmmsg). */
typedef struct {
    linux_msghdr_t msg_hdr;
    uint32_t msg_len, _pad;
} linux_mmsghdr_t;

/* Socket syscall handlers. */

int64_t sys_socket(guest_t *g, int domain, int type, int protocol);
int64_t sys_socketpair(guest_t *g,
                       int domain,
                       int type,
                       int protocol,
                       uint64_t sv_gva);
int64_t sys_bind(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen);
int64_t sys_listen(int fd, int backlog);
int64_t sys_accept(guest_t *g, int fd, uint64_t addr_gva, uint64_t addrlen_gva);
int64_t sys_accept4(guest_t *g,
                    int fd,
                    uint64_t addr_gva,
                    uint64_t addrlen_gva,
                    int flags);
int64_t sys_connect(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen);
int64_t sys_getsockname(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva);
int64_t sys_getpeername(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva);
int64_t sys_sendto(guest_t *g,
                   int fd,
                   uint64_t buf_gva,
                   uint64_t len,
                   int flags,
                   uint64_t dest_gva,
                   uint32_t addrlen);
int64_t sys_recvfrom(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva);
int64_t sys_setsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint32_t optlen);
int64_t sys_getsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint64_t optlen_gva);
int64_t sys_shutdown(int fd, int how);

/* Wait for a blocking socket op (recv/accept/connect/send) to become ready for
 * events (POLLIN/POLLOUT) or be interrupted by a guest signal. No-op for
 * nonblocking fds and MSG_DONTWAIT callers (pass msg_flags = 0 for ops without
 * a flags argument).
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR).
 */
int64_t net_wait_or_interrupted(int host_fd, short events, int msg_flags);

/* Readiness gate for a zero-payload recv/recvfrom/recvmsg: Linux clamps the
 * receive low-water target to one byte, so an empty socket blocks (EINTR on
 * guest signal) or fails EAGAIN when nonblocking, rather than returning 0
 * like the macOS host call. Call before the host receive when the resolved
 * payload length is zero.
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR/EAGAIN).
 */
int64_t net_recv_zero_payload_gate(int host_fd, int msg_flags);

/* True when a socket send/recv should wait interruptibly and retry on EAGAIN
 * rather than surface it (guest wants blocking semantics: no MSG_DONTWAIT, fd
 * not O_NONBLOCK). Send/recv paths pair this with a per-call MSG_DONTWAIT probe
 * so the interruptible wait cannot be defeated by a post-readiness buffer-full
 * or steal race, without toggling the fd's shared O_NONBLOCK flag.
 */
bool sock_op_should_block(int host_fd, int msg_flags);
int64_t sys_sendmsg(guest_t *g, int fd, uint64_t msg_gva, int flags);
int64_t sys_recvmsg(guest_t *g, int fd, uint64_t msg_gva, int flags);
int64_t sys_sendmmsg(guest_t *g,
                     int fd,
                     uint64_t mmsg_gva,
                     unsigned int vlen,
                     int flags);
int64_t sys_recvmmsg(guest_t *g,
                     int fd,
                     uint64_t mmsg_gva,
                     unsigned int vlen,
                     int flags,
                     uint64_t timeout_gva);

/* Netlink emulation. */

/* Initialize netlink subsystem. Called from syscall_init(). */
void netlink_init(void);

/* Create a synthetic netlink socket fd.
 *
 * Returns guest fd, or negative errno. NETLINK_ROUTE (rtnetlink dump
 * emulation) and NETLINK_KOBJECT_UEVENT (silent socket: no events are ever
 * delivered) are supported; other protocols return -EAFNOSUPPORT.
 */
int64_t netlink_socket(int protocol, int type);

/* Netlink bind (always succeeds; nl_groups membership is accepted and
 * ignored since no multicast event is ever synthesized). */
int64_t netlink_bind(int guest_fd,
                     guest_t *g,
                     uint64_t addr_gva,
                     uint32_t addrlen);

/* setsockopt/getsockopt on a netlink fd. SOL_SOCKET options are emulated
 * per-fd (never forwarded to a host socket: there is none); other levels
 * report -ENOPROTOOPT.
 */
int64_t netlink_setsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint32_t optlen);

int64_t netlink_getsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint64_t optlen_gva);

/* Netlink sendmsg: parse the request and buffer a response. */
int64_t netlink_sendmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags);

/* Netlink recvmsg: return buffered response data. */
int64_t netlink_recvmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags);

int64_t netlink_read(int guest_fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t count);

int64_t netlink_send(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t len);

/* Vectored forms of the two above, taking the guest iovec array they stage.
 * One netlink request, and one response, spans the whole iovec: the send
 * gathers every entry into one request and the receive fills every entry from
 * one response, so neither stops at the first entry the way the scalar special
 * fds do.
 */
int64_t netlink_writev(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt);

int64_t netlink_readv(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt);

int64_t netlink_recv(int guest_fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva);

int64_t netlink_getsockname(int guest_fd,
                            guest_t *g,
                            uint64_t addr_gva,
                            uint64_t addrlen_gva);

/* Clean up abstract socket filesystem entry for a fd being closed. */
void absock_unregister_fd(int guest_fd);

/* Get/set the abstract socket namespace identifier shared across fork IPC. */
uint64_t absock_get_namespace_id(void);
void absock_set_namespace_id(uint64_t namespace_id);
