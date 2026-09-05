/*
 * libproc.h, for the analyzer only
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * syscall/proc.c is the one caller. It uses proc_pidpath to answer three
 * questions about a host pid: what elfuse's own binary is (recorded once at
 * startup and served to /proc/self/exe), whether a host pid the process table
 * names is still the process it was, and whether a candidate parent is another
 * elfuse. It enumerates live pids once besides, to reap the process table
 * against what the host still has, and runtime/procemu.c lists one process's
 * open fds to answer /proc/<pid>/fd.
 *
 * Declarations only. Both calls are kernel lookups the analyzer's memory model
 * cannot see into, so a body would be fiction; leaving them unspecified makes
 * WP treat the buffer as written with unknown contents, which is what the
 * callers already assume.
 *
 * Same placement rule as the other Darwin stubs: outside src/, reachable only
 * through FRAMAC_STUB_DIR in mk/verify.mk, never on a compile's include path.
 */

#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

/* sys/syslimits.h. procemu.c uses this for host-side fd path buffers. */
#define MAXPATHLEN 1024

/* sys/proc_info.h spells this (4*MAXPATHLEN), and MAXPATHLEN is 1024. */
#define PROC_PIDPATHINFO_MAXSIZE 4096

/* sys/proc_info.h. The only selector proc_listpids is called with here. */
#define PROC_ALL_PIDS 1

/* sys/proc_info.h. runtime/procemu.c walks a process's open fds with these. */
#define PROC_PIDLISTFDS 1
#define PROC_PIDLISTFD_SIZE (sizeof(struct proc_fdinfo))

/* sys/proc_info.h selector and result for socket fd details. */
#define PROC_PIDFDSOCKETINFO 3

/* sys/proc_info.h fd types; procemu.c only distinguishes sockets. */
#define PROX_FDTYPE_SOCKET 2

struct proc_fdinfo {
    int32_t proc_fd;
    uint32_t proc_fdtype;
};

struct proc_fileinfo {
    uint32_t fi_openflags;
    uint32_t fi_status;
    int64_t fi_offset;
    int32_t fi_type;
    uint32_t fi_guardflags;
};

struct in4in6_addr {
    uint32_t i46a_pad32[3];
    struct in_addr i46a_addr4;
};

struct in_sockinfo {
    int insi_fport;
    int insi_lport;
    uint64_t insi_gencnt;
    uint32_t insi_flags;
    uint32_t insi_flow;
    uint8_t insi_vflag;
    uint8_t insi_ip_ttl;
    uint32_t rfu_1;
    union {
        struct in4in6_addr ina_46;
        struct in6_addr ina_6;
    } insi_faddr, insi_laddr;
    struct {
        uint8_t in4_tos;
    } insi_v4;
    struct {
        uint8_t in6_hlim;
        int in6_cksum;
        uint16_t in6_ifindex;
        short in6_hops;
    } insi_v6;
};

struct tcp_sockinfo {
    struct in_sockinfo tcpsi_ini;
    int tcpsi_state;
    int tcpsi_timer[4];
    int tcpsi_mss;
    uint32_t tcpsi_flags;
    uint32_t rfu_1;
    uint64_t tcpsi_tp;
};

struct un_sockinfo {
    uint64_t unsi_conn_so;
    uint64_t unsi_conn_pcb;
    union {
        struct sockaddr_un ua_sun;
        char ua_dummy[255];
    } unsi_addr;
    union {
        struct sockaddr_un ua_sun;
        char ua_dummy[255];
    } unsi_caddr;
};

struct sockbuf_info {
    uint32_t sbi_cc;
    uint32_t sbi_hiwat;
    uint32_t sbi_mbcnt;
    uint32_t sbi_mbmax;
    uint32_t sbi_lowat;
    short sbi_flags;
    short sbi_timeo;
};

struct socket_info {
    char soi_stat[136];
    uint64_t soi_so;
    uint64_t soi_pcb;
    int soi_type;
    int soi_protocol;
    int soi_family;
    short soi_options;
    short soi_linger;
    short soi_state;
    short soi_qlen;
    short soi_incqlen;
    short soi_qlimit;
    short soi_timeo;
    uint16_t soi_error;
    uint32_t soi_oobmark;
    struct sockbuf_info soi_rcv;
    struct sockbuf_info soi_snd;
    int soi_kind;
    uint32_t rfu_1;
    union {
        struct in_sockinfo pri_in;
        struct tcp_sockinfo pri_tcp;
        struct un_sockinfo pri_un;
    } soi_proto;
};

struct socket_fdinfo {
    struct proc_fileinfo pfi;
    struct socket_info psi;
};

int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
int proc_pidinfo(int pid,
                 int flavor,
                 uint64_t arg,
                 void *buffer,
                 int buffersize);
int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
int proc_listpids(uint32_t type,
                  uint32_t typeinfo,
                  void *buffer,
                  int buffersize);
