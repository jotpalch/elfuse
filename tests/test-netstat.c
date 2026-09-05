/*
 * Validate /proc/net emulation with live sockets
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Creates TCP and UDP sockets, then reads /proc/net/tcp and /proc/net/udp to
 * verify the sockets appear with correct addresses/ports/states. Also exercises
 * /proc/net/unix, /proc/net/tcp6, and /proc/net/raw.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#ifndef SIOCGIFHWADDR
#define SIOCGIFHWADDR 0x8927
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772
#endif

static int read_proc_file(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("FAIL: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0) {
        printf("FAIL: read %s: %s\n", path, strerror(errno));
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

static int hwaddr_all_zero(const unsigned char *addr)
{
    for (int i = 0; i < 6; i++) {
        if (addr[i] != 0)
            return 0;
    }
    return 1;
}

static int check_hwaddr(int sock_fd,
                        const char *ifname,
                        int expected_family,
                        int require_nonzero)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("FAIL: ioctl(SIOCGIFHWADDR, %s): %s\n", ifname, strerror(errno));
        return 0;
    }
    if (ifr.ifr_hwaddr.sa_family != expected_family) {
        printf("FAIL: %s hwaddr family got %d expected %d\n", ifname,
               ifr.ifr_hwaddr.sa_family, expected_family);
        return 0;
    }
    if (require_nonzero &&
        hwaddr_all_zero((const unsigned char *) ifr.ifr_hwaddr.sa_data)) {
        printf("FAIL: %s hwaddr is all zero\n", ifname);
        return 0;
    }
    return 1;
}

int main(void)
{
    int pass = 0, fail = 0;
    char buf[8192];
    int found_eth0 = 0;

    /* 0. Verify /proc/net exists as a directory with expected children. */
    struct stat st;
    if (stat("/proc/net", &st) == 0 && S_ISDIR(st.st_mode)) {
        DIR *dir = opendir("/proc/net");
        if (dir) {
            int found_dev = 0, found_tcp = 0, found_udp = 0, found_unix = 0;
            struct dirent *de;
            while ((de = readdir(dir))) {
                found_dev |= !strcmp(de->d_name, "dev");
                found_tcp |= !strcmp(de->d_name, "tcp");
                found_udp |= !strcmp(de->d_name, "udp");
                found_unix |= !strcmp(de->d_name, "unix");
            }
            closedir(dir);
            if (found_dev && found_tcp && found_udp && found_unix) {
                printf("PASS: /proc/net enumerates synthetic network files\n");
                pass++;
            } else {
                printf("FAIL: /proc/net missing expected entries\n");
                fail++;
            }
        } else {
            printf("FAIL: cannot open /proc/net: %s\n", strerror(errno));
            fail++;
        }
    } else {
        printf("FAIL: /proc/net is not a directory: %s\n", strerror(errno));
        fail++;
    }

    /* 1. Verify /proc/net/dev exposes Linux-style interface rows. */
    if (read_proc_file("/proc/net/dev", buf, sizeof(buf)) == 0) {
        found_eth0 = strstr(buf, "eth0:") != NULL;
        if (strstr(buf, "Inter-|") && strstr(buf, "lo:") && found_eth0) {
            printf("PASS: /proc/net/dev shows interface rows\n");
            pass++;
        } else {
            printf("FAIL: /proc/net/dev missing expected rows\n  got: %s", buf);
            fail++;
        }
    } else {
        fail++;
    }

    int ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl_fd < 0) {
        perror("socket(ioctl)");
        return 1;
    }
    if (check_hwaddr(ioctl_fd, "lo", ARPHRD_LOOPBACK, 0)) {
        printf("PASS: SIOCGIFHWADDR returns loopback identity for lo\n");
        pass++;
    } else {
        fail++;
    }
    if (found_eth0) {
        if (check_hwaddr(ioctl_fd, "eth0", ARPHRD_ETHER, 1)) {
            printf("PASS: SIOCGIFHWADDR returns Ethernet identity for eth0\n");
            pass++;
        } else {
            fail++;
        }
    }
    close(ioctl_fd);

    /* 2. Synthesize live TCP/UDP sockets for socket table checks. */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) {
        perror("socket(TCP)");
        return 1;
    }
    struct sockaddr_in taddr = {0};
    taddr.sin_family = AF_INET;
    taddr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    /* A fixed port is owned by the host, not by this process, so a concurrent
     * run of this test took it first and every later one died on EADDRINUSE.
     */
    taddr.sin_port = htons(0);
    if (bind(tcp_fd, (struct sockaddr *) &taddr, sizeof(taddr)) < 0) {
        perror("bind(TCP)");
        return 1;
    }
    socklen_t tlen = sizeof(taddr);
    if (getsockname(tcp_fd, (struct sockaddr *) &taddr, &tlen) < 0) {
        perror("getsockname(TCP)");
        return 1;
    }
    unsigned tcp_port = ntohs(taddr.sin_port);
    if (listen(tcp_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        perror("socket(UDP)");
        return 1;
    }
    struct sockaddr_in uaddr = {0};
    uaddr.sin_family = AF_INET;
    uaddr.sin_port = htons(0);
    if (bind(udp_fd, (struct sockaddr *) &uaddr, sizeof(uaddr)) < 0) {
        perror("bind(UDP)");
        return 1;
    }
    socklen_t ulen = sizeof(uaddr);
    if (getsockname(udp_fd, (struct sockaddr *) &uaddr, &ulen) < 0) {
        perror("getsockname(UDP)");
        return 1;
    }
    unsigned udp_port = ntohs(uaddr.sin_port);

    /* 3. Verify /proc/net/tcp */
    if (read_proc_file("/proc/net/tcp", buf, sizeof(buf)) == 0) {
        /* 127.0.0.1 is 0100007F in /proc/net format. */
        char want[32];
        snprintf(want, sizeof(want), "0100007F:%04X", tcp_port);
        if (strstr(buf, want) && strstr(buf, " 0A ")) {
            printf("PASS: /proc/net/tcp shows TCP LISTEN on 127.0.0.1:%u\n",
                   tcp_port);
            pass++;
        } else {
            printf("FAIL: /proc/net/tcp missing TCP listener\n  got: %s", buf);
            fail++;
        }
    } else {
        fail++;
    }

    /* 4. Verify /proc/net/udp */
    if (read_proc_file("/proc/net/udp", buf, sizeof(buf)) == 0) {
        char want[32];
        snprintf(want, sizeof(want), "00000000:%04X", udp_port);
        if (strstr(buf, want)) {
            printf("PASS: /proc/net/udp shows UDP on 0.0.0.0:%u\n", udp_port);
            pass++;
        } else {
            printf("FAIL: /proc/net/udp missing UDP socket\n  got: %s", buf);
            fail++;
        }
    } else {
        fail++;
    }

    /* 5. Verify /proc/net/tcp6 opens (empty is fine, no v6 sockets) */
    if (read_proc_file("/proc/net/tcp6", buf, sizeof(buf)) == 0) {
        if (strstr(buf, "local_address")) {
            printf("PASS: /proc/net/tcp6 has valid header\n");
            pass++;
        } else {
            printf("FAIL: /proc/net/tcp6 bad header\n");
            fail++;
        }
    } else {
        fail++;
    }

    /* 6. Verify /proc/net/unix opens */
    if (read_proc_file("/proc/net/unix", buf, sizeof(buf)) == 0) {
        if (strstr(buf, "RefCount")) {
            printf("PASS: /proc/net/unix has valid header\n");
            pass++;
        } else {
            printf("FAIL: /proc/net/unix bad header\n");
            fail++;
        }
    } else {
        fail++;
    }

    /* 7. Verify /proc/net/raw opens */
    if (read_proc_file("/proc/net/raw", buf, sizeof(buf)) == 0) {
        if (strstr(buf, "local_address")) {
            printf("PASS: /proc/net/raw has valid header\n");
            pass++;
        } else {
            printf("FAIL: /proc/net/raw bad header\n");
            fail++;
        }
    } else {
        fail++;
    }

    close(tcp_fd);
    close(udp_fd);

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
