/*
 * Darwin's struct sockaddr_storage, over the modeled libc's Linux one
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Everything else in the modeled sys/socket.h is wanted, so this takes it whole
 * through include_next and replaces one structure. sys/un.h and sys/ipc.h
 * shadow their originals outright because those are small enough to reproduce;
 * 594 lines of socket declarations are not, and reproducing them would put a
 * second copy of the socket API in the tree to drift.
 *
 * The one structure has to be replaced rather than extended because Darwin puts
 * a length byte in front of the family and the modeled libc does not carry it.
 * That byte is what net-abi.c is for: linux_to_mac_sockaddr writes ss_len
 * because Linux has no such field and macOS requires one. Without it the file
 * stopped with "Cannot find field ss_len", so the conversion the whole socket
 * layer funnels through was outside the analyzer.
 *
 * The rename is safe to the extent that the modeled header names the tag
 * exactly once, at its definition, and in no prototype. That is checked rather
 * than assumed: scripts/check-stub-shadow.py fails if a future Frama-C grows a
 * second use, because then the rename would silently change a signature.
 *
 * Layout copied from the macOS SDK sys/socket.h with the padding sizes expanded
 * (_SS_PAD1SIZE is 6 and _SS_PAD2SIZE is 112 for a 128-byte structure with a
 * one-byte length and a one-byte family). sizeof is 128 either way, which is
 * what src/proved/sockaddr.h's destination bound is about, so the proof reasons
 * about the same number it did before; the difference is that the file holding
 * its caller now parses.
 */

#ifndef __ELFUSE_STUB_SYS_SOCKET_H
#define __ELFUSE_STUB_SYS_SOCKET_H

#define sockaddr_storage __fc_linux_sockaddr_storage
#include_next <sys/socket.h>
#undef sockaddr_storage

struct sockaddr_storage {
    unsigned char ss_len;
    unsigned char ss_family;
    char __ss_pad1[6];
    long long __ss_align;
    char __ss_pad2[112];
};

#endif
