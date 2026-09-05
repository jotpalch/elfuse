/*
 * Darwin's struct sockaddr_un, which Frama-C's modeled libc declares as Linux's
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The modeled libc carries a portable sockaddr_un: sa_family_t sun_family
 * followed by char sun_path[108], and its own comment says the length was
 * hard-coded to the Linux value. Darwin's has a length byte in front of the
 * family, the family is one byte rather than two, and the path is 104. That
 * leading byte is the entire reason net-absock.c and net-abi.c exist, so a file
 * that writes sun_len stopped with "Cannot find field sun_len" and the whole
 * abstract-socket path stayed outside the analyzer.
 *
 * Shadowing rather than patching: -I frama-c-stubs is searched before -isystem
 * <frama-c share>/libc whatever their order on the command line, which is the
 * same mechanism the Hypervisor and OSCacheControl stubs already use. A field
 * cannot be added to a struct the modeled header has already defined, so the
 * declaration has to arrive instead of it rather than after it.
 *
 * Layout copied from the macOS SDK sys/un.h. It matters the way the Hypervisor
 * stub's does: nothing proved reads sun_len, but a proof about how much of a
 * sockaddr a conversion may touch is a proof about this layout, so it is the
 * real one rather than an approximation.
 *
 * sun_family is unsigned char, not sa_family_t. The modeled libc defines that
 * as a 16-bit type, which is Linux's width, so spelling it that way would put
 * sun_path at offset 3 and make the structure 107 bytes where Darwin measures
 * offset 2 and 106. The sibling sys/socket.h stub answers the same question the
 * same way for ss_family. Measured on this SDK rather than read off the header:
 * sizeof 106, offsetof(sun_path) 2, sizeof(sun_family) 1.
 */

#ifndef __FC_SYS_UN_H
#define __FC_SYS_UN_H

#include <sys/socket.h>

struct sockaddr_un {
    unsigned char sun_len;
    unsigned char sun_family;
    char sun_path[104];
};

#endif
