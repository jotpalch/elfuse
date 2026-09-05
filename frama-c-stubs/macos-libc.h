/*
 * macOS libc constants Frama-C's modeled libc does not carry
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frama-C models a portable libc, so anything Darwin-specific is absent even
 * when the header it lives in is present. A source using one stops with "Cannot
 * resolve variable", which is a missing declaration rather than a modeling gap:
 * the value is an integer the host header would have supplied.
 *
 * Only what the tree actually references, and only what Frama-C lacks. A new
 * one fails loudly with the same "Cannot resolve variable", which is the
 * intended way to discover it belongs here.
 *
 * Values match Darwin's headers. They matter here in the same narrow way the
 * Hypervisor stub's do: nothing proved reads them, but a value that collided
 * with another arm of the same switch would make a walked branch look
 * unreachable, so they are the real ones rather than placeholders.
 */

#pragma once

/* fcntl.h: return the path of an open fd. procemu.c and io.c use it to answer
 * /proc/self/fd/N and to re-resolve a host fd.
 */
#ifndef F_GETPATH
#define F_GETPATH 50
#endif

/* sys/socket.h: suppress SIGPIPE per socket rather than per process. Darwin's
 * answer to Linux's MSG_NOSIGNAL, which is why the socket layer reaches for it.
 */
#ifndef SO_NOSIGPIPE
#define SO_NOSIGPIPE 0x1022
#endif

/* errno.h: too many references, cannot splice. Darwin defines it; the modeled
 * libc stops at the POSIX set. 59, as sys/errno.h and the "mac 59 -> linux 109"
 * arm of linux_errno() both say. 62 is Darwin's ELOOP, which is another arm of
 * that same switch, so the two must not share a value.
 */
#ifndef ETOOMANYREFS
#define ETOOMANYREFS 59
#endif

/* limits.h: longest single path component. POSIX rather than Darwin-specific,
 * but Frama-C's limits.h omits it, and path.c sizes a component buffer with it.
 * 255, as Darwin's sys/syslimits.h says.
 */
#ifndef NAME_MAX
#define NAME_MAX 255
#endif

/* termios.h: echo control characters as ^X. In the BSD set Darwin carries and
 * the modeled libc does not; io.c translates it in both directions between the
 * guest and host termios lflag words, so it is one arm of a switch whose other
 * arms are real values.
 */
#ifndef ECHOCTL
#define ECHOCTL 0x00000040
#endif

/* termios.h: the BSD local-mode bits Darwin carries and the modeled libc stops
 * short of. io.c translates the lflag word in both directions between the guest
 * and the host, so each of these is one arm of a mask whose other arms are real
 * values; a collision would fold two guest flags onto one host flag.
 */
#ifndef ECHOKE
#define ECHOKE 0x00000001
#endif
#ifndef ECHOPRT
#define ECHOPRT 0x00000020
#endif
#ifndef EXTPROC
#define EXTPROC 0x00000800
#endif
#ifndef FLUSHO
#define FLUSHO 0x00800000
#endif
#ifndef PENDIN
#define PENDIN 0x20000000
#endif

/* sys/ioctl.h: modem control lines, for TIOCMGET and TIOCMSET. The same
 * argument applies: io.c maps the guest's bits onto these.
 */
#ifndef TIOCM_DTR
#define TIOCM_DTR 0x0002
#endif
#ifndef TIOCM_RTS
#define TIOCM_RTS 0x0004
#endif

/* fcntl.h: deallocate a byte range, Darwin's answer to Linux
 * FALLOC_FL_PUNCH_HOLE. io.c takes this fast path in sys_fallocate, so both the
 * command number and the argument struct have to be here: the modeled libc has
 * neither, and without the struct the local declaration is an incomplete type
 * rather than an unresolved name. Layout and field order match Darwin's
 * sys/fcntl.h, since io.c fills it by designated initializer.
 */
#ifndef F_PUNCHHOLE
#define F_PUNCHHOLE 99
struct fpunchhole {
    unsigned int fp_flags;
    unsigned int reserved;
    off_t fp_offset;
    off_t fp_length;
};
#endif

/* netinet/in.h: set the IP don't-fragment bit. Darwin's nearest answer to Linux
 * IP_MTU_DISCOVER, which is what net.c is translating when it reaches for this;
 * the guest's PMTUDISC_DO and PMTUDISC_PROBE both land here.
 */
#ifndef IP_DONTFRAG
#define IP_DONTFRAG 28
#endif

/* sys/stat.h: Darwin names the three timestamp members st_atimespec,
 * st_mtimespec and st_ctimespec, where POSIX and the modeled libc name them
 * st_atim, st_mtim and st_ctim. Same struct timespec, different spelling, and
 * fs-stat.c and fuse.c use the Darwin one in both directions, so the files
 * stopped with "Cannot find field st_atimespec in type struct stat".
 *
 * A macro rather than a shadowed sys/stat.h, because the modeled header already
 * uses exactly this idiom for the same reason one level down: it writes
 * "#define st_atime st_atim.tv_sec" beside the member. These alias the member
 * itself rather than a field of it, so the type is struct timespec on both
 * sides and nothing is reinterpreted.
 *
 * st_birthtimespec has no counterpart at all in the modeled struct and is not
 * mapped: nothing in the tree reads it, and aliasing it onto one of the three
 * that do exist would make two distinct timestamps the same storage.
 */
#ifndef st_atimespec
#define st_atimespec st_atim
#endif
#ifndef st_mtimespec
#define st_mtimespec st_mtim
#endif
#ifndef st_ctimespec
#define st_ctimespec st_ctim
#endif

/* unistd.h confstr selector. syscall/proc.c asks for the per-user temp dir when
 * it composes the process-table path; Frama-C's libc models confstr but not the
 * Darwin selectors it takes.
 */
#define _CS_DARWIN_USER_TEMP_DIR 65537

/* sys/qos.h. syscall/proc.c raises the vCPU threads to the interactive class so
 * the scheduler does not park them behind background work. The SDK spells these
 * as enumerators of qos_class_t, which check-stub-constants.py compares by
 * compiling against the header.
 */
typedef unsigned int qos_class_t;
#define QOS_CLASS_USER_INTERACTIVE 0x21
int pthread_set_qos_class_self_np(qos_class_t qos_class, int relative_priority);
