/*
 * Darwin's struct ipc_perm, which Frama-C's modeled libc declares without a key
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The modeled libc stops at the five POSIX fields. Darwin carries two more,
 * _seq and _key, and sysvipc.c copies _key in both directions because the guest
 * expects Linux's ipc64_perm.key to be there. Reading it stopped the file with
 * "Cannot find field _key in type struct ipc_perm", so the whole SysV shm and
 * sem surface stayed outside the analyzer over one field.
 *
 * Shadowing rather than patching, for the reason frama-c-stubs/sys/un.h gives:
 * a field cannot be added to a struct the modeled header has already defined.
 * Everything else the modeled header declares is reproduced here, since
 * shadowing replaces it whole rather than extending it.
 *
 * Layout and values copied from the macOS SDK sys/ipc.h. The constants agree
 * with the modeled libc's Linux ones for the six POSIX names, which is expected
 * and not a reason to omit them: this file has to stand alone.
 */

#ifndef __FC_SYS_IPC_H
#define __FC_SYS_IPC_H

#include <sys/types.h>

struct ipc_perm {
    uid_t uid;
    gid_t gid;
    uid_t cuid;
    gid_t cgid;
    mode_t mode;
    unsigned short _seq;
    key_t _key;
};

#define IPC_CREAT 001000
#define IPC_EXCL 002000
#define IPC_NOWAIT 004000

#define IPC_PRIVATE ((key_t) 0)

#define IPC_RMID 0
#define IPC_SET 1
#define IPC_STAT 2

/* Darwin-only: modify-control-info permission, one arm of the mode word. */
#define IPC_M 010000

/*@
 assigns \result \from path[0..], id;
*/
extern key_t ftok(const char *path, int id);

#endif
