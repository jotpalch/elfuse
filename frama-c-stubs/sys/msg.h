/*
 * Darwin's struct msqid_ds, which Frama-C's modeled libc declares without the
 * queue byte count
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The modeled libc carries the eight POSIX members. Darwin adds msg_cbytes, the
 * bytes currently queued, and sysvipc.c copies it because Linux's msqid64_ds
 * has __msg_cbytes and a guest reading IPC_STAT expects it filled. Reading it
 * stopped the file with "Cannot find field msg_cbytes in type struct msqid_ds".
 *
 * Shadowing rather than patching, for the reason frama-c-stubs/sys/un.h gives.
 * The reserved members Darwin declares (msg_first, msg_last, the four pads) are
 * kept: nothing in the tree touches them, but leaving them out would make
 * sizeof disagree with what msgctl actually writes into, and this file exists
 * so the analyzer sees the structure the code compiles against.
 *
 * Contracts on the four entry points are the modeled header's, unchanged.
 */

#ifndef __FC_SYS_MSG_H
#define __FC_SYS_MSG_H

#include <sys/ipc.h>
#include <sys/types.h>

typedef unsigned long msgqnum_t;
typedef unsigned long msglen_t;

struct msqid_ds {
    struct ipc_perm msg_perm;
    int msg_first;
    int msg_last;
    msglen_t msg_cbytes;
    msgqnum_t msg_qnum;
    msglen_t msg_qbytes;
    pid_t msg_lspid;
    pid_t msg_lrpid;
    time_t msg_stime;
    int msg_pad1;
    time_t msg_rtime;
    int msg_pad2;
    time_t msg_ctime;
    int msg_pad3;
    int msg_pad4[4];
};

/* Darwin's "do not fail a message larger than the buffer, truncate it". The
 * modeled libc omits it and sysvipc.c maps Linux MSG_NOERROR onto it.
 */
#define MSG_NOERROR 010000

extern int msgctl(int msqid, int cmd, struct msqid_ds *buf);

/*@
  assigns \result \from key, msgflg;
*/
extern int msgget(key_t key, int msgflg);

/*@
  assigns \result, ((char *) msgp)[0 .. msgsz - 1] \from msqid, msgsz, msgtyp,
    msgflg;
*/
extern ssize_t msgrcv(int msqid,
                      void *msgp,
                      size_t msgsz,
                      long msgtyp,
                      int msgflg);

/*@
  assigns \result \from msqid, ((char *) msgp)[0 .. msgsz - 1], msgsz, msgflg;
*/
extern int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);

#endif
