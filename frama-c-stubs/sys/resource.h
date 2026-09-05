/*
 * sys/resource.h, for the analyzer only
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The one stub here that replaces a modeled header outright rather than taking
 * it through #include_next and renaming a name. Frama-C's libc models struct
 * rusage with the two fields POSIX requires, ru_utime and ru_stime. Darwin
 * declares sixteen, and syscall/proc.c does not merely read the extra ones:
 * write_rusage_to_guest asserts sizeof(struct rusage) equals the guest's
 * linux_rusage_t and memcpy's one onto the other, so a two-field model fails
 * the static assertion before any analysis starts. A rename cannot add twelve
 * fields, and defining the struct alongside the modeled one is a redefinition,
 * so this file supplies the whole header.
 *
 * That makes it the stub most likely to go stale: anything the tree starts
 * using from sys/resource.h has to be added here or the file stops parsing. The
 * set below is what src/ uses today (getrusage, getrlimit, setrlimit,
 * getpriority, setpriority, and the constants beside them), and nothing else.
 *
 * Values and layout come from the macOS SDK; scripts/check-stub-constants.py
 * holds the constants to it. The field order matters as much as the names,
 * because the assertion above is about size and the memcpy is about layout.
 *
 * Same placement rule as the other Darwin stubs: outside src/, reachable only
 * through FRAMAC_STUB_DIR in mk/verify.mk, never on a compile's include path.
 */

#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h> /* id_t, for the priority calls below */

typedef uint64_t rlim_t;

/* Darwin's __DARWIN_C_FULL spelling. The first two are what POSIX requires and
 * what Frama-C models; the fourteen longs after them are what this stub exists
 * for.
 */
struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)

#define RLIM_INFINITY (((uint64_t) 1 << 63) - 1)

#define RLIMIT_CPU 0
#define RLIMIT_FSIZE 1
#define RLIMIT_DATA 2
#define RLIMIT_STACK 3
#define RLIMIT_CORE 4
#define RLIMIT_AS 5
#define RLIMIT_RSS RLIMIT_AS
#define RLIMIT_MEMLOCK 6
#define RLIMIT_NPROC 7
#define RLIMIT_NOFILE 8

#define PRIO_PROCESS 0

int getrusage(int who, struct rusage *r_usage);
int getrlimit(int resource, struct rlimit *rlp);
int setrlimit(int resource, const struct rlimit *rlp);
int getpriority(int which, id_t who);
int setpriority(int which, id_t who, int prio);
