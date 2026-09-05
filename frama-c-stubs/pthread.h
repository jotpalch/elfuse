/*
 * Darwin's pthread_setname_np, which takes one argument where Linux takes two
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Darwin names only the calling thread: pthread_setname_np(const char *). The
 * modeled libc declares the Linux form, pthread_setname_np(pthread_t, const
 * char *), so gdbstub.c naming its own thread stopped with "Too few arguments
 * in call to pthread_setname_np" and the whole GDB stub stayed outside the
 * analyzer over one prototype.
 *
 * Same shape as frama-c-stubs/sys/socket.h: the rest of the modeled header is
 * wanted, so it arrives through include_next with the one name renamed out of
 * the way. Renaming rather than omitting keeps the modeled contract reachable
 * under its new name if anything ever wants it, and keeps the diff to this file
 * one function rather than a second copy of pthread.h.
 *
 * The contract is the modeled one with the thread argument dropped, since on
 * Darwin the thread is always the caller.
 */

#ifndef __ELFUSE_STUB_PTHREAD_H
#define __ELFUSE_STUB_PTHREAD_H

#define pthread_setname_np __fc_linux_pthread_setname_np
#include_next <pthread.h>
#undef pthread_setname_np

/*@ requires valid_name: valid_read_string(name);
    assigns \result \from indirect:name[0 .. strlen(name)];
*/
int pthread_setname_np(const char *name);

#endif
