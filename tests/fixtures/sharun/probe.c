/*
 * sharun dynamic-loader probe
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies loader state and ordinary dynamic-process behavior from a sharun
 * bundle.
 */

#include <dlfcn.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern const char *probe_library_value(void);

typedef const char *(*probe_value_fn)(void);

static void *thread_value(void *arg)
{
    return arg;
}

/* Name the failed check on stderr. A bare exit code out of a guest running
 * under a hypervisor says nothing about which stage broke.
 */
static int fail(int code, const char *what)
{
    fprintf(stderr, "probe: %s\n", what);
    return code;
}

static int check_process(void)
{
    char value[2] = {0};
    int fd[2];
    int status;
    int carried;
    pid_t child;

    if (pipe(fd) != 0)
        return fail(6, "pipe failed");
    child = fork();
    if (child < 0) {
        close(fd[0]);
        close(fd[1]);
        return fail(6, "fork failed");
    }
    if (child == 0) {
        size_t sent = 0;

        close(fd[0]);

        /* Looped like the parent's read below, and for the same reason: one
         * write can come back short or EINTR, and the child would then exit 1
         * and fail this arm for something that has nothing to do with the
         * loader it exercises.
         */
        while (sent < 2) {
            ssize_t n = write(fd[1], "ok" + sent, 2 - sent);
            if (n > 0) {
                sent += (size_t) n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        _exit(sent == 2 ? 0 : 1);
    }
    close(fd[1]);

    /* Loop rather than trusting one read: a pipe read can return short, and
     * both read and waitpid can come back EINTR. Treating either as a failure
     * would make this arm flake for reasons that have nothing to do with the
     * loader it is here to exercise.
     */
    carried = 0;
    while (carried < 2) {
        ssize_t n = read(fd[0], value + carried, (size_t) (2 - carried));
        if (n > 0) {
            carried += (int) n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    close(fd[0]);
    if (carried != 2 || memcmp(value, "ok", 2) != 0)
        return fail(6, "pipe did not carry the child's two bytes");
    while (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            continue;
        return fail(6, "waitpid failed");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return fail(6, "child did not exit cleanly");
    return 0;
}

int main(int argc, char **argv)
{
    const char *marker = getenv("SHARUN_FIXTURE_MARKER");
    const char *sharun_dir = getenv("SHARUN_DIR");
    const char *name;
    volatile double angle = 0.0;
    int rc;
    void *handle;
    void *thread_result;
    pthread_t thread;
    probe_value_fn lookup;

    if (argc != 1)
        return fail(1, "the launcher passed extra arguments");
    if (marker == NULL || strcmp(marker, "ok") != 0)
        return fail(1, "SHARUN_FIXTURE_MARKER unset; .env was not applied");
    if (sharun_dir == NULL || *sharun_dir == '\0')
        return fail(1, "SHARUN_DIR unset; the launcher found no bundle root");
    name = strrchr(argv[0], '/');
    if (name == NULL || strcmp(name + 1, "probe") != 0)
        return fail(2, "argv[0] does not name the probe");
    if (strcmp(probe_library_value(), "sharun-library-ok") != 0)
        return fail(2, "DT_NEEDED libprobe.so gave the wrong value");
    handle = dlopen("libprobe-dlopen.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return fail(3, dlerror());
    lookup = (probe_value_fn) dlsym(handle, "probe_dlopen_value");
    if (lookup == NULL)
        return fail(4, dlerror());
    if (strcmp(lookup(), "sharun-dlopen-ok") != 0)
        return fail(4, "the dlopened DSO gave the wrong value");

    /* Checked like every other loader step: unmapping is the teardown half of
     * what this probe exists to cover, and discarding the result would let a
     * bundle whose DSO cannot be unloaded still report success.
     */
    if (dlclose(handle) != 0)
        return fail(4, dlerror());
    if (cos(angle) != 1.0)
        return fail(5, "libm cos(0.0) did not return 1.0");

    /* pthread_create returns the error code rather than setting errno, so
     * strerror needs the return value, not errno.
     */
    rc = pthread_create(&thread, NULL, thread_value, (void *) argv);
    if (rc != 0)
        return fail(5, strerror(rc));
    if (pthread_join(thread, &thread_result) != 0 ||
        thread_result != (void *) argv)
        return fail(5, "pthread_join lost the thread return value");
    rc = check_process();
    if (rc != 0)
        return rc;
    puts("sharun-probe-ok");
    return 0;
}
