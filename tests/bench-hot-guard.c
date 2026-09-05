/*
 * Hot-syscall guardrail bench
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal bench that measures thirteen labels. The guardrail script extracts
 * twelve of them by name and holds each to a ceiling; hvc-floor is reported for
 * the log rather than gated, for the reason its own comment gives below.
 *
 *   getpid          (raw SVC; shim identity fast path)
 *   clock_gettime   (vDSO trampoline; see -DGUARD_USE_LIBC_CG below)
 *   read-urandom1   (raw read; shim urandom ring fast path)
 *   futex-eagain    (raw FUTEX_WAIT on a moved word; shim futex fast path)
 *   hvc-floor       (a futex command the host does not implement; the HVC
 *                    round trip and dispatch with no syscall work under it)
 *   stat-path       (full SVC round trip through guest_read_path)
 *   pipe-roundtrip  (write + read on a pipe; the read/write transfer path)
 *   pipe-eagain     (read of an empty nonblocking pipe; per-transfer cost)
 *   fd-create       (open + close; fd_init_entry including its path work)
 *   pipe-create     (pipe + close; the same allocation without a path)
 *   pipe-bulk       (a megabyte into a pipe a sibling drains)
 *   getpid-mt       (the identity path with a sibling thread alive)
 *   pipe-eagain-mt  (the transfer path with a sibling thread alive)
 *
 * The last three run after the single-threaded cases, so nothing above pays for
 * a second thread existing.
 *
 * Built twice from this single source:
 *   build/bench-hot-guard       -- static glibc. Compiled without
 *       -DGUARD_USE_LIBC_CG: clock_gettime calls the vDSO trampoline
 *       directly via its function-pointer address resolved through
 *       AT_SYSINFO_EHDR. Static glibc never initializes
 *       dl_sysinfo_dso, so its libc clock_gettime wrapper falls back
 *       to raw SVC (~2000 ns/op) regardless of trampoline health --
 *       measuring it would fail the 50 ns ceiling for reasons that
 *       have nothing to do with the vDSO. Direct call isolates the
 *       trampoline.
 *   build/bench-hot-guard-glibc -- dynamic glibc. Compiled with
 *       -DGUARD_USE_LIBC_CG so clock_gettime invokes the libc
 *       wrapper, which on glibc 2.41 + a correctly-stamped vDSO
 *       (NT_GNU_ABI_TAG present, LINUX_2.6.39 versioning) routes the
 *       call through the same trampoline. The guardrail's 50 ns
 *       ceiling here is exactly the "did glibc accept the vDSO?"
 *       regression check called out in the TODO baseline: if the
 *       PT_NOTE or versioning regresses, this measurement jumps to
 *       SVC time and the guardrail fails. The cross-toolchain sysroot
 *       must be passed via --sysroot at runtime.
 *
 * Output format mirrors bench-hot-syscalls.c:
 *
 *   name<padding> XX.X ns/op  last=N
 *
 * so the guardrail's awk extractor reads identical labels across both variants.
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);

typedef long (*bench_fn_t)(void *ctx);

typedef struct {
    const char *name;
    bench_fn_t fn;
    void *ctx;
} bench_case_t;

typedef struct {
    clock_gettime_fn fn;
    struct timespec ts;
} cg_ctx_t;

static uint32_t sysv_hash(const char *name)
{
    uint32_t h = 0, g;
    while (*name) {
        h = (h << 4) + (unsigned char) *name++;
        g = h & 0xf0000000U;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* Walk the vDSO ELF at AT_SYSINFO_EHDR and return the absolute address of
 * __kernel_clock_gettime, or NULL if anything is missing.
 */
static clock_gettime_fn resolve_vdso_clock_gettime(void)
{
    unsigned long base = getauxval(AT_SYSINFO_EHDR);
    if (!base)
        return NULL;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *) base;
    const Elf64_Phdr *ph =
        (const Elf64_Phdr *) ((const uint8_t *) eh + eh->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *) ((const uint8_t *) eh + ph[i].p_offset);
            break;
        }
    }
    if (!dyn)
        return NULL;

    const Elf64_Sym *st = NULL;
    const char *str = NULL;
    const uint32_t *hsh = NULL;
    for (; dyn->d_tag; dyn++) {
        const uint8_t *p = (const uint8_t *) eh + dyn->d_un.d_ptr;
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            st = (const Elf64_Sym *) p;
            break;
        case DT_STRTAB:
            str = (const char *) p;
            break;
        case DT_HASH:
            hsh = (const uint32_t *) p;
            break;
        default:
            break;
        }
    }
    if (!st || !str || !hsh)
        return NULL;

    uint32_t nbucket = hsh[0];
    uint32_t nchain = hsh[1];
    const uint32_t *bucket = &hsh[2];
    const uint32_t *chain = &bucket[nbucket];
    const char *name = "__kernel_clock_gettime";
    uint32_t h = sysv_hash(name) % nbucket;
    for (uint32_t i = bucket[h]; i && i < nchain; i = chain[i]) {
        if (strcmp(&str[st[i].st_name], name) == 0)
            return (clock_gettime_fn) (base + st[i].st_value);
    }
    return NULL;
}

static uint64_t monotonic_ns(clock_gettime_fn cg)
{
    struct timespec ts;
    if (cg(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* A lane that cannot be set up must not simply vanish from the output. The
 * guardrail treats an absent label as a deterministic MISS and does not retry
 * it, so a transient malloc or thread failure would read exactly like a
 * regression. Say which lane and why, and exit non-zero so the run is a setup
 * failure rather than a measurement.
 *
 * The error comes in as an argument because pthread_create reports through its
 * return value and is not required to touch errno; musl does not, so reading
 * errno here would print whatever the last unrelated call left behind.
 */
static void bench_setup_failed(const char *lane, const char *what, int err)
{
    fprintf(stderr, "bench-hot-guard: %s unavailable: %s failed: %s\n", lane,
            what, strerror(err));
    exit(2);
}

static long bench_getpid(void *ctx)
{
    (void) ctx;
    return (long) syscall(SYS_getpid);
}

static long bench_clock_gettime(void *ctx)
{
    cg_ctx_t *c = ctx;
#ifdef GUARD_USE_LIBC_CG
    /* Dynamic glibc build: exercise the libc wrapper so the NT_GNU_ABI_TAG /
     * LINUX_2.6.39 vDSO routing is validated end to end. If glibc falls back to
     * SVC (broken note / version regress) this measurement jumps to ~2000 ns
     * and the guardrail fails.
     */
    (void) c->fn;
    return clock_gettime(CLOCK_MONOTONIC, &c->ts);
#else
    /* Static build (no dl_sysinfo_dso): call the trampoline directly via the
     * resolved function pointer.
     */
    return c->fn(CLOCK_MONOTONIC, &c->ts);
#endif
}

/* Held at 1 while both futex lanes below ask for 0, so neither can block. */
static int futex_word = 1;

/* A futex command the host does not implement (FUTEX_FD), so sys_futex reaches
 * its ENOSYS default having done nothing. That is the HVC round trip and the
 * dispatch, with no syscall work under it: the price of admission for anything
 * the host answers.
 *
 * Reported but deliberately not gated. The regression worth catching here is
 * per-iteration work added to the vCPU run loop for the guest main thread only,
 * which is what a setitimer-backed alarm around every hv_vcpu_run once was: two
 * syscalls per guest syscall, about 38 percent of this row, invisible for as
 * long as every measurement was quoted against a floor that included it.
 *
 * A ratio against getpid does not gate it honestly. getpid is served at EL1 and
 * never pays the round trip, so under host load this row inflates and getpid
 * does not: measured 40x idle against 89x on a loaded box. Any ceiling loose
 * enough not to flake is looser than the regression.
 *
 * The load-invariant form is this same measurement taken on a worker vCPU
 * thread beside the main-thread one, since both pay the round trip and the
 * difference is exactly the main-thread-only work. That needs a case that runs
 * on the sibling rather than beside it, which this harness does not express;
 * the -mt cases run on the main thread with a sibling alive. Until then the row
 * is a number in the make check log rather than a gate, which is still better
 * than living in a bench nothing runs.
 */
static long bench_hvc_floor(void *ctx)
{
    (void) ctx;
    return syscall(__NR_futex, &futex_word, 2 /* FUTEX_FD, unimplemented */, 0,
                   NULL, NULL, 0);
}

/* The futex lane: an untimed FUTEX_WAIT whose word already moved, which the EL1
 * shim answers with EAGAIN without the HVC round trip.
 *
 * A step function like the identity and urandom lanes: served it is ~51 ns, and
 * any bail to the host lands past 2000 ns. Nothing else in the suite covers it,
 * so a regression that merely stopped serving would otherwise pass every gate.
 */
static long bench_futex_eagain(void *ctx)
{
    (void) ctx;
    return syscall(__NR_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0,
                   NULL, NULL, 0);
}

static long bench_read_urandom1(void *ctx)
{
    int fd = *(int *) ctx;
    unsigned char byte;
    return read(fd, &byte, 1);
}

/* The transfer lane: one byte out and the same byte back through a pipe, so
 * each iteration is two guest read/write syscalls over a fd that can block,
 * with the data always ready.
 *
 * This is the path every guest doing real work spends its time on, and until
 * this lane existed nothing here measured it: the other four are served by the
 * shim, the vDSO, or the path helpers, and a 30-50% regression in the
 * read/write transfer path passed the guardrail clean. It regresses as a slope
 * (a host call or a lock acquisition added per transfer), which is why it is
 * checked as a ratio to getpid like stat-path rather than absolutely.
 */
typedef struct {
    int rd, wr;
} pipe_ctx_t;

/* The same transfer path with the data movement and the wakeup taken out: a
 * read of an empty pipe the guest itself set nonblocking. It reaches the fd
 * lookup, the block-state decision and the transfer attempt, and returns EAGAIN
 * without touching the pipe buffer or waking anybody, so it measures
 * per-transfer overhead with far less scheduling noise than the round trip.
 */
static long bench_pipe_eagain(void *ctx)
{
    pipe_ctx_t *p = ctx;
    char c;
    return read(p->rd, &c, 1);
}

static long bench_pipe_roundtrip(void *ctx)
{
    pipe_ctx_t *p = ctx;
    char c = 'x';
    if (write(p->wr, &c, 1) != 1)
        return -1;
    return read(p->rd, &c, 1);
}

/* The bulk lane: a large write into a pipe a sibling thread is draining, so the
 * write fills the buffer, waits, and resumes. That wait-and-resume loop is what
 * a single-byte transfer never reaches, and it is where the ready-poll rewrite
 * left a regression the other lanes could not see: measured 21-31% slower than
 * the parent commit, filed as a P2 with no lane to hold it. This is that lane.
 *
 * Reported as ns/op over a fixed transfer size, so a slope in the retry loop
 * shows up directly rather than through a ratio.
 */
#define BULK_BYTES (1u << 20)

typedef struct {
    int rd, wr;
    unsigned char *buf;
} bulk_ctx_t;

static void *bulk_drain(void *arg)
{
    bulk_ctx_t *b = arg;
    unsigned char sink[65536];
    for (;;) {
        ssize_t n = read(b->rd, sink, sizeof(sink));
        if (n <= 0)
            break;
    }
    return NULL;
}

static long bench_pipe_bulk(void *ctx)
{
    bulk_ctx_t *b = ctx;
    size_t sent = 0;
    while (sent < BULK_BYTES) {
        ssize_t n = write(b->wr, b->buf + sent, BULK_BYTES - sent);
        if (n <= 0)
            return -1;
        sent += (size_t) n;
    }
    return (long) sent;
}

/* The same per-transfer op as pipe-eagain, with a sibling thread alive.
 *
 * elfuse takes fd_lock on the fd-table reads it can skip when only one thread
 * is running (thread_is_single_active), so every lane above measures the
 * lock-free path exclusively. A guest doing real work has more than one thread,
 * and a lock added to the transfer path would be invisible here without this.
 */
static void *idle_sibling(void *arg)
{
    volatile int *stop = arg;
    while (!*stop) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* fd creation with the path work taken out: pipe() makes two descriptors from
 * nothing, so what is left is the table allocation itself. Both slots run
 * fd_init_entry, which decides O_NONBLOCK ownership with two fcntls inside the
 * fd-table lock; the open-based lane below cannot see that cost under the path
 * resolution it also pays.
 */
static long bench_pipe_create(void *ctx)
{
    (void) ctx;
    int p[2];
    if (pipe(p) != 0)
        return -1;
    close(p[0]);
    close(p[1]);
    return 0;
}

/* The fd-creation lane: open and close the same path, so each iteration runs a
 * full fd_init_entry, which stats the host fd and may set O_NONBLOCK on it,
 * both inside the fd-table lock. Nothing else here allocates a descriptor.
 */
static long bench_fd_create(void *ctx)
{
    (void) ctx;
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

/* The path-resolving lane. Every syscall that takes a path pays guest_read_path
 * (guest_read_str_small, then guest_read_str), and stat pays a
 * guest_write_small for the result struct on top, so this is the densest
 * guest-copy caller a one-line bench can reach. The other three cases are all
 * served by the shim or the vDSO and never touch those helpers, which is how a
 * 45% regression in them once passed this guardrail unnoticed.
 */
static long bench_stat_path(void *ctx)
{
    struct stat *st = ctx;
    return stat("/dev/null", st);
}

static void run_case(clock_gettime_fn cg,
                     const bench_case_t *bc,
                     unsigned long iters)
{
    /* Discard a warmup pass. Without it the first case in the table absorbs
     * every one-time cost in the run: first-touch faults on the guest stack,
     * the initial urandom ring fill, and the page tables the path resolver
     * walks once. getpid runs first and was reading 50 ns warm against 62 to 72
     * ns cold, a 40% swing on the lane the stat-path ratio divides by, which is
     * enough to hide a real regression in the numerator.
     */
    unsigned long warmup = iters / 20;
    if (warmup < 1000)
        warmup = 1000;
    if (warmup > iters)
        warmup = iters;
    for (unsigned long i = 0; i < warmup; i++)
        (void) bc->fn(bc->ctx);

    uint64_t start = monotonic_ns(cg);
    long last = 0;
    for (unsigned long i = 0; i < iters; i++)
        last = bc->fn(bc->ctx);
    uint64_t elapsed = monotonic_ns(cg) - start;
    double ns_per_op = (double) elapsed / (double) iters;
    printf("%-20s %10.1f ns/op  last=%ld\n", bc->name, ns_per_op, last);
}

int main(int argc, char **argv)
{
    /* Line-buffered stdout so each completed case is visible immediately when
     * stdout is piped or captured.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    unsigned long iters = 50000;
    if (argc > 1)
        iters = strtoul(argv[1], NULL, 10);
    if (iters == 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 1;
    }

    clock_gettime_fn vdso_cg = resolve_vdso_clock_gettime();
    if (!vdso_cg) {
        fprintf(stderr,
                "could not resolve __kernel_clock_gettime via "
                "AT_SYSINFO_EHDR\n");
        return 1;
    }

    int urandomfd = open("/dev/urandom", O_RDONLY);
    if (urandomfd < 0) {
        perror("open /dev/urandom");
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        close(urandomfd);
        return 1;
    }

    int eagain_fd[2];
    if (pipe(eagain_fd) != 0) {
        perror("pipe");
        close(pipefd[0]);
        close(pipefd[1]);
        close(urandomfd);
        return 1;
    }
    fcntl(eagain_fd[0], F_SETFL, fcntl(eagain_fd[0], F_GETFL) | O_NONBLOCK);
    pipe_ctx_t eagain_ctx = {.rd = eagain_fd[0], .wr = eagain_fd[1]};

    cg_ctx_t cg_ctx = {.fn = vdso_cg};
    struct stat stat_buf;
    pipe_ctx_t pipe_ctx = {.rd = pipefd[0], .wr = pipefd[1]};
    const bench_case_t cases[] = {
        {"getpid", bench_getpid, NULL},
        {"clock_gettime", bench_clock_gettime, &cg_ctx},
        {"read-urandom1", bench_read_urandom1, &urandomfd},
        {"futex-eagain", bench_futex_eagain, NULL},
        {"hvc-floor", bench_hvc_floor, NULL},
        {"stat-path", bench_stat_path, &stat_buf},
        {"pipe-roundtrip", bench_pipe_roundtrip, &pipe_ctx},
        {"pipe-eagain", bench_pipe_eagain, &eagain_ctx},
        {"fd-create", bench_fd_create, NULL},
        {"pipe-create", bench_pipe_create, NULL},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        run_case(vdso_cg, &cases[i], iters);

    /* The bulk lane needs a reader on the other end, and the sibling lane needs
     * a thread that is merely alive. Both run after the single-threaded cases
     * so nothing above pays for a second thread existing.
     */
    int bulk_fd[2];
    unsigned char *bulk_buf = malloc(BULK_BYTES);
    if (bulk_buf && pipe(bulk_fd) == 0) {
        memset(bulk_buf, 0x5a, BULK_BYTES);
        bulk_ctx_t bulk_ctx = {
            .rd = bulk_fd[0], .wr = bulk_fd[1], .buf = bulk_buf};
        pthread_t drain;
        int rc_drain = pthread_create(&drain, NULL, bulk_drain, &bulk_ctx);
        if (rc_drain == 0) {
            /* A megabyte per op, so far fewer iterations than the syscall
             * lanes; the guardrail divides by its own count.
             */
            unsigned long bulk_iters = iters / 200 ? iters / 200 : 1;
            bench_case_t bulk = {"pipe-bulk", bench_pipe_bulk, &bulk_ctx};
            run_case(vdso_cg, &bulk, bulk_iters);
            close(bulk_fd[1]);
            pthread_join(drain, NULL);
            close(bulk_fd[0]);
        } else {
            bench_setup_failed("pipe-bulk", "pthread_create", rc_drain);
            close(bulk_fd[0]);
            close(bulk_fd[1]);
        }
    } else {
        bench_setup_failed("pipe-bulk", bulk_buf ? "pipe" : "malloc", errno);
    }
    free(bulk_buf);

    volatile int stop = 0;
    pthread_t sibling;
    int rc_sibling =
        pthread_create(&sibling, NULL, idle_sibling, (void *) &stop);
    if (rc_sibling == 0) {
        bench_case_t mt[] = {
            {"getpid-mt", bench_getpid, NULL},
            {"pipe-eagain-mt", bench_pipe_eagain, &eagain_ctx},
        };
        for (size_t i = 0; i < sizeof(mt) / sizeof(mt[0]); i++)
            run_case(vdso_cg, &mt[i], iters);
        stop = 1;
        pthread_join(sibling, NULL);
    } else {
        bench_setup_failed("getpid-mt/pipe-eagain-mt", "pthread_create",
                           rc_sibling);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(eagain_fd[0]);
    close(eagain_fd[1]);
    close(urandomfd);
    return 0;
}
