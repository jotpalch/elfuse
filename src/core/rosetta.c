/*
 * x86_64-via-Apple-Rosetta translator setup.
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * rosetta_prepare loads the Apple Rosetta binary into the primary buffer at a
 * low GPA and exposes it at its statically-linked high VA (0x800000000000) via
 * a non-identity mem_region_t.va_base. The TTBR1 kbuf is initialized at a 256
 * MiB window just below the rosetta image. rosetta_finalize wires the
 * bootstrap-visible pieces needed to enter the translator: binary fd setup,
 * binfmt-style argv construction, cmdline refresh, and the TTBR0 kbuf alias.
 * The runtime still depends on the high-VA mmap path in mem.c for Rosetta's own
 * slab and JIT allocations.
 *
 * Elfuse extends mem_region_t with a va_base field instead, so the page-table
 * builder handles non-identity placement in a single pass.
 */

#include "core/rosetta.h"

#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include <CommonCrypto/CommonDigest.h>

#include "core/elf.h"
#include "core/guest.h"
#include "debug/log.h"
#include "hvutil.h"
#include "utils.h"
#include "syscall/internal.h" /* fd_alloc_from, fd_publish_linux_flags, FD_REGULAR */
#include "syscall/proc.h" /* proc_set_cmdline */

/* The VZ_CAPS payload only has room for a 42-byte inline path. Publish
 * /proc/self/fd/<bin_guest_fd> there when the real host path is longer so
 * rosetta sees a valid reopenable path without truncation, while the host-side
 * translator subprocess still retains the full original binary path. Both
 * buffers are read by the VZ_CAPS ioctl handler from any vCPU; writes happen
 * during rosetta_finalize on execve. A pthread_mutex covers both setter and
 * snapshot reader so a multi-vCPU guest doing concurrent execves cannot observe
 * a torn or stale string.
 */
static pthread_mutex_t rosettad_path_lock = PTHREAD_MUTEX_INITIALIZER;
static char rosettad_binary_path[PATH_MAX];
static char rosettad_caps_binary_path[ROSETTA_CAPS_BINARY_PATH_LEN];
static char rosettad_owned_binary_path[PATH_MAX];

/* Move any owned path out of rosettad_owned_binary_path into out (which the
 * caller can then unlink after dropping the lock).
 *
 * Returns true if a path was drained. The path lock must be held by the caller.
 * The unlink itself is deferred to the caller because it can block on slow
 * filesystems (NFS, FUSE), and the path lock is also taken by the VZ_CAPS
 * snapshot helpers on every vCPU; running the syscall inside the critical
 * section would stall those readers.
 */
static bool rosettad_drain_owned_path_locked(char out[PATH_MAX])
{
    if (rosettad_owned_binary_path[0] == '\0')
        return false;
    memcpy(out, rosettad_owned_binary_path, PATH_MAX);
    rosettad_owned_binary_path[0] = '\0';
    return true;
}

void rosettad_set_binary_path(const char *path,
                              bool take_ownership,
                              int bin_guest_fd)
{
    if (!path)
        path = "";
    size_t n = strlen(path);

    char prev_owned[PATH_MAX];
    bool have_prev_owned;

    pthread_mutex_lock(&rosettad_path_lock);

    have_prev_owned = rosettad_drain_owned_path_locked(prev_owned);

    size_t full_n = n;
    if (full_n >= sizeof(rosettad_binary_path)) {
        log_warn("rosetta: full binary path too long, truncating: %s", path);
        full_n = sizeof(rosettad_binary_path) - 1;
    }
    memcpy(rosettad_binary_path, path, full_n);
    rosettad_binary_path[full_n] = '\0';

    const char *caps_path = path;
    char fd_path[sizeof("/proc/self/fd/") + 11];
    if (n >= sizeof(rosettad_caps_binary_path)) {
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", bin_guest_fd);
        caps_path = fd_path;
        log_debug("rosetta: using %s as caps binary path for long target %s",
                  caps_path, path);
    }
    size_t caps_n = strlen(caps_path);
    memcpy(rosettad_caps_binary_path, caps_path, caps_n);
    rosettad_caps_binary_path[caps_n] = '\0';

    if (take_ownership)
        str_copy_trunc(rosettad_owned_binary_path, path,
                       sizeof(rosettad_owned_binary_path));

    pthread_mutex_unlock(&rosettad_path_lock);

    if (have_prev_owned)
        unlink(prev_owned);
}

void rosettad_clear_binary_path(void)
{
    char prev_owned[PATH_MAX];
    bool have_prev_owned;

    pthread_mutex_lock(&rosettad_path_lock);
    have_prev_owned = rosettad_drain_owned_path_locked(prev_owned);
    rosettad_binary_path[0] = '\0';
    rosettad_caps_binary_path[0] = '\0';
    pthread_mutex_unlock(&rosettad_path_lock);

    if (have_prev_owned)
        unlink(prev_owned);
}

/* Common body for the two snapshot helpers below. Copies src into out_buf with
 * NUL termination while holding the rosetta path lock so the reader cannot
 * observe a torn write from a concurrent execve.
 */
static size_t rosettad_snapshot_locked(const char *src,
                                       char *out_buf,
                                       size_t out_size)
{
    if (!out_buf || out_size == 0)
        return 0;
    pthread_mutex_lock(&rosettad_path_lock);
    size_t n = strlen(src);
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out_buf, src, n);
    out_buf[n] = '\0';
    pthread_mutex_unlock(&rosettad_path_lock);
    return n;
}

/* Snapshot the host-side full path; out_buf is sized PATH_MAX by callers. */
size_t rosettad_snapshot_binary_path(char *out_buf, size_t out_size)
{
    return rosettad_snapshot_locked(rosettad_binary_path, out_buf, out_size);
}

/* Snapshot the VZ_CAPS 42-byte path; caller buffer is at least
 * ROSETTA_CAPS_BINARY_PATH_LEN bytes wide.
 */
size_t rosettad_snapshot_caps_binary_path(char *out_buf, size_t out_size)
{
    return rosettad_snapshot_locked(rosettad_caps_binary_path, out_buf,
                                    out_size);
}

int rosetta_prepare(guest_t *g,
                    const char *binary_path,
                    mem_region_t *regions,
                    int *nregions,
                    int max_regions,
                    bool verbose,
                    rosetta_result_t *result)
{
    (void) binary_path; /* used only by rosetta_finalize */

    if (!g || !regions || !nregions || !result)
        return -1;
    memset(result, 0, sizeof(*result));

    if (access(ROSETTA_PATH, X_OK) != 0) {
        log_error(
            "rosetta: x86_64 binary requires the Rosetta Linux "
            "translator at %s",
            ROSETTA_PATH);
        log_error("rosetta: install via 'softwareupdate --install-rosetta'");
        return -1;
    }

    if (elf_load(ROSETTA_PATH, &result->rosetta_info) < 0) {
        log_error("rosetta: failed to load rosetta ELF from %s", ROSETTA_PATH);
        return -1;
    }
    elf_info_t *ri = &result->rosetta_info;
    if (verbose) {
        log_debug("rosetta: ELF entry=0x%llx load=[0x%llx,0x%llx)",
                  (unsigned long long) ri->entry,
                  (unsigned long long) ri->load_min,
                  (unsigned long long) ri->load_max);
    }

    /* Compute 2 MiB-aligned placement covering all rosetta PT_LOAD segments.
     * rosetta is statically linked at 0x800000000000; segments span a small
     * range above that. The mapping must cover the entire span so all segments
     * resolve through a single Stage-2 region.
     */
    uint64_t va_base = ALIGN_2MIB_DOWN(ri->load_min);
    uint64_t va_limit = ALIGN_2MIB_UP(ri->load_max);
    if (va_limit <= va_base) {
        log_error("rosetta: empty load range");
        return -1;
    }
    uint64_t size = va_limit - va_base;

    /* Pick a primary-buffer placement below the full high-IPA infra reserve, 2
     * MiB aligned. guest_init() has already reserved [interp_base -
     * INFRA_RESERVE, interp_base) for the page-table pool, shim text, and shim
     * data, so rosetta must stay below that window.
     *
     * HVF on M1 caps Stage-2 hv_vm_map at the hardware-default IPA width (36
     * bits on this host); a separate Stage-2 mapping at 128 TiB via
     * guest_add_mapping is rejected with HV_BAD_ARGUMENT. Load rosetta into the
     * primary buffer at a low GPA and use the non-identity page-table mapping
     * (mem_region_t.va_base) to expose it at its statically-linked high VA.
     */
    uint64_t guest_base;
    if (g->rosetta_guest_base == 0) {
        uint64_t rosetta_limit, infra_top;
        guest_infra_window(g, &rosetta_limit, &infra_top);
        if (g->interp_base < INFRA_RESERVE || rosetta_limit < size) {
            log_error(
                "rosetta: primary buffer too small for rosetta image "
                "(%llu MiB) below infra reserve [0x%llx,0x%llx)",
                (unsigned long long) (size >> 20),
                (unsigned long long) rosetta_limit,
                (unsigned long long) infra_top);
            return -1;
        }
        guest_base = ALIGN_2MIB_DOWN(rosetta_limit - size);
        if (guest_base < g->stack_top + BLOCK_2MIB) {
            log_error(
                "rosetta: no image gap between stack_top=0x%llx and "
                "rosetta@0x%llx",
                (unsigned long long) g->stack_top,
                (unsigned long long) guest_base);
            return -1;
        }

        /* Load rosetta into the primary buffer: the [va_base, ...) window of
         * the image lands at guest_base. Passing the pair rather than a
         * pre-subtracted base keeps the arithmetic free of wraparound.
         */
        uint64_t infra_lo, infra_hi;
        guest_infra_window(g, &infra_lo, &infra_hi);
        if (elf_map_segments(ri, ROSETTA_PATH, g->host_base, g->guest_size,
                             (elf_window_t) {va_base, guest_base}, infra_lo,
                             infra_hi) < 0) {
            log_error("rosetta: elf_map_segments failed");
            return -1;
        }

        /* Place TTBR1 kbuf in the primary buffer just below the rosetta image.
         * The kbuf needs to fit in [kbuf_gpa, kbuf_gpa + 256 MiB); brk and
         * stack live below it, rosetta above. Validate the gap before
         * subtracting so the underflow case (guest_base near 0) cannot wrap
         * into a huge uint64_t that defeats the gap check.
         */
        if (guest_base < KBUF_SIZE + g->stack_top + BLOCK_2MIB) {
            log_error(
                "rosetta: no kbuf gap between stack_top=0x%llx and "
                "rosetta@0x%llx",
                (unsigned long long) g->stack_top,
                (unsigned long long) guest_base);
            return -1;
        }
        uint64_t kbuf_gpa = ALIGN_2MIB_DOWN(guest_base - KBUF_SIZE);
        if (guest_init_kbuf(g, kbuf_gpa) < 0) {
            log_error("rosetta: guest_init_kbuf failed at 0x%llx",
                      (unsigned long long) kbuf_gpa);
            return -1;
        }

        g->rosetta_guest_base = guest_base;
        g->rosetta_va_base = va_base;
        g->rosetta_size = size;
        g->rosetta_entry = ri->entry;

        if (verbose) {
            log_debug(
                "rosetta: GPA=0x%llx VA=0x%llx size=%llu MiB "
                "kbuf_gpa=0x%llx ttbr1=0x%llx",
                (unsigned long long) guest_base, (unsigned long long) va_base,
                (unsigned long long) (size >> 20),
                (unsigned long long) g->kbuf_gpa,
                (unsigned long long) g->ttbr1);
        }
    } else {
        /* execve re-entry. The placement (guest_base, va_base, kbuf_gpa)
         * survived guest_reset; the PT pool was zeroed so the TTBR1 tree must
         * be rebuilt. Segments get reloaded in place.
         */
        guest_base = g->rosetta_guest_base;
        uint64_t infra_lo, infra_hi;
        guest_infra_window(g, &infra_lo, &infra_hi);
        if (elf_map_segments(ri, ROSETTA_PATH, g->host_base, g->guest_size,
                             (elf_window_t) {va_base, guest_base}, infra_lo,
                             infra_hi) < 0) {
            log_error("rosetta: re-entry elf_map_segments failed");
            return -1;
        }
        if (g->kbuf_base)
            memset(g->kbuf_base, 0, KBUF_SIZE);
        if (guest_init_kbuf(g, g->kbuf_gpa) < 0) {
            log_error("rosetta: re-entry guest_init_kbuf failed");
            return -1;
        }
    }

    /* I-cache invalidation for the loaded executable segments. macOS wrote the
     * bytes via the data side; without explicit invalidation the first
     * execution can hit stale I-cache entries.
     */
    for (int i = 0; i < ri->num_segments; i++) {
        if (!(ri->segments[i].flags & PF_X))
            continue;
        uint64_t seg_offset = ri->segments[i].gpa - va_base;
        if (seg_offset > size || ri->segments[i].memsz > size - seg_offset) {
            log_error("rosetta: segment %d out of placement bounds", i);
            return -1;
        }
        sys_icache_invalidate(
            (uint8_t *) g->host_base + guest_base + seg_offset,
            ri->segments[i].memsz);
    }

    /* One mem_region_t covering the whole rosetta image with the union of
     * segment permissions. The page-table builder honours va_base for
     * non-identity placement: entry indices come from va_base + offset, block
     * descriptors point at guest_base + offset (the primary buffer). RWX is
     * acceptable because rosetta is a static binary whose JIT writes code into
     * separate mmap regions (not into its own image).
     */
    int perms = MEM_PERM_R;
    for (int i = 0; i < ri->num_segments; i++) {
        if (ri->segments[i].flags & PF_W)
            perms |= MEM_PERM_W;
        if (ri->segments[i].flags & PF_X)
            perms |= MEM_PERM_X;
    }
    if (*nregions >= max_regions) {
        log_error("rosetta: page-table region table exhausted");
        return -1;
    }
    regions[(*nregions)++] = (mem_region_t) {
        .gpa_start = guest_base,
        .gpa_end = guest_base + size,
        .va_base = va_base,
        .perms = perms,
    };

    result->entry_point = ri->entry;
    return 0;
}

int rosetta_finalize(guest_t *g,
                     hv_vcpu_t vcpu,
                     const char *binary_host_path,
                     bool binary_host_path_temp,
                     const char *binary_guest_path,
                     int guest_argc,
                     const char **guest_argv,
                     const rosetta_result_t *rr,
                     bool verbose,
                     int *out_argc,
                     const char ***out_argv,
                     uint64_t *out_vdso_addr,
                     int *out_execfd)
{
    (void) vcpu;          /* TCR_EL1 / TTBR1_EL1 set in bootstrap_create_vcpu */
    (void) out_vdso_addr; /* bootstrap drives vdso_build directly */

    if (!g || !binary_host_path || !binary_guest_path || !rr || !out_argc ||
        !out_argv || !out_execfd)
        return -1;
    *out_argc = 0;
    *out_argv = NULL;
    *out_execfd = -1;

    /* Defer every externally-visible state change (guest binary fd, cmdline,
     * out_argc/out_argv) until after every fallible setup step succeeds. Any
     * failure before commit goes through the fail label and tears down only the
     * host-local resources allocated so far.
     */
    const char **rosetta_argv = NULL;
    int rosetta_argc = 0;

    /* Pre-open the x86_64 binary so it can be installed at a guest fd once the
     * full setup succeeds. Rosetta locates its target via the VZ_CAPS binary
     * path (the full guest path, or /proc/self/fd/<execfd> when that path does
     * not fit the 42-byte inline field) plus AT_EXECFD (binfmt_misc
     * convention). This is the first fallible step, so every goto fail below
     * sees bin_host_fd already set (open returns -1 on failure, which the fail
     * label treats as nothing to close).
     */
    int bin_host_fd = open(binary_host_path, O_RDONLY);
    if (bin_host_fd < 0) {
        log_error("rosetta_finalize: failed to open binary '%s': %s",
                  binary_host_path, strerror(errno));
        goto fail;
    }

    /* Construct binfmt_misc-style argv. The lossy form is chosen here:
     *   argv = [ROSETTA_PATH, binary_path, original_argv[1..argc-1], NULL]
     *
     * Rosetta uses argv[1] (the binary path) as the guest's argv[0] after
     * stripping the first two slots. Trade-offs vs the preserving form:
     *   + busybox applet dispatch (basename(argv[0])) works because the
     *     guest sees argv[0] == binary_path, and that path's basename is
     *     the applet name.
     *   - login shells that rely on the leading-dash argv[0] convention
     *     (-sh, -bash) lose the dash.
     *   - execve(path, "altname", ...) loses "altname"; the guest sees
     *     binary_path as argv[0].
     * If a real workload surfaces either pain point, switch to the preserving
     * form (4 slots: rosetta, binary, original_argv[0], original_argv[1..]) and
     * verify rosetta strips both leading slots rather than one.
     *
     * Minimum argc is 2 (rosetta + binary) so rosetta always sees argv[1] even
     * when the caller supplied no argv.
     */
    rosetta_argc = (guest_argc > 0) ? guest_argc + 1 : 2;
    rosetta_argv = malloc(sizeof(char *) * (rosetta_argc + 1));
    if (!rosetta_argv) {
        log_error("rosetta_finalize: malloc(%d argv slots) failed",
                  rosetta_argc + 1);
        goto fail;
    }
    rosetta_argv[0] = ROSETTA_PATH;
    rosetta_argv[1] = binary_guest_path;
    for (int i = 1; i < guest_argc; i++)
        rosetta_argv[i + 1] = guest_argv[i];
    rosetta_argv[rosetta_argc] = NULL;

    /* Install the TTBR0 user-VA alias for the kbuf so rosetta's TaggedPointer
     * extraction (which strips bits 63:48) resolves to the same physical pages
     * as the TTBR1 kernel-VA window. The aliasing-proof invariant (RW + UXN +
     * PXN under both mappings) is enforced inside the helper. An
     * installed-but-unused alias is harmless (read-write pages aliasing the
     * same physical kbuf), so the commit step below does not need to roll it
     * back if a later allocation fails.
     */
    if (guest_install_kbuf_user_alias(g) < 0) {
        log_error("rosetta_finalize: failed to install TTBR0 kbuf alias");
        goto fail;
    }

    /* Install the guest binary fd last so any earlier failure unwinds without
     * needing to roll back the ownership transfer. fd_alloc_from is the final
     * fallible step; once it succeeds, the host fd is owned by the guest fd
     * table and no goto fail must be introduced below, or the fail handler
     * would double-close it.
     *
     * Use the lowest free non-stdio slot rather than a hardcoded fd 3: at
     * initial launch only stdio (0-2) is open, so this still lands on 3, but on
     * an execve re-bootstrap the guest may already hold fd 3 for its own use
     * (apt hands gpgv a status pipe on fd 3). Evicting it would break the
     * child; the dynamic slot steps over whatever the guest already opened.
     *
     * On an exec re-bootstrap this runs past execve's point of no return, where
     * an fd_alloc_from failure would be fatal. sys_execve preflights slot
     * availability via fd_reexec_slot_available(3) before guest_reset and
     * returns -EMFILE there, so an exhausted table fails gracefully instead of
     * aborting mid-exec. The guest fd ceiling sits below the host
     * RLIMIT_NOFILE, so the pre-PNR elf_load host open does not catch this
     * first; the preflight is the real guard and this branch is the backstop.
     */
    int bin_guest_fd = fd_alloc_from(3, FD_REGULAR, bin_host_fd, NULL, NULL);
    if (bin_guest_fd < 0) {
        log_error("rosetta_finalize: fd_alloc_from(3) failed");
        goto fail;
    }

    /* Ownership of bin_host_fd is now held by the guest fd table. Mark the
     * rosetta target fd CLOEXEC so a rosetta-to-native execve does not leak it
     * into the new image. Publish through the fd_lock helper rather than a bare
     * store so this writer stays on the same lock domain as every other
     * linux_flags mutator; fd_alloc_from zero-initialized the slot, so setting
     * the flag outright is correct.
     */
    fd_publish_linux_flags(bin_guest_fd, LINUX_O_CLOEXEC);

    rosettad_set_binary_path(binary_host_path, binary_host_path_temp,
                             bin_guest_fd);
    proc_set_cmdline(rosetta_argc, rosetta_argv);

    if (verbose)
        log_debug("rosetta_finalize: argv=[%s, %s, ...], target_fd=%d",
                  rosetta_argv[0], rosetta_argv[1], bin_guest_fd);

    *out_argc = rosetta_argc;
    *out_argv = rosetta_argv;
    *out_execfd = bin_guest_fd;

    /* The VZ ioctl trio is in; the rosettad translate pipeline and the mem.c
     * body refactor for rosetta high-VA mmap allocations are still pending.
     * Without rosettad, rosetta issues a translate request, hits the socketpair
     * where the handler returns MISS, and exits. Without the high-VA mmap
     * support, rosetta's slab allocator at 240 TiB cannot back its JIT memory
     * and aborts in VMAllocationTracker.
     */
    log_debug(
        "rosetta_finalize: setup complete; runtime path still needs "
        "rosettad bridge + high-VA mmap support");
    return 0;

fail:
    if (bin_host_fd >= 0)
        close(bin_host_fd);
    free(rosetta_argv);
    return -1;
}

/* SHA-256 over a file descriptor */

/* Streaming chunk for digesting a binary fd; matches the typical filesystem
 * read-ahead window so a few syscalls cover most x86_64 ELFs.
 */
#define ROSETTAD_SHA256_CHUNK 65536

static int compute_fd_sha256(int fd, uint8_t digest[ROSETTAD_DIGEST_SIZE])
{
    off_t saved = lseek(fd, 0, SEEK_CUR);
    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    uint8_t buf[ROSETTAD_SHA256_CHUNK];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        CC_SHA256_Update(&ctx, buf, (CC_LONG) n);

    if (saved >= 0)
        (void) lseek(fd, saved, SEEK_SET);
    if (n < 0)
        return -1;

    CC_SHA256_Final(digest, &ctx);
    return 0;
}

/* AOT cache paths */

/* Build <HOME>/.cache/elfuse-rosettad[/suffix] into out. When suffix is NULL,
 * write the bare cache directory; otherwise append "/<suffix>". Lazily creates
 * ~/.cache and the elfuse-rosettad subdirectory; EEXIST on either is fine.
 *
 * Returns 0 on success, -1 on any failure (HOME unset, snprintf truncation,
 * mkdir denied for a reason other than EEXIST).
 */
static int aot_cache_path(const char *suffix, char *out, size_t outsz)
{
    const char *home = getenv("HOME");
    if (!home || !*home)
        return -1;

    /* Make ~/.cache first (fresh-user case), then the elfuse subdirectory. The
     * intermediate path lives in a scratch buffer so out is only written once
     * -- callers may pass the same buffer for both phases.
     */
    char parent[PATH_MAX];
    int pn = snprintf(parent, sizeof(parent), "%s/.cache", home);
    if (pn > 0 && (size_t) pn < sizeof(parent))
        (void) mkdir(parent, 0755);

    char dir[PATH_MAX];
    int dn = snprintf(dir, sizeof(dir), "%s/%s", home, ROSETTAD_CACHE_SUBDIR);
    if (dn < 0 || (size_t) dn >= sizeof(dir))
        return -1;
    if (mkdir(dir, 0755) < 0 && errno != EEXIST)
        return -1;

    int n = suffix ? snprintf(out, outsz, "%s/%s", dir, suffix)
                   : snprintf(out, outsz, "%s", dir);
    if (n < 0 || (size_t) n >= outsz)
        return -1;
    return 0;
}

/* Convenience: build the persistent <cache>/<hex><suffix> path for a digest.
 * suffix is appended verbatim (".aot", ".aot.new.<pid>", etc.).
 */
static int aot_cache_path_for_digest(const uint8_t digest[ROSETTAD_DIGEST_SIZE],
                                     const char *suffix,
                                     char *out,
                                     size_t outsz)
{
    char hex[ROSETTAD_DIGEST_HEX_LEN];
    bytes_to_hex(hex, digest, ROSETTAD_DIGEST_SIZE);
    char leaf[ROSETTAD_DIGEST_HEX_LEN + 32];
    int ln = snprintf(leaf, sizeof(leaf), "%s%s", hex, suffix ? suffix : "");
    if (ln < 0 || (size_t) ln >= sizeof(leaf))
        return -1;
    return aot_cache_path(leaf, out, outsz);
}

/* Open the cached AOT file for a binary with the given digest.
 *
 * Returns the open fd (O_RDONLY) on hit, -1 on miss or any other error. The fd
 * is positioned at offset 0 so the caller can hand it straight back via
 * SCM_RIGHTS.
 */
static int aot_cache_lookup(const uint8_t digest[ROSETTAD_DIGEST_SIZE])
{
    char path[PATH_MAX];
    if (aot_cache_path_for_digest(digest, ".aot", path, sizeof(path)) < 0)
        return -1;
    return open(path, O_RDONLY);
}

/* Materialise the current bytes behind bin_fd into a temp file in the cache
 * directory so the translator reads the same inode contents that were hashed.
 * The caller owns out_path on success and must unlink it after use.
 */
static int aot_materialize_input_fd(int bin_fd, char out_path[PATH_MAX])
{
    if (aot_cache_path("input.XXXXXX", out_path, PATH_MAX) < 0)
        return -1;

    /* Not tmpfile_anon: the translate subprocess opens this scratch file by
     * pathname, since in_path is handed to it in argv, so it cannot be
     * anonymous. It is unlinked once the translation is done; the file that
     * gets renamed into the cache is the translator's output, not this one.
     */
    int out_fd = mkstemp(out_path);
    if (out_fd < 0)
        return -1;

    off_t saved = lseek(bin_fd, 0, SEEK_CUR);
    if (lseek(bin_fd, 0, SEEK_SET) < 0) {
        close(out_fd);
        (void) unlink(out_path);
        return -1;
    }

    uint8_t buf[ROSETTAD_SHA256_CHUNK];
    int rc = -1;
    for (;;) {
        ssize_t nr = read(bin_fd, buf, sizeof(buf));
        if (nr < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        if (nr == 0)
            break;

        uint8_t *p = buf;
        ssize_t remaining = nr;
        while (remaining > 0) {
            ssize_t nw = write(out_fd, p, (size_t) remaining);
            if (nw < 0) {
                if (errno == EINTR)
                    continue;
                goto out;
            }
            p += nw;
            remaining -= nw;
        }
    }

    rc = 0;

out:
    if (saved >= 0)
        (void) lseek(bin_fd, saved, SEEK_SET);
    if (close(out_fd) < 0 && rc == 0)
        rc = -1;
    if (rc < 0)
        (void) unlink(out_path);
    return rc;
}

/* Translator publishes via rename() of its temp file -- a content copy is
 * unnecessary because the AOT output is already in the cache directory. Keeping
 * the cache-store step as a single rename inline in rosettad_translate; a
 * separate copy helper would only be needed for paths that produce the AOT
 * bytes outside the cache directory.
 */

/* SCM_RIGHTS fd-passing */

/* Receive exactly one fd alongside buflen bytes of normal data. On success
 * returns the number of normal bytes received and writes the fd to *out_fd.
 * EINTR is retried. The protocol requires exactly one SCM_RIGHTS cmsg carrying
 * exactly one fd; anything weaker (truncation, extra cmsgs, multiple fds, wrong
 * cmsg payload size) is a malformed peer and rejected. On rejection any
 * kernel-allocated fds are closed to avoid leaking them into the elfuse
 * process.
 */
static ssize_t rosettad_recv_fd(int sock, void *buf, size_t buflen, int *out_fd)
{
    *out_fd = -1;
    struct iovec iov = {.iov_base = buf, .iov_len = buflen};
    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    ssize_t n;
    do {
        n = recvmsg(sock, &msg, 0);
    } while (n < 0 && errno == EINTR);
    if (n <= 0)
        return n;

    /* Take ownership of every fd the kernel delivered so none leak, then accept
     * only the exact single-fd case. cmsg_buf is CMSG_SPACE(sizeof(int)): one
     * fd on macOS, but CMSG alignment lets an LP64 kernel pack two into the
     * same space, so read into distinct slots and close any surplus on reject.
     */
    int fds[sizeof(cmsg_buf) / sizeof(int)];
    size_t nfd = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len >= CMSG_LEN(0)) {
        size_t payload = cmsg->cmsg_len - CMSG_LEN(0);

        /* Cap by the fds that actually fit after the header so a corrupt
         * cmsg_len cannot drive the memcpy source past the end of cmsg_buf.
         */
        size_t cap = (sizeof(cmsg_buf) - CMSG_LEN(0)) / sizeof(int);
        if (payload % sizeof(int) == 0) {
            nfd = payload / sizeof(int);
            if (nfd > cap)
                nfd = cap;
            memcpy(fds, CMSG_DATA(cmsg), nfd * sizeof(int));
        }
    }

    /* Well-formed means exactly one fd, no truncation, no extra cmsg.
     * MSG_CTRUNC means the peer sent more ancillary data than cmsg_buf could
     * hold; a trailing cmsg means more than the one expected fd. nfd == 1
     * short-circuits before CMSG_NXTHDR so a NULL cmsg is never dereferenced.
     */
    bool accept =
        nfd == 1 && !(msg.msg_flags & MSG_CTRUNC) && !CMSG_NXTHDR(&msg, cmsg);
    if (!accept) {
        for (size_t i = 0; i < nfd; i++)
            close(fds[i]);
        errno = EPROTO;
        return -1;
    }
    *out_fd = fds[0];
    return n;
}

/* Send one fd alongside a 1-byte normal-data payload. Rosetta's recv_fd
 * counterpart allocates a 1-byte iov buffer and silently drops anything larger;
 * matching that exactly keeps the protocol bit-compatible.
 */
static ssize_t rosettad_send_fd(int sock, uint8_t payload, int send_fd)
{
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &send_fd, sizeof(int));
    ssize_t n;
    do {
        n = sendmsg(sock, &msg, 0);
    } while (n < 0 && errno == EINTR);
    return n;
}

/* Translate subprocess */

/* Spawn 'elfuse rosettad translate <in_path> <out_path>' and wait for it to
 * exit.
 *
 * Returns 0 if the translator exited successfully and the output file is
 * non-empty, -1 otherwise.
 */
static int translate_via_rosettad(const char *in_path, const char *out_path)
{
    const char *self = proc_get_elfuse_path();
    if (!self) {
        log_error(
            "rosettad: cannot locate elfuse binary for translate "
            "subprocess");
        return -1;
    }
    char *argv[] = {
        (char *) self,    (char *) "rosettad", (char *) "translate",
        (char *) in_path, (char *) out_path,   NULL,
    };
    pid_t pid;
    extern char **environ;
    if (posix_spawn(&pid, self, NULL, NULL, argv, environ) != 0) {
        log_error("rosettad: posix_spawn failed: %s", strerror(errno));
        return -1;
    }

    /* Bounded wait: a hung translator must not stall the handler thread that
     * owns the rosetta socket. ROSETTAD_TRANSLATE_TIMEOUT_SEC bounds the
     * wall-clock budget; on expiry, SIGKILL the child and report MISS to the
     * caller so rosetta falls through to its JIT path. Override via the
     * ELFUSE_ROSETTAD_TIMEOUT env var (seconds) for stress testing.
     */
    int timeout_sec = 120;
    const char *to_env = getenv("ELFUSE_ROSETTAD_TIMEOUT");
    if (to_env && *to_env) {
        long v = strtol(to_env, NULL, 10);
        if (v > 0 && v < 3600)
            timeout_sec = (int) v;
    }
    int status = 0;
    pid_t r = 0;
    int waited_ms = 0;
    const int poll_ms = 50;
    while (waited_ms < timeout_sec * 1000) {
        r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            break;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            log_error("rosettad: waitpid failed: %s", strerror(errno));
            return -1;
        }
        struct timespec sleep_req = {.tv_sec = 0,
                                     .tv_nsec = poll_ms * 1000000L};
        nanosleep(&sleep_req, NULL);
        waited_ms += poll_ms;
    }
    if (r != pid) {
        log_error(
            "rosettad: translate subprocess timed out after %d s, "
            "killing pid %d",
            timeout_sec, (int) pid);
        kill(pid, SIGKILL);
        do {
            r = waitpid(pid, &status, 0);
        } while (r < 0 && errno == EINTR);
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_error("rosettad: translate subprocess exited %d (status=0x%x)",
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1, status);
        return -1;
    }
    struct stat st;
    if (stat(out_path, &st) < 0 || st.st_size == 0) {
        log_error("rosettad: translate produced empty/missing output");
        return -1;
    }
    return 0;
}

/* Run the translate pipeline for a binary fd: SHA-256, cache lookup (hit ->
 * return cached fd), or spawn the translator and publish the result.
 *
 * Returns an O_RDONLY fd pointing at the AOT file on success, -1 on any
 * failure. *out_digest is always written when the SHA-256 succeeds; the caller
 * passes it back to rosetta so subsequent 'd' lookups reuse the same key.
 */
static int rosettad_translate(int bin_fd,
                              uint8_t out_digest[ROSETTAD_DIGEST_SIZE])
{
    /* Materialise first, hash second. Hashing bin_fd directly and then copying
     * its bytes later opens a TOCTOU window: a concurrent writer mutating the
     * inode between the two reads can poison the cache with bytes whose digest
     * does not match. Snapshot the contents into an elfuse-owned temp file,
     * then compute the digest from that snapshot so (hash, bytes) are taken
     * from the same on-disk state.
     */
    char in_path[PATH_MAX];
    if (aot_materialize_input_fd(bin_fd, in_path) < 0) {
        log_error("rosettad: failed to materialize translate input");
        return -1;
    }

    int in_fd = open(in_path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        log_error("rosettad: failed to reopen translate input: %s",
                  strerror(errno));
        (void) unlink(in_path);
        return -1;
    }
    if (compute_fd_sha256(in_fd, out_digest) < 0) {
        log_error("rosettad: digest of translate input failed");
        close(in_fd);
        (void) unlink(in_path);
        return -1;
    }
    close(in_fd);

    int cached = aot_cache_lookup(out_digest);
    if (cached >= 0) {
        (void) unlink(in_path);
        return cached;
    }

    char tmp_suffix[32];
    if (snprintf(tmp_suffix, sizeof(tmp_suffix), ".aot.new.%d",
                 (int) getpid()) < 0) {
        (void) unlink(in_path);
        return -1;
    }
    char tmp_path[PATH_MAX];
    if (aot_cache_path_for_digest(out_digest, tmp_suffix, tmp_path,
                                  sizeof(tmp_path)) < 0) {
        (void) unlink(in_path);
        return -1;
    }

    if (translate_via_rosettad(in_path, tmp_path) < 0) {
        (void) unlink(in_path);
        (void) unlink(tmp_path);
        return -1;
    }
    (void) unlink(in_path);

    int aot_fd = open(tmp_path, O_RDONLY);
    if (aot_fd < 0) {
        (void) unlink(tmp_path);
        return -1;
    }

    /* Publish to the persistent cache; if rename fails another translator is
     * racing this one, but aot_fd still points at the temp file's data and is
     * safe to return.
     */
    char final_path[PATH_MAX];
    if (aot_cache_path_for_digest(out_digest, ".aot", final_path,
                                  sizeof(final_path)) == 0) {
        if (rename(tmp_path, final_path) < 0)
            (void) unlink(tmp_path);
    }
    return aot_fd;
}

/* rosettad handler thread */

/* Maximum size of the per-translate params buffer rosetta sends alongside the
 * binary fd. The protocol allows up to this many bytes of opaque data; the
 * handler reads them but does not interpret them today.
 */
#define ROSETTAD_PARAMS_MAX 256

/* Rosetta's view of the socketpair: the fd it received via sys_socket. Recorded
 * so sys_connect / recvmsg / sendmsg can short-circuit the connect (the
 * socketpair is pre-wired) and pick rosettad-aware paths. Static visibility: at
 * most one rosettad bridge per elfuse process.
 *
 * The handler thread writes -1 to this field at termination while syscall
 * threads keep reading it via rosettad_is_socket. Plain int would let the
 * compiler tear or fold the load; atomic load/store with relaxed ordering is
 * enough since each read is independent of any other state.
 */
static _Atomic int rosettad_client_fd = -1;

bool rosettad_is_socket(int host_fd)
{
    int active =
        atomic_load_explicit(&rosettad_client_fd, memory_order_relaxed);
    return host_fd >= 0 && host_fd == active;
}

bool rosettad_wait_for_idle(unsigned int max_ms)
{
    /* 1 ms granularity poll on the atomic. The handler thread clears the marker
     * on EOF or on explicit QUIT; both paths run inside the detached worker,
     * which the caller cannot join.
     */
    for (unsigned int i = 0; i < max_ms; i++) {
        if (atomic_load_explicit(&rosettad_client_fd, memory_order_acquire) ==
            -1)
            return true;
        usleep(1000);
    }
    return atomic_load_explicit(&rosettad_client_fd, memory_order_acquire) ==
           -1;
}

static int rosettad_write_byte(int fd, uint8_t b)
{
    return write_all(fd, &b, 1);
}

/* Send the success reply for a TRANSLATE or DIGEST command: {HIT byte, optional
 * 32-byte digest, AOT fd via SCM_RIGHTS in a 1-byte iov}. Pass digest=NULL on
 * the DIGEST path (rosetta already knows the key).
 * Returns 0 on success, -1 if any wire write failed.
 */
static int rosettad_send_aot(int fd, const uint8_t *digest, int aot_fd)
{
    if (rosettad_write_byte(fd, ROSETTAD_RESP_HIT) < 0)
        return -1;
    if (digest && write_all(fd, digest, ROSETTAD_DIGEST_SIZE) < 0)
        return -1;
    if (rosettad_send_fd(fd, 0, aot_fd) < 0)
        return -1;
    return 0;
}

static void *rosettad_handler_thread(void *arg)
{
    int fd = (int) (intptr_t) arg;

    /* Block the host-directed signals elfuse uses internally so the handler
     * thread is not interrupted in the middle of a protocol exchange. The
     * SIGPIPE / SIGCHLD masking matches the rest of elfuse's worker threads;
     * SIGUSR1 is the vCPU timer kick.
     */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    for (;;) {
        uint8_t cmd;
        ssize_t n;
        do {
            n = read(fd, &cmd, 1);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            break;

        switch (cmd) {
        case ROSETTAD_CMD_HANDSHAKE:
            /* Reply HIT so rosetta proceeds with the AOT-aware code path. */
            if (rosettad_write_byte(fd, ROSETTAD_RESP_HIT) < 0)
                goto done;
            break;

        case ROSETTAD_CMD_TRANSLATE: {
            /* Translate request: rosetta sends the binary fd via sendmsg with
             * up to ROSETTAD_PARAMS_MAX bytes of params. Compute the SHA-256,
             * look up the persistent AOT cache, and on miss invoke the
             * translator subprocess. Reply is {HIT, digest[32], fd via
             * SCM_RIGHTS in a 1-byte iov payload} or MISS on any failure.
             *
             * recv_fd failure means protocol desync (no way to tell what
             * rosetta did or did not send): close the connection. Translate
             * failure is recoverable -- reply MISS and keep serving.
             */
            uint8_t params[ROSETTAD_PARAMS_MAX];
            int bin_fd = -1;
            ssize_t rn = rosettad_recv_fd(fd, params, sizeof(params), &bin_fd);
            if (rn <= 0 || bin_fd < 0) {
                if (bin_fd >= 0)
                    close(bin_fd);
                (void) rosettad_write_byte(fd, ROSETTAD_RESP_MISS);
                goto done;
            }
            uint8_t digest[ROSETTAD_DIGEST_SIZE];
            int aot_fd = rosettad_translate(bin_fd, digest);
            close(bin_fd);
            if (aot_fd < 0) {
                if (rosettad_write_byte(fd, ROSETTAD_RESP_MISS) < 0)
                    goto done;
                break;
            }
            int sr = rosettad_send_aot(fd, digest, aot_fd);
            close(aot_fd);
            if (sr < 0)
                goto done;
            break;
        }

        case ROSETTAD_CMD_DIGEST: {
            /* Digest lookup: rosetta caches its own .flu digests across runs
             * and asks here first to skip re-translation. Cache hit sends back
             * the AOT fd; miss makes rosetta fall through to a full translate
             * request.
             */
            uint8_t digest[ROSETTAD_DIGEST_SIZE];
            if (read_all(fd, digest, sizeof(digest), false) !=
                (ssize_t) sizeof(digest))
                goto done;
            int cached = aot_cache_lookup(digest);
            if (cached < 0) {
                if (rosettad_write_byte(fd, ROSETTAD_RESP_MISS) < 0)
                    goto done;
                break;
            }
            int sr = rosettad_send_aot(fd, NULL, cached);
            close(cached);
            if (sr < 0)
                goto done;
            break;
        }

        case ROSETTAD_CMD_QUIT:
            goto done;

        default:
            /* Unknown command: reply MISS to keep the wire balanced and hope
             * rosetta recovers. A real cache miss / handshake noise landing in
             * this branch would otherwise hang the protocol.
             */
            if (rosettad_write_byte(fd, ROSETTAD_RESP_MISS) < 0)
                goto done;
            break;
        }
    }

done:
    /* Drop the client-fd marker so rosettad_is_socket stops misclassifying a
     * recycled fd number. The actual client fd was closed by the guest (or will
     * be) -- this just retracts the bridge claim. The handler does not race
     * with sys_socket starting another bridge: at most one rosetta bridge per
     * elfuse process by design.
     */
    atomic_store_explicit(&rosettad_client_fd, -1, memory_order_relaxed);
    close(fd);
    return NULL;
}

int rosettad_start_handler(int handler_fd, int client_fd)
{
    if (handler_fd < 0 || client_fd < 0)
        return -1;

    /* Only one bridge per process is supported. Claim the slot via a single
     * atomic compare-exchange so two threads cannot both observe -1 and then
     * race to install their own client fd; the loser sees the winner's fd
     * loaded into 'expected' and fails out cleanly.
     */
    int expected = -1;
    if (!atomic_compare_exchange_strong_explicit(
            &rosettad_client_fd, &expected, client_fd, memory_order_acq_rel,
            memory_order_relaxed)) {
        log_error("rosettad_start_handler: bridge already active on fd %d",
                  expected);
        return -1;
    }

    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&thr, &attr, rosettad_handler_thread,
                            (void *) (intptr_t) handler_fd);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        log_error("rosettad_start_handler: pthread_create failed: %s",
                  strerror(rc));
        atomic_store_explicit(&rosettad_client_fd, -1, memory_order_release);
        return -1;
    }
    return 0;
}
