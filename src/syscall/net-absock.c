/*
 * Abstract AF_UNIX emulation helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "utils.h"

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/net.h"
#include "syscall/net-abi.h"
#include "syscall/net-absock.h"
#include "syscall/path.h"

#define ABSOCK_MAX_ENTRIES 64
#define ABSOCK_MAX_NAME 107

/* Derived-name budget shared by both namers: a literal prefix capped at
 * ABSOCK_PREFIX_MAX bytes for debuggability, then ABSOCK_DIGEST_HEX hex
 * characters of 64-bit FNV-1a that never truncate.
 */
#define ABSOCK_PREFIX_MAX 20
#define ABSOCK_DIGEST_HEX 16
/* Linux struct sockaddr_un carries at most 108 sun_path bytes. */
#define LINUX_UNIX_PATH_MAX 108

/* Width of the leading sun_family field, so the offset at which sun_path begins
 * and the length arithmetic around it cannot drift apart.
 */
#define LINUX_SA_FAMILY_LEN 2

typedef struct {
    int guest_fd;
    uint8_t name[ABSOCK_MAX_NAME];
    uint32_t name_len;
    char fs_path[104];
    bool active;
} absock_entry_t;

static pthread_mutex_t absock_lock = PTHREAD_MUTEX_INITIALIZER;
static absock_entry_t absock_table[ABSOCK_MAX_ENTRIES];
static char absock_dir[128];
static bool absock_dir_created;
static _Atomic uint64_t absock_namespace_id;
static _Atomic uint32_t absock_autobind_counter;

/* Shortening links this process minted, recorded so exit unlinks exactly its
 * own: links are per-process property (the pid-scoped name guarantees no other
 * process shares one), so no sweep over the shared directory is needed and none
 * may run, because a sweep cannot tell a sibling's live link from a leftover.
 * Guarded by absock_lock.
 */
#define ABSOCK_MAX_LINKS 64
static char absock_links[ABSOCK_MAX_LINKS][104];
static int absock_link_count;

static void absock_cleanup(void);

/* Spell the namespace directory for @namespace_id. Shared so a reader can name
 * the directory without depending on this process being the one that created
 * it, which is not the same thing: fork spawns a fresh process that inherits
 * the id and reads back sockaddrs pointing into the shared dir.
 */
static int absock_dir_format(char *out, size_t out_sz, uint64_t namespace_id)
{
    return snprintf(out, out_sz, "/tmp/elfuse-absock-%llu",
                    (unsigned long long) namespace_id);
}

static int absock_ensure_dir_locked(void)
{
    uint64_t namespace_id =
        atomic_load_explicit(&absock_namespace_id, memory_order_relaxed);

    if (absock_dir_created) {
        struct stat st;

        /* The directory is removed by whichever namespace participant exits
         * last, and this process may outlive that: its cached flag then points
         * at a directory that is gone, and every later mint would die with
         * ENOENT. Recreate instead; create_private_dir tolerates EEXIST and
         * re-validates ownership, and the atexit hook is already armed.
         */
        if (lstat(absock_dir, &st) == 0)
            return 0;
        return create_private_dir(absock_dir);
    }

    if (namespace_id == 0) {
        namespace_id = (uint64_t) getpid();
        atomic_store_explicit(&absock_namespace_id, namespace_id,
                              memory_order_relaxed);
    }
    absock_dir_format(absock_dir, sizeof(absock_dir), namespace_id);

    /* The namespace-id path is guessable; create_private_dir rejects a
     * pre-planted symlink or foreign-owned directory in world-writable /tmp.
     */
    if (create_private_dir(absock_dir) < 0)
        return -1;

    /* Arm the exit sweep here, the one point where on-disk namespace state
     * first appears. Every producer of that state (abstract bind, autobind,
     * connect rewrite, and the pathname-socket shortening links) reaches the
     * dir through this function, so a single registration covers them all.
     * Reaching this line already means absock_dir_created was false and the
     * directory was just created, and it is set below and never cleared, so
     * this runs exactly once and needs no separate guard.
     */
    atexit(absock_cleanup);

    absock_dir_created = true;
    return 0;
}

uint64_t absock_get_namespace_id(void)
{
    uint64_t namespace_id =
        atomic_load_explicit(&absock_namespace_id, memory_order_relaxed);
    if (namespace_id == 0)
        return (uint64_t) getpid();
    return namespace_id;
}

void absock_set_namespace_id(uint64_t namespace_id)
{
    if (namespace_id == 0)
        namespace_id = (uint64_t) getpid();
    atomic_store_explicit(&absock_namespace_id, namespace_id,
                          memory_order_relaxed);
}

void absock_encode_name(const char *dir,
                        const uint8_t *name,
                        uint32_t len,
                        char *out,
                        size_t out_sz)
{
    size_t dir_len = strlen(dir);
    size_t max_hex = out_sz - dir_len - 2;
    size_t hex_needed = (size_t) len * 2;

    size_t pos = (size_t) snprintf(out, out_sz, "%s/", dir);
    if (hex_needed <= max_hex) {
        for (uint32_t i = 0; i < len && pos + 2 < out_sz; i++)
            pos += (size_t) snprintf(out + pos, out_sz - pos, "%02x", name[i]);
    } else {
        /* The digest never truncates: the literal prefix shrinks to fit
         * instead, because the prefix is debuggability while the digest is the
         * only collision resistance a long name gets.
         */
        size_t avail = out_sz > pos + ABSOCK_DIGEST_HEX + 1
                           ? out_sz - pos - ABSOCK_DIGEST_HEX - 1
                           : 0;
        uint32_t prefix_bytes = avail / 2 < ABSOCK_PREFIX_MAX
                                    ? (uint32_t) (avail / 2)
                                    : ABSOCK_PREFIX_MAX;

        if (prefix_bytes > len)
            prefix_bytes = len;
        for (uint32_t i = 0; i < prefix_bytes; i++)
            pos += (size_t) snprintf(out + pos, out_sz - pos, "%02x", name[i]);
        snprintf(out + pos, out_sz - pos, "%016llx",
                 (unsigned long long) fnv1a64(name, len));
    }
}

int absock_link_name(const char *dir,
                     const char *host_path,
                     char *out,
                     size_t out_sz)
{
    size_t len = strlen(host_path);
    int n = snprintf(out, out_sz, "%s/p%d-", dir, (int) getpid());

    if (n < 0 || (size_t) n >= out_sz ||
        out_sz - (size_t) n < ABSOCK_DIGEST_HEX + 1) {
        errno = ENAMETOOLONG;
        return -1;
    }

    size_t pos = (size_t) n;
    size_t avail = out_sz - pos - ABSOCK_DIGEST_HEX - 1;
    size_t prefix_bytes =
        avail / 2 < ABSOCK_PREFIX_MAX ? avail / 2 : ABSOCK_PREFIX_MAX;

    if (prefix_bytes > len)
        prefix_bytes = len;
    for (size_t i = 0; i < prefix_bytes; i++)
        pos += (size_t) snprintf(out + pos, out_sz - pos, "%02x",
                                 (unsigned char) host_path[i]);
    snprintf(out + pos, out_sz - pos, "%016llx",
             (unsigned long long) fnv1a64(host_path, len));
    return 0;
}

static const char *absock_lookup_locked(const uint8_t *name, uint32_t name_len)
{
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active && absock_table[i].name_len == name_len &&
            !memcmp(absock_table[i].name, name, name_len)) {
            return absock_table[i].fs_path;
        }
    }
    return NULL;
}

static int absock_register_locked(int guest_fd,
                                  const uint8_t *name,
                                  uint32_t name_len,
                                  char *fs_path_out,
                                  size_t fs_path_sz)
{
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (!absock_table[i].active) {
            absock_table[i].guest_fd = guest_fd;
            absock_table[i].name_len = name_len;
            memcpy(absock_table[i].name, name, name_len);
            absock_encode_name(absock_dir, name, name_len,
                               absock_table[i].fs_path,
                               sizeof(absock_table[i].fs_path));
            if (fs_path_out)
                snprintf(fs_path_out, fs_path_sz, "%s",
                         absock_table[i].fs_path);
            return i;
        }
    }
    return -1;
}

void absock_unregister_fd(int guest_fd)
{
    pthread_mutex_lock(&absock_lock);
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active && absock_table[i].guest_fd == guest_fd) {
            unlink(absock_table[i].fs_path);
            absock_table[i].active = false;
        }
    }
    pthread_mutex_unlock(&absock_lock);
}

bool absock_reverse_lookup(const char *fs_path,
                           uint8_t *out_name,
                           uint32_t *out_len)
{
    pthread_mutex_lock(&absock_lock);
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active &&
            !strcmp(absock_table[i].fs_path, fs_path)) {
            *out_len = absock_table[i].name_len;
            memcpy(out_name, absock_table[i].name, absock_table[i].name_len);
            pthread_mutex_unlock(&absock_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&absock_lock);
    return false;
}

int absock_is_abstract_unix(const uint8_t *linux_sa, uint32_t addrlen)
{
    if (addrlen < 4)
        return 0;
    uint16_t fam;
    memcpy(&fam, linux_sa, LINUX_SA_FAMILY_LEN);
    if (fam != LINUX_AF_UNIX)
        return 0;
    return linux_sa[LINUX_SA_FAMILY_LEN] == '\0';
}

static int absock_build_sun(const char *fs_path,
                            struct sockaddr_storage *mac_sa)
{
    struct sockaddr_un *sun = (struct sockaddr_un *) mac_sa;
    memset(sun, 0, sizeof(*sun));
    sun->sun_len = sizeof(*sun);
    sun->sun_family = AF_UNIX;
    size_t path_len = strlen(fs_path);
    if (path_len >= sizeof(sun->sun_path))
        return -1;
    memcpy(sun->sun_path, fs_path, path_len + 1);
    return (int) (offsetof(struct sockaddr_un, sun_path) + path_len + 1);
}

/* Remember a minted link so absock_cleanup can unlink it. Full-table overflow
 * drops the record, never the link: an untracked link leaks until the last
 * participant's rmdir at worst, while refusing the mint would fail a live bind
 * or connect over bookkeeping.
 */
static void absock_record_link_locked(const char *link_path)
{
    for (int i = 0; i < absock_link_count; i++)
        if (!strcmp(absock_links[i], link_path))
            return;
    if (absock_link_count >= ABSOCK_MAX_LINKS)
        return;
    str_copy_trunc(absock_links[absock_link_count], link_path,
                   sizeof(absock_links[0]));
    absock_link_count++;
}

/* Point a short symlink in the private absock dir at an over-long translated
 * socket path so it fits sun_path. bind(2) through a dangling symlink creates
 * the socket at the target and connect(2) follows it (probed on macOS 15). The
 * link name is pid-scoped (absock_link_name), so no two live processes ever
 * share one: a connect re-derives its own link, never a sibling's.
 */
static int absock_shorten_path(const char *host_path, char *out, size_t out_sz)
{
    pthread_mutex_lock(&absock_lock);
    if (absock_ensure_dir_locked() < 0 ||
        absock_link_name(absock_dir, host_path, out, out_sz) < 0) {
        pthread_mutex_unlock(&absock_lock);
        return -1;
    }
    int rc = symlink(host_path, out);

    /* ENOENT here is the namespace directory vanishing between the ensure above
     * and the symlink: another participant exited last and removed it. One
     * re-ensure closes the race; a second loss just fails.
     */
    if (rc < 0 && errno == ENOENT && absock_ensure_dir_locked() == 0)
        rc = symlink(host_path, out);
    if (rc < 0) {
        char existing[LINUX_PATH_MAX];
        ssize_t n = -1;
        if (errno == EEXIST)
            n = readlink(out, existing, sizeof(existing) - 1);
        if (n < 0 || (size_t) n != strlen(host_path) ||
            /* cppcheck-suppress legacyUninitvar
             * Short-circuit || guarantees memcmp only runs when n ==
             * strlen(host_path) and readlink filled exactly
             * existing[0..n-1] on success.
             */
            memcmp(existing, host_path, (size_t) n)) {
            /* A mismatched entry under a pid-scoped name is a leftover from a
             * crashed run whose pid was recycled: no live process can own it,
             * so replacing it is safe.
             */
            (void) unlink(out);
            if (symlink(host_path, out) < 0) {
                pthread_mutex_unlock(&absock_lock);
                return -1;
            }
        }
    }
    absock_record_link_locked(out);
    pthread_mutex_unlock(&absock_lock);
    return 0;
}

/* Reverse-map one returned pathname AF_UNIX address to its guest spelling.
 * Returns the Linux sockaddr length when the address was rewritten, or -1 when
 * it is not a translated pathname and the generic converter should run.
 */
static int absock_sockaddr_un_from_mac(const struct sockaddr_un *sun,
                                       uint32_t mac_len,
                                       uint8_t *linux_sa,
                                       uint32_t linux_sa_size)
{
    /* Bound every read by mac_len: macOS may fill all 104 sun_path bytes with
     * no terminator, and only mac_len bytes of the caller's sockaddr_storage
     * are initialized.
     */
    size_t sp_max = mac_len - offsetof(struct sockaddr_un, sun_path);
    if (sp_max > sizeof(sun->sun_path))
        sp_max = sizeof(sun->sun_path);
    size_t sp_len = strnlen(sun->sun_path, sp_max);
    if (sp_len == 0)
        return -1;
    char mac_path[sizeof(sun->sun_path) + 1];
    memcpy(mac_path, sun->sun_path, sp_len);
    mac_path[sp_len] = '\0';

    /* Undo the over-length shortening symlink, then map the host path back to
     * the guest namespace so the guest reads back the spelling it bound or
     * connected with, not the sysroot-prefixed (and possibly escaped) host
     * path.
     */
    char host_path[LINUX_PATH_MAX];
    str_copy_trunc(host_path, mac_path, sizeof(host_path));

    /* Compare against the whole directory component, not a byte prefix of it:
     * namespace 1234 would otherwise claim the paths of namespace 12345 and
     * readlink a directory it does not own.
     */
    char ns_dir[sizeof(absock_dir)];
    int ns_len =
        absock_dir_format(ns_dir, sizeof(ns_dir), absock_get_namespace_id());
    if (ns_len > 0 && (size_t) ns_len < sizeof(ns_dir) &&
        !strncmp(host_path, ns_dir, (size_t) ns_len) &&
        host_path[ns_len] == '/') {
        char target[LINUX_PATH_MAX];
        ssize_t n = readlink(host_path, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            str_copy_trunc(host_path, target, sizeof(host_path));
        }
    }

    char guest_path[LINUX_PATH_MAX];
    if (path_host_to_guest(host_path, guest_path, sizeof(guest_path)) != 0 ||
        !strcmp(guest_path, mac_path))
        return -1;

    /* Write the Linux sockaddr directly: the guest may have bound a Linux-legal
     * name longer than the 103 usable bytes of a macOS sun_path, and rebuilding
     * a mac sockaddr first would fail for exactly the paths the shortening
     * symlink serves.
     */
    size_t glen = strlen(guest_path);
    if (glen > LINUX_UNIX_PATH_MAX || linux_sa_size < LINUX_SA_FAMILY_LEN)
        return -1;
    uint16_t fam16 = LINUX_AF_UNIX;
    memcpy(linux_sa, &fam16, LINUX_SA_FAMILY_LEN);
    uint32_t avail = linux_sa_size - LINUX_SA_FAMILY_LEN;
    uint32_t copy = (uint32_t) glen;
    if (glen < LINUX_UNIX_PATH_MAX)
        copy++; /* include the terminator, kernel-style */
    if (copy > avail)
        copy = avail;
    memcpy(linux_sa + LINUX_SA_FAMILY_LEN, guest_path, copy);
    return (int) (LINUX_SA_FAMILY_LEN + copy);
}

int net_sockaddr_from_mac(const struct sockaddr *mac_sa,
                          uint32_t mac_len,
                          uint8_t *linux_sa,
                          uint32_t linux_sa_size)
{
    if (mac_sa && mac_len > offsetof(struct sockaddr_un, sun_path) &&
        mac_sa->sa_family == AF_UNIX) {
        int rc =
            absock_sockaddr_un_from_mac((const struct sockaddr_un *) mac_sa,
                                        mac_len, linux_sa, linux_sa_size);
        if (rc >= 0)
            return rc;
    }
    return mac_to_linux_sockaddr(mac_sa, (socklen_t) mac_len, linux_sa,
                                 linux_sa_size);
}

/* linux_errno() reports an int64_t syscall result, while these converters
 * return int to match linux_to_mac_sockaddr, the sibling they stand in for.
 * Every Linux errno is well under 4096 in magnitude, so the narrowing is exact;
 * it is spelled out rather than left implicit so it does not read as an
 * accident, and so -Wnarrowing-style analysis stays quiet about it.
 */
static int absock_errno(void)
{
    return (int) linux_errno();
}

int net_sockaddr_to_mac(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        bool create,
                        struct sockaddr_storage *mac_sa)
{
    uint16_t fam = 0;
    if (addrlen >= LINUX_SA_FAMILY_LEN)
        memcpy(&fam, linux_sa, LINUX_SA_FAMILY_LEN);

    if (fam == LINUX_AF_UNIX && addrlen > LINUX_SA_FAMILY_LEN &&
        linux_sa[LINUX_SA_FAMILY_LEN] != '\0') {
        /* Pathname socket: the name is a filesystem path and must go through
         * sysroot translation like every other path-taking syscall; the raw
         * bytes would name the unrelated host-literal file. Linux permits an
         * unterminated sun_path, so bound the copy by addrlen. A bind uses
         * create semantics, which spell an absent case-protected leaf at its
         * escape, so the socket file lands where stat and connect will look; a
         * name already bound resolves to the occupied spelling and the host
         * bind reports EADDRINUSE, matching Linux.
         */
        char guest_path[LINUX_UNIX_PATH_MAX + 1];
        uint32_t plen = addrlen - LINUX_SA_FAMILY_LEN;
        if (plen > LINUX_UNIX_PATH_MAX)
            return -LINUX_EINVAL;
        memcpy(guest_path, linux_sa + LINUX_SA_FAMILY_LEN, plen);
        guest_path[plen] = '\0';

        path_translation_t tx;
        if (path_translate_at(LINUX_AT_FDCWD, guest_path,
                              create ? PATH_TR_CREATE : PATH_TR_NONE, &tx) < 0)
            return absock_errno();
        if (tx.fuse_path || tx.proc_resolved != 0)
            return -LINUX_ENOSYS;

        /* A shm leaf carries the never-follow rule, but bind(2) and connect(2)
         * take a sockaddr rather than a dirfd and at_flags, so it cannot ride
         * on an open flag here and is checked outright. Following a
         * guest-planted link would bind the socket at the link's target,
         * outside the tree entirely, and would answer connect with ENOTSOCK for
         * a host file that exists against ENOENT for one that does not, telling
         * the guest whether any path exists. Both reach exactly what
         * is_guest_system_path() denies the guest by name. See
         * dev_shm_resolve_path() in procemu.c.
         */
        if (tx.is_dev_shm) {
            struct stat leaf_st;
            if (lstat(tx.host_path, &leaf_st) == 0 && S_ISLNK(leaf_st.st_mode))
                return -LINUX_ELOOP;
        }

        char short_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
        const char *host_path = tx.host_path;
        if (strlen(host_path) >= sizeof(short_path)) {
            /* Surface the real failure (EACCES, EIO, ENOSPC, ...): the guest
             * name is Linux-legal, so reporting ENAMETOOLONG would misattribute
             * a symlink-layer error to the pathname length.
             */
            if (absock_shorten_path(host_path, short_path, sizeof(short_path)) <
                0)
                return absock_errno();
            host_path = short_path;
        }
        int mac_len = absock_build_sun(host_path, mac_sa);
        if (mac_len < 0)
            return -LINUX_ENAMETOOLONG;
        return mac_len;
    }

    int mac_len = linux_to_mac_sockaddr(linux_sa, addrlen, mac_sa);
    return mac_len < 0 ? -LINUX_EINVAL : mac_len;
}

int absock_rewrite_connect(const uint8_t *linux_sa,
                           uint32_t addrlen,
                           struct sockaddr_storage *mac_sa)
{
    const uint8_t *abs_name = linux_sa + 3;
    uint32_t abs_len = addrlen - 3;
    if (abs_len > ABSOCK_MAX_NAME)
        abs_len = ABSOCK_MAX_NAME;

    pthread_mutex_lock(&absock_lock);
    const char *fs_path = absock_lookup_locked(abs_name, abs_len);
    char path_buf[104];
    if (!fs_path) {
        if (absock_ensure_dir_locked() < 0) {
            pthread_mutex_unlock(&absock_lock);
            return -1;
        }
        absock_encode_name(absock_dir, abs_name, abs_len, path_buf,
                           sizeof(path_buf));
        fs_path = path_buf;
    }
    int ret = absock_build_sun(fs_path, mac_sa);
    pthread_mutex_unlock(&absock_lock);
    return ret;
}

int absock_bind_prepare(const uint8_t *linux_sa,
                        uint32_t addrlen,
                        struct sockaddr_storage *mac_sa,
                        int guest_fd,
                        int *out_len)
{
    uint8_t name_buf[ABSOCK_MAX_NAME];
    const uint8_t *abs_name;
    uint32_t abs_len;

    if (addrlen <= 3) {
        uint32_t seq = absock_autobind_counter++;
        abs_len = (uint32_t) snprintf((char *) name_buf, sizeof(name_buf),
                                      "%05x", seq);
        abs_name = name_buf;
    } else {
        abs_name = linux_sa + 3;
        abs_len = addrlen - 3;
        if (abs_len > ABSOCK_MAX_NAME)
            return -1;
    }

    pthread_mutex_lock(&absock_lock);
    if (absock_ensure_dir_locked() < 0) {
        pthread_mutex_unlock(&absock_lock);
        return -1;
    }
    if (absock_lookup_locked(abs_name, abs_len)) {
        pthread_mutex_unlock(&absock_lock);
        return -2;
    }

    char fs_path[104];
    int idx = absock_register_locked(guest_fd, abs_name, abs_len, fs_path,
                                     sizeof(fs_path));
    pthread_mutex_unlock(&absock_lock);
    if (idx < 0)
        return -1;

    *out_len = absock_build_sun(fs_path, mac_sa);
    if (*out_len < 0)
        return -1;
    return idx;
}

void absock_bind_commit(int idx)
{
    pthread_mutex_lock(&absock_lock);
    absock_table[idx].active = true;
    pthread_mutex_unlock(&absock_lock);
}

void absock_bind_rollback(int idx)
{
    pthread_mutex_lock(&absock_lock);
    absock_table[idx].name_len = 0;
    absock_table[idx].guest_fd = -1;
    pthread_mutex_unlock(&absock_lock);
}

static void absock_cleanup(void)
{
    /* Every process unlinks its own table-tracked sockets. A forked child
     * starts from an empty table because fork hands over only the namespace id,
     * so an entry here is never a sibling's.
     */
    for (int i = 0; i < ABSOCK_MAX_ENTRIES; i++) {
        if (absock_table[i].active)
            unlink(absock_table[i].fs_path);
    }

    if (!absock_dir_created)
        return;

    /* Shortening links are per-process property, recorded at mint time, so each
     * process unlinks exactly its own whatever its relation to the namespace
     * owner: a link another process still resolves through is never touched,
     * and a child that minted links after the owner exited leaves nothing
     * behind. An owner-only directory sweep gets both cases wrong, unlinking
     * live siblings' links and skipping the orphan child's.
     */
    for (int i = 0; i < absock_link_count; i++)
        unlink(absock_links[i]);

    /* Any participant may retire the directory, not just the owner: rmdir
     * succeeds only once it is empty, so the last one out removes it and a
     * namespace whose directory was created by a forked child cannot leak.
     */
    rmdir(absock_dir);
}
