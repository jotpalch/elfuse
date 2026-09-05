/*
 * Sysroot capability probing and provisioning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "linux-limits.h"

typedef struct {
    bool active;
    bool detach_on_cleanup;
    char mount_path[LINUX_PATH_MAX];
    char image_path[LINUX_PATH_MAX];
} sysroot_mount_t;

int sysroot_validate_case_sensitivity(const char *path);
int sysroot_probe_case_sensitivity(const char *path,
                                   bool *case_sensitive,
                                   bool *case_preserving);
int sysroot_create_mount(const char *mount_path, sysroot_mount_t *mount);
void sysroot_cleanup_mount(sysroot_mount_t *mount);
int sysroot_ensure_dir_exists(const char *path);
int sysroot_validate_dir_prefix(const char *path);
