/*
 * The per-bus devnum cap keeps minors from crossing bus ranges
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: the fallback devnum assignment and its 127 cap in
 * src/runtime/usb-sysfs.c (usb_minor() encodes devnum-1 as the low 7 bits of
 * the minor, so a 128th device on a bus would land on the next bus's range).
 *
 * Run with ELFUSE_USB_FIXTURE=overflow, which routes 129 address-less devices
 * on bus 1 plus one on bus 2 through the fallback path. Without the cap bus1's
 * 129th device takes devnum 129 and shares minor 128 with bus2's first device;
 * with it, everything past devnum 127 is dropped. The assertions: every device
 * directory has a devnum in 1..127, no two share a (major, minor), and bus 1
 * kept exactly 127 of its 129 while bus 2 kept its one.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define DEVICES_DIR "/sys/bus/usb/devices"

static int read_attr_int(const char *dev, const char *attr)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/%s", DEVICES_DIR, dev, attr);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return (int) strtol(buf, NULL, 10);
}

/* Read the minor from the device's "dev" attribute ("189:MINOR\n"). */
static int read_minor(const char *dev)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/dev", DEVICES_DIR, dev);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    const char *colon = strchr(buf, ':');
    return colon ? (int) strtol(colon + 1, NULL, 10) : -1;
}

int main(void)
{
    printf("test-usb-sysfs-overflow: the per-bus devnum cap\n");

    DIR *d = opendir(DEVICES_DIR);
    if (!d) {
        printf("  cannot open %s\n", DEVICES_DIR);
        printf("\ntest-usb-sysfs-overflow: 0 passed, 1 failed - FAIL\n");
        return 1;
    }

    int minors[512];
    int nminors = 0;
    int bus1 = 0, bus2 = 0;
    bool devnum_ok = true, minor_ok = true, name_ok = true;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        /* Device directories only; interface directories carry a ':'. */
        if (strchr(e->d_name, ':'))
            continue;
        int busnum = read_attr_int(e->d_name, "busnum");
        int devnum = read_attr_int(e->d_name, "devnum");
        int minor = read_minor(e->d_name);
        if (busnum == 1)
            bus1++;
        else if (busnum == 2)
            bus2++;
        if (devnum < 1 || devnum > 127)
            devnum_ok = false;

        /* Every kept device must expose a readable dev minor to compare. */
        if (minor < 0)
            name_ok = false;
        for (int i = 0; i < nminors; i++)
            if (minors[i] == minor)
                minor_ok = false;
        if (nminors < (int) (sizeof(minors) / sizeof(minors[0])))
            minors[nminors++] = minor;
    }
    closedir(d);

    TEST("every device has a devnum in 1..127");
    EXPECT_TRUE(devnum_ok, "a device kept a devnum outside 1..127");

    TEST("no two devices share a minor");
    EXPECT_TRUE(minor_ok, "two devices collided on one minor");

    TEST("every device exposes a dev attribute");
    EXPECT_TRUE(name_ok, "a device had no readable dev minor");

    TEST("bus 1 kept exactly 127 of its 129 devices");
    EXPECT_EQ(bus1, 127, "bus 1 device count wrong");

    TEST("bus 2 kept its single device");
    EXPECT_EQ(bus2, 1, "bus 2 device count wrong");

    SUMMARY("test-usb-sysfs-overflow");
    return fails ? 1 : 0;
}
