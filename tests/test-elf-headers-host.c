/*
 * Native-host unit test for ELF64 header validation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Builds small synthetic ELF64 images on disk and checks the verdict
 * elf_load_fd reaches on each. The cases here are the ones that decide whether
 * a malformed image is rejected while execve can still return ENOEXEC, or is
 * carried far enough to be discovered after the point of no return.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "core/elf.h"
#include "utils.h"

#include "debug/log.h"
#include "host-test-util.h"

/* Dummy log implementation to avoid linking debug/log.o */
void log_impl(int level, const char *file, int line, const char *fmt, ...)
{
    (void) level;
    (void) file;
    (void) line;
    (void) fmt;
}

/* File layout every image here shares: header, then the program header table,
 * then a data area the segments and the PT_INTERP string draw from.
 */
#define PHOFF sizeof(elf64_ehdr_t)
#define MAX_PH 6
#define DATA_OFF (PHOFF + MAX_PH * sizeof(elf64_phdr_t))
#define DATA_LEN 512

typedef struct {
    elf64_ehdr_t ehdr;
    elf64_phdr_t ph[MAX_PH];
    int nph;
    uint8_t data[DATA_LEN];
    size_t truncate_to; /* 0 keeps the whole file */
} image_t;

static void image_init(image_t *img, uint16_t e_type)
{
    memset(img, 0, sizeof(*img));
    img->ehdr.e_ident[0] = ELFMAG0;
    img->ehdr.e_ident[1] = ELFMAG1;
    img->ehdr.e_ident[2] = ELFMAG2;
    img->ehdr.e_ident[3] = ELFMAG3;
    img->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    img->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    img->ehdr.e_type = e_type;
    img->ehdr.e_machine = EM_AARCH64;
    img->ehdr.e_version = 1;
    img->ehdr.e_entry = 0x1000;
    img->ehdr.e_phoff = PHOFF;
    img->ehdr.e_ehsize = sizeof(elf64_ehdr_t);
    img->ehdr.e_phentsize = sizeof(elf64_phdr_t);
}

static elf64_phdr_t *image_add_ph(image_t *img, uint32_t type)
{
    assert(img->nph < MAX_PH);
    elf64_phdr_t *ph = &img->ph[img->nph++];
    img->ehdr.e_phnum = (uint16_t) img->nph;
    ph->p_type = type;
    return ph;
}

/* Add a PT_LOAD covering data_len bytes taken from the data area. */
static elf64_phdr_t *image_add_load(image_t *img,
                                    uint64_t vaddr,
                                    uint64_t filesz,
                                    uint64_t memsz)
{
    elf64_phdr_t *ph = image_add_ph(img, PT_LOAD);
    ph->p_flags = PF_R | PF_X;
    ph->p_offset = DATA_OFF;
    ph->p_vaddr = vaddr;
    ph->p_paddr = vaddr;
    ph->p_filesz = filesz;
    ph->p_memsz = memsz;
    ph->p_align = 0x1000;
    return ph;
}

/* Add a PT_INTERP naming path. filesz overrides the length written into the
 * header, so a caller can drop the NUL or claim bytes the file does not have.
 */
static elf64_phdr_t *image_add_interp(image_t *img,
                                      size_t data_pos,
                                      const char *path,
                                      uint64_t filesz)
{
    size_t len = strlen(path) + 1;
    assert(data_pos + len <= DATA_LEN);
    memcpy(img->data + data_pos, path, len);

    elf64_phdr_t *ph = image_add_ph(img, PT_INTERP);
    ph->p_offset = DATA_OFF + data_pos;
    ph->p_filesz = filesz;
    ph->p_memsz = filesz;
    return ph;
}

static int image_open(const image_t *img)
{
    int fd = tmpfile_anon("elf-headers");
    if (fd < 0) {
        perror("tmpfile_anon");
        exit(1);
    }

    uint8_t file[DATA_OFF + DATA_LEN];
    memset(file, 0, sizeof(file));
    memcpy(file, &img->ehdr, sizeof(img->ehdr));
    memcpy(file + PHOFF, img->ph, (size_t) img->nph * sizeof(img->ph[0]));
    memcpy(file + DATA_OFF, img->data, DATA_LEN);

    size_t len = img->truncate_to ? img->truncate_to : sizeof(file);
    if (write_all(fd, file, len) < 0) {
        perror("write_all");
        exit(1);
    }
    return fd;
}

static const char *current;

#define CHECK(cond) host_check((cond), current, #cond)

/* Parse img and report whether elf_load_fd accepted it. */
static bool parse(const image_t *img, elf_info_t *info)
{
    int fd = image_open(img);
    bool ok = elf_load_fd(fd, "test", info) == 0;
    close(fd);
    return ok;
}

static void test_baseline(void)
{
    current = "baseline dynamic image";
    image_t img;
    elf_info_t info;

    image_init(&img, ET_DYN);
    image_add_load(&img, 0x0000, 256, 256);
    image_add_load(&img, 0x4000, 256, 4096);
    image_add_interp(&img, 300, "/lib/ld-musl-aarch64.so.1", 26);

    CHECK(parse(&img, &info));
    CHECK(info.num_segments == 2);
    CHECK(strcmp(info.interp_path, "/lib/ld-musl-aarch64.so.1") == 0);
    CHECK(info.load_min == 0x0000);
    CHECK(info.load_max == 0x4000 + 4096);
}

static void test_interp_rejections(void)
{
    image_t img;
    elf_info_t info;

    current = "PT_INTERP of zero length";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "/lib/ld.so", 0);
    CHECK(!parse(&img, &info));

    current = "PT_INTERP of one byte";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "/lib/ld.so", 1);
    CHECK(!parse(&img, &info));

    /* The last character is not dropped to make room for a terminator: an
     * unterminated name is a different name, not a shorter one.
     */
    current = "PT_INTERP without its NUL";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "/lib/ld.so", 10);
    CHECK(!parse(&img, &info));

    current = "PT_INTERP with data after its NUL";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "/lib/ld.so", 12);
    img.data[11] = 'x';
    CHECK(!parse(&img, &info));

    current = "PT_INTERP naming the empty string";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "", 1);
    CHECK(!parse(&img, &info));

    /* Terminated where Linux looks for it, and still empty. Accepting this puts
     * an empty interp_path in front of callers that read that as "statically
     * linked", which is the downgrade the whole check exists to stop, so the
     * length rule alone does not cover it.
     */
    current = "PT_INTERP terminated at its first byte";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "", 2);
    CHECK(!parse(&img, &info));

    /* A short read used to leave interp_path empty and report success, which
     * every caller reads as "statically linked".
     */
    current = "PT_INTERP running past the end of the file";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 0,
                   16); /* no file data, so only the name is short */
    image_add_interp(&img, 0, "/lib/ld.so", 11);
    img.truncate_to = DATA_OFF + 4;
    CHECK(!parse(&img, &info));
}

static void test_first_interp_wins(void)
{
    /* Linux stops at the first PT_INTERP. A second, unusable one must not
     * replace a good first one, nor fail the load.
     */
    current = "first PT_INTERP wins";
    image_t img;
    elf_info_t info;
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "/lib/ld.so", 11);
    image_add_interp(&img, 100, "", 1);

    CHECK(parse(&img, &info));
    CHECK(strcmp(info.interp_path, "/lib/ld.so") == 0);
}

static void test_segment_rejections(void)
{
    image_t img;
    elf_info_t info;

    current = "overlapping PT_LOAD extents";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0x1000, 256, 0x2000);
    image_add_load(&img, 0x2000, 256, 256);
    CHECK(!parse(&img, &info));

    current = "PT_LOAD extents that only touch";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0x1000, 256, 0x1000);
    image_add_load(&img, 0x2000, 256, 256);
    CHECK(parse(&img, &info));
    CHECK(info.num_segments == 2);

    /* Byte-disjoint but sharing a page, listed high address first. The mapper
     * zeroes to the end of the page a segment's extent lands in, so loading
     * these in file order puts the low segment's fill on top of the high
     * segment's bytes. The parse sorts them instead of rejecting: Linux runs an
     * out-of-order image.
     */
    current = "PT_LOADs recorded in ascending address order";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0x2200, 0x100, 0x100);
    image_add_load(&img, 0x2000, 0x80, 0x80);
    CHECK(parse(&img, &info));
    CHECK(info.num_segments == 2);
    CHECK(info.segments[0].gpa == 0x2000);
    CHECK(info.segments[1].gpa == 0x2200);

    /* The sort must not turn a genuine overlap into an accepted image. */
    current = "overlapping PT_LOADs listed high address first";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0x2000, 256, 0x1000);
    image_add_load(&img, 0x1000, 256, 0x1800);
    CHECK(!parse(&img, &info));

    current = "PT_LOAD filesz above memsz";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 128);
    CHECK(!parse(&img, &info));

    current = "PT_LOAD file range past the end of the file";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, DATA_LEN + 1, DATA_LEN + 1);
    CHECK(!parse(&img, &info));

    /* A BSS-only segment reads nothing, so its p_offset is not judged. */
    current = "BSS-only PT_LOAD with an offset past the end of the file";
    image_init(&img, ET_DYN);
    elf64_phdr_t *bss = image_add_load(&img, 0, 0, 4096);
    bss->p_offset = DATA_OFF + DATA_LEN + 4096;
    CHECK(parse(&img, &info));

    current = "PT_LOAD extent wrapping the address space";
    image_init(&img, ET_DYN);
    image_add_load(&img, UINT64_MAX - 16, 16, 4096);
    CHECK(!parse(&img, &info));
}

/* The ordering hazard at its point of impact: map two byte-disjoint segments
 * that share a page, listed high address first, and check both survive. The
 * zero fill for the low segment runs to the end of the shared page, so without
 * the ascending sort it lands on bytes the high segment already placed.
 */
static void test_shared_page_load_order(void)
{
    current = "a shared page keeps both segments' bytes";
    image_t img;
    elf_info_t info;

    image_init(&img, ET_DYN);
    elf64_phdr_t *high = image_add_load(&img, 0x2200, 0x100, 0x100);
    elf64_phdr_t *low = image_add_load(&img, 0x2000, 0x80, 0x80);
    high->p_offset = DATA_OFF;
    low->p_offset = DATA_OFF + 0x100;
    memset(img.data, 0xbb, 0x100);
    memset(img.data + 0x100, 0xaa, 0x80);

    int fd = image_open(&img);
    if (elf_load_fd(fd, "test", &info) != 0) {
        CHECK(false);
        close(fd);
        return;
    }

    const uint64_t slab_size = 0x8000;
    uint8_t *slab = calloc(1, slab_size);
    CHECK(elf_map_segments_fd(&info, fd, "test", slab, slab_size,
                              (elf_window_t) {0, 0}, 0, 0) == 0);
    close(fd);

    CHECK(slab[0x2000] == 0xaa && slab[0x207f] == 0xaa);
    CHECK(slab[0x2200] == 0xbb && slab[0x22ff] == 0xbb);
    free(slab);
}

/* The mapper must not depend on segment order. The parse sorts, so reaching
 * this needs an elf_info_t built by hand: two byte-disjoint segments sharing a
 * page, recorded high address first. One pass would zero the low segment's page
 * tail on top of the high segment's bytes.
 */
static void test_mapper_ignores_segment_order(void)
{
    current = "mapper is order-independent";
    image_t img;

    image_init(&img, ET_DYN);
    elf64_phdr_t *high = image_add_load(&img, 0x2200, 0x100, 0x100);
    elf64_phdr_t *low = image_add_load(&img, 0x2000, 0x80, 0x80);
    high->p_offset = DATA_OFF;
    low->p_offset = DATA_OFF + 0x100;
    memset(img.data, 0xbb, 0x100);
    memset(img.data + 0x100, 0xaa, 0x80);

    elf_info_t info;
    memset(&info, 0, sizeof(info));
    info.num_segments = 2;
    info.segments[0] = (elf_segment_t) {.gpa = 0x2200,
                                        .offset = DATA_OFF,
                                        .filesz = 0x100,
                                        .memsz = 0x100,
                                        .flags = PF_R};
    info.segments[1] = (elf_segment_t) {.gpa = 0x2000,
                                        .offset = DATA_OFF + 0x100,
                                        .filesz = 0x80,
                                        .memsz = 0x80,
                                        .flags = PF_R};

    const uint64_t slab_size = 0x8000;
    uint8_t *slab = calloc(1, slab_size);
    int fd = image_open(&img);
    CHECK(elf_map_segments_fd(&info, fd, "test", slab, slab_size,
                              (elf_window_t) {0, 0}, 0, 0) == 0);
    close(fd);

    CHECK(slab[0x2000] == 0xaa && slab[0x207f] == 0xaa);
    CHECK(slab[0x2200] == 0xbb && slab[0x22ff] == 0xbb);
    free(slab);
}

static void test_interp_loadable(void)
{
    image_t img;
    elf_info_t info;

    current = "ET_DYN interpreter is loadable";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    CHECK(parse(&img, &info));
    CHECK(elf_interp_is_loadable(&info, "ld.so"));

    /* Both load paths place the interpreter at interp_base + p_vaddr, which is
     * the wrong address for an image linked to run where it says.
     */
    current = "ET_EXEC interpreter is refused";
    image_init(&img, ET_EXEC);
    image_add_load(&img, 0x400000, 256, 256);
    CHECK(parse(&img, &info));
    CHECK(!elf_interp_is_loadable(&info, "ld.so"));

    current = "interpreter naming its own interpreter is refused";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0, 256, 256);
    image_add_interp(&img, 0, "/lib/ld.so", 11);
    CHECK(parse(&img, &info));
    CHECK(!elf_interp_is_loadable(&info, "ld.so"));
}

static void test_placement(void)
{
    image_t img;
    elf_info_t info;
    const uint64_t guest_size = 0x100000;
    const elf_window_t at_zero = {0, 0};

    current = "placement inside the slab";
    image_init(&img, ET_DYN);
    image_add_load(&img, 0x1000, 256, 0x1000);
    CHECK(parse(&img, &info));
    CHECK(elf_check_placement(&info, "test", guest_size, at_zero, 0, 0));

    current = "placement past the end of the slab";
    CHECK(!elf_check_placement(&info, "test", 0x1000, at_zero, 0, 0));

    /* The reserve holds the page tables, the shim text and shim_data, and the
     * writes elf_map_segments_fd makes go through host_base directly.
     */
    current = "placement overlapping the infra reserve";
    CHECK(!elf_check_placement(&info, "test", guest_size, at_zero, 0x1800,
                               0x2000));

    current = "placement clear of the infra reserve";
    CHECK(elf_check_placement(&info, "test", guest_size, at_zero, 0x8000,
                              0x9000));

    /* The executable's caller forbids everything from the reserve to the top of
     * the slab, not just the reserve itself: the interpreter is mapped above
     * it, so a segment up there would be overwritten by the loader that lands
     * on the same addresses.
     */
    current = "placement above the reserve, with the window open to the top";
    image_init(&img, ET_EXEC);
    image_add_load(&img, 0x4000, 256, 0x1000);
    CHECK(parse(&img, &info));
    CHECK(!elf_check_placement(&info, "test", guest_size, at_zero, 0x2000,
                               guest_size));
    CHECK(elf_check_placement(&info, "test", guest_size, at_zero, 0x2000,
                              0x3000));
}

int main(void)
{
    test_baseline();
    test_interp_rejections();
    test_first_interp_wins();
    test_segment_rejections();
    test_shared_page_load_order();
    test_mapper_ignores_segment_order();
    test_interp_loadable();
    test_placement();

    return host_summary("test-elf-headers-host");
}
