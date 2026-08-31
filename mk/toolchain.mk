# Compiler and toolchain detection

MAKEFLAGS += --no-builtin-rules --no-builtin-variables

# Primary compiler. GNU make predefines CC=cc, so replace only that
# default while preserving explicit user/environment overrides.
ifeq ($(origin CC),default)
  CC := clang
else
  CC ?= clang
endif

# GNU objcopy for Mach-O / ELF -> raw binary
ifdef GNU_OBJCOPY
  OBJCOPY := $(GNU_OBJCOPY)
else ifneq ($(wildcard /opt/homebrew/opt/binutils/bin/objcopy),)
  OBJCOPY ?= /opt/homebrew/opt/binutils/bin/objcopy
else
  OBJCOPY ?= llvm-objcopy
endif

# Bare-metal aarch64 ELF toolchain for assembly tests
ELF_TOOLCHAIN ?= /opt/toolchain/aarch64-none-elf
ifneq ($(wildcard $(ELF_TOOLCHAIN)/bin/aarch64-none-elf-as),)
  BAREMETAL_CROSS ?= $(ELF_TOOLCHAIN)/bin/aarch64-none-elf-
else
  BAREMETAL_CROSS ?= aarch64-none-elf-
endif

# Linux cross-compiler (for guest test binaries when
# GUEST_TEST_BINARIES is unset)
LINUX_TOOLCHAIN ?= /opt/toolchain/aarch64-linux-gnu
ifneq ($(wildcard $(LINUX_TOOLCHAIN)/bin/aarch64-linux-gnu-gcc),)
  CROSS_COMPILE ?= $(LINUX_TOOLCHAIN)/bin/aarch64-linux-gnu-
else
  CROSS_COMPILE ?= aarch64-linux-gnu-
endif

# The cross-glibc sysroot that ships with LINUX_TOOLCHAIN, and whether anything
# can actually be built against it. Guards that build dynamic guest binaries and
# the --sysroot those binaries need are the same fact, so they read it from here
# rather than each spelling the path.
#
# Computed once and exported. Answering this costs several compiler probes, and
# "make check" reaches 43 recursive sub-makes, each of which re-parses this file:
# measured at 218 compiler spawns for one "make -n check" before the export, all
# but five of them recomputing an answer the parent already had. The origin test
# keeps a command-line override winning, since that origin is not "undefined".

CROSS_GLIBC_CC := $(CROSS_COMPILE)gcc

# := not ?=, and expanded once into a simple variable. A recursively-expanded
# ?= re-runs its $(shell) at every reference, and this block references the
# sysroot three times, so the probe ran three times per parse.
ifeq ($(origin CROSS_GLIBC_SYSROOT),undefined)
  CROSS_GLIBC_SYSROOT := $(shell $(CROSS_GLIBC_CC) -print-sysroot 2> /dev/null)
endif

# Guarded on the identity, not on the presence answer below. The two are
# different questions: what the fixtures were built against, versus whether they
# can be built at all. Sharing one guard meant that overriding
# CROSS_GLIBC_SYSROOT_PRESENT on the command line left the hash empty, so every
# toolchain named the same stamp and fixtures linked against one runtime were
# reused with another.
ifeq ($(origin CROSS_GLIBC_ID_HASH),undefined)
# What the fixtures were built against, not merely where it lives. Two paths
# are the same two paths after a toolchain is upgraded in place, so a stamp keyed
# on them alone leaves fixtures linked against the old glibc looking current. The
# compiler version and the size and date of the libc it resolves to move when the
# install does. -dumpfullversion first: GCC 7 and later answer -dumpversion with
# the major alone, so two compilers in one release series would hash the same
# and the fixtures one built would be reused by the other. -dumpversion is the
# fallback for the compilers that predate the fuller spelling. Not a content hash: this is read on every top-level make, and
# hashing a sysroot to catch an edit that leaves both untouched would cost more
# than the rebuild it saves.
#
# No 'case' here, and no bare ')' anywhere in the recipe: make counts parentheses
# to find the end of $(shell ...), so the ')' that closes a case pattern ends the
# expansion early and leaves the rest of the line as literal text. That is not a
# syntax error, it is a fingerprint that silently becomes a constant, which is
# what happened: the compiler version and the libc timestamp dropped out of the
# hash while every test still passed, because a constant is stable across
# locales and the sysroot reached the identity by another component.
CROSS_GLIBC_FINGERPRINT := $(shell { \
    $(CROSS_GLIBC_CC) -dumpfullversion 2> /dev/null \
        || $(CROSS_GLIBC_CC) -dumpversion; \
    f="$$($(CROSS_GLIBC_CC) --sysroot=$(CROSS_GLIBC_SYSROOT) \
        -print-file-name=libc.so.6)"; \
    m="$$(stat -Lf '%z %m' "$$f" 2> /dev/null)"; \
    [ -n "$$m" ] && [ -z "$$(printf '%s' "$$m" | tr -d '0-9 ')" ] \
        || m="$$(stat -Lc '%s %Y' "$$f" 2> /dev/null)"; \
    printf '%s' "$$m"; \
    } 2> /dev/null | tr -s ' \n' '__')
CROSS_GLIBC_ID := $(CROSS_COMPILE)|$(CROSS_GLIBC_SYSROOT)|$(CROSS_GLIBC_FINGERPRINT)
CROSS_GLIBC_ID_HASH := $(shell printf '%s' '$(CROSS_GLIBC_ID)' \
    | shasum -a 256 2> /dev/null | cut -c1-12)

# The hash names a file, so an empty one is not a degraded answer, it is every
# toolchain sharing a stamp and reusing each other's fixtures. cksum is POSIX
# and answers when shasum does not; if neither does, say so rather than build
# against a stamp that cannot tell toolchains apart.
ifeq ($(CROSS_GLIBC_ID_HASH),)
  CROSS_GLIBC_ID_HASH := $(shell printf '%s' '$(CROSS_GLIBC_ID)' \
      | cksum 2> /dev/null | cut -d' ' -f1)
endif

endif

ifeq ($(origin CROSS_GLIBC_SYSROOT_PRESENT),undefined)
# Link something, rather than looking for parts. Every earlier spelling of this
# guard asked whether some file was present (the sysroot directory, then the
# loader, then crt1.o) and each one accepted a tree that still could not build:
# "/" exists everywhere, a runtime-only tree has a loader but no headers, and a
# tree with crt1.o can still be missing crti.o. The guarded targets compile and
# link, so compiling and linking is the question, and it answers every layout
# including a distro multiarch compiler whose sysroot is "/".
#
# Build the fixtures, rather than asking questions that resemble building them.
# Four earlier spellings of this guard each asked something narrower than the
# targets ask ("does the sysroot exist", "is the loader there", "is crt1.o
# there", "does a bare main link", "do the headers parse and do the libraries
# link") and each let through a sysroot the build then failed on. The targets
# compile a shared library and link a program against it, so that is what this
# does, into a temporary directory it removes.
#
# Measured at 0.49s, paid once: this block is guarded on its own origin and
# exported below, so the 43 recursive sub-makes "make check" spawns inherit the
# answer rather than each re-deriving it. It is on the path of every top-level
# make, including ones that build nothing, which is the price of the guard being
# right.
CROSS_GLIBC_SYSROOT_PRESENT := $(shell d=$$(mktemp -d 2> /dev/null) || exit 0; \
    $(CROSS_GLIBC_CC) --sysroot=$(CROSS_GLIBC_SYSROOT) -fPIC -shared \
        -o "$$d/libprobe.so" tests/fixtures/sharun/probe-lib.c > /dev/null 2>&1 \
    && $(CROSS_GLIBC_CC) --sysroot=$(CROSS_GLIBC_SYSROOT) -o "$$d/probe" \
        tests/fixtures/sharun/probe.c -L"$$d" -lprobe -ldl -lm -pthread \
        > /dev/null 2>&1 && echo yes; \
    rm -rf "$$d")

# Which toolchain and sysroot the guest fixtures were built against. Make
# compares timestamps, and neither of those is a file, so a probe built against
# one glibc looks up to date after a switch to another and the lane then runs it
# against a sysroot it was never linked for. The fixture targets take this stamp
# as an ordinary prerequisite, so a changed identity rebuilds them.
#
# The FLAVOR stamp in mk/common.mk does this for the host objects and
# deliberately excludes the cross-compiled guest binaries, which carry
# CROSS_TEST_CFLAGS rather than CFLAGS. This is the matching record for them.
#
# Named here beside the rest of the cross-glibc configuration, but written in
# mk/common.mk: BUILD_DIR comes from mk/config.mk, which is read after this
# file, so a path built from it here resolves to "/" and the write lands on a
# read-only filesystem.
endif

# Checked outside the block that computes it, so an override is checked too. The
# hash names a file, and an empty one is not a weaker key, it is every toolchain
# sharing one stamp and reusing each other's fixtures. Supplying it empty on the
# command line skipped the computation and the check with it.
ifeq ($(strip $(CROSS_GLIBC_ID_HASH)),)
  $(error CROSS_GLIBC_ID_HASH is empty; it names the fixture stamp, so an empty \
value would let every toolchain share one)
endif

export CROSS_GLIBC_SYSROOT
export CROSS_GLIBC_SYSROOT_PRESENT
export CROSS_GLIBC_ID_HASH

# Shim assembler (defaults to Apple's assembler)
SHIM_AS ?= as
SHIM_ASFLAGS ?= -arch arm64

# clang-format
CLANG_FORMAT ?= clang-format
