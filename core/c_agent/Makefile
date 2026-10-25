# core/c_agent/Makefile
#
# Hosted C agent library, unit tests and fuzz targets.
#
# The agent is assembled from pluggable providers, one per external dependency,
# mirroring core/modules/stager_linux's TRANSPORT=<name> model. Select them on
# the command line, e.g.:
#
#   make agent CRYPTO=mbedtls GZIP=miniz TRANSPORT=libcurl
#
# Each group is implemented by src/<group>/<name>.c; drop a new file
# in and build with <GROUP>=<name> to add your own backend. A transport owns
# its own wire implementation (HTTP/TCP/UDP, raw sockets or a dynamically
# loaded library), so there is no separate HTTP selector. The malleable HTTP
# profile itself comes from the C2-embedded config, not from a build provider.

# zig is the project's compiler (shipped with emp3r0r, pinned in core/build.py),
# so it builds the library and agent. `CC = zig cc` (not `?=`) forces it even
# when the environment exports CC; `make CC=gcc` still overrides.
CC = zig cc
HOSTCC ?= gcc
AR ?= ar
WARN = -Wall -Wextra -Werror -std=c99

# ---- hosted ABI ------------------------------------------------------------
# ARCH selects the target architecture the hosted agent and library are
# cross-built for. The names are the operator-facing Go-style names; zig uses
# its own target spelling, mapped below. Only architectures the hosted agent
# supports are listed.
ARCH ?= amd64
ifeq ($(ARCH),amd64)
  ZIG_ARCH = x86_64
else ifeq ($(ARCH),386)
  ZIG_ARCH = x86
else ifeq ($(ARCH),arm)
  ZIG_ARCH = arm
else ifeq ($(ARCH),arm64)
  ZIG_ARCH = aarch64
else ifeq ($(ARCH),riscv64)
  ZIG_ARCH = riscv64
else
  $(error unsupported ARCH=$(ARCH); available: amd64, 386, arm, arm64, riscv64)
endif

# LIBC selects the C library the hosted agent and library link:
#   glibc (default) : glibc, dynamically linked and pinned to GLIBC_VERSION.
#   musl            : musl, dynamically linked against zig's bundled musl.
# Neither is ever linked statically: the agent loads libcrypto/libcurl at
# runtime through dynload, which needs a dynamic loader and a /proc/self/maps
# libc segment. zig's musl default is a static binary (no loader, no dlopen),
# so the musl target adds -dynamic.
#
# GLIBC_VERSION pins the oldest glibc ABI to link against; zig then uses its
# bundled glibc headers/stubs for that version, so the build is host-independent
# and the binary runs on every glibc at or above it (newer host headers
# otherwise leak in: newer glibc makes strstr a macro and pulls <strings.h>
# from <string.h>). It is ignored when LIBC=musl: musl keeps a stable ABI, so
# the agent runs on any musl host that provides /lib/ld-musl-<arch>.so.1.
#
# DYNLOAD_MODE picks which libc symbols dynload resolves at runtime:
#   libc_dl : __libc_dlopen_mode/__libc_dlsym/__libc_dlclose (glibc < 2.34)
#   public  : dlopen/dlsym/dlclose (moved into libc.so.6 in glibc 2.34)
#   auto    : resolve libc_dl, then fall back to the public names
# musl only exports the public names (from the loader itself, no libdl), so
# LIBC=musl defaults DYNLOAD_MODE to public.
LIBC ?= glibc
ifeq ($(LIBC),musl)
  DYNLOAD_MODE ?= public
else
  DYNLOAD_MODE ?= libc_dl
endif

ifeq ($(DYNLOAD_MODE),public)
  DYNLOAD_MODE_CFLAG = -DDYNLOAD_MODE=0
  GLIBC_VERSION ?= 2.34
else ifeq ($(DYNLOAD_MODE),auto)
  DYNLOAD_MODE_CFLAG = -DDYNLOAD_MODE=2
  GLIBC_VERSION ?= 2.17
else
  DYNLOAD_MODE_CFLAG = -DDYNLOAD_MODE=1
  GLIBC_VERSION ?= 2.17
endif

# The two glibc knobs are independent: a binary linked for an older ABI still
# runs on newer glibc, and any symbol set can be paired with any target version.
# The default glibc pair (2.17 + libc_dl) covers the widest range of old
# systems; use DYNLOAD_MODE=auto to build one binary that loads on both old and
# new glibc.

# musl has no libdl and no __libc_dlopen_mode/__libc_dlsym/__libc_dlclose: the
# public dlopen/dlsym/dlclose are exported by the loader/libc segment itself
# (see dynload_find_libc), so public is the only mode that can work.
ifeq ($(LIBC),musl)
  ifneq ($(DYNLOAD_MODE),public)
    $(error LIBC=musl only supports DYNLOAD_MODE=public, got '$(DYNLOAD_MODE)')
  endif
endif

ifeq ($(LIBC),musl)
  ifeq ($(ARCH),arm)
    HOSTED_TARGET ?= -target arm-linux-musleabihf -dynamic
  else
    HOSTED_TARGET ?= -target $(ZIG_ARCH)-linux-musl -dynamic
  endif
else ifeq ($(ARCH),arm)
  HOSTED_TARGET ?= -target arm-linux-gnueabihf.$(GLIBC_VERSION)
else
  HOSTED_TARGET ?= -target $(ZIG_ARCH)-linux-gnu.$(GLIBC_VERSION)
endif

# zig cannot provide riscv64 glibc at the project's oldest supported ABI.
ifeq ($(ARCH),riscv64)
  ifneq ($(LIBC),musl)
    $(error ARCH=riscv64 requires LIBC=musl: zig has no riscv64 glibc 2.17 target)
  endif
endif

HOSTED_CFLAGS = $(HOSTED_TARGET) $(DYNLOAD_MODE_CFLAG)

# ---- provider selection ----------------------------------------------------
# CRYPTO:    openssl (default, system libcrypto via dynload) | mbedtls (vendored)
# GZIP:      miniz (default, vendored) | none
# TRANSPORT: libcurl (default, HTTP poll via dynload) | http_raw (raw TCP) |
#            libssl (raw TCP + TLS via dynload) | transport_<name>.c you add
CRYPTO ?= openssl
GZIP ?= miniz
TRANSPORT ?= libcurl

CRYPTO_SRC = src/crypto/$(CRYPTO).c
GZIP_SRC = src/gzip/$(GZIP).c
TRANSPORT_SRC = src/transport/transport_$(TRANSPORT).c
# Transports that only supply the HTTP engine reuse the shared http_poll state
# machine. A fully custom transport implements c2_transport_create() and
# c2_transport_name() itself and needs no entry here.
HTTP_POLL_TRANSPORTS := libcurl http_raw libssl
TRANSPORT_CFLAG =
TRANSPORT_SUPPORT_SRC =
ifneq ($(filter $(TRANSPORT),$(HTTP_POLL_TRANSPORTS)),)
  TRANSPORT_SUPPORT_SRC = src/transport/http_poll.c
endif
ifeq ($(TRANSPORT),libssl)
  TRANSPORT_SUPPORT_SRC += src/transport/transport_http_raw.c
  TRANSPORT_CFLAG = -DHP_HTTP_RAW_AS_HELPER=1
endif
HOSTED_CFLAGS += $(TRANSPORT_CFLAG)

# Vendored mbedTLS (self-contained), linked only when CRYPTO=mbedtls. See
# vendor/mbedtls/README.emp3r0r.md; the .a files are gitignored build artifacts.
MBEDTLS_DIR ?= vendor/mbedtls
MBEDTLS_INC = -I$(MBEDTLS_DIR)/include
MBEDTLS_CRYPTO_LIB = $(MBEDTLS_DIR)/library/libmbedcrypto.a

# Vendored miniz amalgamation (MIT), compiled only when GZIP=miniz. See
# vendor/miniz/README.emp3r0r.md.
MINIZ_SRC = vendor/miniz/miniz.c
MINIZ_DEFS = -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_ARCHIVE_WRITING_APIS \
             -DMINIZ_NO_STDIO -DMINIZ_NO_ZLIB_APIS \
             -DMINIZ_NO_ZLIB_COMPATIBLE_NAMES

EXTRA_SRC =
EXTRA_LIBS =
EXTRA_INCLUDES =
ifeq ($(CRYPTO),mbedtls)
  EXTRA_LIBS += $(MBEDTLS_CRYPTO_LIB)
  EXTRA_INCLUDES += $(MBEDTLS_INC)
endif
ifeq ($(GZIP),miniz)
  EXTRA_SRC += $(MINIZ_SRC)
endif

# Project headers are found with `-iquote` (quote includes only) and are
# addressed as "<name>.h" or "util/<name>.h", so a bare <strings.h> from
# glibc can never be intercepted. Vendor headers keep -I so both "cbor.h" and
# <cbor.h> work.
INCLUDES = -iquote include -Ivendor/tinycbor -Ivendor/miniz $(MINIZ_DEFS) \
           $(EXTRA_INCLUDES)

# Vendored tinycbor (MIT). See vendor/tinycbor/README.md.
TINYCBOR_SRC = vendor/tinycbor/cborencoder.c \
               vendor/tinycbor/cborencoder_close_container_checked.c \
               vendor/tinycbor/cborparser.c \
               vendor/tinycbor/cborparser_dup_string.c \
               vendor/tinycbor/cborerrorstrings.c \
               vendor/tinycbor/cborvalidation.c

# Protocol layer plus the selected providers. util/strings.c / util/system.c /
# util/net_utils.c are freestanding-only (they override libc) and are excluded.
PORTABLE_SRC = src/util/rc4.c src/util/packer.c src/util/dynload.c src/util/dynload_hosted.c \
               src/util/doh.c \
               src/util/elfload.c src/util/debug.c src/common.c src/crypto.c \
               src/messages.c src/agent_info.c src/config.c \
               src/secureconn.c src/session.c src/memfile.c \
               src/bof.c src/sysinfo.c src/module.c \
               $(GZIP_SRC) $(CRYPTO_SRC) $(TRANSPORT_SRC) $(TRANSPORT_SUPPORT_SRC) \
               $(EXTRA_SRC)

SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer
# Extra flags for the unit tests, e.g. `make test COV=--coverage SAN=` for
# gcov instrumentation (see the `coverage` target).
COV ?=
TEST_CFLAGS = $(WARN) -O1 -g $(INCLUDES) $(SAN) $(COV)

BUILD = build

.PHONY: all lib agent so test test-mbedtls vendor-mbedtls fuzz coverage clean

all: lib

# ---- vendored mbedTLS ------------------------------------------------------
$(MBEDTLS_CRYPTO_LIB):
	$(MAKE) -C $(MBEDTLS_DIR)/library \
		CC="$(CC) $(HOSTED_TARGET)" libmbedcrypto.a libmbedtls.a

vendor-mbedtls: $(MBEDTLS_CRYPTO_LIB)

# ---- hosted static library -------------------------------------------------
lib: $(BUILD)/libagent.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/libagent.a: $(PORTABLE_SRC) $(TINYCBOR_SRC) | $(BUILD)
	@rm -rf $(BUILD)/lib && mkdir -p $(BUILD)/lib
	@set -e; for s in $(PORTABLE_SRC) $(TINYCBOR_SRC); do \
		o=$(BUILD)/lib/$$(basename $$s .c).o; \
		$(CC) $(WARN) -O2 -g $(INCLUDES) $(HOSTED_CFLAGS) -c $$s -o $$o; \
	done
	$(AR) rcs $@ $(BUILD)/lib/*.o

# ---- reference agent executable -------------------------------------------
# The encrypted CBOR build config and the build-wide magic string are compiled
# as a generated C translation unit. The Go C2 renders it (lib/cagent) and
# passes its path here, so building the agent needs no Python or Go toolchain:
#
#   make agent CONFIG_SRC=/path/to/config_embedded.c
#
# Without CONFIG_SRC the agent links with weak empty defaults and exits at
# startup (it has nothing to decrypt).
CONFIG_SRC ?=

# The agent links only what it reaches at runtime. rc4, packer, the debug shim
# and the c2_status_str table are stager/test-only; four of the six vendored
# tinycbor translation units are never called by the agent. Dropping them by
# name keeps the binary small even before --gc-sections.
AGENT_COMMON_SRC = src/agent_args.c src/util/dynload.c src/util/dynload_hosted.c \
                   src/util/doh.c src/util/elfload.c src/crypto.c src/messages.c \
                   src/agent_info.c src/config.c src/secureconn.c \
                   src/session.c src/memfile.c src/bof.c \
                   src/sysinfo.c src/module.c
TINYCBOR_MIN_SRC = vendor/tinycbor/cborencoder.c vendor/tinycbor/cborparser.c

AGENT_CONFIG_SRC =
ifneq ($(strip $(CONFIG_SRC)),)
  AGENT_CONFIG_SRC = $(CONFIG_SRC)
endif
AGENT_SRC = $(AGENT_COMMON_SRC) $(GZIP_SRC) $(CRYPTO_SRC) $(TRANSPORT_SRC) $(TRANSPORT_SUPPORT_SRC) \
            $(EXTRA_SRC) $(TINYCBOR_MIN_SRC) src/agent.c \
            $(AGENT_CONFIG_SRC)

# Release flags: shrink for size, one section per function/data so
# --gc-sections can drop what the agent never calls, no unwind tables, stripped
# symbols, no build-id. -DNDEBUG drops assert machinery (and its __FILE__ and
# message strings); the fuzzers keep asserts so an invariant violation is loud.
AGENT_CFLAGS = -Os -DNDEBUG -ffunction-sections -fdata-sections -fno-ident \
               -fno-asynchronous-unwind-tables -fno-unwind-tables \
               -fno-stack-protector -fvisibility=hidden
AGENT_LDFLAGS = -Wl,--gc-sections -Wl,--build-id=none -Wl,-z,noexecstack -s
# The linker's .comment ident is not needed at runtime. Removing it needs
# binutils strip; it is best-effort so the build still works without it.
STRIP ?= strip

agent: $(BUILD)/agent

$(BUILD)/agent: $(AGENT_SRC) $(EXTRA_LIBS) | $(BUILD)
	$(CC) $(WARN) $(AGENT_CFLAGS) $(INCLUDES) $(HOSTED_CFLAGS) $(AGENT_LDFLAGS) \
	  $(AGENT_SRC) $(EXTRA_LIBS) -o $@
	@command -v $(STRIP) >/dev/null 2>&1 && \
	  $(STRIP) --remove-section=.comment $@ || true

# ---- shared object ---------------------------------------------------------
# The same agent as a PIC ET_DYN, for in-process loading (dlopen/injection) and
# as the input to malasada (raw PIC). main stays exported in .dynsym (see
# agent.c); -Wl,-u,main keeps it even with --gc-sections, and a normal
# -s strip keeps .dynsym while dropping the rest. Unlike the executable, the
# shared object keeps a PT_NOTE (build-id): malasada repurposes a PT_NOTE or
# PT_GNU_EH_FRAME into the executable segment for its stage0 stub, and the
# release flags (-fno-unwind-tables / --build-id=none) otherwise remove both.
AGENT_SO_CFLAGS = $(AGENT_CFLAGS) -fPIC
AGENT_SO_LDFLAGS = -shared -Wl,--gc-sections -Wl,--build-id \
                   -Wl,-z,noexecstack -Wl,-u,main -s

so: $(BUILD)/agent.so

$(BUILD)/agent.so: $(AGENT_SRC) $(EXTRA_LIBS) | $(BUILD)
	$(CC) $(WARN) $(AGENT_SO_CFLAGS) $(INCLUDES) $(HOSTED_CFLAGS) \
	  $(AGENT_SO_LDFLAGS) $(AGENT_SRC) $(EXTRA_LIBS) -o $@

# ---- unit tests ------------------------------------------------------------
# test_dynload needs the real dynamic loader and libc, so it is not linked with
# strings.c (which would override libc's strstr/strcmp). The gzip round-trip
# test only makes sense when a real gzip provider is selected.
ifeq ($(GZIP),miniz)
  GZIP_TEST = $(BUILD)/test_gzip $(BUILD)/test_memfile
  GZIP_FUZZ = $(BUILD)/fuzz_gzip $(BUILD)/fuzz_memfile
endif

# BOF execution test: build the real coffloader_linux loader and the real
# hello_linux BOF from the module tree, then run the BOF through the agent's
# runner. Skipped when the module sources are absent (standalone checkout).
BOF_MODULE_DIR = ../modules/coffloader_linux
BOF_HELLO_DIR = ../modules/hello_linux
ifneq ($(wildcard $(BOF_MODULE_DIR)/loader_linux.c),)
  BOF_TEST = $(BUILD)/test_bof $(BUILD)/test_elfload
  BOF_FUZZ = $(BUILD)/fuzz_bof
endif

test: $(BUILD)/test_strings $(BUILD)/test_rc4 $(BUILD)/test_packer \
      $(BUILD)/test_net_parse $(BUILD)/test_dynload \
      $(BUILD)/test_auth $(BUILD)/test_messages \
      $(BUILD)/test_agent_info $(BUILD)/test_config $(BUILD)/test_doh \
      $(BUILD)/test_sysinfo $(BUILD)/test_module \
      $(BUILD)/test_secureconn $(GZIP_TEST) $(BOF_TEST) \
      $(BUILD)/test_crypto_openssl
	@set -e; for t in $^; do echo "--- $$t"; ./$$t; done

# The self-contained backend is only built when mbedTLS is vendored.
test-mbedtls: vendor-mbedtls $(BUILD)/test_crypto_mbedtls
	@echo "--- $(BUILD)/test_crypto_mbedtls"; ./$(BUILD)/test_crypto_mbedtls

$(BUILD)/test_strings: tests/test_strings.c src/util/strings.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) -fno-builtin $< src/util/strings.c -o $@

$(BUILD)/test_rc4: tests/test_rc4.c src/util/rc4.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/util/rc4.c -o $@

$(BUILD)/test_packer: tests/test_packer.c src/util/packer.c src/util/strings.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) -fno-builtin $< src/util/packer.c src/util/strings.c -o $@

$(BUILD)/test_net_parse: tests/test_net_parse.c src/util/net_utils.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/util/net_utils.c -o $@

$(BUILD)/test_dynload: tests/test_dynload.c src/util/dynload.c src/util/dynload_hosted.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/util/dynload.c src/util/dynload_hosted.c -o $@

C2_TEST_SRC = src/messages.c src/agent_info.c src/config.c \
              src/crypto.c src/common.c $(TINYCBOR_SRC)
STUB_SRC = tests/stub_crypto.c

CRYPTO_COMMON_SRC = src/crypto.c src/common.c

$(BUILD)/test_crypto_openssl: tests/test_crypto.c tests/test.h \
                                  $(CRYPTO_COMMON_SRC) \
                                  src/crypto/openssl.c \
                                  src/util/dynload.c src/util/dynload_hosted.c | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_crypto.c $(CRYPTO_COMMON_SRC) \
		src/crypto/openssl.c src/util/dynload.c src/util/dynload_hosted.c -o $@

$(BUILD)/test_crypto_mbedtls: tests/test_crypto.c tests/test.h \
                                 $(CRYPTO_COMMON_SRC) \
                                 src/crypto/mbedtls.c \
                                 $(MBEDTLS_CRYPTO_LIB) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $(MBEDTLS_INC) tests/test_crypto.c \
		$(CRYPTO_COMMON_SRC) src/crypto/mbedtls.c \
		$(MBEDTLS_CRYPTO_LIB) -o $@

$(BUILD)/test_auth: tests/test_auth.c $(C2_TEST_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(C2_TEST_SRC) -o $@

$(BUILD)/test_messages: tests/test_messages.c $(C2_TEST_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(C2_TEST_SRC) -o $@

$(BUILD)/test_doh: tests/test_doh.c src/util/doh.c src/common.c \
                   src/util/dynload.c src/util/dynload_hosted.c \
                   tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_doh.c src/util/doh.c src/common.c \
		src/util/dynload.c src/util/dynload_hosted.c -o $@

$(BUILD)/test_agent_info: tests/test_agent_info.c tests/test.h \
                             src/agent_info.c src/common.c \
                             $(TINYCBOR_SRC) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_agent_info.c src/agent_info.c \
		src/common.c $(TINYCBOR_SRC) -o $@

$(BUILD)/test_config: tests/test_config.c tests/test.h \
                         src/config.c src/crypto.c src/common.c \
                         src/crypto/openssl.c \
                         src/util/dynload.c src/util/dynload_hosted.c \
                         $(TINYCBOR_SRC) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_config.c src/config.c \
		src/crypto.c src/common.c src/crypto/openssl.c \
		src/util/dynload.c src/util/dynload_hosted.c $(TINYCBOR_SRC) -o $@

$(BUILD)/test_secureconn: tests/test_secureconn.c src/secureconn.c src/common.c $(STUB_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/secureconn.c src/common.c $(STUB_SRC) -o $@

$(BUILD)/test_gzip: tests/test_gzip.c $(GZIP_SRC) $(EXTRA_SRC) \
                       src/common.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(GZIP_SRC) $(EXTRA_SRC) src/common.c -o $@

$(BUILD)/coffloader_linux.so: $(BOF_MODULE_DIR)/loader_linux.c | $(BUILD)
	$(MAKE) -C $(BOF_MODULE_DIR) >/dev/null
	cp $(BOF_MODULE_DIR)/coffloader_linux.so $@
	$(MAKE) -C $(BOF_MODULE_DIR) clean >/dev/null

$(BUILD)/hello_linux.o: $(BOF_HELLO_DIR)/hello_linux.c | $(BUILD)
	$(MAKE) -C $(BOF_HELLO_DIR) >/dev/null
	cp $(BOF_HELLO_DIR)/hello_linux.o $@
	$(MAKE) -C $(BOF_HELLO_DIR) clean >/dev/null

$(BUILD)/test_bof: tests/test_bof.c src/bof.c src/util/dynload.c \
                      src/util/elfload.c $(BUILD)/coffloader_linux.so \
                      $(BUILD)/hello_linux.o tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) \
	  -DBOF_LOADER_PATH='"$(BUILD)/coffloader_linux.so"' \
	  -DBOF_OBJ_PATH='"$(BUILD)/hello_linux.o"' \
	  tests/test_bof.c src/bof.c src/util/dynload.c \
	  src/util/elfload.c -o $@

$(BUILD)/test_elfload: tests/test_elfload.c src/util/elfload.c \
                          src/util/dynload.c $(BUILD)/coffloader_linux.so \
                          $(BUILD)/faulty_ctor.so tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) \
	  -DBOF_LOADER_PATH='"$(BUILD)/coffloader_linux.so"' \
	  -DFAULTY_CTOR_PATH='"$(BUILD)/faulty_ctor.so"' \
	  tests/test_elfload.c src/util/elfload.c src/util/dynload.c -o $@

# Deliberately faulting constructor, for the loader crash-guard regression test.
# -nostdlib keeps the image free of undefined crt symbols the loader would have
# to resolve before it can reach the constructor.
$(BUILD)/faulty_ctor.so: tests/faulty_ctor.c | $(BUILD)
	$(HOSTCC) -shared -fPIC -O0 -nostdlib -o $@ $<

$(BUILD)/test_module: tests/test_module.c tests/test.h \
                       src/module.c src/common.c \
                       $(TINYCBOR_SRC) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_module.c src/module.c \
		src/common.c $(TINYCBOR_SRC) -o $@

$(BUILD)/test_memfile: tests/test_memfile.c tests/test.h \
                          src/memfile.c $(GZIP_SRC) $(EXTRA_SRC) \
                          src/crypto.c src/common.c \
                          src/crypto/openssl.c \
                          src/util/dynload.c src/util/dynload_hosted.c | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_memfile.c src/memfile.c \
		$(GZIP_SRC) $(EXTRA_SRC) src/crypto.c src/common.c \
		src/crypto/openssl.c src/util/dynload.c src/util/dynload_hosted.c -o $@

$(BUILD)/test_sysinfo: tests/test_sysinfo.c tests/test.h \
                          src/sysinfo.c src/memfile.c \
                          src/messages.c src/agent_info.c \
                          src/crypto.c src/common.c $(GZIP_SRC) \
                          $(EXTRA_SRC) src/crypto/openssl.c \
                          src/util/dynload.c src/util/dynload_hosted.c \
                          $(TINYCBOR_SRC) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_sysinfo.c src/sysinfo.c \
		src/memfile.c src/messages.c src/agent_info.c \
		src/crypto.c src/common.c $(GZIP_SRC) $(EXTRA_SRC) \
		src/crypto/openssl.c src/util/dynload.c src/util/dynload_hosted.c \
		$(TINYCBOR_SRC) -o $@

# ---- fuzzing ---------------------------------------------------------------
# Coverage-guided fuzzing with libFuzzer is the primary mode:
#
#   make fuzz FUZZER=libfuzzer HOSTCC=clang CC=clang
#
# It runs every target for FUZZ_TIME seconds (default 60) and persists newly
# discovered inputs under $(FUZZ_OUT)/<target>, so a later run resumes instead
# of starting over. Crashes land in $(BUILD)/crash/. Set FUZZ_ARGS to add
# libFuzzer flags (e.g. FUZZ_ARGS='-jobs=4 -workers=4 -runs=1000000').
#
# Without clang the dependency-free mutational runner exercises the same
# targets under ASan/UBSan for FUZZ_ITERS iterations.
FUZZER ?= runner
ifeq ($(FUZZER),libfuzzer)
  FUZZ_LINK = -fsanitize=fuzzer,address,undefined
  FUZZ_DRIVER =
  FUZZ_TIME ?= 60
  FUZZ_ARGS ?= -max_total_time=$(FUZZ_TIME) -max_len=65536 \
               -dict=$(abspath fuzz/cagent.dict) -print_final_stats=1 \
               -artifact_prefix=$(abspath $(BUILD)/crash)/
  # libFuzzer takes corpus directories; the output corpus comes first so new
  # units are persisted there and the checked-in seed dir is never modified.
  FUZZ_INPUTS = $$out $$(test -d $(FUZZ_CORPUS)/$$name && echo $(FUZZ_CORPUS)/$$name)
else
  FUZZ_LINK = -fsanitize=address,undefined -fno-omit-frame-pointer
  FUZZ_DRIVER = fuzz/fuzz_runner.c
  FUZZ_ARGS ?=
  # The fallback runner takes individual seed files and ignores directories.
  FUZZ_INPUTS = $$out $$(ls $(FUZZ_CORPUS)/$$name/* 2>/dev/null || true)
endif

FUZZ_CFLAGS = $(WARN) -O1 -g $(INCLUDES) $(FUZZ_LINK)
FUZZ_ITERS ?= 50000
FUZZ_CORPUS ?= fuzz/corpus
FUZZ_OUT ?= $(BUILD)/corpus

fuzz: $(BUILD)/fuzz_rc4 $(BUILD)/fuzz_packer $(BUILD)/fuzz_inet_aton \
      $(BUILD)/fuzz_messages $(BUILD)/fuzz_agent_info $(BUILD)/fuzz_config \
      $(BUILD)/fuzz_config_decrypt $(BUILD)/fuzz_session \
      $(BUILD)/fuzz_command_args $(BUILD)/fuzz_http_poll \
      $(BUILD)/fuzz_secureconn $(BUILD)/fuzz_text $(BUILD)/fuzz_encdec \
      $(GZIP_FUZZ) $(BOF_FUZZ) $(BUILD)/fuzz_dynload $(BUILD)/fuzz_maps \
      $(BUILD)/fuzz_module $(BUILD)/fuzz_strings $(BUILD)/fuzz_elfload \
      $(BUILD)/fuzz_doh $(BUILD)/fuzz_http_raw
	@set -e; mkdir -p $(BUILD)/crash; \
	for t in $^; do \
	  name=$$(basename $$t); name=$${name#fuzz_}; \
	  out=$(FUZZ_OUT)/$$name; mkdir -p $$out; \
	  echo "--- $$t"; \
	  FUZZ_ITERS=$(FUZZ_ITERS) FUZZ_CORPUS_OUT=$$out \
	    FUZZ_CRASH=$(BUILD)/crash/$$name.bin ./$$t $(FUZZ_ARGS) $(FUZZ_INPUTS); \
	done

$(BUILD)/fuzz_rc4: fuzz/fuzz_rc4.c $(FUZZ_DRIVER) src/util/rc4.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/util/rc4.c -o $@

$(BUILD)/fuzz_packer: fuzz/fuzz_packer.c $(FUZZ_DRIVER) src/util/packer.c src/util/strings.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -fno-builtin $< $(FUZZ_DRIVER) src/util/packer.c src/util/strings.c -o $@

$(BUILD)/fuzz_inet_aton: fuzz/fuzz_inet_aton.c $(FUZZ_DRIVER) src/util/net_utils.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/util/net_utils.c -o $@

$(BUILD)/fuzz_messages: fuzz/fuzz_messages.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_agent_info: fuzz/fuzz_agent_info.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_config: fuzz/fuzz_config.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_config_decrypt: fuzz/fuzz_config_decrypt.c $(FUZZ_DRIVER) \
                               src/config.c src/crypto.c src/common.c \
                               $(STUB_SRC) $(TINYCBOR_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Itests $< $(FUZZ_DRIVER) src/config.c \
		src/crypto.c src/common.c $(STUB_SRC) $(TINYCBOR_SRC) -o $@

$(BUILD)/fuzz_session: fuzz/fuzz_session.c $(FUZZ_DRIVER) $(C2_TEST_SRC) \
                       src/session.c src/secureconn.c $(GZIP_SRC) $(EXTRA_SRC) \
                       $(STUB_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Itests $< $(FUZZ_DRIVER) $(C2_TEST_SRC) \
		src/session.c src/secureconn.c $(GZIP_SRC) $(EXTRA_SRC) \
		$(STUB_SRC) -o $@

$(BUILD)/fuzz_command_args: fuzz/fuzz_command_args.c $(FUZZ_DRIVER) \
                            src/agent_args.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/agent_args.c -o $@

$(BUILD)/fuzz_http_poll: fuzz/fuzz_http_poll.c $(FUZZ_DRIVER) \
                         src/transport/http_poll.c src/common.c \
                         fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Isrc/transport $< $(FUZZ_DRIVER) \
		src/transport/http_poll.c src/common.c -o $@

$(BUILD)/fuzz_secureconn: fuzz/fuzz_secureconn.c $(FUZZ_DRIVER) $(STUB_SRC) \
                         src/secureconn.c src/common.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Itests $< $(FUZZ_DRIVER) $(STUB_SRC) \
		src/secureconn.c src/common.c -o $@

$(BUILD)/fuzz_text: fuzz/fuzz_text.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_encdec: fuzz/fuzz_encdec.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_gzip: fuzz/fuzz_gzip.c $(FUZZ_DRIVER) $(GZIP_SRC) $(EXTRA_SRC) \
                    src/common.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(GZIP_SRC) $(EXTRA_SRC) \
		src/common.c -o $@

$(BUILD)/fuzz_memfile: fuzz/fuzz_memfile.c $(FUZZ_DRIVER) src/memfile.c \
                       $(GZIP_SRC) $(EXTRA_SRC) src/crypto.c \
                       src/common.c $(STUB_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Itests $< $(FUZZ_DRIVER) src/memfile.c \
		$(GZIP_SRC) $(EXTRA_SRC) src/crypto.c src/common.c $(STUB_SRC) -o $@

$(BUILD)/fuzz_bof: fuzz/fuzz_bof.c $(FUZZ_DRIVER) src/bof.c \
                   src/util/dynload.c src/util/elfload.c \
                   $(BUILD)/coffloader_linux.so fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -DELFLOAD_NO_EXEC \
		-DFUZZ_BOF_LOADER='"$(BUILD)/coffloader_linux.so"' \
		$< $(FUZZ_DRIVER) src/bof.c src/util/dynload.c src/util/elfload.c -o $@

$(BUILD)/fuzz_dynload: fuzz/fuzz_dynload.c $(FUZZ_DRIVER) src/util/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/util/dynload.c -o $@

$(BUILD)/fuzz_maps: fuzz/fuzz_maps.c $(FUZZ_DRIVER) src/util/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/util/dynload.c -o $@

$(BUILD)/fuzz_module: fuzz/fuzz_module.c $(FUZZ_DRIVER) src/module.c \
                      src/common.c $(TINYCBOR_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/module.c \
		src/common.c $(TINYCBOR_SRC) -o $@

$(BUILD)/fuzz_strings: fuzz/fuzz_strings.c $(FUZZ_DRIVER) src/util/strings.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -fno-builtin $< $(FUZZ_DRIVER) src/util/strings.c -o $@

$(BUILD)/fuzz_doh: fuzz/fuzz_doh.c $(FUZZ_DRIVER) src/util/doh.c \
                  src/util/dynload.c src/util/dynload_hosted.c \
                  fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -DDOH_FUZZ $< $(FUZZ_DRIVER) \
		src/util/doh.c src/util/dynload.c src/util/dynload_hosted.c -o $@

$(BUILD)/fuzz_http_raw: fuzz/fuzz_http_raw.c $(FUZZ_DRIVER) \
                        src/transport/transport_http_raw.c src/util/doh.c \
                        src/util/dynload.c src/util/dynload_hosted.c \
                        fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -DHTTP_RAW_FUZZ -Isrc/transport $< $(FUZZ_DRIVER) \
		src/transport/transport_http_raw.c src/util/doh.c \
		src/util/dynload.c src/util/dynload_hosted.c -o $@

# The image is untrusted, so the fuzz build records (rather than runs)
# image-supplied constructors and IFUNC/IRELATIVE resolvers.
$(BUILD)/fuzz_elfload: fuzz/fuzz_elfload.c $(FUZZ_DRIVER) src/util/elfload.c \
                       src/util/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -DELFLOAD_NO_EXEC $< $(FUZZ_DRIVER) \
		src/util/elfload.c src/util/dynload.c -o $@

# ---- coverage --------------------------------------------------------------
# `make coverage` rebuilds the unit tests with gcov (sanitizers off) and prints
# a per-source line-coverage summary; the annotated <source>.gcov files are left
# for inspection.
coverage:
	./scripts/coverage.sh

clean:
	rm -rf $(BUILD)
	$(MAKE) -C $(MBEDTLS_DIR)/library clean
