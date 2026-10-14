# core/c_agent/Makefile
#
# Hosted C agent library, unit tests and fuzz targets.
#
# The agent is assembled from pluggable providers, one per external dependency,
# mirroring core/modules/stager_linux's TRANSPORT=<name> model. Select them on
# the command line, e.g.:
#
#   make agent CRYPTO=mbedtls GZIP=miniz HTTP=libcurl
#
# Each group is implemented by src/<group>/c2_<group>_<name>.c; drop a new file
# in and build with <GROUP>=<name> to add your own backend.

# zig is the project's compiler (shipped with emp3r0r, pinned in core/build.py),
# so it builds the library and agent by default. Make predefines CC=cc, so a
# plain `CC ?=` would never fire; override only the built-in default and leave a
# command-line/environment CC (and HOSTCC) alone.
ifeq ($(origin CC),default)
  CC = zig cc
endif
HOSTCC ?= gcc
AR ?= ar
WARN = -Wall -Wextra -Werror -std=c99

# ---- provider selection ----------------------------------------------------
# CRYPTO:    openssl (default, system libcrypto via dynload) | mbedtls (vendored)
# GZIP:      miniz (default, vendored) | none
# HTTP:      libcurl (default, system libcurl via dynload)
# TRANSPORT: http_poll (default)
CRYPTO ?= openssl
GZIP ?= miniz
HTTP ?= libcurl
TRANSPORT ?= http_poll

CRYPTO_SRC = src/crypto/c2_crypto_$(CRYPTO).c
GZIP_SRC = src/gzip/c2_gzip_$(GZIP).c
HTTP_SRC = src/transport/c2_http_client_$(HTTP).c
TRANSPORT_SRC = src/transport/c2_transport_$(TRANSPORT).c

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

INCLUDES = -Iinclude -Ivendor/tinycbor -Ivendor/miniz $(MINIZ_DEFS) \
           $(EXTRA_INCLUDES)

# Vendored tinycbor (MIT). See vendor/tinycbor/README.md.
TINYCBOR_SRC = vendor/tinycbor/cborencoder.c \
               vendor/tinycbor/cborencoder_close_container_checked.c \
               vendor/tinycbor/cborparser.c \
               vendor/tinycbor/cborparser_dup_string.c \
               vendor/tinycbor/cborerrorstrings.c \
               vendor/tinycbor/cborvalidation.c

# Protocol layer plus the selected providers. strings.c / system.c /
# net_utils.c are freestanding-only (they override libc) and are excluded.
PORTABLE_SRC = src/rc4.c src/packer.c src/dynload.c src/dynload_hosted.c \
               src/debug.c src/c2_common.c src/c2_crypto.c \
               src/c2_messages.c src/c2_agent_info.c src/c2_config.c \
               src/c2_secureconn.c src/c2_session.c src/c2_memfile.c \
               src/c2_bof.c src/c2_sysinfo.c src/c2_module.c \
               $(GZIP_SRC) $(CRYPTO_SRC) $(TRANSPORT_SRC) $(HTTP_SRC) \
               $(EXTRA_SRC)

SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_CFLAGS = $(WARN) -O1 -g $(INCLUDES) $(SAN)

BUILD = build

.PHONY: all lib agent test test-mbedtls vendor-mbedtls fuzz clean

all: lib

# ---- vendored mbedTLS ------------------------------------------------------
$(MBEDTLS_CRYPTO_LIB):
	$(MAKE) -C $(MBEDTLS_DIR)/library libmbedcrypto.a libmbedtls.a

vendor-mbedtls: $(MBEDTLS_CRYPTO_LIB)

# ---- hosted static library -------------------------------------------------
lib: $(BUILD)/libc2agent.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/libc2agent.a: $(PORTABLE_SRC) $(TINYCBOR_SRC) | $(BUILD)
	@rm -rf $(BUILD)/lib && mkdir -p $(BUILD)/lib
	@set -e; for s in $(PORTABLE_SRC) $(TINYCBOR_SRC); do \
		o=$(BUILD)/lib/$$(basename $$s .c).o; \
		$(CC) $(WARN) -O2 -g $(INCLUDES) -c $$s -o $$o; \
	done
	$(AR) rcs $@ $(BUILD)/lib/*.o

# ---- reference agent executable -------------------------------------------
# The encrypted CBOR build config and the build-wide magic string are compiled
# as a generated C translation unit. The Go C2 renders it (lib/cagent) and
# passes its path here, so building the agent needs no Python or Go toolchain:
#
#   make agent CONFIG_SRC=/path/to/c2_config_embedded.c
#
# Without CONFIG_SRC the agent links with weak empty defaults and exits at
# startup (it has nothing to decrypt).
CONFIG_SRC ?=

# The agent links only what it reaches at runtime. rc4, packer, the debug shim
# and the c2_status_str table are stager/test-only; four of the six vendored
# tinycbor translation units are never called by the agent. Dropping them by
# name keeps the binary small even before --gc-sections.
AGENT_COMMON_SRC = src/dynload.c src/dynload_hosted.c \
                   src/c2_crypto.c src/c2_messages.c src/c2_agent_info.c \
                   src/c2_config.c src/c2_secureconn.c src/c2_session.c \
                   src/c2_memfile.c src/c2_bof.c src/c2_sysinfo.c \
                   src/c2_module.c
TINYCBOR_MIN_SRC = vendor/tinycbor/cborencoder.c vendor/tinycbor/cborparser.c

AGENT_CONFIG_SRC =
ifneq ($(strip $(CONFIG_SRC)),)
  AGENT_CONFIG_SRC = $(CONFIG_SRC)
endif
AGENT_SRC = $(AGENT_COMMON_SRC) $(GZIP_SRC) $(CRYPTO_SRC) $(TRANSPORT_SRC) \
            $(HTTP_SRC) $(EXTRA_SRC) $(TINYCBOR_MIN_SRC) src/c2_agent.c \
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

agent: $(BUILD)/c2_agent

$(BUILD)/c2_agent: $(AGENT_SRC) $(EXTRA_LIBS) | $(BUILD)
	$(CC) $(WARN) $(AGENT_CFLAGS) $(INCLUDES) $(AGENT_LDFLAGS) \
	  $(AGENT_SRC) $(EXTRA_LIBS) -o $@
	@command -v $(STRIP) >/dev/null 2>&1 && \
	  $(STRIP) --remove-section=.comment $@ || true

# ---- unit tests ------------------------------------------------------------
# test_dynload needs the real dynamic loader and libc, so it is not linked with
# strings.c (which would override libc's strstr/strcmp). The gzip round-trip
# test only makes sense when a real gzip provider is selected.
ifeq ($(GZIP),miniz)
  GZIP_TEST = $(BUILD)/test_c2_gzip $(BUILD)/test_c2_memfile
  GZIP_FUZZ = $(BUILD)/fuzz_gzip $(BUILD)/fuzz_memfile
endif

# BOF execution test: build the real coffloader_linux loader and the real
# hello_linux BOF from the module tree, then run the BOF through the agent's
# runner. Skipped when the module sources are absent (standalone checkout).
BOF_MODULE_DIR = ../modules/coffloader_linux
BOF_HELLO_DIR = ../modules/hello_linux
ifneq ($(wildcard $(BOF_MODULE_DIR)/loader_linux.c),)
  BOF_TEST = $(BUILD)/test_c2_bof
  BOF_FUZZ = $(BUILD)/fuzz_bof
endif

test: $(BUILD)/test_strings $(BUILD)/test_rc4 $(BUILD)/test_packer \
      $(BUILD)/test_net_parse $(BUILD)/test_dynload \
      $(BUILD)/test_c2_auth $(BUILD)/test_c2_messages \
      $(BUILD)/test_c2_sysinfo $(BUILD)/test_c2_module \
      $(BUILD)/test_c2_secureconn $(GZIP_TEST) $(BOF_TEST) \
      $(BUILD)/test_c2_crypto_openssl
	@set -e; for t in $^; do echo "--- $$t"; ./$$t; done

# The self-contained backend is only built when mbedTLS is vendored.
test-mbedtls: vendor-mbedtls $(BUILD)/test_c2_crypto_mbedtls
	@echo "--- $(BUILD)/test_c2_crypto_mbedtls"; ./$(BUILD)/test_c2_crypto_mbedtls

$(BUILD)/test_strings: tests/test_strings.c src/strings.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/strings.c -o $@

$(BUILD)/test_rc4: tests/test_rc4.c src/rc4.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/rc4.c -o $@

$(BUILD)/test_packer: tests/test_packer.c src/packer.c src/strings.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/packer.c src/strings.c -o $@

$(BUILD)/test_net_parse: tests/test_net_parse.c src/net_utils.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/net_utils.c -o $@

$(BUILD)/test_dynload: tests/test_dynload.c src/dynload.c src/dynload_hosted.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/dynload.c src/dynload_hosted.c -o $@

C2_TEST_SRC = src/c2_messages.c src/c2_agent_info.c src/c2_config.c \
              src/c2_crypto.c src/c2_common.c $(TINYCBOR_SRC)
STUB_SRC = tests/stub_crypto.c

CRYPTO_COMMON_SRC = src/c2_crypto.c src/c2_common.c

$(BUILD)/test_c2_crypto_openssl: tests/test_c2_crypto.c tests/test.h \
                                  $(CRYPTO_COMMON_SRC) \
                                  src/crypto/c2_crypto_openssl.c \
                                  src/dynload.c src/dynload_hosted.c | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_c2_crypto.c $(CRYPTO_COMMON_SRC) \
		src/crypto/c2_crypto_openssl.c src/dynload.c src/dynload_hosted.c -o $@

$(BUILD)/test_c2_crypto_mbedtls: tests/test_c2_crypto.c tests/test.h \
                                 $(CRYPTO_COMMON_SRC) \
                                 src/crypto/c2_crypto_mbedtls.c \
                                 $(MBEDTLS_CRYPTO_LIB) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $(MBEDTLS_INC) tests/test_c2_crypto.c \
		$(CRYPTO_COMMON_SRC) src/crypto/c2_crypto_mbedtls.c \
		$(MBEDTLS_CRYPTO_LIB) -o $@

$(BUILD)/test_c2_auth: tests/test_c2_auth.c $(C2_TEST_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(C2_TEST_SRC) -o $@

$(BUILD)/test_c2_messages: tests/test_c2_messages.c $(C2_TEST_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(C2_TEST_SRC) -o $@

$(BUILD)/test_c2_secureconn: tests/test_c2_secureconn.c src/c2_secureconn.c src/c2_common.c $(STUB_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/c2_secureconn.c src/c2_common.c $(STUB_SRC) -o $@

$(BUILD)/test_c2_gzip: tests/test_c2_gzip.c $(GZIP_SRC) $(EXTRA_SRC) \
                       src/c2_common.c tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(GZIP_SRC) $(EXTRA_SRC) src/c2_common.c -o $@

$(BUILD)/coffloader_linux.so: $(BOF_MODULE_DIR)/loader_linux.c | $(BUILD)
	$(MAKE) -C $(BOF_MODULE_DIR) >/dev/null
	cp $(BOF_MODULE_DIR)/coffloader_linux.so $@
	$(MAKE) -C $(BOF_MODULE_DIR) clean >/dev/null

$(BUILD)/hello_linux.o: $(BOF_HELLO_DIR)/hello_linux.c | $(BUILD)
	$(MAKE) -C $(BOF_HELLO_DIR) >/dev/null
	cp $(BOF_HELLO_DIR)/hello_linux.o $@
	$(MAKE) -C $(BOF_HELLO_DIR) clean >/dev/null

$(BUILD)/test_c2_bof: tests/test_c2_bof.c src/c2_bof.c src/dynload.c \
                      $(BUILD)/coffloader_linux.so $(BUILD)/hello_linux.o \
                      tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) \
	  -DBOF_LOADER_PATH='"$(BUILD)/coffloader_linux.so"' \
	  -DBOF_OBJ_PATH='"$(BUILD)/hello_linux.o"' \
	  tests/test_c2_bof.c src/c2_bof.c src/dynload.c -o $@

$(BUILD)/test_c2_module: tests/test_c2_module.c tests/test.h \
                       src/c2_module.c src/c2_common.c \
                       $(TINYCBOR_SRC) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_c2_module.c src/c2_module.c \
		src/c2_common.c $(TINYCBOR_SRC) -o $@

$(BUILD)/test_c2_memfile: tests/test_c2_memfile.c tests/test.h \
                          src/c2_memfile.c $(GZIP_SRC) $(EXTRA_SRC) \
                          src/c2_crypto.c src/c2_common.c \
                          src/crypto/c2_crypto_openssl.c \
                          src/dynload.c src/dynload_hosted.c | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_c2_memfile.c src/c2_memfile.c \
		$(GZIP_SRC) $(EXTRA_SRC) src/c2_crypto.c src/c2_common.c \
		src/crypto/c2_crypto_openssl.c src/dynload.c src/dynload_hosted.c -o $@

$(BUILD)/test_c2_sysinfo: tests/test_c2_sysinfo.c tests/test.h \
                          src/c2_sysinfo.c src/c2_memfile.c \
                          src/c2_messages.c src/c2_agent_info.c \
                          src/c2_crypto.c src/c2_common.c $(GZIP_SRC) \
                          $(EXTRA_SRC) src/crypto/c2_crypto_openssl.c \
                          src/dynload.c src/dynload_hosted.c \
                          $(TINYCBOR_SRC) | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) tests/test_c2_sysinfo.c src/c2_sysinfo.c \
		src/c2_memfile.c src/c2_messages.c src/c2_agent_info.c \
		src/c2_crypto.c src/c2_common.c $(GZIP_SRC) $(EXTRA_SRC) \
		src/crypto/c2_crypto_openssl.c src/dynload.c src/dynload_hosted.c \
		$(TINYCBOR_SRC) -o $@

# ---- fuzzing ---------------------------------------------------------------
# Default: the fallback mutational runner + sanitizers. For libFuzzer:
#   make fuzz CC=clang HOSTCC=clang FUZZER=libfuzzer
FUZZER ?= runner
ifeq ($(FUZZER),libfuzzer)
  FUZZ_LINK = -fsanitize=fuzzer,address,undefined
  FUZZ_DRIVER =
else
  FUZZ_LINK = -fsanitize=address,undefined -fno-omit-frame-pointer
  FUZZ_DRIVER = fuzz/fuzz_runner.c
endif

FUZZ_CFLAGS = $(WARN) -O1 -g $(INCLUDES) $(FUZZ_LINK)
FUZZ_ITERS ?= 50000
FUZZ_CORPUS ?= fuzz/corpus
FUZZ_OUT ?= $(BUILD)/corpus

fuzz: $(BUILD)/fuzz_rc4 $(BUILD)/fuzz_packer $(BUILD)/fuzz_inet_aton \
      $(BUILD)/fuzz_messages $(BUILD)/fuzz_agent_info $(BUILD)/fuzz_secureconn \
      $(BUILD)/fuzz_text $(BUILD)/fuzz_encdec $(GZIP_FUZZ) $(BOF_FUZZ) \
      $(BUILD)/fuzz_dynload $(BUILD)/fuzz_maps
	@set -e; mkdir -p $(BUILD)/crash; \
	for t in $^; do \
	  name=$$(basename $$t); name=$${name#fuzz_}; \
	  seeds=$$(ls $(FUZZ_CORPUS)/$$name/* 2>/dev/null || true); \
	  out=$(FUZZ_OUT)/$$name; mkdir -p $$out; \
	  echo "--- $$t ($$(echo $$seeds | wc -w) seed files)"; \
	  FUZZ_ITERS=$(FUZZ_ITERS) FUZZ_CORPUS_OUT=$$out \
	    FUZZ_CRASH=$(BUILD)/crash/$$name.bin ./$$t $$seeds; \
	done

$(BUILD)/fuzz_rc4: fuzz/fuzz_rc4.c $(FUZZ_DRIVER) src/rc4.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/rc4.c -o $@

$(BUILD)/fuzz_packer: fuzz/fuzz_packer.c $(FUZZ_DRIVER) src/packer.c src/strings.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/packer.c src/strings.c -o $@

$(BUILD)/fuzz_inet_aton: fuzz/fuzz_inet_aton.c $(FUZZ_DRIVER) src/net_utils.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/net_utils.c -o $@

$(BUILD)/fuzz_messages: fuzz/fuzz_messages.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_agent_info: fuzz/fuzz_agent_info.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_secureconn: fuzz/fuzz_secureconn.c $(FUZZ_DRIVER) $(STUB_SRC) \
                         src/c2_secureconn.c src/c2_common.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Itests $< $(FUZZ_DRIVER) $(STUB_SRC) \
		src/c2_secureconn.c src/c2_common.c -o $@

$(BUILD)/fuzz_text: fuzz/fuzz_text.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_encdec: fuzz/fuzz_encdec.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_gzip: fuzz/fuzz_gzip.c $(FUZZ_DRIVER) $(GZIP_SRC) $(EXTRA_SRC) \
                    src/c2_common.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(GZIP_SRC) $(EXTRA_SRC) \
		src/c2_common.c -o $@

$(BUILD)/fuzz_memfile: fuzz/fuzz_memfile.c $(FUZZ_DRIVER) src/c2_memfile.c \
                       $(GZIP_SRC) $(EXTRA_SRC) src/c2_crypto.c \
                       src/c2_common.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/c2_memfile.c $(GZIP_SRC) \
		$(EXTRA_SRC) src/c2_crypto.c src/c2_common.c -o $@

$(BUILD)/fuzz_bof: fuzz/fuzz_bof.c $(FUZZ_DRIVER) src/c2_bof.c src/dynload.c \
                   $(BUILD)/coffloader_linux.so fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -DFUZZ_BOF_LOADER='"$(BUILD)/coffloader_linux.so"' \
		$< $(FUZZ_DRIVER) src/c2_bof.c src/dynload.c -o $@

$(BUILD)/fuzz_dynload: fuzz/fuzz_dynload.c $(FUZZ_DRIVER) src/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/dynload.c -o $@

$(BUILD)/fuzz_maps: fuzz/fuzz_maps.c $(FUZZ_DRIVER) src/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/dynload.c -o $@

clean:
	rm -rf $(BUILD)
	$(MAKE) -C $(MBEDTLS_DIR)/library clean
