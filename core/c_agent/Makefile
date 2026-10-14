# core/c_agent/Makefile
#
# Hosted C agent library, unit tests and fuzz targets.
#
# Payload artifacts (the stager, the agent's own .so/.exe) are built by the
# module Makefiles under core/modules with the pinned zig toolchain. This
# Makefile builds the reusable library and drives the hosted tests/fuzzers.
#
# The builder image's zig cannot link the sanitizer runtimes, so tests/fuzzers
# use the host compiler by default. Pass HOSTCC="zig cc" to compile without
# sanitizers if no host compiler is available.

CC ?= zig cc
HOSTCC ?= gcc
AR ?= ar
INCLUDES = -Iinclude -Ivendor/tinycbor
WARN = -Wall -Wextra -Werror -std=c99

# Vendored tinycbor (MIT). See vendor/tinycbor/README.md.
TINYCBOR_SRC = vendor/tinycbor/cborencoder.c \
               vendor/tinycbor/cborencoder_close_container_checked.c \
               vendor/tinycbor/cborparser.c \
               vendor/tinycbor/cborparser_dup_string.c \
               vendor/tinycbor/cborerrorstrings.c \
               vendor/tinycbor/cborvalidation.c

# Portable sources a hosted agent links. strings.c / system.c / net_utils.c are
# freestanding-only (they override libc) and are deliberately excluded.
PORTABLE_SRC = src/rc4.c src/packer.c src/dynload.c src/dynload_hosted.c \
               src/debug.c src/c2_common.c src/c2_messages.c \
               src/c2_secureconn.c

SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_CFLAGS = $(WARN) -O1 -g $(INCLUDES) $(SAN)

BUILD = build

.PHONY: all lib test fuzz clean

all: lib

# ---- hosted static library -------------------------------------------------
lib: $(BUILD)/libc2agent.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/libc2agent.a: $(PORTABLE_SRC) $(TINYCBOR_SRC) | $(BUILD)
	@rm -rf $(BUILD)/lib && mkdir -p $(BUILD)/lib
	@set -e; for s in $(PORTABLE_SRC) $(TINYCBOR_SRC); do \
		o=$(BUILD)/lib/$$(basename $$s .c).o; \
		$(HOSTCC) $(WARN) -O2 -g $(INCLUDES) -c $$s -o $$o; \
	done
	$(AR) rcs $@ $(BUILD)/lib/*.o

# ---- unit tests ------------------------------------------------------------
# test_dynload needs the real dynamic loader and libc, so it is not linked with
# strings.c (which would override libc's strstr/strcmp).
test: $(BUILD)/test_strings $(BUILD)/test_rc4 $(BUILD)/test_packer \
      $(BUILD)/test_net_parse $(BUILD)/test_dynload \
      $(BUILD)/test_c2_auth $(BUILD)/test_c2_messages \
      $(BUILD)/test_c2_secureconn
	@set -e; for t in $^; do echo "--- $$t"; ./$$t; done

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

C2_TEST_SRC = src/c2_messages.c src/c2_common.c $(TINYCBOR_SRC)
STUB_SRC = tests/stub_crypto.c

$(BUILD)/test_c2_auth: tests/test_c2_auth.c $(C2_TEST_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(C2_TEST_SRC) -o $@

$(BUILD)/test_c2_messages: tests/test_c2_messages.c $(C2_TEST_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< $(C2_TEST_SRC) -o $@

$(BUILD)/test_c2_secureconn: tests/test_c2_secureconn.c src/c2_secureconn.c src/c2_common.c $(STUB_SRC) tests/test.h | $(BUILD)
	$(HOSTCC) $(TEST_CFLAGS) $< src/c2_secureconn.c src/c2_common.c $(STUB_SRC) -o $@

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
      $(BUILD)/fuzz_messages $(BUILD)/fuzz_secureconn $(BUILD)/fuzz_text \
      $(BUILD)/fuzz_encdec $(BUILD)/fuzz_dynload $(BUILD)/fuzz_maps
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

$(BUILD)/fuzz_secureconn: fuzz/fuzz_secureconn.c $(FUZZ_DRIVER) $(STUB_SRC) \
                         src/c2_secureconn.c src/c2_common.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) -Itests $< $(FUZZ_DRIVER) $(STUB_SRC) \
		src/c2_secureconn.c src/c2_common.c -o $@

$(BUILD)/fuzz_text: fuzz/fuzz_text.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_encdec: fuzz/fuzz_encdec.c $(FUZZ_DRIVER) $(C2_TEST_SRC) fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) $(C2_TEST_SRC) -o $@

$(BUILD)/fuzz_dynload: fuzz/fuzz_dynload.c $(FUZZ_DRIVER) src/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/dynload.c -o $@

$(BUILD)/fuzz_maps: fuzz/fuzz_maps.c $(FUZZ_DRIVER) src/dynload.c fuzz/fuzz_common.h | $(BUILD)
	$(HOSTCC) $(FUZZ_CFLAGS) $< $(FUZZ_DRIVER) src/dynload.c -o $@

clean:
	rm -rf $(BUILD)
