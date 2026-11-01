# Build the RV32IMA interpreter as the shared object shipped with this module.
#
# The C agent maps it in memory (core/c_agent/src/util/elfload.c) and the Go
# agent through memmod; both call the exported `Run`. Keep this the single
# source of the interpreter.
#
# The module links libc dynamically to implement the guest syscall gate.

CC = zig cc
ZIG_TARGET ?= x86_64-linux-gnu.2.17
# Instruction budget per run: a runaway-guest guard, not a latency SLA.
# Scanning BOFs (tasklist, find, grep) legitimately run for hundreds of
# millions of guest instructions, so the bound is loose.
RV_MAX_INSNS ?= 0xffffffff
CFLAGS = -O2 -fPIC -std=c99 -Wall -Wextra -Werror -fvisibility=hidden \
         -fno-builtin -fno-stack-protector -fno-sanitize=all -fno-ident \
         -ffunction-sections -fdata-sections \
         -DRV_MAX_INSNS=$(RV_MAX_INSNS)
LDFLAGS = -shared -Wl,--gc-sections -Wl,--build-id=none -Wl,-z,noexecstack \
          -Wl,--hash-style=both
TARGET = rvvm_linux.so
SOURCES = rvvm.c
HEADERS = vendor/mini-rv32ima/mini-rv32ima.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) -target $(ZIG_TARGET) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)
	@command -v strip >/dev/null 2>&1 && \
	  strip --remove-section=.comment $@ || true

clean:
	rm -f $(TARGET)
