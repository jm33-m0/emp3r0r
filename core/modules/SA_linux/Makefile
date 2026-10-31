# Linux BOFs from TrustedSec ELFLoader (see LICENSE.txt).
#
# These are freestanding x86_64 ET_REL objects, so they do not link a libc ABI.
# They are compiled with the zig toolchain shipped with emp3r0r; the loader
# resolves their libc calls on the target. -fno-sanitize=all is required so no
# UBSan runtime symbols leak into a BOF.
CC = zig cc
ZIG_TARGET ?= x86_64-linux-gnu.2.17
CFLAGS = -O2 -fPIC -c -fno-stack-protector -fno-sanitize=all \
         -fvisibility=hidden -I includes
SOURCES = $(wildcard SA/src/*.c)
OBJECTS = $(SOURCES:.c=.o)

# Portable variants: RV32 ET_REL objects for the rvvm_linux interpreter.
# RV32I only (no compressed instructions), non-PIC so the in-VM loader sees
# absolute relocations, and no unwind tables or debug sections.
RV_CC = zig cc
RV_TARGET ?= riscv32-linux-musl
RV_CFLAGS = -target $(RV_TARGET) -mcpu=generic_rv32 -O2 -g0 -fno-pic \
            -mno-relax -msmall-data-limit=0 -fno-asynchronous-unwind-tables \
            -fno-unwind-tables -fno-builtin -fno-stack-protector \
            -fno-sanitize=all -fvisibility=hidden -I includes
# ifconfig needs getifaddrs, which the guest runtime does not provide yet.
RV_SOURCES = $(filter-out SA/src/ifconfig.c,$(SOURCES))
RV_OBJECTS = $(RV_SOURCES:.c=.rv.o)

all: $(OBJECTS) $(RV_OBJECTS)

SA/src/%.o: SA/src/%.c
	$(CC) -target $(ZIG_TARGET) $(CFLAGS) -o $@ $<

SA/src/%.rv.o: SA/src/%.c
	$(RV_CC) $(RV_CFLAGS) -c -o $@ $<

clean:
	rm -f SA/src/*.o SA/src/*.rv.o
