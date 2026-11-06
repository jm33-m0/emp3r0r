# Standalone debug runner for the RV32IMA interpreter.
#
# rvvmrun links ../rvvm.c instead of mapping rvvm_linux.so, so a debugger stops
# in the loader, the guest memory bus and the syscall gate. The interpreter is
# compiled with RV_TRACE so `rvvmrun -t` can trace guest syscalls; the module
# build never defines it.

CC ?= cc
ZIG ?= zig

# Debug builds: no optimisation, full symbols. The vendored interpreter trips
# -Wsign-compare, which is not actionable here.
CFLAGS ?= -O0 -g3 -std=c99 -Wall -Wextra -Wno-sign-compare -DRV_TRACE \
          -I../../../c_agent/include

# The guest entry shim and linker script the C2 embeds, baked in for
# `rvvmrun build`.
GUEST_DIR = ../../../internal/cc/modules/rvguest
GUEST_DEFS = -DRV_GUEST_SHIM='"$(abspath $(GUEST_DIR))/main.c"' \
             -DRV_GUEST_LD='"$(abspath $(GUEST_DIR))/guest.ld"'

all: rvvmrun

rvvmrun: rvvmrun.c ../rvvm.c ../vendor/mini-rv32ima/mini-rv32ima.h \
         ../../../c_agent/include/rvvm_abi.h
	$(CC) $(CFLAGS) $(GUEST_DEFS) -o $@ rvvmrun.c ../rvvm.c

clean:
	rm -f rvvmrun

.PHONY: all clean
