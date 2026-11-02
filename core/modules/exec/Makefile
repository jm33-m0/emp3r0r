# exec BOF: one relocatable object per architecture.
#
# The native object is freestanding position-independent code; the loader
# resolves its libc calls on the target, so it is compiled against the pinned
# glibc ABI. The RV32 object is linked with musl by the C2 into a guest
# executable. -fno-sanitize=all keeps UBSan runtime symbols out of the object:
# zig injects UBSan instrumentation by default.
#
# Compiler variables are module-local: the C2 exports CC and ZIG_TARGET for a
# RISC-V module build, and a shared name would otherwise compile the native
# object for RV32.
BOF_CC = zig cc
BOF_ZIG_TARGET ?= x86_64-linux-gnu.2.17
CFLAGS = -O2 -fPIC -c -fno-stack-protector -fno-sanitize=all \
         -fvisibility=hidden

RV_CC = zig cc
RV_TARGET ?= riscv32-linux-musl
RV_CFLAGS = -target $(RV_TARGET) -mcpu=generic_rv32 -O2 -g0 -fno-pic \
            -mno-relax -msmall-data-limit=0 -fno-asynchronous-unwind-tables \
            -fno-unwind-tables -fno-builtin -fno-stack-protector \
            -fno-sanitize=all -fvisibility=hidden

SOURCE = exec.c
TARGET = exec.o
RV_TARGET_OBJ = exec.rv.o

# A failed objcopy (for example a wrong architecture) must not leave a partial
# object behind for the next run to package.
.DELETE_ON_ERROR:

all: $(TARGET) $(RV_TARGET_OBJ)

$(TARGET): $(SOURCE)
	$(BOF_CC) -target $(BOF_ZIG_TARGET) $(CFLAGS) -o $@ $<
	objcopy --strip-debug $@

$(RV_TARGET_OBJ): $(SOURCE)
	$(RV_CC) $(RV_CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(RV_TARGET_OBJ)
