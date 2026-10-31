# Build the RV32IMA interpreter as the shared object shipped with this module.
#
# The C agent maps it in memory (core/c_agent/src/util/elfload.c) and the Go
# agent through memmod; both call the exported `rv_run`. Keep this the single
# source of the interpreter.
#
# The module links libc dynamically: its host-call layer uses open/read/stat/
# opendir and friends to serve the guest BOF runtime. The RV32 runtime itself
# (runtime/rv_bof_runtime.o) is freestanding and embedded in the .so.

CC = zig cc
ZIG_TARGET ?= x86_64-linux-gnu.2.17
# Instruction budget per run: a DoS guard, not a latency SLA. RISC-V BOFs run
# an order of magnitude slower than native ones, so allow a couple of seconds.
RV_MAX_INSNS ?= 536870912
CFLAGS = -O2 -fPIC -std=c99 -Wall -Wextra -Werror -fvisibility=hidden \
         -fno-builtin -fno-stack-protector -fno-sanitize=all -fno-ident \
         -ffunction-sections -fdata-sections -Iinclude \
         -DRV_MAX_INSNS=$(RV_MAX_INSNS)
LDFLAGS = -shared -Wl,--gc-sections -Wl,--build-id=none -Wl,-z,noexecstack \
          -Wl,--hash-style=both
TARGET_LINUX = rvvm_linux.so
TARGET_WINDOWS = rvvm_windows.dll
SOURCES = rvvm.c
POSIX_HOST = rv_host_posix.c
WIN_HOST = rv_host_win32.c

# Guest runtime: RV32IMA only (no compressed instructions), musl headers for
# ABI-compatible struct layouts, but no libc linked into the guest.
RV_CC = zig cc
RV_TARGET ?= riscv32-linux-musl
RV_CFLAGS = -target $(RV_TARGET) -mcpu=generic_rv32 -O2 -g0 -fno-pic \
            -mno-relax -msmall-data-limit=0 -fno-asynchronous-unwind-tables \
            -fno-unwind-tables -fno-builtin -fno-stack-protector \
            -fno-sanitize=all -Iinclude
RUNTIME = runtime/rv_bof_runtime.o
RUNTIME_BLOB = runtime/rv_bof_runtime_blob.c
HEADERS = vendor/mini-rv32ima/mini-rv32ima.h include/rv_hostcall.h

all: $(TARGET_LINUX) $(TARGET_WINDOWS)

$(RUNTIME): runtime/rv_bof_runtime.c include/rv_hostcall.h
	$(RV_CC) $(RV_CFLAGS) -c -o $@ runtime/rv_bof_runtime.c

# A C array rather than .incbin: zig's compiler cache tracks the generated
# source, so changing the runtime rebuilds the module.
$(RUNTIME_BLOB): $(RUNTIME)
	@printf '#include <stdint.h>\nconst uint8_t rv_bof_runtime_image[] __attribute__((aligned(16))) = {\n' > $@
	@od -An -v -tu1 $(RUNTIME) | awk '{for(i=1;i<=NF;i++) printf "0x%02x,", $$i; printf "\n"}' >> $@
	@printf '};\nconst unsigned int rv_bof_runtime_image_len = %s;\n' "$$(wc -c < $(RUNTIME))" >> $@

$(TARGET_LINUX): $(SOURCES) $(POSIX_HOST) $(RUNTIME_BLOB) $(HEADERS)
	$(CC) -target $(ZIG_TARGET) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) \
	  $(POSIX_HOST) $(RUNTIME_BLOB)
	@command -v strip >/dev/null 2>&1 && \
	  strip --remove-section=.comment $@ || true

# Windows build: Win32 APIs only, no libc. The guest payload is identical.
WIN_TARGET ?= x86_64-windows-gnu
WIN_CFLAGS = -O2 -std=c99 -Wall -Wextra -Werror -fvisibility=hidden \
             -fno-builtin -fno-stack-protector -fno-sanitize=all \
             -ffunction-sections -fdata-sections -Iinclude \
             -DRV_MAX_INSNS=$(RV_MAX_INSNS)
WIN_OBJDIR = build/win
WIN_OBJS = $(WIN_OBJDIR)/rvvm.o $(WIN_OBJDIR)/rv_host_win32.o \
           $(WIN_OBJDIR)/rv_bof_runtime_blob.o

$(WIN_OBJDIR):
	mkdir -p $@

$(WIN_OBJDIR)/rvvm.o: rvvm.c $(HEADERS) | $(WIN_OBJDIR)
	$(CC) -target $(WIN_TARGET) $(WIN_CFLAGS) -c -o $@ $<

$(WIN_OBJDIR)/rv_host_win32.o: rv_host_win32.c $(HEADERS) | $(WIN_OBJDIR)
	$(CC) -target $(WIN_TARGET) $(WIN_CFLAGS) -c -o $@ $<

$(WIN_OBJDIR)/rv_bof_runtime_blob.o: $(RUNTIME_BLOB) | $(WIN_OBJDIR)
	$(CC) -target $(WIN_TARGET) $(WIN_CFLAGS) -c -o $@ $<

# No CRT: the agent's PE loader maps the image and calls the exports, so a
# minimal DllMain is all the entry point needs. Imports stay kernel32-only.
$(TARGET_WINDOWS): $(WIN_OBJS)
	$(CC) -target $(WIN_TARGET) -shared -nostdlib -Wl,-e,DllMain -o $@ \
	  $(WIN_OBJS) -lkernel32 -Wl,--gc-sections

clean:
	rm -f $(TARGET_LINUX) $(TARGET_WINDOWS) $(RUNTIME) $(RUNTIME_BLOB)
	rm -rf $(WIN_OBJDIR)
