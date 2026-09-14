# Shared toolchain and flags for the Crystal Palace loader object builds.
#
# These objects are linked into PICO shellcode by Crystal Palace, which can
# only relocate the small set of references a plain freestanding compile
# emits. Zig's `cc` is frequently installed as x86_64-w64-mingw32-gcc and does
# not match that expectation out of the box:
#   - it injects UBSan and stack-protector runtime references at its default
#     -O0 (__ubsan_handle_*, __stack_chk_guard/__stack_chk_fail);
#   - it lowers aggregate zero-initialization to libc memset calls at -O0,
#     and -O2 turns the hand-rolled zeroing loops into memset as well;
#   - -O2 may emit jump tables in .rdata, which Crystal Palace rejects.
# -O2 with the -fno-* flags below keeps the code free of all of those while
# still letting Crystal Palace's own `make pic +optimize` control final size.
# -g0 also drops CodeView debug info from the shellcode.

CC_64 ?= x86_64-w64-mingw32-gcc
NASM ?= nasm

CFLAGS_COMMON = -DWIN_X64 -shared -Wall -Wno-pointer-arith -O2 -g0 \
	-fno-builtin -fno-jump-tables -fno-sanitize=undefined -fno-stack-protector

# Native MinGW gcc needs a Windows temp path when invoked from MSYS/Cygwin;
# otherwise it falls back to C:\Windows and fails to create temporary files.
# Keep /tmp on Linux/macOS where cygpath is not present.
TMP_WIN := $(shell if command -v cygpath >/dev/null 2>&1; then cygpath -w /tmp; else echo /tmp; fi)
export TMP := $(TMP_WIN)
export TEMP := $(TMP_WIN)
export TMPDIR := $(TMP_WIN)
