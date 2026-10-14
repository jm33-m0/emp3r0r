
# Linux test BOF, compiled with the shipped zig toolchain pinned to glibc 2.17
# (the manylinux2014 builder ABI) instead of the host compiler.
#
# -fno-sanitize=all is required: zig cc injects UBSan instrumentation by
# default, and a BOF is freestanding position-independent code with no
# sanitizer runtime, so __ubsan_handle_* symbols can never be resolved by the
# loader.
CC=zig cc -target x86_64-linux-gnu.2.17
CFLAGS=-fPIC -c -I../bof_common -fno-stack-protector -fvisibility=hidden -g0 \
       -fno-sanitize=all
TARGET=hello_linux.o
SOURCE=hello_linux.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<
	objcopy --strip-debug $@

clean:
	rm -f $(TARGET)
