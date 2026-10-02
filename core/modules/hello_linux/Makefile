
# Linux test BOF, compiled with the shipped zig toolchain pinned to glibc 2.17
# (the manylinux2014 builder ABI) instead of the host compiler.
CC=zig cc -target x86_64-linux-gnu.2.17
CFLAGS=-fPIC -c -I../bof_common -fno-stack-protector -fvisibility=hidden -g0
TARGET=hello_linux.o
SOURCE=hello_linux.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<
	objcopy --strip-debug $@

clean:
	rm -f $(TARGET)
