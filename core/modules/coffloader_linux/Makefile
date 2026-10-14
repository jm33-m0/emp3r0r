# Build the Linux BOF loader as the shared object shipped with this module.
#
# Both agents map it as the coffloader_linux dependency: the C agent through
# dynload, the Go agent through memmod (core/lib/coffloader). Keep this the
# single source of the loader.
#
# Hosted artifact: glibc is linked dynamically and pinned to the oldest
# supported ABI (2.17). Never link glibc statically. The C2 runs this on every
# module invocation; the build is idempotent.
CC = zig cc
ZIG_TARGET ?= x86_64-linux-gnu.2.17
CFLAGS = -O2 -fPIC -Wall
TARGET = coffloader_linux.so
SOURCE = loader_linux.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) -target $(ZIG_TARGET) -shared $(CFLAGS) -o $@ $(SOURCE) -ldl
	@command -v strip >/dev/null 2>&1 && \
	  strip --remove-section=.comment $@ || true

clean:
	rm -f $(TARGET)
