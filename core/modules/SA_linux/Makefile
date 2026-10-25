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

all: $(OBJECTS)

SA/src/%.o: SA/src/%.c
	$(CC) -target $(ZIG_TARGET) $(CFLAGS) -o $@ $<

clean:
	rm -f SA/src/*.o
