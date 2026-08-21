CC_64=x86_64-w64-mingw32-gcc
NASM=nasm

# Native MinGW gcc needs a Windows temp path when invoked from MSYS/Cygwin;
# otherwise it falls back to C:\Windows and fails to create temporary files.
# Compute it here so direct `make` invocations work too, and keep /tmp on
# Linux/macOS where cygpath is not present.
TMP_WIN := $(shell if command -v cygpath >/dev/null 2>&1; then cygpath -w /tmp; else echo /tmp; fi)
export TMP := $(TMP_WIN)
export TEMP := $(TMP_WIN)
export TMPDIR := $(TMP_WIN)

all: bin/loader.x64.o

bin:
	mkdir bin

bin/loader.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/loader.c   -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/services.c -o bin/services.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/pico.c     -o bin/pico.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/hooks.c    -o bin/hooks.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/SilentMoonwalk.c -o bin/SilentMoonwalk.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/mask.c     -o bin/mask.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/cfg.c      -o bin/cfg.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/cleanup.c  -o bin/cleanup.x64.o
	
	$(NASM) src/DesyncSpoofer.asm -o bin/DesyncSpoofer.x64.bin

clean:
	rm -f bin/*
