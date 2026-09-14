include ../common.mk

all: bin/loader.x64.o

bin:
	mkdir bin

bin/loader.x64.o: bin
	$(CC_64) $(CFLAGS_COMMON) -c src/loader.c   -o bin/loader.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/services.c -o bin/services.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/pico.c     -o bin/pico.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/hooks.c    -o bin/hooks.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/SilentMoonwalk.c -o bin/SilentMoonwalk.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/mask.c     -o bin/mask.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/cfg.c      -o bin/cfg.x64.o
	$(CC_64) $(CFLAGS_COMMON) -c src/cleanup.c  -o bin/cleanup.x64.o
	
	$(NASM) src/DesyncSpoofer.asm -o bin/DesyncSpoofer.x64.bin

clean:
	rm -f bin/*
