CC_64=x86_64-w64-mingw32-gcc
NASM=nasm

all: bin/loader.x64.o

bin:
	mkdir bin

bin/loader.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/loader.c   -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/services.c -o bin/services.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/pico.c     -o bin/pico.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/hooks.c    -o bin/hooks.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/spoof.c    -o bin/spoof.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/mask.c     -o bin/mask.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/cfg.c      -o bin/cfg.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/cleanup.c  -o bin/cleanup.x64.o
	
	$(NASM) src/draugr.asm -o bin/draugr.x64.bin

clean:
	rm -f bin/*
