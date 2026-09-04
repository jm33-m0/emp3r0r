BOFNAME := scshellbof
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOFNAME).x64.o -Os -c ${BOFNAME}.c
	$(CC_x86) -o $(BOFNAME).x86.o -Os -c ${BOFNAME}.c
	$(CC_x86) -o $(BOFNAME).imp.x86.o -Os -c ${BOFNAME}.c -D_IMP
	$(CC_x64) -o $(BOFNAME).imp.x64.o -Os -c ${BOFNAME}.c -D_IMP
clean:
	rm $(BOFNAME).*.o
