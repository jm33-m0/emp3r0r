BOFNAME := global_unprotect
COMINCLUDE := -I ../../common
LIBINCLUDE := 
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC := x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF 
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../Remote/$(BOFNAME) 
	mv $(BOFNAME)*.o ../../../Remote/$(BOFNAME)

test:
	$(CC_x64) entry.c $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe  
	$(CC_x86) entry.c $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe 

scanbuild:
	$(CC) entry.c $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).scanbuild.exe

check:
	cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction $(COMINCLUDE) --platform=win64 entry.c

clean:
	rm $(BOFNAME).*.exe