BOFNAME := tables
COMINCLUDE := -I ../../common
LIBINCLUDE := -lodbc32
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF 
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../SQL/$(BOFNAME) 
	mv $(BOFNAME)*.o ../../../SQL/$(BOFNAME)

goad:
	$(MAKE) all
	scp ../../../SQL/$(BOFNAME)/* jon.snow@10.2.10.11:BOFs/

test:
	$(CC_x64) entry.c -g $(COMINCLUDE) $(LIBINCLUDE)  -o $(BOFNAME).x64.exe
	$(CC_x86) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

test_goad:
	$(MAKE) test
	scp $(BOFNAME)*.exe jon.snow@10.2.10.11:BOFs/

scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all $(COMINCLUDE) --platform=win64 entry.c

clean:
	rm $(BOFNAME).*.exe