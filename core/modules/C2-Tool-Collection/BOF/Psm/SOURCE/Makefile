SRC = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRC))
CC_x86 := i686-w64-mingw32-gcc
CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x86 := i686-w64-mingw32-strip
STRIP_x64 := x86_64-w64-mingw32-strip
CFLAGS := -masm=intel

all: $(OBJS)

%.o: %.c
	$(CC_x64) $(CFLAGS) -o ../$*.x64.o -c $<
	$(STRIP_x64) --strip-unneeded ../$*.x64.o

	$(CC_x86) $(CFLAGS) -o ../$*.x86.o -DWOW64 -c $<
	$(STRIP_x86) --strip-unneeded ../$*.x86.o

clean:
	rm ../*.o
