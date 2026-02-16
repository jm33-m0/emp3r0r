
CC=gcc
CFLAGS=-fPIC -c -I../bof_common -fno-stack-protector -fvisibility=hidden -g0
TARGET=hello_linux.o
SOURCE=hello_linux.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<
	objcopy --strip-debug $@

clean:
	rm -f $(TARGET)
