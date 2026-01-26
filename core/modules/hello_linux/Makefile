
CC=zig cc
CFLAGS=-fPIC -c -I../bof_common -fno-stack-protector -fvisibility=hidden -target x86_64-linux-musl
TARGET=hello_linux.o
SOURCE=hello_linux.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
