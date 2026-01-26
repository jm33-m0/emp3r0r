
CC=gcc
CFLAGS=-fPIC -c -I../bof_common -fno-stack-protector -fvisibility=hidden
TARGET=process_list_handles_linux.o
SOURCE=process_list_handles_linux.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
