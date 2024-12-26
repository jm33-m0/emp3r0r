# The loader (main) needs to be position-independant, otherwise the loader and the file to
# load (dummy) would be loaded onto the same offset => crash!
#
# run demo.exe and loader.so will be opened, put some binary called `emp3r0r` and it will be executed
all: loader_so runner_so demo stager_so

debug: loader_so_debug stager_so_debug demo

runner_so:
	${CC} -DOS_LINUX -DARCH_X86_64 runner.c -o runner.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

loader_so:
	${CC} -DOS_LINUX -DARCH_X86_64 elf.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

loader_so_debug:
	${CC} -DOS_LINUX -DARCH_X86_64 elf.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -g -DDEBUG

# Add tinf source files
TINF_SRC = adler32.c crc32.c tinfgzip.c tinflate.c tinfzlib.c tinf.h

# Update the list of source files
SRC = stager.c aes.c elf.c $(TINF_SRC)

stager_so:
	${CC} -DOS_LINUX -DARCH_X86_64 $(SRC) -o stager.so -pie -fPIC -shared -ldl -nostdlib -nodefaultlibs -s

stager_so_debug:
	${CC} -DOS_LINUX -DARCH_X86_64 $(SRC) -o stager.so -pie -fPIC -shared -ldl -nostdlib -nodefaultlibs -g -DDEBUG

demo:
	${CC} demo.c -g -ldl -o demo.exe

clean:
	rm -f *.so *.exe
