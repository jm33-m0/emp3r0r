# The loader (main) needs to be position-independant, otherwise the loader and the file to
# load (dummy) would be loaded onto the same offset => crash!
all: so demo

debug: so_debug demo

so:
	gcc -DOS_LINUX -DARCH_X86_64 elf.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

so_debug:
	gcc -DOS_LINUX -DARCH_X86_64 elf.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -g

demo:
	gcc demo.c -g -ldl -o demo.exe

clean:
	rm -f loader.so demo.exe
