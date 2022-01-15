# The loader (main) needs to be position-independant, otherwise the loader and the file to
# load (dummy) would be loaded onto the same offset => crash!
all:
	gcc -DOS_LINUX -DARCH_X86_64 elf.c main.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

clean:
	rm main_{32,64} dummy_{32,64}
