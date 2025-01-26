loader_so:
	${CC} -DOS_LINUX -DARCH_X86_64 elf_loader.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

loader_so_debug:
	${CC} -DOS_LINUX -DARCH_X86_64 elf_loader.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -g -DDEBUG

clean:
	rm -f *.so *.exe
