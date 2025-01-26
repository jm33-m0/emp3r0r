# Add tinf source files
TINF_SRC = adler32.c crc32.c tinfgzip.c tinflate.c tinfzlib.c tinf.h

# Update the list of source files
SRC = stager.c aes.c elf_loader.c $(TINF_SRC)

stager_so:
	${CC} -DOS_LINUX -DARCH_X86_64 $(SRC) -o stager.so -pie -fPIC -shared -ldl -nostdlib -nodefaultlibs -s

stager_so_debug:
	${CC} -DOS_LINUX -DARCH_X86_64 $(SRC) -o stager.so -pie -fPIC -shared -ldl -nostdlib -nodefaultlibs -g -DDEBUG
