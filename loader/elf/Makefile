# The loader (main) needs to be position-independant, otherwise the loader and the file to
# load (dummy) would be loaded onto the same offset => crash!
#
# run demo.exe and loader.so will be opened, put some binary called `emp3r0r` and it will be executed
all: loader_so runner_so demo

debug: loader_so_debug demo

runner_so:
	${CC} -DOS_LINUX -DARCH_X86_64 runner.c -o runner.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

loader_so:
	${CC} -DOS_LINUX -DARCH_X86_64 elf.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s

loader_so_debug:
	${CC} -DOS_LINUX -DARCH_X86_64 elf.c loader.c -o loader.so -pie -fPIC -shared -nostdlib -nodefaultlibs -g

demo:
	${CC} demo.c -g -ldl -o demo.exe

clean:
	rm -f *.so *.exe
