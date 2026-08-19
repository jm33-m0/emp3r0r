# Crystal-Kit PICO loader DLL (emp3r0r module payload)
#
# make dll -> build ../CrystalKit.x64.dll (needs x86_64-w64-mingw32-gcc)
#
# make_all.sh passes DEBUG=1 through when EMP3R0R_DEBUG=1 (set by core/build.py
# for --debug builds).

DEBUG_FLAG := $(if $(filter 1 true yes,$(DEBUG)),-DDEBUG,)

# Function/data sections + --gc-sections drop the unused BOF compatibility
# helpers (token/spawn/inject) that we don't call, keeping the loader small.
all: dll

dll:
	x86_64-w64-mingw32-gcc -shared -O2 -Wall -ffunction-sections -fdata-sections \
		-Wl,--gc-sections -s $(DEBUG_FLAG) -DBUILD_DLL \
		crystal-loader.c beacon_compatibility.c -o ../CrystalKit.x64.dll

clean:
	rm -f ../CrystalKit.x64.dll
