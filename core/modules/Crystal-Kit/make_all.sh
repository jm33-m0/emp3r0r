#!/usr/bin/env bash
# Build the Crystal-Kit artifacts:
#
#   1. CrystalKit.x64.dll        — emp3r0r DLL module payload (PICO runner)
#   2. postex-loader objects      — Crystal Palace linker specs (PE -> PICO)
#
# Invoked automatically by core/build.py during a full emp3r0r build. The
# build is non-fatal when the cross compiler or nasm is missing so the global
# build still succeeds with prebuilt artifacts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Building Crystal-Kit..."

# Native MinGW gcc needs a Windows temp path when invoked from MSYS; otherwise
# it falls back to C:\Windows and fails to create temporary files.
if command -v cygpath >/dev/null 2>&1; then
    TMP_WIN="$(cygpath -w "${TMP:-/tmp}")"
    export TMP="$TMP_WIN" TEMP="$TMP_WIN" TMPDIR="$TMP_WIN"
fi

# core/build.py sets EMP3R0R_DEBUG=1 for --debug builds.
DEBUG_FLAG=""
if [ "${EMP3R0R_DEBUG:-}" = "1" ]; then
    DEBUG_FLAG="-DDEBUG"
fi

# CrystalKit.x64.dll (emp3r0r module payload). Built directly here because
# invoking make from MSYS can lose TMP/TEMP and break gcc's temp-file handling.
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[*] Building CrystalKit.x64.dll"
    x86_64-w64-mingw32-gcc -shared -O2 -Wall -ffunction-sections -fdata-sections \
        -Wl,--gc-sections -s $DEBUG_FLAG -DBUILD_DLL \
        "$HERE/wrapper/crystal-loader.c" "$HERE/wrapper/beacon_compatibility.c" \
        -o "$HERE/CrystalKit.x64.dll"
else
    echo "[!] x86_64-w64-mingw32-gcc not found, skipping CrystalKit.x64.dll"
fi

# Crystal Palace postex-loader objects (used by build.sh / crystal_pack to
# link a PE into PICO).
can_build=1
if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[!] x86_64-w64-mingw32-gcc not found"
    can_build=0
fi
if ! command -v nasm >/dev/null 2>&1; then
    echo "[!] nasm not found"
    can_build=0
fi

if [ "$can_build" = "1" ]; then
    make -C "$HERE/postex-loader"
else
    echo "[*] Skipping object build; using prebuilt postex-loader objects if present"
fi

echo "[*] Crystal-Kit artifacts:"
for obj in \
    "$HERE/CrystalKit.x64.dll" \
    "$HERE/postex-loader/bin/loader.x64.o" \
    "$HERE/postex-loader/bin/pico.x64.o" \
    "$HERE/postex-loader/bin/draugr.x64.bin"; do
    if [ -f "$obj" ]; then
        echo "    ok: $obj"
    else
        echo "    missing: $obj"
    fi
done
