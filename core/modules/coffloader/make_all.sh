#!/bin/bash
set -e

echo "[*] Building COFFLoader DLLs..."

# core/build.py sets EMP3R0R_DEBUG=1 for --debug builds. Pass it through to
# make so the DLLs are compiled with -DDEBUG (DEBUG_PRINT tracing).
MAKE_DEBUG=""
if [ "${EMP3R0R_DEBUG}" = "1" ]; then
    MAKE_DEBUG="DEBUG=1"
fi

# COFFLoader.x64.dll
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[*] Building COFFLoader.x64.dll"
    make dll $MAKE_DEBUG
else
    echo "[!] x86_64-w64-mingw32-gcc not found, skipping COFFLoader.x64.dll"
fi

# COFFLoader.x86.dll
if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[*] Building COFFLoader.x86.dll"
    make dll32 $MAKE_DEBUG
else
    echo "[!] i686-w64-mingw32-gcc not found, skipping COFFLoader.x86.dll"
fi
