#!/bin/bash
set -e

echo "[*] Building COFFLoader DLLs..."

# COFFLoader.x64.dll
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[*] Building COFFLoader.x64.dll"
    make dll
else
    echo "[!] x86_64-w64-mingw32-gcc not found, skipping COFFLoader.x64.dll"
fi

# COFFLoader.x86.dll
if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[*] Building COFFLoader.x86.dll"
    make dll32
else
    echo "[!] i686-w64-mingw32-gcc not found, skipping COFFLoader.x86.dll"
fi
