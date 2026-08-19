#!/usr/bin/env bash
# Build the benign PICO fixtures used by core/internal/cc/modules/
# crystal_kit_windows_test.go:
#
#   testdata/noop.x64.dll           -> noop.pico.bin          (no-op DllMain)
#   testdata/capture.x64.dll        -> capture.pico.bin       (writes runtime args)
#   testdata/capture.x64.dll        -> capture_baked.pico.bin (args baked at link time)
#
# The .dll and .pico.bin files are gitignored build artifacts. Requires
# x86_64-w64-mingw32-gcc, Java and the vendored crystalpalace.jar.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Native MinGW gcc needs a Windows temp path when invoked from MSYS; otherwise
# it falls back to C:\Windows and fails to create temporary files.
if command -v cygpath >/dev/null 2>&1; then
    TMP_WIN="$(cygpath -w "${TMP:-/tmp}")"
    export TMP="$TMP_WIN" TEMP="$TMP_WIN" TMPDIR="$TMP_WIN"
fi

CC="${CC:-x86_64-w64-mingw32-gcc}"
JAVA="${JAVA:-java}"
CRYSTALPALACE_JAR="$HERE/crystalpalace/crystalpalace.jar"
SPEC="$HERE/postex-loader/loader.spec"

command -v "$CC" >/dev/null 2>&1 || { echo "[-] $CC not found" >&2; exit 1; }
[ -f "$CRYSTALPALACE_JAR" ] || { echo "[-] crystalpalace.jar not found" >&2; exit 1; }
[ -f "$SPEC" ] || { echo "[-] postex-loader spec not found" >&2; exit 1; }

mkdir -p "$HERE/testdata"

"$CC" -shared -O2 -Wall "$HERE/testdata/noop.c" -o "$HERE/testdata/noop.x64.dll"
"$CC" -shared -O2 -Wall "$HERE/testdata/capture.c" -o "$HERE/testdata/capture.x64.dll"

link_pico() {
    local dll="$1"
    local args_file="$2"
    local out="$3"
    "$JAVA" -jar "$CRYSTALPALACE_JAR" link "$SPEC" "$dll" "$out" "%ARGFILE=$args_file"
}

EMPTY_ARGS="$(mktemp)"
: > "$EMPTY_ARGS"
trap 'rm -f "$EMPTY_ARGS" "$BAKED_ARGS"' EXIT

link_pico "$HERE/testdata/noop.x64.dll"    "$EMPTY_ARGS" "$HERE/testdata/noop.pico.bin"
link_pico "$HERE/testdata/capture.x64.dll" "$EMPTY_ARGS" "$HERE/testdata/capture.pico.bin"

BAKED_ARGS="$(mktemp)"
printf 'baked args test\0' > "$BAKED_ARGS"
link_pico "$HERE/testdata/capture.x64.dll" "$BAKED_ARGS" "$HERE/testdata/capture_baked.pico.bin"

echo "[+] wrote testdata/noop.pico.bin, capture.pico.bin, capture_baked.pico.bin"
