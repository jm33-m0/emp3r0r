#!/usr/bin/env bash
# Crystal-Kit PICO linker: convert a Windows DLL into Crystal Palace PICO
# shellcode using the postex-loader spec (self-contained ror13 resolution).
#
# Runs on the C2 as a local module ("crystal_pack") and needs Java plus the
# vendored crystalpalace.jar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYSTALPALACE_JAR="$SCRIPT_DIR/crystalpalace/crystalpalace.jar"
POSTEX_DIR="$SCRIPT_DIR/postex-loader"
SPEC="$POSTEX_DIR/loader.spec"
LIBTCG="$SCRIPT_DIR/libtcg.x64.zip"

# Native MinGW gcc needs a Windows temp path when invoked from MSYS/Cygwin;
# otherwise it falls back to C:\Windows and fails to create temporary files.
# The guard keeps this portable: plain Linux/macOS builds keep /tmp.
if command -v cygpath >/dev/null 2>&1; then
    TMP_WIN="$(cygpath -w "${TMPDIR:-${TMP:-/tmp}}")"
    export TMP="$TMP_WIN" TEMP="$TMP_WIN" TMPDIR="$TMP_WIN"
fi

DLL=""
OUTPUT=""
ARGS=""
JAVA="${JAVA:-}"

print_usage() {
  cat <<'EOF'
usage: crystal_pack --dll <input.dll> [options]

options:
  --dll <path>     Windows DLL to wrap into PICO (required, x64)
  --output <path>  output .bin shellcode (default: <dll>.pico.bin)
  --args <string>  optional args baked into the PICO (delivered to DllMain
                   as lpReserved when no runtime args are supplied)
EOF
}

# resolve a path to an absolute path without requiring the target to exist
abspath() {
  local p="$1"
  case "$p" in
    /*|[A-Za-z]:*|//*) printf '%s' "$p" ;;
    *)
      local d b resolved
      d="$(dirname "$p")"
      b="$(basename "$p")"
      if resolved="$(cd "$d" 2>/dev/null && pwd)"; then
        printf '%s/%s' "$resolved" "$b"
      else
        printf '%s/%s' "$(pwd)" "$p"
      fi
      ;;
  esac
}

# does this flag consume a value?
needs_value() {
  case "$1" in
    --dll|--input|--input-dll|--dll-path|--output|--out|--output-file|--args)
      return 0 ;;
  esac
  return 1
}

set_opt() {
  local key="$1" val="$2"
  case "$key" in
    --dll|--input|--input-dll|--dll-path) DLL="$val" ;;
    --output|--out|--output-file) OUTPUT="$val" ;;
    --args) ARGS="$val" ;;
  esac
}

# ---- parse args (order independent) ----
while [[ $# -gt 0 ]]; do
  arg="$1"
  case "$arg" in
    --help|-h)
      print_usage
      exit 0
      ;;
    --*=*)
      set_opt "${arg%%=*}" "${arg#*=}"
      shift 1
      ;;
    --*)
      if needs_value "$arg" && [[ $# -ge 2 ]] && [[ "$2" != --* ]]; then
        set_opt "$arg" "$2"
        shift 2
      else
        set_opt "$arg" ""
        shift 1
      fi
      ;;
    *)
      shift 1
      ;;
  esac
done

# ---- validate ----
if [ -z "$DLL" ]; then
  echo "[-] --dll is required" >&2
  print_usage
  exit 1
fi

if [ ! -f "$CRYSTALPALACE_JAR" ]; then
  echo "[-] crystalpalace.jar not found: $CRYSTALPALACE_JAR" >&2
  exit 1
fi

if [ ! -f "$SPEC" ]; then
  echo "[-] loader spec not found: $SPEC" >&2
  exit 1
fi

if [ ! -f "$LIBTCG" ]; then
  echo "[-] libtcg.x64.zip not found: $LIBTCG" >&2
  exit 1
fi

if [ -z "$JAVA" ]; then
  if command -v java >/dev/null 2>&1; then
    JAVA="$(command -v java)"
  else
    echo "[-] java not found in PATH. Install a JRE or set JAVA=/path/to/java." >&2
    exit 1
  fi
fi

DLL_ABS="$(abspath "$DLL")"
if [ ! -f "$DLL_ABS" ]; then
  echo "[-] input DLL not found: $DLL_ABS" >&2
  exit 1
fi

if [ -z "$OUTPUT" ]; then
  OUTPUT="${DLL_ABS%.*}.pico.bin"
fi
OUTPUT_ABS="$(abspath "$OUTPUT")"
mkdir -p "$(dirname "$OUTPUT_ABS")"

# ---- build the postex-loader objects (non-fatal) ----
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 && command -v nasm >/dev/null 2>&1; then
  echo "[*] Building postex-loader objects"
  make -C "$POSTEX_DIR" all
else
  echo "[*] Skipping object build; using prebuilt postex-loader objects if present"
fi

# ---- bake optional args into a dll_args section ----
ARGS_FILE="$(mktemp)"
trap 'rm -f "$ARGS_FILE"' EXIT
printf '%s\0' "$ARGS" > "$ARGS_FILE"

# ---- link ----
echo "[+] Crystal-Kit: converting DLL to PICO shellcode"
echo "    DLL:     $DLL_ABS"
echo "    Spec:    $SPEC"
echo "    Args:    ${ARGS:-<none>}"
echo "    Output:  $OUTPUT_ABS"

"$JAVA" -jar "$CRYSTALPALACE_JAR" link "$SPEC" "$DLL_ABS" "$OUTPUT_ABS" "%ARGFILE=$ARGS_FILE"

if [ -f "$OUTPUT_ABS" ]; then
  SIZE="$(wc -c < "$OUTPUT_ABS" | tr -d '[:space:]')"
  echo "[+] PICO shellcode written to $OUTPUT_ABS"
  echo "    size: $SIZE bytes"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "    sha256: $(sha256sum "$OUTPUT_ABS" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    echo "    sha256: $(shasum -a 256 "$OUTPUT_ABS" | awk '{print $1}')"
  fi
else
  echo "[-] Crystal Palace did not produce an output file" >&2
  exit 1
fi
