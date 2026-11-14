#!/usr/bin/env bash
# Donut shellcode producer, built from the vendored source tree in src/.
#
# The loader stub and the Donut generator are rebuilt on every invocation, so
# edits to src/loader or src/donut.c take effect in the generated shellcode.
# The build is self-contained: a host zig toolchain builds both the Windows
# stubs (freestanding, no CRT) and the Linux generator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

INPUT=""
OUTPUT=""
ARCH="2"
ENTROPY="3"
COMPRESSION="2"
BYPASS="3"
DECOY=""
METHOD=""
PARAMS=""
RUN_THREAD="1"
EXIT_MODE="1"

print_usage() {
	cat <<'EOF'
usage: donut --input <pe> [options]

Builds Donut from src/ and converts a Windows PE into shellcode.

options:
  --input <path>        Windows PE (EXE/DLL) to convert (required)
  --output <path>       output .bin shellcode (default: <input>.donut.bin)
  --arch <1|2|3>        target architecture (default: 2, amd64)
  --entropy <1|2|3>     entropy level (default: 3)
  --compression <1|2|3> compression (default: 2)
  --bypass <1|2|3>      AMSI/WLDP bypass (default: 3)
  --decoy <path>        decoy module for module overloading
  --method <name>       entrypoint method for a DLL
  --params <string>     payload command-line parameters
  --run-thread <0|1>    run the entrypoint in a new thread (default: 1)
  --exit <1|2|3>        loader exit behaviour (default: 1)
EOF
}

die() {
	echo "[-] $*" >&2
	exit 1
}

abspath() {
	local p="$1"
	case "$p" in
	/* | [A-Za-z]:*) printf '%s' "$p" ;;
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

need_value() {
	case "$1" in
	--input | --output | --arch | --entropy | --compression | --bypass | --decoy | --method | --params | --run-thread | --exit)
		return 0
		;;
	esac
	return 1
}

set_opt() {
	local key="$1" value="$2"
	case "$key" in
	--input) INPUT="$value" ;;
	--output) OUTPUT="$value" ;;
	--arch) ARCH="$value" ;;
	--entropy) ENTROPY="$value" ;;
	--compression) COMPRESSION="$value" ;;
	--bypass) BYPASS="$value" ;;
	--decoy) DECOY="$value" ;;
	--method) METHOD="$value" ;;
	--params) PARAMS="$value" ;;
	--run-thread) RUN_THREAD="$value" ;;
	--exit) EXIT_MODE="$value" ;;
	*) die "unknown option: $key" ;;
	esac
}

while [[ $# -gt 0 ]]; do
	arg="$1"
	case "$arg" in
	--help | -h)
		print_usage
		exit 0
		;;
	--*=*)
		set_opt "${arg%%=*}" "${arg#*=}"
		shift 1
		;;
	--*)
		if need_value "$arg" && [[ $# -ge 2 ]]; then
			set_opt "$arg" "$2"
			shift 2
		else
			die "$arg requires a value"
		fi
		;;
	*) die "unexpected argument: $arg" ;;
	esac
done

[[ -n "$INPUT" ]] || die "--input is required"
INPUT="$(abspath "$INPUT")"
[[ -f "$INPUT" ]] || die "input not found: $INPUT"
case "${INPUT,,}" in
*.exe | *.dll | *.bin) ;;
*) die "input must be a PE or shellcode file" ;;
esac
if [[ -z "$OUTPUT" ]]; then
	OUTPUT="${INPUT}.donut.bin"
fi
OUTPUT="$(abspath "$OUTPUT")"
mkdir -p "$(dirname "$OUTPUT")"

case "$ARCH" in 1 | 2 | 3) ;; *) die "--arch must be 1, 2, or 3" ;; esac
case "$ENTROPY" in 1 | 2 | 3) ;; *) die "--entropy must be 1, 2, or 3" ;; esac
case "$COMPRESSION" in 1 | 2 | 3) ;; *) die "--compression must be 1, 2, or 3" ;; esac
case "$BYPASS" in 1 | 2 | 3) ;; *) die "--bypass must be 1, 2, or 3" ;; esac
case "$RUN_THREAD" in 0 | 1) ;; *) die "--run-thread must be 0 or 1" ;; esac
case "$EXIT_MODE" in 1 | 2 | 3) ;; *) die "--exit must be 1, 2, or 3" ;; esac
if [[ -n "$DECOY" ]]; then
	DECOY="$(abspath "$DECOY")"
	[[ -f "$DECOY" ]] || die "decoy not found: $DECOY"
fi

ZIG="${ZIG:-zig}"
ZIG_BIN="$(command -v "$ZIG" || true)"
[[ -n "$ZIG_BIN" ]] || die "zig not found; set ZIG or install zig"
ZIG_LIB="$(dirname "$(readlink -f "$ZIG_BIN")")/lib"
WIN_INCLUDE="$ZIG_LIB/libc/include/any-windows-any"
[[ -d "$WIN_INCLUDE" ]] || die "zig windows headers not found at $WIN_INCLUDE"
[[ -d "$SRC_DIR" ]] || die "Donut source missing at $SRC_DIR"

BUILDDIR="$(mktemp -d "${TMPDIR:-/tmp}/donut.XXXXXX")"
trap 'rm -rf "$BUILDDIR"' EXIT
cp -r "$SRC_DIR"/. "$BUILDDIR"/
cd "$BUILDDIR"

# Host tool that turns a PE .text section into the loader headers donut.c
# includes. UBSan is disabled because zig's runtime depends on newer libc
# symbols than the freestanding generator needs.
"$ZIG_BIN" cc -fno-sanitize=all -I include loader/exe2h/exe2h.c -o exe2h

# Rebuild both loader stubs from source. -nostdlib drops the CRT, -ffreestanding
# and -fno-builtin keep clang from emitting libc calls, and mem_shim.c supplies
# the few symbols it still lowers to. The entry symbol is irrelevant because
# exe2h extracts the .text section, but the linker needs one.
for target in x86-windows-gnu x86_64-windows-gnu; do
	"$ZIG_BIN" cc -target "$target" -nostdlib -isystem "$WIN_INCLUDE" \
		-fno-sanitize=all -ffreestanding -fno-builtin \
		-Wno-pragma-pack -Wno-pointer-sign \
		-DBYPASS_AMSI_B -DBYPASS_WLDP_A -DBYPASS_ETW_B \
		-fpack-struct=8 -fPIC -O0 \
		loader/loader.c loader/depack.c loader/clib.c loader/mem_shim.c \
		hash.c encrypt.c -I include \
		-Wl,--subsystem,console -Wl,-e,DonutLoader \
		-o loader.exe
	./exe2h loader.exe
done

# Linux generator. lib/aplib64.a is the vendored upstream archive.
"$ZIG_BIN" cc -fno-sanitize=all -Wunused-function -Wall -Wno-pragma-pack \
	-Wno-pointer-sign -fpack-struct=8 -DDONUT_EXE -I include \
	donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a -o donut

rm -f "$OUTPUT"
args=(-i "$INPUT" -o "$OUTPUT" -a "$ARCH" -e "$ENTROPY" -z "$COMPRESSION" -b "$BYPASS" -x "$EXIT_MODE" -f 1)
[[ "$RUN_THREAD" == "1" ]] && args+=(-t)
[[ -n "$DECOY" ]] && args+=(-j "$DECOY")
[[ -n "$METHOD" ]] && args+=(-m "$METHOD")
[[ -n "$PARAMS" ]] && args+=(-p "$PARAMS")

./donut "${args[@]}"

[[ -s "$OUTPUT" ]] || die "donut produced no output at $OUTPUT"
size="$(wc -c <"$OUTPUT" | tr -d '[:space:]')"
echo "[+] generated payload: $OUTPUT ($size bytes)"
