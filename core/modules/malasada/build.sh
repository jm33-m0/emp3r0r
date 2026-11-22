#!/usr/bin/env bash
# malasada shellcode producer. The converter is Go source in src/; every build
# compiles the current tree so a detection-loop edit changes the next blob.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

INPUT=""
OUTPUT=""
CALL_EXPORT="main"
COMPRESS="on"

die() {
	echo "[-] $*" >&2
	exit 1
}

set_opt() {
	local key="$1" value="$2"
	case "$key" in
	--input) INPUT="$value" ;;
	--output) OUTPUT="$value" ;;
	--call-export) CALL_EXPORT="$value" ;;
	--compress) COMPRESS="$value" ;;
	*) die "unknown option: $key" ;;
	esac
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--*=*)
		set_opt "${1%%=*}" "${1#*=}"
		shift 1
		;;
	--input | --output | --call-export | --compress)
		[[ $# -ge 2 ]] || die "$1 requires a value"
		set_opt "$1" "$2"
		shift 2
		;;
	*) die "unexpected argument: $1" ;;
	esac
done

[[ -n "$INPUT" ]] || die "--input is required"
[[ -f "$INPUT" ]] || die "input not found: $INPUT"
[[ -z "$OUTPUT" ]] && OUTPUT="${INPUT}.malasada.bin"
case "$COMPRESS" in
on | 1 | true | yes) COMPRESS_BOOL=true ;;
off | 0 | false | no) COMPRESS_BOOL=false ;;
*) die "--compress must be on or off" ;;
esac

GO_BIN="${GO:-}"
if [[ -z "$GO_BIN" ]]; then
	shipped_go="$SCRIPT_DIR/../../go/bin/go"
	if [[ -x "$shipped_go" ]]; then
		GO_BIN="$shipped_go"
		export GOROOT="$(cd "$SCRIPT_DIR/../../go" && pwd)"
	else
		GO_BIN="$(command -v go || true)"
	fi
fi
[[ -n "$GO_BIN" && -x "$GO_BIN" ]] || die "Go toolchain not found; set GO or install the operator kit's go directory"
[[ -f "$SRC_DIR/go.mod" ]] || die "malasada source missing at $SRC_DIR"

BUILDDIR="$(mktemp -d "${TMPDIR:-/tmp}/malasada.XXXXXX")"
trap 'chmod -R u+w "$BUILDDIR" 2>/dev/null || true; rm -rf "$BUILDDIR"' EXIT

echo "[+] Building malasada converter from $SRC_DIR"
(
	cd "$SRC_DIR"
	export GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod CGO_ENABLED=0
	export GOCACHE="$BUILDDIR/go-cache" GOPATH="$BUILDDIR/gopath"
	"$GO_BIN" build -trimpath -o "$BUILDDIR/malasada" ./cmd/malasada
)

args=(--call-export "$CALL_EXPORT" -o "$OUTPUT")
[[ "$COMPRESS_BOOL" == true ]] && args+=(--compress)
"$BUILDDIR/malasada" "${args[@]}" -- "$INPUT"
