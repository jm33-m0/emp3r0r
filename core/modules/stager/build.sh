#!/bin/bash
set -e

# Default configuration values
STAGER_FORMAT="shellcode"
TRANSPORT="http"
DOWNLOAD_HOST="127.0.0.1"
DOWNLOAD_PORT="8000"
DOWNLOAD_PATH="/"
DOWNLOAD_KEY=""
UNPACKER="rc4"

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
  --unpacker)
    UNPACKER="$2"
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
      --unpacker) UNPACKER="$val" ;;
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
echo "    Download Host: $DOWNLOAD_HOST"
echo "    Download Port: $DOWNLOAD_PORT"
echo "    Download Path: $DOWNLOAD_PATH"
echo "    Download Key:  [SET]"

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
  TRANSPORT="$TRANSPORT" \
  UNPACKER="$UNPACKER"

echo "[+] Stager build complete."
