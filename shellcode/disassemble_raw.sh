#!/bin/bash

if ! command -v rasm2 >/dev/null 2>&1; then
    echo "rasm2 not found, please install radare2 first"
    exit 1
fi

if [ -z "$1" ]; then
    echo "usage: $0 <shellcode.bin>"
    exit 1
fi

rasm2 -D -a x86 -b 64 "$(xxd -i "$1" | grep 0x | tr -d ',' | tr -d '[:space:]' | sed 's/0x//g')"
