#!/bin/bash
# Build the socks5 object the C2 asked for. A RISC-V module build exports
# EMP3R0R_BOF_ARCH=riscv32 and a riscv32 compiler environment; building the
# native object in that pass would compile it for the wrong architecture.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

target=socks5.o
if [[ "${EMP3R0R_BOF_ARCH:-}" == "riscv32" ]]; then
	target=socks5.rv.o
fi

make clean
exec make "$target"
