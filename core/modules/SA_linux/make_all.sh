#!/bin/bash
# Build every ELFLoader BOF with the shipped zig toolchain.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec make
