#!/bin/bash
set -e
echo "[INFO] Building SA modules"
for dir in SA/*; do
  if [[ -d "$dir" && -f "$dir/Makefile" ]]; then
    echo "[INFO] Building SA module: $(basename "$dir")"
    make -C "$dir" -j$(nproc) || echo "[WARN] Failed to build SA module $(basename "$dir")"
  fi
done
