#!/bin/bash
#
# Build every SQL-BOF BOF into SQL/<name>/<name>.{x64,x86}.o, which is where
# config.json expects them. core/build.py calls this automatically.
set -e

cd src/SQL
for dir in */; do
    dir=${dir%/}
    if [ -f "$dir/Makefile" ]; then
        make -C "$dir" >/dev/null
        echo "- $dir"
    fi
done
