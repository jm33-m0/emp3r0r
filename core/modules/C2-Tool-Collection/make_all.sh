#!/bin/bash
#
# Build every Outflank C2 Tool Collection BOF. core/build.py calls each
# module's make_all.sh automatically; the compiled objects land next to each
# tool's SOURCE directory and are listed in config.json.
set -e

make -C BOF
