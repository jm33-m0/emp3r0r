#!/bin/bash
#
# Build every Outflank C2 Tool Collection BOF. The C2 module builder runs this
# when a declared payload is missing; the compiled objects land next to each
# tool's SOURCE directory and are listed in config.json.
set -e

make -C BOF
