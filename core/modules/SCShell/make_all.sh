#!/bin/bash
# Build SCShell's BOF objects for the emp3r0r module system.
#
# Invoked by core/build.py and CI (test.yml) from the module directory.
# CS-BOF/Makefile cross-compiles with MinGW-w64 and emits:
#   CS-BOF/scshellbof.{x64,x86,imp.x64,imp.x86}.o
# The module config (config.json) references the non-imp objects for the
# "scshell" COFF module.
set -e

make -C CS-BOF
