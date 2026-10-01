#!/bin/sh
# The C2 appends the module flags (--obj, --prog, --action) to the build
# command. They are not Makefile options, so ignore them and just ensure
# libbpf.so is built.
set -e
exec make
