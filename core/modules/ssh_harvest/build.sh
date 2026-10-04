#!/bin/sh
# The C2 appends the module flags (--reg-name, --code-pattern, ...) to the
# build command. They are not make options, so ignore them and just rebuild
# the BPF object.
set -e
exec make
