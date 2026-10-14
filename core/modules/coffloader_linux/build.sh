#!/bin/sh
# The C2 appends the module flags (--obj, --prog, ...) to the build command.
# They are not make options, so ignore them and just ensure the loader builds.
set -e
exec make
