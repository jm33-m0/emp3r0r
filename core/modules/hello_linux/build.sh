#!/bin/sh
# The C2 appends a module's invocation flags (--who ...) to its build command.
# They parameterize the BOF run, not the build, so ignore them and just build.
set -e
exec make
