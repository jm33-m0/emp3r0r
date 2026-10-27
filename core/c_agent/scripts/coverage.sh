#!/bin/sh
# Merge gcov data from every unit-test binary and print a per-source summary.
#
# Run as `make coverage`. Each test binary is built with gcov instrumentation
# (COV=--coverage, sanitizers off so the profiles are comparable), runs, and
# then, for each source, all of its .gcno files are handed to a single gcov
# invocation so the per-binary profiles are merged before the summary.
#
# The generated <source>.gcov files annotate every line: `####` is not covered,
# a count is covered. They are left in the working directory for inspection.
set -e
cd "$(dirname "$0")/.."

make clean
# gcov is a GCC runtime; the normal test/fuzz builds use zig cc.
make test COV=--coverage SAN= HOSTCC=gcc

rm -f ./*.gcov
srcs=$(ls build/*.gcno | sed 's#.*-##; s#\.gcno$##' | sort -u)
for src in $srcs; do
  case "$src" in
    stub_* | test_* | fuzz_*) continue ;;
  esac
  set -- build/*-"$src".gcno
  [ -e "$1" ] || continue
  printf '%-24s ' "$src.c"
  gcov -b -c "$@" 2>/dev/null | grep -A3 "/$src.c'" | grep 'Lines executed' ||
    echo "no data"
done
