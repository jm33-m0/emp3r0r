# exec

Runs one command on a Linux C agent through the BOF loader and prints its
combined stdout/stderr. The C2 `exec` command dispatches this module for C
agents; x86-64 runs the native object, every other architecture runs the RV32
guest through the interpreter. The `mode` parameter selects `/bin/sh -c`
(`shell`, the default) or a direct exec of the tokenized command line (`exec`).

Process spawning is not opsec: the command runs in a child process with a
readable command line and leaves process-table and audit artefacts.

Usage and constraints: [docs/exec_bof.md](../../../docs/exec_bof.md).
