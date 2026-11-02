# Command execution

`exec` runs one command on the target agent and returns its combined stdout and
stderr. The Go agent has the handler built in; a C agent runs the `exec` Linux
BOF (`core/modules/exec`).

> **Process spawning is not opsec.** The command runs in a child process with a
> readable command line, appears in the host's process table, and is visible to
> `ps`, `/proc`, auditd and any EDR. The console prints this warning before it
> dispatches, and the module manifest says the same.

## Usage

```text
exec --cmd 'id'
exec --cmd 'cat /etc/hostname'
exec --cmd 'uname -a 2>&1'
exec --cmd 'find /tmp -name "*.log"' --no-shell
```

| Option       | Meaning                                                    |
| ------------ | ---------------------------------------------------------- |
| `--cmd`      | Command line to run. Required.                             |
| `--no-shell` | Execute the command directly instead of through `/bin/sh`. |

By default a C agent runs the command through `/bin/sh -c`, so redirections,
pipes and quoting work as they do in a shell. `--no-shell` splits the command
line into words and executes the first word directly: quotes and backslashes
group and escape words, but there is no expansion, redirection, pipeline or
shell builtin, and no shell process is created. The module parameter behind the
flag is `mode` (`shell` or `exec`).

A Go agent keeps its own handler, which always runs the program directly, so
`--no-shell` matches its behavior and has no effect.

## Output

The BOF returns the command's combined stdout and stderr as the job's result,
which the operator console displays like any other command output. The capture
stops at 64 KiB; the output is followed by
`exec: output truncated at 65535 bytes` when that happens.

A command that produces no output prints nothing. A command that cannot be
started prints the host's reason, for example `exec: cannot fork`,
`exec: cannot execute` (the program was not found in direct mode) or
`exec: command timed out`.

## Limits

- The call is synchronous on the agent's message loop: the agent does not poll
  while the command runs, and its sleep mask cannot start until it returns.
- A command gets 30 seconds. When the budget expires the child is killed and the
  BOF reports `exec: command timed out`.
- `&` does not return early: the child inherits the output pipe, so a
  backgrounded job keeps the agent waiting until the timeout. Run short commands.
- Without a shell there is no `&`, no redirection and no pipeline; each is a
  literal argument for the program. Use the default mode when the command line
  needs shell syntax.
- The child inherits no descriptors from the agent: every descriptor above
  stderr is closed before `exec`, so the C2 transport cannot leak to the
  command.
- Exit status is not reported separately; the command's own output and error
  text are.

## x86-64 and other architectures

A Linux x86-64 C agent runs the native object through `coffloader_linux`, so its
libc calls resolve to the host libc. Every other Linux architecture runs the
same source as an RV32 guest through `rvvm_linux`, with `ExecCmd` forwarded
through the interpreter's syscall gate. The C2 builds the guest on first use; a
later `exec` reuses it.

## Prerequisites

- The `exec` module must be installed in the operator's module directory.
- The agent needs BOF support (`BOF=1`) and `coffloader_linux`; non-x86-64
  agents additionally need `RVVM=1` and `rvvm_linux`.
- The C2 needs the pinned zig toolchain to build the module the first time.
