# linux_host

Starlark modules that inspect or adjust local Linux host state from the agent's
in-memory scripting engine. No interpreter or binary is dropped on the target.

## Attribution

These modules are Starlark ports of tools from
**[Furtex](https://github.com/MatheuZSecurity/Furtex)** by
[MatheuZ](https://github.com/MatheuZSecurity).

- Upstream: <https://github.com/MatheuZSecurity/Furtex>
- Upstream license: MIT License, Copyright (c) 2026 MatheuZ
- Ported sources: `edrs/time_stomp.c`, `edrs/oom_cage.c`,
  `edrs/cgroup_freeze.c`, `edrs/pidfd_steal.c`, `edrs/fd_steal_read.c`

The original MIT notice is retained here as required by that license.

## Modules

| Command | Description |
| --- | --- |
| `linux_time_stomp` | Set a file's atime/mtime to now, zero, or an explicit epoch (`utimensat(2)`) |
| `oom_cage` | Show or set `/proc/<pid>/oom_score_adj` (protect/expose a process) |
| `cgroup_freeze` | Report/freeze/thaw a process's cgroup v2, refusing the agent's own cgroup |
| `pidfd_steal` | Duplicate and read another process's fd via `pidfd_getfd` |

### linux_time_stomp

```text
linux_time_stomp --path /tmp/artifact            # stamp with now
linux_time_stomp --mode zero --path /tmp/artifact
linux_time_stomp --mode set --path /tmp/artifact --epoch 1600000000
```

### oom_cage

```text
oom_cage                                   # show the agent's score
oom_cage --action protect                  # oom_score_adj = -1000 (needs CAP_SYS_RESOURCE to lower)
oom_cage --action expose --pid 1234        # oom_score_adj = 1000
oom_cage --action set --pid 1234 --value 500
```

### cgroup_freeze

```text
cgroup_freeze                              # show the agent's cgroup
cgroup_freeze --action freeze --pid 1234   # freeze a target on another cgroup
cgroup_freeze --action thaw --pid 1234
```

### pidfd_steal

```text
linux_proc_fd_scan                        # find a pid/fd to steal
pidfd_steal --pid 1234 --fd 7             # duplicate and read that fd
```

Pair with `linux_proc_fd_scan`: scan finds the descriptor, `pidfd_steal` reads it
without the agent ever calling `open(2)` on the path. Requires ptrace access to
the target (`CAP_SYS_PTRACE`, or same-uid with `ptrace_scope=0`). Only
regular-looking targets are read; pipes/sockets/devices are refused so a
blocking read cannot hang the agent.

## Notes and differences from upstream

- **No timestamp cloning.** `linux_time_stomp clone` needs `struct stat`, which is
  architecture-specific and not exposed to Starlark; only now/zero/explicit are
  implemented.
- **Own-cgroup guard.** `cgroup_freeze` refuses to freeze the cgroup the agent
  itself is in (the usual systemd case), because that would freeze the agent.
- **`oom_score_adj` privilege.** Lowering the score (protect) requires
  `CAP_SYS_RESOURCE`; the module reports the kernel errno instead of aborting.
- All writes go through direct `openat`/`write`/`close` so failures become
  reported errnos rather than engine exceptions.
