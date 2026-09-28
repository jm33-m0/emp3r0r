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
  `edrs/cgroup_freeze.c`

The original MIT notice is retained here as required by that license.

## Modules

| Command | Description |
| --- | --- |
| `linux_time_stomp` | Set a file's atime/mtime to now, zero, or an explicit epoch (`utimensat(2)`) |
| `linux_oom_cage` | Show or set `/proc/<pid>/oom_score_adj` (protect/expose a process) |
| `linux_cgroup_freeze` | Report/freeze/thaw a process's cgroup v2, refusing the agent's own cgroup |

### linux_time_stomp

```text
linux_time_stomp --path /tmp/artifact            # stamp with now
linux_time_stomp --mode zero --path /tmp/artifact
linux_time_stomp --mode set --path /tmp/artifact --epoch 1600000000
```

### linux_oom_cage

```text
linux_oom_cage                                   # show the agent's score
linux_oom_cage --action protect                  # oom_score_adj = -1000 (needs CAP_SYS_RESOURCE to lower)
linux_oom_cage --action expose --pid 1234        # oom_score_adj = 1000
linux_oom_cage --action set --pid 1234 --value 500
```

### linux_cgroup_freeze

```text
linux_cgroup_freeze                              # show the agent's cgroup
linux_cgroup_freeze --action freeze --pid 1234   # freeze a target on another cgroup
linux_cgroup_freeze --action thaw --pid 1234
```

## Notes and differences from upstream

- **No timestamp cloning.** `time_stomp clone` needs `struct stat`, which is
  architecture-specific and not exposed to Starlark; only now/zero/explicit are
  implemented.
- **Own-cgroup guard.** `cgroup_freeze` refuses to freeze the cgroup the agent
  itself is in (the usual systemd case), because that would freeze the agent.
- **`oom_score_adj` privilege.** Lowering the score (protect) requires
  `CAP_SYS_RESOURCE`; the module reports the kernel errno instead of aborting.
- All writes go through direct `openat`/`write`/`close` so failures become
  reported errnos rather than engine exceptions.
