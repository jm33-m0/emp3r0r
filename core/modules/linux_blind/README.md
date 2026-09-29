# linux_blind

Starlark modules that suppress or defeat the Linux telemetry an EDR relies on,
and remove the artifacts an operator leaves behind. They run in the agent's
embedded Starlark engine: no binary is dropped, no interpreter or child
process is spawned, and every write goes through direct `openat`/`write`
syscalls so the agent's at-rest file encryption is never applied to system
files.

## Attribution

These modules are Starlark ports of the evasion and anti-forensics tools from
**[Furtex](https://github.com/MatheuZSecurity/Furtex)** by
[MatheuZ](https://github.com/MatheuZSecurity).

- Upstream: <https://github.com/MatheuZSecurity/Furtex>
- Upstream license: MIT License, Copyright (c) 2026 MatheuZ
- Ported sources: `edrs/ftrace_enum.c`, `edrs/sysctl_blind.c`,
  `edrs/dmesg_wipe.c`, `edrs/log_wipe.c`, `edrs/coredump_block.c`,
  `edrs/vma_hide.c`, `edrs/self_delete.c`, `edrs/mount_over.c`,
  `edrs/proc_hide.c`, `edrs/tetragon_blind.c`, `edrs/kmod_unload.c`,
  `edrs/mmap_read.c`

The original MIT notice is retained here as required by that license.

## Modules

| Command | Description | Privilege |
| --- | --- | --- |
| `kprobe_clear` | List/clear kprobe & uprobe events, disable tracing | root, writable tracefs |
| `linux_sysctl_blind` | Show/blind/open/set security sysctls | root to write |
| `dmesg_wipe` | Read/grep/clear the kernel ring buffer | root, `dmesg_restrict=0` |
| `linux_log_wipe` | Truncate or pattern-scrub logs, history, lastlog | root for `/var/log` |
| `linux_coredump_block` | Disable core dumps and memory-scanner access | self unprivileged |
| `linux_vma_hide` | `MADV_DONTDUMP` / rename an anonymous mapping | unprivileged |
| `linux_self_delete` | Unlink the running binary from disk | owner |
| `linux_mount_over` | Bind/tmpfs mounts, read-only remount, file shadowing | `CAP_SYS_ADMIN` |
| `linux_proc_hide` | Hide a PID from `/proc` via bind mount | `CAP_SYS_ADMIN` |
| `tetragon_blind` | Scan/freeze/thaw/kill Tetragon, Falco, Cilium | root for freeze/kill |
| `lkm_unload` | List/hunt/info/unload kernel modules | `CAP_SYS_MODULE` |
| `linux_mmap_read` | Read a file via `mmap(2)`, no `read(2)` | unprivileged |

## Usage

```text
kprobe_clear                                    # list tracefs hooks
kprobe_clear --action clear-kprobes --dry_run   # show what would go
kprobe_clear --action clear-kprobes             # remove them

linux_sysctl_blind                              # show current values
linux_sysctl_blind --action blind --dry_run     # preview restriction
linux_sysctl_blind --action set --name kernel.kptr_restrict --value 2

dmesg_wipe --action wipe                        # clear the ring buffer
linux_log_wipe --path /var/log/auth.log --pattern attacker
linux_log_wipe --action hist --home /root

linux_coredump_block --action self
linux_coredump_block --action pid --pid 1234
linux_vma_hide --action dontdump
linux_self_delete

linux_mount_over --action bind --src /tmp/empty --dst /etc/cron.d
linux_mount_over --action hide --src /root/.bash_history
linux_mount_over --action umount --dst /root/.bash_history

linux_proc_hide --action hide --pid 1234
linux_proc_hide --action list
linux_proc_hide --action unhide --pid 1234

tetragon_blind                                  # scan
tetragon_blind --action freeze --pid 1234
tetragon_blind --action kill --pid 1234

lkm_unload --action hunt
lkm_unload --action info --name falco
lkm_unload --action unload --name falco

linux_mmap_read --path /etc/shadow --cap 65536
```

## Notes and differences from upstream

- **No shellcode execution.** `linux_vma_hide`'s upstream `hide` demo maps RWX
  shellcode and executes it. Starlark cannot execute a mapping it allocated, so
  only the `dontdump` and `name` primitives are ported — the parts an operator
  can apply to the agent's own memory.
- **No memfd re-exec.** `linux_self_delete` deletes the running image but does not
  re-exec from a memfd: spawning a child process is not part of the agent
  model. The agent stays resident with no image on disk.
- **No raw BPF.** `tetragon_blind`'s link-detach and program-enumeration half
  needs `union bpf_attr` handling that belongs in Go, not Starlark; only the
  process-level scan/freeze/thaw/kill actions are ported. `freeze`/`thaw` act
  on the target's existing cgroup v2 (unlike upstream, which creates a
  dedicated cgroup) and refuse the agent's own cgroup.
- **No `utmp` rewrite.** `linux_log_wipe` skips the binary `struct utmp` munging;
  text logs, shell history and `lastlog` cover the common case.
- **`tracefs`/`path` overrides.** `kprobe_clear` accepts a tracefs root
  and `linux_log_wipe` a specific path so the parse logic is testable without
  root or a mounted tracefs.
- **Unprivileged default.** Every module degrades to a reported errno instead
  of aborting when a capability is missing; nothing here escalates privileges.
