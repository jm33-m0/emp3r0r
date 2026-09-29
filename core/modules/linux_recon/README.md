# linux_recon

Starlark recon modules for Linux agents. They audit the local host for EDR
telemetry, credential material and kernel hardening without dropping a binary
or spawning a process: the agent's embedded Starlark engine runs each script in
memory.

## Attribution

These modules are Starlark ports of the recon tools from
**[Furtex](https://github.com/MatheuZSecurity/Furtex)** by
[MatheuZ](https://github.com/MatheuZSecurity), a post-exploitation and evasion
research toolkit for Linux built around `io_uring` and eBPF.

- Upstream: <https://github.com/MatheuZSecurity/Furtex>
- Upstream license: MIT License, Copyright (c) 2026 MatheuZ
- Ported sources: `edrs/edr_recon.c`, `edrs/env_scrape.c`,
  `edrs/proc_fd_scan.c`, `edrs/sysctl_blind.c`

The original MIT notice is retained here as required by that license. Only the
userspace, file-based logic was ported; the kernel-facing parts of Furtex were
not, for the reasons in [Differences from upstream](#differences-from-upstream).

## Modules

| Command | Description |
| --- | --- |
| `linux_edr_recon` | EDR process / artifact / module / kprobe / ftrace / LSM / perf-BPF audit across 12 vendor profiles |
| `linux_env_scrape` | Harvest secrets and `SSH_AUTH_SOCK` from `/proc/<pid>/environ` |
| `linux_proc_fd_scan` | Find processes holding credential/secret files open (scans `/proc/<pid>/fd`) |
| `linux_sysctl_audit` | Read security-relevant kernel sysctls |

### linux_edr_recon

```text
linux_edr_recon                       # all default sections
linux_edr_recon --section procs,arts  # only these sections
linux_edr_recon --section avail       # opt-in; see caveat below
```

Sections: `procs`, `arts` (files/devices), `mods`, `kprobes`, `ftrace`, `lsm`,
`perf`, and `avail`. Default `all` runs every section except `avail`.

Matches are scored per vendor (processes 10, modules 10, devices 8, artifacts 5,
kprobe/ftrace hits 2-3), then summarised as LOW / MEDIUM / HIGH confidence.

### linux_env_scrape

```text
linux_env_scrape                       # secrets from same-uid processes
linux_env_scrape --mode all --scope all
linux_env_scrape --mode ssh            # SSH_AUTH_SOCK only, with a ready ssh-add command
```

### linux_proc_fd_scan

```text
linux_proc_fd_scan
linux_proc_fd_scan --pid 1234
linux_proc_fd_scan --filter id_rsa
```

### linux_sysctl_audit

```text
linux_sysctl_audit
```

Read-only. It reports where the target sits on `dmesg_restrict`,
`kptr_restrict`, `perf_event_paranoid`, `yama/ptrace_scope`,
`unprivileged_bpf_disabled`, `bpf_jit_harden` and `modules_disabled`.

## Differences from upstream

- **No `bpf(2)` enumeration.** Furtex's `linux_edr_recon` also walks BPF programs,
  links and maps via raw `bpf(2)` commands. Driving `union bpf_attr` and the
  `bpf_prog_info`/`bpf_map_info` layouts from Starlark is error-prone and
  version-sensitive; it belongs in Go (or a Linux BOF), not a script.
- **No `available_filter_functions` in the default run.** On a full kernel that
  file is tens of megabytes, and `read_file` loads it whole. It is available as
  `--section avail` when the operator accepts the memory cost.
- **Discovery only, no content dump.** `linux_proc_fd_scan` lists matching fd
  targets but does not read them: a blocking read of a pipe, socket or device
  would stall the agent.
- **Read-only sysctls.** This suite only reads the values; the write-capable
  `blind`/`open`/`set` actions live in the `linux_blind` suite
  (`linux_sysctl_blind`). Changing sysctls (especially `modules_disabled`) is
  an explicit operator action, not recon.

## Notes

- Every script uses `read_file(..., default=...)` / `read_link(..., default=...)`
  (both Go builtins) because Starlark has no `try`/`except`; a vanished `/proc`
  entry must not abort the scan.
- These modules are Linux-only. On Windows the C2 rejects them by platform.
