# ssh_harvest

Capture clear-text SSH credentials from `sshd` with an eBPF uprobe. This
replaces the old ptrace-based `ssh_harvester` Go module: instead of attaching
ptrace, scanning the text segment for a byte pattern, and patching an `INT3`,
the module locates the pattern in the on-disk `sshd` image and attaches an
in-memory eBPF uprobe at that file offset. The target process is not stopped,
modified, or traced.

## How it works

1. `ebpf_code_offset(path, pattern)` searches the executable segments of the
   `sshd` ELF for the code pattern and returns the file offset a uprobe
   attaches to.
2. `ebpf_uprobe_capture(...)` loads `probe.bpf.o`, points its `cfg` map at the
   register that holds the password, attaches the `probe` program, and drains
   the `events` map for the configured timeout.
3. The script filters events to `sshd` comms with printable values,
   de-duplicates them, and reports each one with the PAM result read from
   `RAX` (`valid=yes`/`valid=no`).

The BPF object is a companion file (`probe.bpf.o`) built by `make` with the
bundled zig toolchain; the module loader caches it in encrypted memfs and
exposes it through `module_files`. The `libbpf` dependency provides the loader.
Because the object is uploaded to the agent, `sanitize_bpf.py` runs after the
compile and strips the debug metadata (DWARF and the `.BTF.ext` line text) that
would otherwise carry the build path and the probe source into the artifact.

## Testing

`test/real_sshd_test.go` is an opt-in end-to-end test that downloads and
builds a pinned OpenSSH server, starts it on a loopback port, runs the real
`ssh_harvest.star` + `probe.bpf.o` through the agent's script engine, and
drives a genuine password authentication attempt with
`golang.org/x/crypto/ssh`. It then asserts the password was captured.

```bash
cd core
export PATH=/usr/local/go/bin:/usr/local/bin:$PATH
EMP3R0R_TEST_REAL_SSHD=1 CGO_ENABLED=1 \
  go test ./modules/ssh_harvest/test/ -run TestRealSSHDAuthCapture -v -timeout 300s
```

Optional environment variables:

- `EMP3R0R_TEST_OPENSSH_CACHE` - OpenSSH build cache (default
  `$TMPDIR/emp3r0r-openssh-cache`); repeat runs reuse it.
- `EMP3R0R_TEST_LIBBPF` - prebuilt `libbpf.so`; when unset the test runs
  `make` in `modules/libbpf`.

The test needs root (to run sshd and attach the uprobe), a C toolchain, zig,
and network access, so it skips unless `EMP3R0R_TEST_REAL_SSHD` is set.

## Which binary to probe

On OpenSSH 9.8+ the per-connection monitor that calls `auth_password` is
`sshd-session` (`sshd-auth` is the unprivileged pre-auth child that forwards
the password over the monitor socket). Point `--path` at that binary when the
default `/usr/sbin/sshd` does not contain the pattern, e.g.
`--path /usr/libexec/openssh/sshd-session`.

## Usage

```text
ssh_harvest --reg-name RSI --timeout 30
ssh_harvest --path /usr/sbin/sshd --pid 1234 --reg-name RDX
ssh_harvest --code-pattern 4883c4080fb6c021
```

Defaults mirror the old module: register `RSI`, the classic code pattern
`4883c4080fb6c021`, and `/usr/sbin/sshd`.

Requires a Linux agent with `CAP_BPF` or `CAP_SYS_ADMIN` (running as root
implies both) and a kernel with `bpf_probe_read_user_str` (5.5+). The module
is x86_64-only because the register mapping and `struct pt_regs` layout are
architecture-specific.
