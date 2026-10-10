# Operator Guide

This guide covers the full emp3r0r deployment: building and launching the C2
server, installing and running the operator console (natively on Linux or from
a container -- the recommended path on Windows), and generating agent payloads.
The console is driven through a tmux session; its keybindings are documented in
[TMUX.md](TMUX.md).

The C2 server is a standalone deployment: it publishes random public ports, so
it is intentionally not containerized.

## Quick Start

### 1. C2 Server Installation

Building emp3r0r requires Docker or Podman on the host -- no local Go toolchain.

```bash
git clone --depth=1 https://github.com/jm33-m0/emp3r0r.git && cd emp3r0r
./install.py
```

The installer builds everything in a throwaway container and prepares the
operator kit. Useful flags: `--lightweight` (Linux/Windows amd64 only, fastest),
`--targets OS/ARCH,...`, `--agent-slim` / `--agent-tags` (trim agent features to
shrink the implant and reduce fingerprinting), `--debug`, `--skip-build`.

Launch the server:

```bash
emp3r0r server --c2-hosts 1.2.3.4 --http-port 12345 --operator-port 13377 \
  --operators alice bob carl
```

`--operators` names the operators to provision on the **first** start (they are
persisted in `wg_config.json` and printed as a table). Names can be
comma-separated (`--operators alice,bob`), repeated
(`--operators alice --operators bob`) or given as positional arguments after
`server`. A single integer still works as a count (`--operators 3` creates
`operator-1..operator-3`), and with no names one default operator is created.

Each operator gets its own WireGuard key/IP and is identified by that IP at the
mTLS layer. On every later start the existing identities are kept as-is:
`--operators` is refused once `wg_config.json` exists, so a restart can never
regenerate (and invalidate) an operator's keys. To add more operators without
touching the existing ones, use `--add-operator` with the same name syntax. To
start over, delete `wg_config.json` and restart.

```bash
# add two named operators to an existing deployment
emp3r0r server --c2-hosts 1.2.3.4 --add-operator dave erin
```

Names must be unique and free of control characters; they are used in the
console and the audit log.

> **Firewall warning.** WireGuard gives every provisioned operator IP-level
> access to the C2's tunnel subnet. Firewall the WireGuard UDP port and the
> operator mTLS port so only your operators can reach them, and never expose the
> WG subnet to an untrusted network. The server prints this warning on startup.

#### Multiple operators

Multiple operators can connect at the same time. Operator identity comes from
the provisioned WireGuard IP, not from a client-supplied header, so each
operator keeps its own jobs, pivots, file streams and agent claims.

- **One agent, one operator.** `target <agent>` claims the agent. While claimed,
  other operators see the owner in the agent list (`Operator` column) and are
  refused with "Agent ... is operated by ...". The claim is released when the
  operator switches target, disconnects, or stops talking to the C2 for the
  operator idle timeout.
- **Agent list.** The `Operator` column shows who is on what agent.
- **Adding operators.** Run the server with `--add-operator <names>`; existing
  keys and IPs are preserved and only the new named rows are appended to
  `wg_config.json` and the printed table. `--operators` is for the first run
  only.

#### Operator audit log

The server appends every operator action to `~/.emp3r0r/operator_audit.log`
(mode `0600`), one timestamped line per event, naming the operator, its
WireGuard IP and public key, the action and the target:

```text
2026-10-11T04:02:15Z operator="alice" wg_ip="10.123.180.207" wg_pubkey="..." action="command" target="1a2b3c4d (uuid)" detail="ls -la"
```

Recorded actions include `connect`, `disconnect`, `claim`/`claim_denied`,
`command`/`command_denied`, `forget_agent`, `sign_agent`, `set_idle_timeout`
and `resume`. The log is append-only; rotate or archive it as needed.

#### Upgrading without breaking existing agents

The `MagicString` is the static pre-shared key the agent uses for check-in.
Every build embeds the value configured by the builder, so upgrading does not
orphan already-deployed agents. The builder owns this: on the build host it
keeps the value in `~/.emp3r0r/magic_string` (mode `0600`) and reuses it on every
later build. `install.py` passes that value into the builder container, and
`core/build.py` embeds it with `-ldflags`. Go code only consumes the embedded
value; there is no runtime configuration.

- **First build** generates a random value and stores it.
- **Later builds** reuse the stored value automatically — no flag needed.
- **`--magic-string VALUE`** (or `EMP3R0R_MAGIC_STRING`) sets the value: it is
  persisted to the store, so later builds can omit it and still reuse the same
  key:

```bash
./install.py --magic-string '<value from an existing deployment>'
# or, when running the builder directly:
python3 core/build.py --install --magic-string '<value>'
```

`~/.emp3r0r/magic_string` is a secret: treat it like `wg_config.json`, keep it
out of version control, and back it up — losing it means the next build mints
agents that cannot talk to the running C2.

### 2. Operator Machine Setup

The build produced `core/emp3r0r-operator-kit.tar.zst`. Copy that archive to the
operator machine, then follow one of the two paths below.

#### Linux (native)

```bash
tar --zstd -xpf emp3r0r-operator-kit.tar.zst
cd ./emp3r0r-operator-kit && ./install.py
```

Connect with the WireGuard credentials the server printed:

```bash
emp3r0r client --c2-port 13377 \
  --server-wg-key '<SERVER_WG_KEY>' --server-wg-ip '<SERVER_WG_IP>' \
  --operator-wg-ip '<OPERATOR_WG_IP>' --operator-wg-key '<OPERATOR_WG_KEY>' \
  --c2-host 1.2.3.4
```

#### Windows (container)

`install.py` is Linux-only, but you do not build the image by hand: running
`./install.py` on the build host builds the operator image and exports it to
`core/emp3r0r-operator-image.tar.zst`. Pass `--no-operator-image` to skip that.

**1. Move the image to the operator machine.** On the build host, after
`./install.py`:

```bash
ls core/emp3r0r-operator-image.tar.zst
```

Copy that `.tar.zst` over however you like (scp, USB, ...), then load it on the
operator machine:

```powershell
docker load -i "emp3r0r-operator-image.tar.zst"
```

**2. Run the console.** Everything (the console, its panes and any shell you
open) lives inside the container's tmux session. Pass the full `emp3r0r`
command -- the image has no entrypoint, so `docker run IMAGE emp3r0r ...` works
exactly like running it on the host:

```powershell
docker run -it --rm -v emp3r0r-operator:/root/.emp3r0r emp3r0r-operator:latest `
  emp3r0r client --c2-port 13377 --server-wg-key '<SERVER_WG_KEY>' `
  --server-wg-ip '<SERVER_WG_IP>' --operator-wg-ip '<OPERATOR_WG_IP>' `
  --operator-wg-key '<OPERATOR_WG_KEY>' --c2-host 1.2.3.4
```

- `-it` is required: the client always starts a tmux session and needs a TTY to
  attach. Windows Terminal renders it like any other console.
- The named volume keeps the operator workspace (`~/.emp3r0r`: WireGuard keys,
  generated payloads, logs) across `--rm` runs.
- The container runs as root, so drop `sudo` from any hint the console prints.
- The image is only tagged `latest`; tag the imported image however you like.

If the image was not exported (for example you passed `--no-operator-image`),
you can build it on any Docker host from the kit instead:

```bash
tar --zstd -xpf emp3r0r-operator-kit.tar.zst
cd emp3r0r-operator-kit
docker build -t emp3r0r-operator:latest .
docker save -o emp3r0r-operator-image.tar emp3r0r-operator:latest
zstd -T0 -3 -f emp3r0r-operator-image.tar -o emp3r0r-operator-image.tar.zst
rm -f emp3r0r-operator-image.tar
```

### 3. Generate Agent Payloads

Inside the operator console:

```bash
# Direct C2 agent
generate --type linux_executable --arch amd64 --cc your.domain.com

# Mesh gateway agent (also reachable from the C2 directly)
generate --type linux_executable --arch amd64 --cc your.domain.com \
  --p2p --direct-c2 --p2p-transport mtls

# Mesh intermediate peer (relays for other agents)
generate --type linux_executable --arch amd64 --cc your.domain.com \
  --p2p --p2p-transport mtls --peers 1.2.3.4

# Windows mesh peer over SMB named pipes (local \\.\pipe, cross-host \\host\pipe),
# AES-GCM framed like the other transports
# (requires the Windows SMB stack / logon session to reach the peer)
generate --type windows_executable --arch amd64 --cc your.domain.com \
  --p2p --p2p-transport smb
```

Mesh nodes may run different transports. Each agent advertises the transport and
port its relay listens on, and dialers always use the _peer's_ advertised
transport, so a mixed mesh (for example Windows SMB nodes alongside Linux mTLS
nodes) routes through a peer that shares a usable transport instead of assuming
everyone runs the local default. `smb` is only accepted for Windows payloads;
kcp/mtls work everywhere.

## Container capabilities

The default container run needs no extra privileges: the client's WireGuard runs
entirely in userspace.

### tun2socks

`tun2socks` creates a kernel TUN device and installs routes, so the container
needs `CAP_NET_ADMIN` and access to `/dev/net/tun`:

```powershell
docker run -it --rm --cap-add NET_ADMIN --device /dev/net/tun `
  -v emp3r0r-operator:/root/.emp3r0r emp3r0r-operator:latest emp3r0r client ...
```

If Docker Desktop's Linux VM does not expose `/dev/net/tun`, run the operator
natively or start the container with `--privileged`.

### proxy-ns

`proxy-ns` runs each command in its own network namespace with a TUN device and
fake DNS, so it needs several powerful capabilities (`cap_sys_admin`,
`cap_net_admin`, ...). It is unlikely to work in a container without being
privileged:

```powershell
docker run -it --rm --privileged -v emp3r0r-operator:/root/.emp3r0r emp3r0r-operator:latest emp3r0r client ...
```

`--privileged` is a large grant. Prefer the native Linux install for
`proxy-ns`, or use the built-in SOCKS5 pivot without it.

## tmux console

The console, every shell it opens, and every pane run under one tmux session.
The prefix is **<kbd>Ctrl</kbd>+<kbd>x</kbd>** (the default
<kbd>Ctrl</kbd>+<kbd>b</kbd> is unbound). A few keys worth memorising right
away:

| Keys | Action |
| --- | --- |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>c</kbd> | new window |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>z</kbd> | zoom / maximize the current pane |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>_</kbd> / <kbd>-</kbd> | split top/bottom / left/right |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>h</kbd>/<kbd>j</kbd>/<kbd>k</kbd>/<kbd>l</kbd> | move between panes |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>x</kbd> / <kbd>&amp;</kbd> | kill pane / window |
| <kbd>Shift</kbd>+drag | select with the terminal, i.e. copy to the OS clipboard |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>?</kbd> | list every key binding |

The full reference -- mouse and clipboard, all window/pane/session keys, copy
mode, and everything this config changes versus stock tmux -- is in
[TMUX.md](TMUX.md). Reload an edited config with
`tmux source-file /usr/local/lib/emp3r0r/tmux/.tmux.conf`.

## Workspace

The operator workspace is `~/.emp3r0r` (override with `EMP3R0R_WORKSPACE`). It
holds `emp3r0r.json`, the WireGuard keys, `file-get/` downloads, generated
payloads and `emp3r0r.log`. Mount it (or use a named volume) if you want this
state to survive container recreation.
