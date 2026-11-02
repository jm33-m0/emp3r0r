# SOCKS5 pivot

`socks_start` starts a SOCKS5 listener on the C2 and binds it to one agent. The
listener accepts operator or tool traffic; for every `CONNECT` it asks the agent
to dial the requested target and open a dedicated C2 relay stream, then relays
bytes between the operator connection and that stream.

The operator experience is the same for every agent: one `socks_start` command,
the same listener, port and ownership checks. Only the agent side differs:

- the Go agent answers `!proxy_start` with the relay built into it;
- the C agent answers the same `!proxy_start` by running the `socks5` Linux BOF.

The C2 server never dispatches a module for this: it sends the command it always
sends and, for a C agent, serves the BOF archive the operator hosted.

## Sequence

1. The operator runs `socks_start <port>` on the target agent.
2. The console hosts the relay BOF for that agent when it is a C agent: it makes
   `socks5.<arch>.gz` and the matching loader (`coffloader_linux.<arch>.gz`, or
   `rvvm_linux.<arch>.gz` for non-x86-64) downloadable by that agent. Nothing
   about this reaches the operator.
3. The C2 starts its listener.
4. Each `CONNECT` sends `!proxy_start --token <t> --target <host:port>` to the
   agent, with the proxy stream token as the job ID.
5. The C agent fetches the BOF once (cached in memfs), runs its `go` entry with
   the token and target, and the BOF does the rest:
   1. parse `target` into host and port, rejecting a missing host, a missing
      port and a port outside `1..65535`;
   2. resolve the host and dial it, spending at most 20 seconds per candidate;
   3. hand the connected socket to `RelaySocket(token, fd, idle_seconds)`,
      which opens the C2 relay stream and pumps bytes.
6. A refusal prints the reason (`cannot resolve …`, `cannot connect to …`) as the
   command result, which the C2 turns into a SOCKS5 refusal reply. A started
   relay prints `socks5: relay started` long before the connection ends.

Only the byte pump runs inside the agent. It has to: the loader unmaps a BOF
object when its entry point returns, and the RV32 guest is single threaded, so a
relay that outlives the call cannot execute module code at all. `RelaySocket` is
therefore a generic primitive — a connected socket plus a C2 stream — and holds
no SOCKS5 knowledge.

## `socks5` module

An ordinary COFF module whose two parameters are `internal`: the C2 supplies
them and the console never asks for them. Running the module by hand is refused
with a pointer to `socks_start`, because the token only exists while a `CONNECT`
waits for its relay.

| Option   | Meaning                |
| -------- | ---------------------- |
| `token`  | C2 proxy stream token. |
| `target` | Target `host:port`.    |

## x86-64 and other architectures

A Linux x86-64 C agent runs the native object through `coffloader_linux`, so its
socket calls resolve to the host libc. Every other Linux architecture runs the
same source as an RV32 guest through `rvvm_linux`; `socks_start` builds that
guest if needed and hosts it under the same stable name, `socks5.<arch>.gz`.

## Prerequisites

- The `socks5` module must be installed in the operator's module directory. If it
  is missing, `socks_start` fails with that reason instead of starting a listener
  whose connections a C agent could not serve.
- The agent needs BOF support (`BOF=1`) and `coffloader_linux`; non-x86-64
  agents additionally need `RVVM=1` and `rvvm_linux`.
- The agent's transport must support a read deadline. The built-in `http_poll`
  transports (`libcurl`, `http_raw`, `libssl`) and `tor` do; a custom transport
  without one refuses the relay with an unsupported error.

## Stealth cost

A bound pivot needs the agent to react quickly, so `socks_start` temporarily
changes its poll profile while the pivot lives:

- the C agent polls every 15 seconds instead of its configured interval (60
  seconds by default) and keeps its message window open for 10 seconds instead
  of its configured value;
- the sleep mask is suspended for as long as any relay runs, so the agent stays
  unmasked while it serves connections.

That trades stealth for latency: beacons are far more frequent, the agent is
awake and unmasked much more often, and it is easier to spot in memory scans and
network telemetry. The operator console warns at `socks_start` with the exact
interval and window it applies, and the C2 log carries the same warning.

The agent saves its own profile and restores it when the pivot stops
(`socks_stop`), including when the operator that started it disconnects. The
restore is a command like any other, so it is applied at the agent's next poll —
at most one tuned cycle later. A dormant agent that has passed its
offline grace is gone and has no profile left to restore.

`socks_start` itself does not require a live message tunnel. An agent that is
sleeping between polls is still accepted, and the commands that follow are
queued for its next check-in; only an agent that passed its reported offline
grace is reported as gone.

## Limits

- Up to 128 relays per agent. A `CONNECT` beyond that is refused.
- A relay ends when either side closes or when it stays completely idle for 15
  minutes: the C2 closes its side after 15 minutes without traffic, and the agent
  closes its own relay after the same idle period even if the C2 is gone.
- The relay runs on its own threads, so a busy pivot does not block the agent's
  command tunnel.

## Sleep mask

A running relay suspends the stager's sleep mask. The mask encrypts the agent
image, its heap and every thread stack, so it may only run when no other agent
code executes. While at least one relay is alive, the C agent performs its normal
interval sleep **unmasked** and resumes masking at the first sleep after the last
relay ends. A busy pivot therefore keeps the process unmasked for its lifetime;
an idle one is capped by the 15-minute timeout above.

Agent file transfer is unaffected: its host calls are synchronous on the agent's
main thread, so a transfer always finishes (or aborts with the C2 stream) before
the agent masks.
