# `socks5`

The agent half of the C2 SOCKS5 pivot as a Linux BOF. On every `socks_start`
CONNECT the C2 sends the same `!proxy_start --token <t> --target <host:port>`
command a Go agent handles; the C agent runs this BOF with those two arguments
instead of a built-in relay.

`!proxy_start` fetches the BOF once (the operator hosted `socks5.<arch>.gz` when
it ran `socks_start`) and runs it. The object parses the target, resolves it,
dials it, and hands the connected socket to the agent's `RelaySocket` primitive,
which pumps it through the C2 stream. The C2 keeps the listener and the
operator-facing relay, so the SOCKS5 wire protocol is unchanged.

Linux x86-64 C agents run the native object; every other Linux C architecture
runs the RV32 guest build through `rvvm_linux`.

See [`docs/socks5_bof.md`](../../../docs/socks5_bof.md).
