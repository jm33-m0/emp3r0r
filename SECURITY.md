# Security Policy

## Supported Versions

Always use the latest version

## AI Usage

- Feel free to use AI for automation. I also use it.
- When communicating the vulnerabilities to me, please make sure you understand what you are reporting and write the messages on your own.
- You still need to test your vulnerability. Don't paste an AI-generated code auditing report without any verification.

## Threat Model

- Treat C2 server and operators as trusted. Multiple operators are supported:
  each operator has its own WireGuard identity and mTLS session, and an agent is
  owned by exactly one operator at a time (claimed on `target`, released when the
  operator switches away, disconnects, or its lease times out).
- All operators have to be authenticated via WireGuard and mTLS. Communication is therefore protected.
- Treat agents as hostile. TOFU model assumes the first run of an agent is trusted.
- The operator config bundle served over WireGuard contains only the shared
  operator client cert/key and the operator CA. The agent CA key, the C2 keys
  and `wg_config.json` (all operator WireGuard private keys) stay on the C2.
- **Firewall the WireGuard UDP port and the operator mTLS port.** WireGuard
  gives every provisioned operator IP-level access to the C2's tunnel subnet,
  and the server warns about this on startup. Do not expose the WG port or the
  WG subnet to an untrusted network.

## Reporting a Vulnerability

- Send them via encrypted email with instructions [here](https://jm33.me/pages/gpg.html)
- Open a security advisory [here](https://github.com/jm33-m0/emp3r0r/security/advisories/new)
