# Security Policy

## Supported Versions

Always use the latest version

## AI Usage

- Feel free to use AI for automation. I also use it.
- When communicating the vulnerabilities to me, please make sure you understand what you are reporting and write the messages on your own.
- You still need to test your vulnerability. Don't paste an AI-generated code auditing report without any verification.

## Threat Model

### Deployment modes

**Single-operator (local or remote).** Assume the operator owns the server. There is no separation between the two: the operator holds the server's keys, its workspace and full control of the agents. Trust is implicit and no operator-facing isolation is expected (or possible). This is the default and recommended setup for a solo operator.

**Multi-operator.** The server is the ultimate trust root. Operators are authenticated humans who have been granted access, but each is treated as untrusted _relative to the server and to the other operators_: operators are clients of the server and peers of one another, and neither relationship grants more than the server allows. In this mode an operator must not be able to attack the server or another operator. This is a defensive boundary, not an assumption of bad intent — it caps the blast radius of a stolen operator credential and stops one operator from disrupting another's work. Multi-operator mode is new in v5; before v5 only single-operator mode existed, and the isolation guarantees below apply only to v5 and later.

### Threat ranking

Ranked by impact, from highest to lowest:

1. **Agent → server/operator (primary threat, highest impact).** Agents are hostile. A compromised or malicious agent must not be able to take over the C2, another agent, or an operator. TOFU assumes only the first run of an agent is trustworthy. This gets the strongest controls (pinned identity, PFS session re-keying, per-session admission, signed peer lists, …).
2. **Operator → server/other operators (secondary, lower impact).** An operator already holds the shared operator credential and was granted access, so this is misuse of privilege rather than a remote takeover. The damage is confined to the control plane — identity spoofing, cross-operator interference, or log tampering — and cannot exceed what the operators are collectively trusted to do. It is still worth hardening, and the invariants below do.

### Multi-operator invariants

- **Identity is the provisioned WireGuard IP.** The server derives the operator identity from the authenticated WireGuard peer address. The `operator_session` header is trusted only from loopback (local mode, embedders, tests), so a network peer cannot self-identify by header.
- **All operator endpoints require an identity** and reject unidentified callers with 401.
- **Operators cannot interfere with each other or the server:**
  - an agent is claimed by exactly one operator; a second claim is `409`;
  - a command is refused (`409`) unless the caller owns the agent;
  - `forget_agent` is refused while another operator owns the agent;
  - a job's owner is never reassigned, so output cannot be redirected;
  - SOCKS5 pivots and FTP streams are owner-checked; another operator cannot stop a pivot or hijack a stream token.
- **The CA is not a general signing oracle:** `sign_agent` only signs a valid UUID.
- **SOCKS5 pivots can only bind loopback or the C2's WireGuard address**, never a public interface.
- **Inputs are bounded:** HTTP request bodies (1 MiB) and message-tunnel frames (4 MiB).
- **Every operator action is recorded** in `~/.emp3r0r/operator_audit.log` with the operator name, WireGuard IP/public key, action and target, including denied attempts.

### Deployment requirements

- **Firewall the WireGuard UDP port and the operator mTLS port.** WireGuard gives every provisioned operator IP-level access to the C2's tunnel subnet, and the server warns about this on startup. Do not expose the WG port or the WG subnet to an untrusted network.
- The operator config bundle served over WireGuard contains only the shared operator client cert/key and the operator CA. The agent CA key, the C2 keys and `wg_config.json` (all operator WireGuard private keys) stay on the C2.

## Reporting a Vulnerability

- Send them via encrypted email with instructions [here](https://jm33.me/pages/gpg.html)
- Open a security advisory [here](https://github.com/jm33-m0/emp3r0r/security/advisories/new)
