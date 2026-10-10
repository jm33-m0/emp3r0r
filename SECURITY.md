# Security Policy

## Supported Versions

Always use the latest version

## AI Usage

- Feel free to use AI for automation. I also use it.
- When communicating the vulnerabilities to me, please make sure you understand what you are reporting and write the messages on your own.
- You still need to test your vulnerability. Don't paste an AI-generated code auditing report without any verification.

## Threat Model

### Deployment modes

**Single-operator (local or remote).** Assume the operator owns the server. There is no separation between the two: the operator holds the server's keys, its workspace and full control of the agents. Trust is implicit and no operator-facing isolation is expected (or possible). This is the default and recommended setup for a solo operator, and an operator "attacking" the server in this mode is out of scope.

**Multi-operator.** The server is the ultimate trust root. Operators are authenticated humans who have been granted access, but each is treated as untrusted _relative to the server and to the other operators_: operators are clients of the server and peers of one another, and neither relationship grants more than the server allows. In this mode an operator must not be able to attack the server or another operator, and an agent must not be able to make one operator affect another. This is a defensive boundary, not an assumption of bad intent — it caps the blast radius of a stolen operator credential and stops one operator from disrupting another's work. Multi-operator mode is new in v5; these isolation guarantees apply only to v5 and later. The concrete invariants the server enforces are implementation guidance and are documented in `AGENTS.md`.

### Threat ranking

Ranked by impact, from highest to lowest:

1. **Agent → server/operator (primary threat, highest impact).** Agents are hostile. A compromised or malicious agent must not be able to take over the C2, another agent, or an operator. TOFU assumes only the first run of an agent is trustworthy. This gets the strongest controls (pinned identity, PFS session re-keying, per-session admission, signed peer lists, …).
2. **Operator → server/other operators (secondary, lower impact).** An operator already holds the shared operator credential and was granted access, so this is misuse of privilege rather than a remote takeover. The damage is confined to the control plane — identity spoofing, cross-operator interference, or log tampering — and cannot exceed what the operators are collectively trusted to do. It is still in scope.

### Out of scope

- An operator attacking the server in single-operator mode: the operator owns the server there.
- Anything that requires the C2 host to already be compromised.
- Denial of service that only affects the attacker's own connection.

## Reporting a Vulnerability

- Send them via encrypted email with instructions [here](https://jm33.me/pages/gpg.html)
- Open a security advisory [here](https://github.com/jm33-m0/emp3r0r/security/advisories/new)
