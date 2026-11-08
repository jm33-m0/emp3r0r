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

**Multi-operator.** The server is the ultimate trust root. Operators are authenticated humans who have been granted access, but each is treated as untrusted _relative to the server and to the other operators_: operators are clients of the server and peers of one another, and neither relationship grants more than the server allows. In this mode an operator must not be able to attack the server or another operator, and an agent must not be able to make one operator affect another. This is a defensive boundary, not an assumption of bad intent: it caps the blast radius of a stolen operator credential and stops one operator from disrupting another's work. Multi-operator mode is new in v5; these isolation guarantees apply only to v5 and later.

### Threat ranking

Ranked by impact, from highest to lowest:

1. **Agent → server/operator/model (primary threat, highest impact).** Agents and target outputs are hostile. A compromised or malicious agent must not be able to take over the C2, another agent, or an operator. TOFU assumes only the first run of an agent is trustworthy. This gets the strongest controls (pinned identity, PFS session re-keying, per-session admission, signed peer lists, terminal-escape sanitization, …). When `ask` or `emp3r0r mcp` is used, job output, process and file tables, and logs are untrusted target data that may carry indirect prompt-injection text:
   - `ask` exposes only read-only tools and cannot dispatch work.
   - `emp3r0r mcp` screens every mutating call through the deterministic `mcp.json` policy before it reaches a target or removes C2 state (`forget_agent`).
   - `upload_file` and `put` reject protected operator files (`wg_config.json`, `emp3r0r.json`, `mcp.json`, `assistant.json`, private keys, SSH/cloud credentials, and symlinks to them) so an injected model turn cannot stage operator credentials on a target.
2. **Autonomous model → target/C2 state (operational blast radius).** An MCP client runs on the operator host with the operator's local OS privileges; `emp3r0r mcp` is not a local filesystem sandbox for the MCP client. Its boundary is between the model and the C2/target surface: `mcp.json` enforces capability dispositions (`allow`, `warn`, `block`), `max_noise`, `allow_irreversible`, module allow/deny lists, rate limits, and fail-closed pre/post audit logging (`~/.emp3r0r/mcp_audit.log`).
3. **Operator host → model provider (telemetry and credential egress).** Prompts and tool results can contain target hostnames, addresses, and credentials. `assistant.json` defaults to loopback (`allow_remote: false`), refuses HTTP redirects to non-loopback hosts without `allow_remote`, and rejects group/world-writable config files or world-readable inline `api_key` files. Audit logs redact credential-bearing flags and arguments.
4. **Operator → server/other operators (secondary control-plane boundary).** An operator already holds a valid WireGuard credential (its private key is provisioned by the server and authenticates it to the tunnel) and was granted access, so this is misuse of privilege rather than a remote takeover. Both the console and `emp3r0r mcp` are untrusted operator clients of the C2 server: the server enforces WireGuard peer identity, single-owner target locks, and job ownership.

### Out of scope

- An operator attacking the server in single-operator mode: the operator owns the server there.
- Sandboxing the MCP client process against the local operator filesystem: the MCP client runs as the operator user and already owns its local file and shell tools.
- Anything that requires the C2 host to already be compromised.
- Denial of service that only affects the attacker's own connection.

## Reporting a Vulnerability

- Send them via encrypted email with instructions [here](https://jm33.me/pages/gpg.html)
- Open a security advisory [here](https://github.com/jm33-m0/emp3r0r/security/advisories/new)
