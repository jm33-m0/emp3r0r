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

1. **Agent → server/operator/model (primary threat, highest impact).** Agents and target outputs are hostile. A compromised or malicious agent must not be able to take over the C2, another agent, or an operator. TOFU assumes only the first run of an agent is trustworthy. This gets the strongest controls (pinned identity, PFS session re-keying, per-session admission, signed peer lists, terminal-escape sanitization, …). When `emp3r0r mcp` is used, job output, process and file tables, and logs are untrusted target data that may carry indirect prompt-injection text:
   - Read-only tools expose C2 and job state but cannot dispatch work.
   - `emp3r0r mcp` screens every mutating call through the deterministic `mcp.json` policy before it reaches a target or removes C2 state (`forget_agent`).
   - `upload_file` and `put` reject protected operator files (`wg_config.json`, `emp3r0r.json`, `mcp.json`, private keys, SSH/cloud credentials, and symlinks to them) so an injected model turn cannot stage operator credentials on a target.
2. **Autonomous model → target/C2 state (operational blast radius).** An MCP client runs on the operator host with the operator's local OS privileges; `emp3r0r mcp` is not a local filesystem sandbox for the MCP client. Its boundary is between the model and the C2/target surface: `mcp.json` enforces capability dispositions (`allow`, `warn`, `block`), `max_noise`, `allow_irreversible`, module allow/deny lists, rate limits, and fail-closed pre/post audit logging (`~/.emp3r0r/mcp_audit.log`).
3. **Operator host → model provider (telemetry and credential egress).** Prompts and tool results can contain target hostnames, addresses, and credentials. The harness chooses the provider and its data-handling policy; emp3r0r does not control that egress. Audit logs redact credential-bearing flags and arguments.
4. **Operator → server/other operators (secondary control-plane boundary).** An operator already holds a valid WireGuard credential (its private key is provisioned by the server and authenticates it to the tunnel) and was granted access, so this is misuse of privilege rather than a remote takeover. Both the console and `emp3r0r mcp` are untrusted operator clients of the C2 server: the server enforces WireGuard peer identity, single-owner target locks, and job ownership.

### Out of scope

- An operator attacking the server in single-operator mode: the operator owns the server there.
- Sandboxing the MCP client process or the AI harness against the local operator filesystem: both run as the operator user and already own its local file and shell tools. A compromised harness is an operator-host compromise, not an MCP vulnerability.
- Anything that requires the C2 host to already be compromised.
- Denial of service that only affects the attacker's own connection.

## AI security

This section covers the MCP server. The operator's AI harness is
**trusted and outside this threat model**. It runs with the operator's
privileges and already has full control of the operator host. Restricting its
tool calls does not contain it, and no MCP-side control can stop it from using
another path. A compromised or malicious harness is an operator-host compromise,
not an MCP vulnerability.

### Architecture limitation

emp3r0r cannot mitigate all AI-related threats because it does not control the
AI harness, the model, the prompt, the model provider, or the harness's own
file and shell tools. Examples outside its control include a compromised or
misconfigured harness, a malicious model or provider, prompt and tool-result
egress to a provider, the harness reading local credentials or files directly,
and the harness ignoring or reimplementing a tool call.

Those risks belong to the operator. Rely on the harness's own security controls
and on host isolation: run the operator in a dedicated VM or container, keep
host and cloud credentials out of it, restrict its network egress, and review
what the harness can read and execute. The MCP screen and audit log bound calls
made through this server; they are not a sandbox for the harness.

The only AI-specific attack path emp3r0r can influence is the chain from the
agent: target-controlled output enters the model's context as a prompt
injection, the model emits a tool call, and that call reaches the C2, the
operator, or another target. The deterministic screen, output sanitization, C2
identity and locking, and upload restrictions exist to break that chain. They
bound what an injected model can do; they are not a boundary against the
operator or the harness.

### Trust boundaries

| Component | Role | Consequence |
| --- | --- | --- |
| Operator host, harness, and MCP client | Out of scope | The harness owns the model, its context, and its local file and shell tools. Its behaviour is the operator's responsibility. |
| Model output | Untrusted instruction source | Target data can steer the model into a valid tool call. The server evaluates the action, not the intent behind it. |
| Agent and target output | Hostile data | Job output, process and file tables, filenames, directory attributes, and logs can contain prompt-injection text and credentials. |
| OPSEC policy (`mcp.json`) | Trusted configuration | It is deterministic and cannot be rewritten by target output. It decides capability, noise, reversibility, module, and rate limits. |
| MCP tool annotations | Advisory | `readOnlyHint` and `destructiveHint` inform the client; they do not enforce anything on the server. |
| C2 server | Trust root | It authenticates the WireGuard peer, applies operator locks, and owns job records regardless of what the model does. |

### Prompt injection

Indirect injection is the expected case, not an edge case. Any target-controlled
string can carry it: command output, a filename in `ls`, a process command line,
an LDAP attribute, a log line, or a module result. The model may then propose
or call a tool that is valid under the policy. The screen evaluates the action's
capability, not the intent behind it.

Mitigations that work:

- Treat every `result_summary`, `read_job_output`, and `read_log` result as
  data. Do not follow instructions found inside tool output.
- Keep high-impact capabilities at `block` in `mcp.json`. A `warn` capability
  still executes; it only returns a warning.
- Keep `allow_irreversible` off, and use `allowed_modules` as an allowlist when
  the engagement permits it.
- Use the OPSEC policy as the security control. A per-call approval prompt in
  the client is an operator preference; it is not part of this threat model,
  and it does not contain a harness that chooses another path.
- Scope the session to one target. A model that can switch targets can spread a
  single injection across the engagement.
- Reset the conversation when output looks adversarial. Poisoned text persists
  in the model's history.

Mitigations that do not work on their own:

- Asking the model to ignore injected instructions.
- Relying on tool descriptions, annotations, or `warnings` to stop an action.
- Reading a filename, hash, or parsed table and assuming its content is safe.
- Detecting injection by keyword. The screen is a capability heuristic, not a
  content classifier.
- Treating the harness as an adversary. If the harness is hostile, it already
  has the operator's privileges; no MCP-side restriction contains it.

### Data egress

An MCP server does not contact a model provider; the harness does. Provider
choice and harness configuration are outside this threat model. When the
harness uses a hosted provider, prompts and tool results leave the operator
host; the only lever here is what the server returns. Use a local model, or
explicitly accept that target hostnames, credentials, hashes, and job output
will be sent to the provider.

`read_log` can return credential-bearing lines produced by modules or by the
target. Sanitization removes terminal escapes and binary data, not secrets.
Do not paste secrets into prompts, and prefer `result_summary` over raw output
when the harness sends context off-host.

### Credentials and local files

- The MCP client and harness already hold the operator's local privileges.
  No MCP-side control contains the harness. Run the operator host in an
  isolated VM or container without host credentials, cloud tokens, or SSH
  agent forwarding; the isolation is the operator's responsibility.
- `upload_file` and `put` reject known operator secrets by filename and
  directory, and reject pseudo-files under `/proc`, `/sys`, `/dev`, and `/run`,
  to stop an injected model, not to sandbox the harness. That is a
  prompt-injection speed bump, not data-loss prevention: a sensitive file with
  an innocuous name is still not covered. Review every upload and keep only the
  engagement files reachable from the operator account.
- Prefer `--operator-wg-key-file` over `--operator-wg-key`; argv is visible in
  the process list. Keep the key file at `0600` and delete it after the session.
- Give autonomous MCP a separate operator identity from the interactive
  console. A stolen or confused session then has only that operator's jobs and
  locks, and can be revoked without disrupting the console.
- `generate` and `generate_c` build artifacts on the operator host. Treat
  model-requested builds as local code execution and review the output path and
  C2 address before deploying anything.
- Model-requested source edits under `~/.emp3r0r/modules` and
  `~/.emp3r0r/c_agent` are also local code execution. The harness is trusted,
  but an injected model can still propose a harmful change; review workspace
  edits and keep them out of target-facing artifacts unless intended.

### Autonomy checklist

Before handing an agent unattended access:

1. Is the operator host isolated, with no host, cloud, or personal credentials?
2. Is `mcp.json` `0600`, and does it block every capability you would refuse
   to approve interactively?
3. Is `allow_irreversible` off?
4. Is the session scoped to the intended targets and operator identity?
5. Are you accepting every action the policy permits, including `warn`
   capabilities?
6. Does the provider see data it must not see?
7. Can you stop the session by closing stdin and revoke the operator key?
8. Is `~/.emp3r0r/mcp_audit.log` preserved for review?

## Reporting a Vulnerability

- Send them via encrypted email with instructions [here](https://jm33.me/pages/gpg.html)
- Open a security advisory [here](https://github.com/jm33-m0/emp3r0r/security/advisories/new)
