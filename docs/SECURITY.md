# Security Policy

## Supported Versions

Latest release.

## AI Usage

> [!NOTE]
> AI-assisted automation is acceptable. Reports must be understood and written by the reporter, and the issue must be reproduced before reporting. Unverified AI-generated audit output is not accepted.

## Threat Model

- Single-operator: the operator owns the server, workspace, and agents. Operator-side attacks are out of scope.
- Multi-operator: the server is the trust root. Operators are untrusted relative to the server and each other; an agent must not let one operator affect another.
- Agents and target output are hostile. They may carry credentials or prompt injection and must not take over the C2, another agent, or an operator.
- The MCP client and AI harness run with operator privileges. `mcp.json` constrains tool calls, not the operator host.
- Prompts and tool results can leave the operator host when a hosted model provider is used.

Out of scope: attacks initiated from the operator host, operator credentials, or the AI harness; sandboxing the harness from the local filesystem; isolating the detection loop from the operator host; attacks that require the C2 host to already be compromised; self-DoS.

## What to Report

Valid:
- Agent- or target-initiated C2 takeover, cross-operator impact, or control of another agent, including through prompt-injected model tool calls.
- Authentication, TOFU, session re-keying, WireGuard identity, operator-isolation, lock, or job-ownership bypass.
- Server-side privilege escalation or remote code execution reachable from agent or target input.
- Checks that let agent-controlled input stage operator credentials or read or write protected files.

Invalid:
- Anything initiated by the operator host, operator credentials, or the AI harness.
- Local code execution that the operator already has.
- Self-DoS, missing hardening without a concrete exploit, or unverified scanner output.

## AI Security

> [!CAUTION]
> AI features are not a containment boundary.

- Agent-initiated C2 takeover is in scope when agent or target input, including prompt injection, makes the model take a practical action that reaches the C2, another agent, or an operator.
- Operator-initiated actions are not vulnerabilities: the operator host already has the same privileges, and model-driven source or build edits requested from that host are expected.
- Source edits and build inputs (`build.sh`, `Makefile`, `config.json`, generated source) can execute commands; review reduces exposure but does not contain the model.
- Prompt and tool descriptions are soft guardrails against prompt injection, not defenses.
- Complete host or VM isolation is the only reliable control for autonomous use.

## Reporting a Vulnerability

- Encrypted email: https://jm33.me/pages/gpg.html
- GitHub advisory: https://github.com/jm33-m0/emp3r0r/security/advisories/new
