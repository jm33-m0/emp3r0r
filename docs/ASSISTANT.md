# Operator Assistant

The console `ask` command and the MCP server share the same operator skills,
tool schemas, and deterministic OPSEC reviewer. `ask` uses the read-only tool
set and never executes anything; MCP adds the screened action tools.

The assistant uses an OpenAI-compatible model endpoint configured in
`~/.emp3r0r/assistant.json`. It is optional: without a model endpoint, the
console, modules, and MCP server still work, but `ask` cannot answer.

For autonomous execution through an external model, use the
[MCP server](./MCP.md).

## Requirements

- A model endpoint that supports tool calling.
- One of two APIs:
  - `chat`: `POST {base_url}/chat/completions` (Ollama, vLLM, llama.cpp,
    OpenRouter, and most gateways).
  - `responses`: `POST {base_url}/responses` (OpenAI Responses API and
    gateways that expose only that shape).
- A model large enough to follow tool instructions reliably. A 32B local model
  is a reasonable floor; smaller models often invent flags or ignore tools.

## Configuration

The console reads `~/.emp3r0r/assistant.json` (or
`$EMP3R0R_WORKSPACE/assistant.json`). The file is optional: without it, the
assistant targets a local Ollama server at `http://127.0.0.1:11434/v1` with
`qwen2.5:32b`.

```json
{
  "api": "chat",
  "base_url": "http://127.0.0.1:11434/v1",
  "model": "qwen2.5:32b",
  "api_key": "",
  "api_key_env": "",
  "allow_remote": false,
  "stream": true,
  "max_tool_rounds": 8,
  "request_timeout_seconds": 180,
  "max_tokens": 4096,
  "max_result_bytes": 4194304,
  "history_messages": 24
}
```

| Field | Meaning |
| --- | --- |
| `api` | `chat` for `/chat/completions`, `responses` for `/responses`. |
| `base_url` | Provider root. The endpoint suffix is added automatically. |
| `model` | Model identifier exactly as the provider expects it. |
| `api_key` | Inline bearer token. Use only in a `0600` config file. `api_key_env` takes precedence. |
| `api_key_env` | Name of the environment variable holding the bearer token, not the token itself. If both key fields are empty, `OPENAI_API_KEY` is used. |
| `allow_remote` | Must be `true` for a non-loopback `base_url`. Off by default. |
| `stream` | Stream the answer as it is generated. Set `false` if the provider rejects SSE. |
| `max_tool_rounds` | Maximum tool-call rounds per request (1-32). |
| `request_timeout_seconds` | Per-request timeout (1-600). |
| `max_tokens` | Maximum answer tokens. |
| `max_result_bytes` | Maximum job output fetched for analysis. |
| `history_messages` | Conversation turns kept in memory; `0` disables history. |

The API key is read at request time. It is never written to a log or shown in
the console. `api_key_env` must be a valid environment variable name. Prefer an
environment variable over storing the key in the file.

A hosted endpoint requires an explicit opt-in:

```json
{
  "api": "responses",
  "base_url": "https://gateway.example/v1",
  "model": "vendor/model-name",
  "api_key_env": "ASSISTANT_API_KEY",
  "allow_remote": true
}
```

## Usage

```text
ask what modules can enumerate domain trusts?
ask --module sa_ldapsearch
ask --module sa_ldapsearch "how do I find kerberoastable users?"
ask --last "what stands out?"
ask --job 1a2b3c4d-... "summarise these LDAP results"
ask --reset
```

| Flag | Meaning |
| --- | --- |
| `--module NAME` | Include the module's description, parameters, usage, and examples. |
| `--job UUID` | Analyse a specific job. |
| `--last` | Analyse the most recently dispatched job. |
| `--reset` | Clear the conversation history. |
| `--model NAME` | Override the configured model for this request. |

Without a question, `--job`/`--last` asks for an analysis and `--module` asks
for an explanation. Module questions work without a selected target;
target-specific answers need an active agent.

`ask` returns immediately. The answer streams into the tmux agent output pane,
not the command prompt pane: the operator can keep typing while the model
generates. Output is plain text; the model is instructed not to emit Markdown.
If an answer is cut off, raise `max_tokens`.

## What the assistant can read

- The installed module catalog for the target, included in the system prompt.
  Module names, descriptions, parameters, defaults, choices, generated usage
  lines, manifest `examples`/`help`, and optional `opsec` metadata are available
  through the tools.
- A bounded tail of the operator log, and `read_log` for more.
- The visible agent list and the selected target's OS, architecture, user, and
  privilege level.
- Recent jobs dispatched by this console and their persisted output.
- Parsed results:
  - LDAP: accounts, groups, trusts, domain password policy, ADCS templates, and
    deterministic findings such as AS-REP roastable accounts, kerberoastable
    accounts, delegation, LAPS readability, SID history, and ESC1 candidates.
  - `ps`, `ls`, `stat`, `list_tokens`, and `list_sessions` tables.
  - Other output: a bounded head/tail sample.

## OPSEC review

`review_command` returns the same deterministic review the MCP screen uses:

```json
{
  "kind": "module",
  "valid": true,
  "command": "sa_ldapsearch --filter '(objectClass=user)'",
  "opsec": {
    "rules": [],
    "reasons": [],
    "artifacts": ["target query"],
    "noise": "medium",
    "reversible": true,
    "requires": [],
    "unknowns": ["module has no opsec metadata; capabilities are matched from its description"]
  }
}
```

- `rules` lists the capability IDs that matched; the MCP policy maps each ID
  to `allow`, `warn`, or `block`.
- `noise` is independent of capability. A BOF can read credentials with low
  noise; a subprocess has at least medium noise. Scripts and broad enumeration
  raise noise to high.
- Modules without `opsec` metadata are matched by their rendered command and
  flag values, plus high-confidence action phrases in the module name, comment,
  or help. A broad filter such as `(objectClass=*)` carries `noisy-query`; a
  precise filter does not.
- `writes_disk` metadata adds `filesystem-artifact`. `touches_credentials` adds
  `credential-access`.
- Command rules are detectability-first: process creation, filesystem artifacts
  (including memfd/`/dev/shm`), script execution, CLR loading, LOLBins,
  credential access, Kerberos ticket access, persistence, defense or audit
  tampering, injection, privilege changes, noisy enumeration, data transfer,
  and destructive commands.
- Exec commands always carry `process-creation`; built-in agent commands do not.
  In MCP the default policy warns for `run_exec`, while `run_command` remains
  available for in-process queries.
- `reversible` is rule-specific. Destructive rules and target-state changes are
  irreversible; reading a credential or listing tickets is not.
- The MCP policy turns each capability into an `allow`, `warn`, or `block`
  disposition. `review_command` shows the rule IDs that trigger them; a
  `warn` result executes and returns `warnings`.
- Windows modules accept per-module `--token`, `--user`, and `--ticket`. The Go
  agent applies the token, netonly account, or imported ticket for that
  invocation. A `/ptt` BOF parameter applies the ticket to the shared logon
  session; the per-module flag scopes the identity to one invocation.

## Module help metadata

Manifests may add optional `examples`, `help`, and `opsec` fields. They are used
by `ask`, help output, and the MCP screen; they never change how a module runs.

```json
{
  "name": "sa_ldapsearch",
  "comment": "LDAP search",
  "examples": [
    "sa_ldapsearch --filter '(objectClass=user)' --attributes sAMAccountName,memberOf --scope 2"
  ],
  "help": "Longer operator-facing description, including flag semantics.",
  "opsec": {
    "noise": "low",
    "writes_disk": false,
    "network_egress": ["ldap"],
    "touches_credentials": false,
    "requires_admin": false,
    "artifacts": ["4624"],
    "reversible": true,
    "notes": "Read-only LDAP query."
  }
}
```

## Security

- Read-only by design. The assistant exposes only read-only tools; injection in
  target output can produce bad advice, never an action.
- Target data is untrusted. Tool results are sanitized, bounded, and treated as
  data by the prompt.
- Default configuration is loopback only. A non-loopback endpoint or an HTTP
  redirect to a non-loopback host is refused unless `allow_remote` is `true`.
- `assistant.json` must not be group- or world-writable, and must be mode
  `0600` when `api_key` is set inline.
- Job output is truncated before it is sent: `max_result_bytes` bounds the
  fetched output, and each tool result is capped independently.
- Output can contain credentials, hashes, and SIDs. Point the assistant at a
  local model if that data must not leave the operator host.

## Data handling

- Conversation history is kept only in memory for the current console process
  and resets when the target changes or the console exits.
- The console warns on every request when `allow_remote` is enabled.

## Limitations

- A model without reliable tool calling will produce poor answers. Use a model
  that supports tools and verify with `ask --module <name>`.
- The assistant sees the operator's console state, not another operator's. It
  cannot read jobs owned by another operator.
- Result analysis is deterministic for parsed facts; the narrative is
  model-generated. Treat suggested next steps as suggestions, not findings.
- OPSEC rules are heuristics. A missed rule is not safety.
- The LDAP analyser expects the `attribute: value` output produced by the
  bundled `sa_ldapsearch` module.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `assistant: connect` | No endpoint is listening at `base_url`. Start Ollama or set the right URL. |
| `provider returned 404` | `api` does not match the endpoint, or `base_url` is missing `/v1`. |
| `provider returned 401` | Set `api_key` or export the variable named by `api_key_env`. |
| `provider returned 400` and mentions tools | The model does not support tool calling or the API shape. |
| The assistant invents flags | Use a larger model; ask it to call `module_help` first. |
