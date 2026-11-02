# File transfer

File transfer has two directions and two entry points:

- `put` (operator -> agent) is a plain agent command. The C2 hosts the file,
  registers it for the target agent, and sends
  `put --file <hosted name> --path <dest> --checksum <sha256>`.
  Both agents stream the body to the destination and verify the digest after the
  transfer; the C agent writes a `.part` file and renames it only on success.
- `get` (agent -> operator) is the operator command; it dispatches the
  `get_file` Linux BOF (`core/modules/file_transfer_bof`). The C2 registers an
  FTP stream, hands the BOF its token and the resume offset, and the agent
  streams the file to the operator over the FTP route. `get_file` remains the
  module command (and is the only one that takes `--riscv`).

## Downloads are operator-initiated

An agent can only fetch a file the operator registered for it. The C2 keeps the
registry (`network.WWWDownloads`), the operator stores the same entry locally and
serves the file, and a registration is bound to one agent and consumed by one
transfer:

- a name that was never registered is refused, even if the file exists in the
  operator's www root;
- a registration made for another agent is refused for this one;
- a registration that already served a transfer is refused on the next request.

The agent presents only the registered name (a random token, not the operator's
path) on the www route; the C2 resolves it and routes the request to the operator
that registered it.

## `put`

```text
put --src /tmp/tool.bin --dst /tmp/tool.bin
put --src /tmp/agent.gz --dst memfs:///agent.gz
```

| Option | Meaning                                              |
| ------ | ---------------------------------------------------- |
| `src`  | Local file on the C2 to send.                        |
| `dst`  | `memfs:///key` (encrypted RAM) or a disk path.       |

A disk destination is streamed, so file size is not bounded by agent memory; a
memfs destination is buffered because memfs is memory (64 MiB cap).

## `get` / `get_file`

`get` is the operator command and `get_file` the module it dispatches. The module
takes:

| Option   | Required | Meaning                                          |
| -------- | -------- | ------------------------------------------------ |
| `path`   | yes      | File or directory on the target.                 |
| `filter` | no       | Regex matched against file names in a directory. |

The operator command spells the filter `--regex` and adds `--recursive`: it lists
the directory through the module, then runs one transfer per listed file.

`get` uses the module on Linux x86-64 C agents, the only agents that install
the BOF host bridge. Go agents and other platforms keep using the agent's
built-in `get` command, so they are unaffected.

The C2 stats `path`, registers the FTP stream, and passes the token plus the
resume offset of any partial download to the BOF. The agent streams the file as
consecutive gzip members, so neither the BOF nor the agent holds it in memory.
For a directory the BOF prints the matching file paths instead of sending data.

```text
get --path /etc/hosts
get --recursive --regex '\.log$' --path /var/log
get_file --path /etc/hosts
get_file --riscv --path /etc/hosts
```

## Prerequisites

- `get` and `get_file` need a Linux agent built from `core/c_agent` with BOF
  support, and the `coffloader_linux` dependency (hosted automatically).
  `--riscv` uses `rvvm_linux`, also hosted automatically.
