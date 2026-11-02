# `file_transfer_bof`

`get_file`, the agent -> operator half of file transfer, as a Linux BOF. The
operator `get` command dispatches this module on Linux x86-64 C agents (the
agents that install the BOF host bridge); it is also available directly as
`get_file` (which is where `--riscv` lives). The agent's host bridge exposes
`UploadFile`, which streams a local file (disk or memfs) to the FTP route
starting at the resume offset the C2 registered; this object owns the directory
walk and passes the offset through.

Operator uploads are not a BOF: `put` is a plain agent command that uses the same
www-route download primitive a module payload uses, gated by an operator-issued
download token.

Runs natively and as a RISC-V BOF with `--riscv`. See
[`docs/file_transfer_bof.md`](../../../docs/file_transfer_bof.md).
