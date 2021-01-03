# packer

pack your agent binary with

- ELF runtime encryptor
- ELF infector

## ELF runtime encryptor

```bash
cp /path/to/agent ./agent
# now change passphrase in ./internal/utils/aes.go
./build.sh # generates ./cryptor.exe
./cryptor.exe -input agent
# your agent is packed as agent.packed.exe
```

this cryptor encrypts `agent` binary with AES, and embed it inside `stub`

running `agent.packed.exe` decrypts `agent` and writes it into a memory location, `exec` it from memory, the parent process then exits

## ELF infector

TODO

## thanks

based on [guitmz](https://github.com/guitmz)'s [great work](https://github.com/guitmz/ezuri)
