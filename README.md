# emp3r0r
post-exploitation framework for linux


**This project is NOT finished**

## updates

<a href="https://jm33.me/emp3r0r-0x00.html" target="_blank">https://jm33.me/emp3r0r-0x00.html</a>

## demo

[![asciicast](https://asciinema.org/a/TyicxXCmZXcr5iG8lylDNa11m.svg)](https://asciinema.org/a/TyicxXCmZXcr5iG8lylDNa11m)

## how to test

```bash
git clone git@github.com:jm33-m0/emp3r0r.git

cd emp3r0r

cp .tmux.conf ~ # if you wish to use my tmux config

cd core
./build.py # select a target to build: ./build.py <cc/agent>
./emp3r0r # launch CC server (with a user interface)

# on the target linux machine
./agent
```

## about tmux

### in case you don't know

emp3r0r utilizes [tmux](https://github.com/tmux/tmux/wiki) to provide features like remote editing, cmd output viewing.

if you wish to use my tmux config, you can put `.tmux.conf` under your `$HOME`

```
cp .tmux.conf ~
```

### key bindings


| Key Binding      | Description        |
|------------------|--------------------|
| `C-x -`          | Split vertically   |
| `C-x _`          | Split horizontally |
| `C-x x`          | Kill current pane  |
| `C-x c`          | New tab            |
| `C-x [1,2,3...]` | Switch to tab      |
| `C-x ,`          | Rename tab         |

legend:

- `C-x -` means `ctrl plus x, then -`
- `[1,2,3...]` means any numeric key

## thanks

- [pty](https://github.com/creack/pty)
- [readline](https://github.com/chzyer/readline)
- [h2conn](https://github.com/posener/h2conn)
- [diamorphine](https://github.com/m0nad/Diamorphine)
- [Upgrading Simple Shells to Fully Interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
