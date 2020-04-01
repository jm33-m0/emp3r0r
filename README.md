# emp3r0r
post-exploitation framework for linux


**This project is NOT finished**

## updates

<a href="https://jm33.me/emp3r0r-0x00.html" target="_blank">https://jm33.me/emp3r0r-0x00.html</a>

## demo

### reverse shell

<p align="center">
    <img width="600" src="/img/rshell.svg">
</p>

### port forwarding

<p align="center">
    <img width="600" src="/img/portfwd.svg">
</p>

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


| Key Binding                | Description        |
|----------------------------|--------------------|
| <kbd>C-x - </kbd>          | Split vertically   |
| <kbd>C-x _ </kbd>          | Split horizontally |
| <kbd>C-x x </kbd>          | Kill current pane  |
| <kbd>C-x c </kbd>          | New tab            |
| <kbd>C-x [1,2,3...] </kbd> | Switch to tab      |
| <kbd>C-x , </kbd>          | Rename tab         |

legend:

- <kbd>C-x -</kbd> means <kbd>Ctrl</kbd> plus <kbd>X</kbd>, then <kbd>-</kbd>
- <kbd>[1,2,3...]</kbd> means any numeric key

## thanks

- [pty](https://github.com/creack/pty)
- [readline](https://github.com/chzyer/readline)
- [h2conn](https://github.com/posener/h2conn)
- [diamorphine](https://github.com/m0nad/Diamorphine)
- [Upgrading Simple Shells to Fully Interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
