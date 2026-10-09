# tmux Console Cheat Sheet

The operator console, every shell it opens, and every pane run inside one tmux
session. The bundled config is at
`/usr/local/lib/emp3r0r/tmux/.tmux.conf`; the launcher starts tmux with `-f`
pointing at it.

The prefix is **<kbd>Ctrl</kbd>+<kbd>x</kbd>** (the default
<kbd>Ctrl</kbd>+<kbd>b</kbd> is unbound). Press it, then the key. Everything
below is a live binding in this console; entries marked **stock** are tmux
defaults that the config leaves alone, the rest are the config's own bindings.
<kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>?</kbd> prints the complete list at any time,
and <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>:</kbd> accepts a raw tmux command for
anything not bound to a key.

There is one thing to internalise: because this is tmux, keys are intercepted
before they reach the program. To send the prefix itself through, use
<kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>x</kbd>. To get text out to
the OS clipboard, see [Mouse, scrolling and the system
clipboard](#mouse-scrolling-and-the-system-clipboard).

## Windows (tabs)

| Keys                                                         | Action                                                                                   |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>c</kbd>                    | **create a new window** (stock)                                                          |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>n</kbd>                    | next window (stock)                                                                      |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M-p</kbd>                  | previous window (<kbd>Alt</kbd>+<kbd>p</kbd>, stock)                                     |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M-n</kbd>                  | next window with an alert (stock)                                                        |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>PPage</kbd>                | previous window (<kbd>PageUp</kbd>, stock)                                               |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>1</kbd>...<kbd>9</kbd>     | select window by number (stock)                                                          |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>'</kbd>                    | prompt for a window number (stock)                                                       |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Tab</kbd>                  | jump to the last active window                                                           |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>w</kbd>                    | pick a window from a tree (stock)                                                        |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>f</kbd>                    | search panes for text (stock)                                                            |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>,</kbd>                    | rename current window (stock)                                                            |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>.</kbd>                    | move current window to another index (stock)                                             |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>&amp;</kbd>                | **kill current window** (asks to confirm, stock)                                         |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>i</kbd>                    | show window information (stock)                                                          |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>E</kbd>                    | spread panes out evenly (stock)                                                          |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Space</kbd>                | cycle through pane layouts (stock)                                                       |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M-1</kbd>...<kbd>M-5</kbd> | even-horizontal / even-vertical / main-horizontal / main-vertical / tiled layout (stock) |

The stock previous-window key <kbd>p</kbd> is reassigned to paste inside this
config, so use <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M-p</kbd>,
<kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>PPage</kbd>, or
<kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Tab</kbd> to go back a window.

## Panes

| Keys                                                                                                 | Action                                                  |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>_</kbd>                                                            | split top/bottom (new pane below)                       |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>-</kbd>                                                            | split left/right (new pane to the right)                |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>"</kbd>                                                            | split top/bottom (stock)                                |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>%</kbd>                                                            | split left/right (stock)                                |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>z</kbd>                                                            | **zoom / maximize the pane** (toggle fullscreen, stock) |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>x</kbd>                                                            | kill current pane (asks to confirm, stock)              |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>!</kbd>                                                            | break pane out into its own window (stock)              |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>o</kbd>                                                            | next pane (stock)                                       |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>;</kbd>                                                            | previously active pane (stock)                          |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>q</kbd>                                                            | show pane numbers; press a number to jump (stock)       |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>h</kbd>/<kbd>j</kbd>/<kbd>k</kbd>/<kbd>l</kbd>                     | move left/down/up/right (repeatable)                    |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>&larr;</kbd>/<kbd>&darr;</kbd>/<kbd>&uarr;</kbd>/<kbd>&rarr;</kbd> | move (stock, repeatable)                                |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>H</kbd>/<kbd>J</kbd>/<kbd>K</kbd>/<kbd>L</kbd>                     | resize left/down/up/right by 2 (repeatable)             |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M-&larr;/&darr;/&uarr;/&rarr;</kbd>                                | resize by 5 (stock, repeatable)                         |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>C-&larr;/&darr;/&uarr;/&rarr;</kbd>                                | resize by 1 (stock, repeatable)                         |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>{</kbd> / <kbd>}</kbd>                                             | swap pane up / down (stock)                             |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>&lt;</kbd> / <kbd>&gt;</kbd>                                       | swap pane previous / next                               |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>C-o</kbd>                                                          | rotate panes (stock)                                    |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M-o</kbd>                                                          | rotate panes in reverse (stock)                         |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Space</kbd>                                                        | cycle pane layouts (stock)                              |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>E</kbd>                                                            | spread panes out evenly (stock)                         |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>m</kbd>                                                            | mark the pane (stock)                                   |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>M</kbd>                                                            | clear the marked pane (stock)                           |

## Sessions and clients

| Keys                                                      | Action                                      |
| --------------------------------------------------------- | ------------------------------------------- |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>c</kbd> | new session                                 |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>s</kbd>                 | choose a session from a tree (stock)        |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>f</kbd> | find / switch session by name               |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>(</kbd> / <kbd>)</kbd>  | previous / next session (stock)             |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>$</kbd>                 | rename current session (stock)              |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>L</kbd>                 | switch to the last client (stock)           |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>D</kbd>                 | choose a client to detach (stock)           |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>d</kbd>                 | detach, leaving the session running (stock) |

Reattach after detaching from inside the container:

```bash
tmux ls                 # the session is named emp3r0r
tmux attach -t emp3r0r
```

## Mouse, scrolling and the system clipboard

`mouse on` is set, so the mouse selects panes, drags pane borders to resize,
scrolls the pane under the cursor (the wheel enters copy mode), and
double/triple-clicks to select a word or line. That convenience comes at a cost:
**while tmux owns the mouse your terminal never sees the selection, so a plain
drag copies into tmux's own buffer, not the OS clipboard.**

To move text between the console and another application:

1. **Inside tmux.** The wheel, <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>[</kbd>, or
   <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Enter</kbd> enters copy mode. Select with
   the vi keys, press <kbd>y</kbd> (or <kbd>Enter</kbd>) to copy and exit, then
   paste with <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>]</kbd>. This buffer is shared
   across panes and windows but lives only inside tmux.
2. **Bypass tmux and use the terminal's own selection.** Hold
   <kbd>Shift</kbd> while dragging (some terminals, e.g. iTerm2 and kitty, use
   <kbd>Alt</kbd>/<kbd>Option</kbd>). The modifier makes tmux ignore the mouse
   and hand it to the terminal, which performs its normal selection and copies
   it to the **system clipboard**. Paste with the terminal's own shortcut:
   <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>V</kbd>,
   <kbd>Cmd</kbd>+<kbd>V</kbd>, right-click, or middle-click on X11.

This works identically whether the client runs natively or from the
`docker run -it` container, because the terminal doing the selection is the one
on the operator host.

## Copy mode (vi)

Enter with <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>[</kbd>,
<kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Enter</kbd>, the mouse wheel, or
<kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>PageUp</kbd> (stock, scrolls up on entry).

| Keys                                                           | Action                                            |
| -------------------------------------------------------------- | ------------------------------------------------- |
| <kbd>h</kbd>/<kbd>j</kbd>/<kbd>k</kbd>/<kbd>l</kbd>, arrows    | move the cursor                                   |
| <kbd>w</kbd>/<kbd>b</kbd>/<kbd>e</kbd>                         | next word / previous word / end of word           |
| <kbd>0</kbd> / <kbd>$</kbd> / <kbd>^</kbd>                     | line start / line end / first non-blank           |
| <kbd>v</kbd>                                                   | begin a character selection                       |
| <kbd>V</kbd>                                                   | select the whole line                             |
| <kbd>Ctrl</kbd>+<kbd>v</kbd>                                   | toggle rectangle (block) selection                |
| <kbd>y</kbd> / <kbd>Enter</kbd> / <kbd>Ctrl</kbd>+<kbd>j</kbd> | copy the selection and exit                       |
| <kbd>o</kbd>                                                   | move the cursor to the other end of the selection |
| <kbd>H</kbd> / <kbd>L</kbd>                                    | jump to line start / line end                     |
| <kbd>g</kbd> / <kbd>G</kbd>                                    | jump to the start / end of the scrollback         |
| <kbd>Ctrl</kbd>+<kbd>u</kbd> / <kbd>Ctrl</kbd>+<kbd>d</kbd>    | half-page up / down                               |
| <kbd>Ctrl</kbd>+<kbd>b</kbd> / <kbd>Ctrl</kbd>+<kbd>f</kbd>    | page up / down                                    |
| <kbd>/</kbd> / <kbd>?</kbd>                                    | search forward / backward                         |
| <kbd>n</kbd> / <kbd>N</kbd>                                    | next / previous match                             |
| <kbd>q</kbd>, <kbd>Esc</kbd>, <kbd>Ctrl</kbd>+<kbd>c</kbd>     | cancel                                            |
| drag with the mouse                                            | copy the selection on release                     |

## Paste buffers

| Keys                                                               | Action                               |
| ------------------------------------------------------------------ | ------------------------------------ |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>]</kbd>                          | paste the most recent buffer (stock) |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>P</kbd>                          | choose which buffer to paste         |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>=</kbd>                          | choose which buffer to paste (stock) |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>b</kbd>                          | list all buffers                     |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>#</kbd>                          | list all buffers (stock)             |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>:</kbd> <kbd>delete-buffer</kbd> | delete the most recent buffer        |

Stock <kbd>-</kbd> (delete-buffer) is reassigned by this config to a horizontal
split, so delete buffers through the command prompt instead.

## Miscellaneous

| Keys                                                      | Action                                                     |
| --------------------------------------------------------- | ---------------------------------------------------------- |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>?</kbd>                 | list **all** key bindings (stock)                          |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>:</kbd>                 | open the tmux command prompt (stock)                       |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Ctrl</kbd>+<kbd>x</kbd> | send a literal <kbd>Ctrl</kbd>+<kbd>x</kbd> to the program |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>t</kbd>                 | clock (stock)                                              |
| <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>~</kbd>                 | show messages (stock)                                      |
| <kbd>Ctrl</kbd>+<kbd>l</kbd>                              | clear screen and scrollback (no prefix)                    |

Reload the config after editing it:

```bash
tmux source-file /usr/local/lib/emp3r0r/tmux/.tmux.conf
```

> <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>r</kbd> sources `~/.tmux.conf`, which the
> container does not create, so it will not pick up the bundled config.

## How this config differs from stock tmux

Useful when you land in a plain tmux session and muscle memory fails:

- Prefix is <kbd>Ctrl</kbd>+<kbd>x</kbd>; <kbd>Ctrl</kbd>+<kbd>b</kbd> is
  unbound.
- <kbd>Ctrl</kbd>+<kbd>z</kbd> (suspend) is unbound to avoid blanking the
  console.
- Splits: <kbd>_</kbd> and <kbd>-</kbd> in addition to stock <kbd>"</kbd> and
  <kbd>%</kbd>.
- Pane motion on <kbd>h</kbd>/<kbd>j</kbd>/<kbd>k</kbd>/<kbd>l</kbd> and resize
  on <kbd>H</kbd>/<kbd>J</kbd>/<kbd>K</kbd>/<kbd>L</kbd> (stock <kbd>l</kbd> was
  last-window).
- <kbd>Ctrl</kbd>+<kbd>x</kbd> <kbd>Tab</kbd> is last-window.
- <kbd>&lt;</kbd>/<kbd>&gt;</kbd> swap panes (stock behaviour for these keys is a
  menu); stock <kbd>{</kbd>/<kbd>}</kbd> still swap.
- <kbd>p</kbd> pastes, replacing stock previous-window (use
  <kbd>M-p</kbd>).
- <kbd>b</kbd> lists buffers and <kbd>P</kbd> chooses one (stock <kbd>#</kbd>
  and <kbd>=</kbd> still work); <kbd>-</kbd> no longer deletes a buffer.
- <kbd>Enter</kbd> enters copy mode, and inside it <kbd>v</kbd> starts a
  selection, <kbd>H</kbd>/<kbd>L</kbd> move to line start/end, and
  <kbd>y</kbd> copies and exits.
- <kbd>Ctrl</kbd>+<kbd>l</kbd> clears screen and scrollback without the prefix.
- Mouse is on, history is 10000 lines, and panes carry title bars in the status
  line.
