# Compatibility contract

Crush aims to replace the `ssh` command at the invocation boundary while using
the fastest transport compatible with the requested operation.

## Transport matrix

| Operation | Auto behavior |
| --- | --- |
| Interactive login shell, matching helper, direct IPv4 UDP | Mobile state sync |
| Default helper missing or old, remote release access, direct IPv4 UDP | Install or upgrade helper, then mobile state sync |
| Automatic helper setup or direct UDP unavailable | OpenSSH PTY relay |
| SSH proxy bootstrap with independently reachable IPv4 UDP | Mobile state sync |
| SSH proxy bootstrap without direct UDP | OpenSSH PTY relay |
| Remote command with explicit `-t` | OpenSSH PTY relay |
| Noninteractive command | Direct OpenSSH execution |
| Forwarding, subsystem, multiplex control, `-G`, `-V`, `-T` | Direct OpenSSH execution |
| Unknown/malformed option shape | Direct OpenSSH execution |

`CRUSH_TRANSPORT=mobile` turns a missing mobile prerequisite into an error.
`CRUSH_TRANSPORT=ssh` disables helper bootstrap. `CRUSH_MODE=passthrough`
directly executes OpenSSH regardless of transport settings.

OpenSSH remains responsible for configuration, `Include`/`Match`,
canonicalization, authentication, host keys, agents, certificates, security
keys, connection sharing, forwarding, jump hosts, remote commands, subsystems,
and escape semantics on SSH paths.

## Platforms

| Platform | Architectures | Status |
| --- | --- | --- |
| Linux | x86-64, ARM64 | Supported target |
| macOS 11+ | x86-64, Apple Silicon | Supported target |
| Windows/ConPTY | — | Deferred |

The source-build MSRV is Rust 1.85. Crush checks the default helper version and
installs or upgrades it to match the client before starting a mobile session.
Custom helpers must be kept at the same version manually.

## Mobile prerequisites

- The remote host can run the bundled POSIX installer and reach GitHub Releases
  on first setup or upgrade, or the matching helper is installed manually.
- A custom `CRUSH_SERVER` path is installed and upgraded manually.
- The SSH destination resolves to a directly reachable IPv4 address.
- A return UDP flow to the helper's configured port/range is permitted
  (`60000:61000` by default).
- The invocation requests an interactive login shell.
- Client input/output/error are the same usable terminal device.

The helper runs without privilege as the authenticated user. It starts a login
shell with Crush's `TERM=xterm-256color` emulator baseline and
`COLORTERM=truecolor`; it does not leak a local wrapper name such as
`tmux-256color` into the remote PTY.

## Terminal and application behavior

The mobile helper emulates the remote terminal and synchronizes visible screen
state. It supports primary/alternate screen, color/rendition, cursor and common
input modes, resize, title, bell, terminal-generated PTY replies, and single- or
wide-cell base characters. Combining marks and OSC 8 hyperlink metadata are not
yet serialized; visible base text remains.

Only the current visible screen is synchronized. As in Mosh, arbitrary local
scrollback cannot be reconstructed from states the client never received. Use
remote tmux history/copy mode for complete remote history.

Prediction supports printable ASCII, space, overwrite-style backspace,
conditional Enter and left/right cursor movement, Kitty printable-key encoding,
and xterm modifyOtherKeys. Unicode input, paste, mouse/focus events, tmux
prefixes, and other controls are sent immediately but not speculatively
displayed.

`CRUSH_PREDICT=off` disables all local prediction while retaining mobile screen
state synchronization.

## Tmux

Remote tmux is a primary supported path, not a client-side parser exception.
The helper sits outside tmux's client PTY and sees tmux's final authoritative
screen. Tmux may consume an inner Codex/Claude synchronized update; Crush does
not depend on that inner marker because it synchronizes tmux's resulting screen
state.

The client mirrors application cursor/keypad, bracketed paste, mouse, focus,
alternate-screen, and Kitty keyboard modes. Prefix keys and pane input remain
unaltered bytes. Attach/detach and process exit are reflected by the remote PTY
lifecycle.

Tmux OSC 52 clipboard writes are synchronized to the local terminal. This
restores `set-clipboard` workflows such as copy-on-selection while leaving the
local terminal's clipboard policy in control. Remote clipboard reads remain
disabled.

Every speculative character overwrites its target cell at an absolute
coordinate. Existing cells to its right are never copied or shifted. Automated
real-tmux coverage asserts that a right-side row decoration stays stationary and
that no insert-character terminal operation is emitted.

Nested local tmux may not pass synchronized-update mode through to the physical
terminal, but the changed-cell output remains correct; the outer tmux controls
when it presents the completed local paint.

Side-by-side remote panes are detected from tmux's visible vertical border run.
Predicted wrapping and Enter stay within the active pane and do not address the
divider or the status row below it. Moving or replacing the split invalidates
the old pane anchor before another speculative paint.

## Coding agents

Continuous Codex/Claude output is coalesced into the newest server framebuffer
rather than queued as every PTY byte. The client also drains each already-ready
UDP burst before painting and skips all but its newest complete framebuffer.
Remote truth and conditional predictions are composed before one minimal diff
is generated, so a status redraw or delayed input-widget repaint does not erase,
repaint, or roll the speculative suffix backward. Matching input normalizes from
faint to authoritative style without a cursor rewind.

Explicit synchronized Codex updates are never snapshotted halfway through. If
an outer tmux removes those boundaries, the helper stabilizes cursor coordinates
across forced progress frames and commits the final coordinate when output is
quiet, preventing renderer-internal cursor motion from becoming visible UI.
Prediction pauses while a progress repaint relocates the input cursor to a
different row, then resumes after that row repeats or output settles. Same-row
typing and echo stay speculative during continuous output. A newline
acknowledgement releases the local cursor immediately, and an unstable cursor
hold has a short upper bound.

Applications that intentionally transform, reorder, or hide typed text may show
a temporary prediction until an input barrier. Turn prediction off for modal or
secret workflows where a temporary visual guess is undesirable.

## Known mobile limitations

- IPv6-only paths.
- UDP tunneling through SSH jump/proxy hosts when no independent route exists.
- Mobile remote commands and subsystems.
- Reattaching after the local Crush process exits.
- Full local scrollback reconstruction.
- Version mismatch at a custom `CRUSH_SERVER` path.
- Complete combining-character, hyperlink, clipboard-read, and graphics protocols.

Each limitation falls back to OpenSSH in `auto` when the invocation can do so
before terminal takeover. A failure after an established mobile session is
reported rather than silently starting a second shell.
