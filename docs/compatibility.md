# Compatibility contract

Crush aims to be a drop-in command replacement for interactive OpenSSH on
supported POSIX clients. Compatibility means the SSH process receives the same
arguments, environment (apart from removed `CRUSH_*` settings), terminal input,
window changes, and lifecycle events it would receive through a direct local
terminal.

## Supported clients

| Platform | Architectures | Version 1 status |
| --- | --- | --- |
| Linux | x86-64, ARM64 | Supported with static musl release archives |
| macOS 11 or newer | x86-64, Apple Silicon | Supported |
| Windows/ConPTY | — | Deferred until after 1.0 |

The minimum supported Rust version applies to source builds, not release users.
The installer selects the static musl archive on every Linux distribution,
including glibc-based systems. GNU target archives remain available for explicit
manual download and source-oriented compatibility work, but their minimum glibc
runtime version is not part of this compatibility contract.

## OpenSSH behavior

OpenSSH is discovered through `PATH`, unless `CRUSH_SSH` selects an explicit
executable. Recursive resolution back to Crush is rejected.

The following remain OpenSSH features and must behave exactly as they do under
`ssh`:

- user and system configuration, `Include`, `Match`, and canonicalization;
- agent use and forwarding, host-key checking, certificates, security keys, and
  authentication prompts;
- `ProxyCommand`, `ProxyJump`, port/socket forwarding, and connection sharing;
- remote commands, subsystems, escape commands, stop/resume, signals, and exit
  status; and
- unknown future options when Crush cannot classify them safely.

Crush directly executes OpenSSH for clearly noninteractive or semantically
uncertain forms. This includes `-T`, `-N`, `-W`, `-G`, `-O`, background mode,
forwarding-only sessions, a non-TTY caller, and malformed/unknown option shapes.
Direct execution is a compatibility feature, not an error.

## Terminals and applications

Crush does not replace `$TERM`, add a terminfo entry, or claim capabilities on
the terminal's behalf. It preserves `TERM`, `COLORTERM`, `TERM_PROGRAM`, locale,
and normal process environment.

Automatic prediction is limited to recognized VT/xterm-style `TERM` families,
including `xterm`, `screen`, and `tmux`. Unknown/custom terminal names use the
raw relay. Prediction also assumes the conventional VT mode state at a normal
shell-to-application handoff—the same entry state tmux relies on. If a custom
launcher deliberately leaves unusual display modes or character sets active,
use `CRUSH_PREDICT=off`.

The byte relay supports any terminal sequence that OpenSSH can carry. Prediction
is deliberately narrower and may turn off for:

- terminals or sequences the shadow parser cannot model confidently;
- non-ASCII or multi-cell input;
- password/no-echo prompts;
- alternate-screen transitions, full redraws, synchronized-update blocks, or
  incomplete control strings; and
- queue pressure, resize races, malformed data, or a disagreement with remote
  output.

Falling back affects only the local overlay. It does not alter application
input/output.

## Tmux

Remote tmux is a release-blocking supported application. Required coverage
includes:

- attach, detach, nested sessions, windows, panes, resize, zoom, and status
  redraws;
- default and custom prefixes, including `C-a` and `C-g`, and prefix-free key
  bindings;
- copy/search/choose modes, prompts, popups, paste, mouse, focus, and synchronized
  panes;
- alternate-screen applications, Vim/Neovim, shells, secret prompts, and output
  floods in another pane;
- extended-key protocols, OSC hyperlinks/clipboard, DCS passthrough, terminal
  queries and replies, synchronized updates, and pixel resize; and
- physical terminal → Crush → remote tmux, local tmux → Crush → remote tmux, and
  nested remote tmux.

Normal text entry in a tmux pane can be predicted after one confirmed echo.
Prefix actions, copy mode, pane switches, prompts, popups, attach/detach, resize,
and ambiguous redraws suspend prediction. After tmux produces a safe
rendition-first redraw and normal pane input resumes, Crush automatically probes
again. Until then it remains a byte-transparent raw relay.

On resize, Crush intentionally does not erase an overlay at its old coordinates.
A few plain speculative characters can therefore remain transiently if the
resize interrupts a partially written frame; tmux's authoritative resize redraw
replaces them while prediction remains disabled.

An arbitrary printable `bind-key -n` cannot be known by a client-only predictor
before tmux processes it. A plain speculative cell may appear briefly if the prior
pane was trusted, but it must be removed on the first contradiction or deadline;
the tmux action and final screen remain authoritative.

When Crush itself runs inside a local tmux, `pipe-pane` and raw terminal recorders
may capture Crush's temporary overlay control sequences. Use
`CRUSH_PREDICT=off` when a byte-exact recording of process output is required.

## Known non-goals for version 1

- Reconnect, roaming, session persistence, or surviving a broken SSH transport.
- Lower network latency for remote output; Crush can only avoid adding local
  buffering.
- A built-in SSH protocol, SSH server, tmux client, tmux control-mode renderer,
  or remote tmux plugin.
- Perfect prediction of arbitrary prompts, bindings, terminal applications, or
  Unicode editing.
- Replacing `scp`, `sftp`, `ssh-add`, `ssh-agent`, or `ssh-keygen`.
