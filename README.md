# Crush

**Crisp Remote Uninterrupted Shell** — a responsive remote terminal built on
SSH authentication and Mosh-style screen synchronization.

> [!WARNING]
> Crush is pre-1.0 software. The executable name also conflicts with
> [Charmbracelet's Crush](https://github.com/charmbracelet/crush); the installer
> never replaces an existing `crush` path unless `--force` is supplied.

```sh
crush user@example.com
```

For an interactive login shell, Crush uses OpenSSH to authenticate and launch
an unprivileged `crush --server` helper. Keystrokes and authoritative terminal
screen states then travel over authenticated, encrypted UDP. The server sends
the newest framebuffer instead of making the client replay every intermediate
terminal byte, so streamed coding-agent output cannot build a stale display
queue.

The helper detaches after the one-time key and port are delivered, so the SSH
bootstrap closes and the live terminal no longer depends on a TCP connection.

If the helper or direct UDP is unavailable, `CRUSH_TRANSPORT=auto` falls back to
the existing OpenSSH PTY relay. Noninteractive commands, forwarding, subsystems,
configuration queries, and uncertain SSH option forms still execute OpenSSH
directly.

## Why it feels local

- Printable input is painted immediately at absolute screen coordinates.
- Prediction is an **overwrite-only overlay**. It never inserts a cell or moves
  existing text on the row, fixing Mosh's default same-row/right-prompt shift.
- Authoritative remote snapshots confirm or replace predicted cells inside one
  synchronized terminal update—there is no erase-then-rewind cleanup phase.
- Remote snapshots are independent, LZ4-compressed states. Missing or obsolete
  frames can be skipped instead of blocking newer coding-agent output.
- Input packets are sequenced and retransmitted independently of screen frames.
- A valid packet from a new client address updates the session endpoint, which
  allows ordinary network roaming while the local process remains alive.

Mosh exposes its equivalent overwrite behavior as `mosh -o` or
`mosh --predict-overwrite`. Crush makes that behavior unconditional because
moving unrelated tmux, prompt, or coding-agent text is never a valid local
prediction.

## Tmux and coding agents

The remote helper owns the terminal emulator outside tmux, so it receives
tmux's authoritative final display rather than trying to infer nested redraws
from a client-side SSH byte stream. Crush synchronizes application cursor,
keypad, mouse, focus, bracketed-paste, alternate-screen, and Kitty keyboard
modes with the local terminal.

Zsh line editing, tmux, and coding agents all normally put their outer PTY in
raw/no-echo mode and draw input themselves. Crush therefore uses visible-screen
context instead of the kernel `ECHO` bit, while blocking common password,
passphrase, secret, token, and login prompt shapes. Bracketed-paste payloads and
ambiguous controls are never predicted; simple left/right cursor motion is
conditional and corrected by the next authoritative state.

The mobile transport has automated real-PTY and real-tmux coverage, including
same-row text that must remain stationary while a predicted character appears.

## Install

Crush must be available locally and on the remote host for the mobile transport.
Release archives target macOS and Linux on x86-64 and ARM64. Inspect the
installer before running it:

```sh
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://raw.githubusercontent.com/copperlaneai/crush/main/install.sh
less install.sh
sh install.sh
```

Run the same installer on the server, or copy a matching release binary to a
directory in its `PATH`, normally `~/.local/bin/crush`. The helper is
unprivileged and is launched only after successful SSH authentication.

```sh
ssh user@example.com 'command -v crush && crush --version'
```

The default local destination is `~/.local/bin/crush`. To pin a version or
choose a different directory:

```sh
sh install.sh --version 0.1.0 --dir "$HOME/bin"
```

The installer checks the release archive against `SHA256SUMS` and, when Cosign
is available, verifies the checksum manifest's Sigstore bundle. See
[release verification](docs/releasing.md#verify-a-release).

## Use and configuration

Crush does not consume ordinary SSH options:

```sh
crush user@example.com
crush -i ~/.ssh/work_ed25519 user@example.com
crush -p 2222 user@example.com
```

Crush-specific configuration is environment-only and is removed before any SSH
or remote shell process starts:

| Variable | Values | Purpose |
| --- | --- | --- |
| `CRUSH_TRANSPORT` | `auto`, `mobile`, `ssh` | Prefer mobile with fallback, require it, or use the legacy SSH relay. |
| `CRUSH_SERVER` | remote command/path | Select the remote helper executable (default `crush`). |
| `CRUSH_PORT` | port or `FIRST:LAST` | Select the server UDP port/range (default `60000:61000`). |
| `CRUSH_SSH` | executable path | Select a local OpenSSH client. |
| `CRUSH_MODE` | `auto`, `passthrough`, `force` | Classify normally, execute SSH directly, or require an interactive wrapper. |
| `CRUSH_PREDICT` | `auto`, `fast`, `off` | Enable prediction, force first-key prediction in the SSH fallback, or disable it. |
| `CRUSH_TRACE` | file path | Write private timing/state metadata without terminal or keystroke contents. |
| `CRUSH_ACTION` | `version`, `doctor` | Run a local diagnostic action. |

Examples:

```sh
# Require the new helper instead of silently falling back.
CRUSH_TRANSPORT=mobile crush user@example.com

# Compare with the byte-transparent SSH relay.
CRUSH_TRANSPORT=ssh CRUSH_PREDICT=off crush user@example.com

# Use a helper installed outside remote PATH.
CRUSH_SERVER='$HOME/bin/crush' crush user@example.com
```

The first mobile version supports interactive login shells over directly
reachable IPv4 UDP. `ProxyJump`, `ProxyCommand`, remote commands, forwarding,
and an unavailable helper use SSH behavior in `auto`. The server chooses the
first available port in `60000:61000` by default; firewalls/security groups must
allow the configured datagram range. A single pre-opened port can be selected
with `CRUSH_PORT=60000`.

## Build and test

Crush uses Rust 2024 with a minimum supported Rust version of 1.85.

```sh
cargo +stable build --locked
cargo +stable test --all-targets --all-features --locked
cargo +stable clippy --all-targets --all-features --locked -- -D warnings
```

Run the real local tmux mobile path with:

```sh
CRUSH_RUN_MOBILE_TMUX_TESTS=1 \
CRUSH_TMUX_BIN="$(command -v tmux)" \
cargo +stable test --test mobile --locked -- --nocapture
```

See [Architecture](docs/architecture.md),
[Compatibility](docs/compatibility.md), [Testing](docs/testing.md), and the
[Security model](docs/security-model.md) for the detailed contracts.

## Current limits

- The remote helper and wire protocol are new and not yet interoperable across
  different Crush versions.
- Only the visible framebuffer is synchronized; local scrollback reconstruction
  is not yet implemented.
- Combining marks and OSC 8 hyperlink metadata are not yet serialized with cell
  snapshots, though their base text remains visible.
- IPv6-only mobile sessions and UDP tunneling through SSH jump hosts are not yet
  implemented and fall back to SSH in `auto`.
- A local process restart cannot resume an existing remote session yet.

## License

Licensed under either Apache-2.0 or MIT at your option. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
