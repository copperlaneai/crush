# Crush

**Crisp Remote Uninterrupted Shell** — a low-latency, byte-transparent wrapper
around the OpenSSH client.

> [!WARNING]
> The executable is named `crush`. It conflicts with
> [Charmbracelet's Crush](https://github.com/charmbracelet/crush). The installer
> refuses to replace any existing `crush` path unless `--force` is supplied.

Crush keeps the SSH implementation you already trust. It launches the system
`ssh` binary with the arguments you supplied, relays its PTY without batching,
and locally predicts only text that it has learned is safe to echo. Authentication,
host-key verification, connection setup, forwarding, and encryption remain
OpenSSH's responsibility.

Crush is pre-1.0 software. It should not yet be used as the only way to reach a
critical machine.

## Why

At interactive-network latencies, ordinary SSH makes each typed character feel
one round trip behind. Some wrappers hide that delay by taking ownership of the
terminal screen, but doing so can corrupt tmux, full-screen applications, paste,
terminal queries, or newer keyboard protocols.

Crush is built around a stricter rule: remote bytes always win. Prediction is a
disposable visual overlay; it is never part of the authoritative terminal state.
If Crush cannot prove that prediction is safe, it immediately behaves like plain
SSH.

## Design promises

- **OpenSSH compatible.** `crush user@host` accepts the same arguments as
  `ssh user@host`; Crush-specific settings live in the environment.
- **Byte transparent.** Input and output are forwarded exactly once, in order,
  without semantic re-encoding or synthetic terminal replies.
- **tmux native.** Remote tmux uses its normal terminal protocol. Crush reserves
  no prefix key and requires no tmux plugin or configuration.
- **Fail passive.** Parser lag, unfamiliar terminal state, and prediction
  disagreement disable the overlay rather than slowing or altering the session.
- **Private by default.** There is no telemetry. Optional traces contain timing
  and state metadata, never keystrokes or terminal payloads.

See [Architecture](docs/architecture.md), [Compatibility](docs/compatibility.md),
and the [Security model](docs/security-model.md) for the detailed contracts.

## Install

Release archives will support macOS and Linux on x86-64 and ARM64. Inspect the
installer before piping it to a shell:

```sh
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://raw.githubusercontent.com/copperlaneai/crush/main/install.sh
less install.sh
sh install.sh
```

The default destination is `~/.local/bin/crush`. Pin a version or choose another
directory with:

```sh
sh install.sh --version 0.1.0 --dir "$HOME/bin"
```

The installer verifies the archive against the release's `SHA256SUMS`. If
`cosign` is installed, it also verifies the checksum manifest's Sigstore bundle.
It never executes an existing destination to identify it; reinstalling or
upgrading in place requires `--force`.
See [Release verification](docs/releasing.md#verify-a-release) for a fully
authenticated manual flow.

## Use

Use `crush` anywhere you would normally start an interactive SSH session:

```sh
crush user@example.com
crush -J bastion.internal user@app.internal
crush -i ~/.ssh/work_ed25519 user@example.com
```

Noninteractive, forwarding-only, configuration, multiplex-control, and uncertain
invocations are passed directly to OpenSSH.

Crush consumes no command-line flags of its own. Configuration is environment
only:

| Variable | Values | Purpose |
| --- | --- | --- |
| `CRUSH_SSH` | executable path | Select a specific OpenSSH client. |
| `CRUSH_MODE` | `auto`, `passthrough`, `force` | Select conservative auto-detection, direct execution, or a required interactive PTY relay. |
| `CRUSH_PREDICT` | `auto`, `off` | Enable conservative learned prediction or use the raw relay only. |
| `CRUSH_TRACE` | file path | Write a private metadata-only diagnostic trace. |
| `CRUSH_ACTION` | `version`, `doctor` | Print build information or run local diagnostics without connecting. |

All `CRUSH_*` variables are removed from the child SSH environment.

To compare behavior with plain SSH:

```sh
CRUSH_PREDICT=off crush user@example.com
CRUSH_MODE=passthrough crush user@example.com
```

Prediction deliberately does not assume that the untouched part of an existing
terminal line is blank. It arms only after remote output establishes default
rendition, then clears the screen and anchors an absolute cursor. The ordering
matters because a later rendition reset cannot prove the attributes of cells
erased earlier. Tmux and full-screen programs normally perform complete redraws,
but Crush may stay raw-relay-only through startup or an ambiguous frame until a
safe redraw appears. This is a conservative pre-1.0 limitation, not a connection
failure.

After skipped output or suspend/resume, Crush also treats the terminal's parser
grammar as unknown. It remains raw-relay-only unless authoritative output proves
ANSI mode by emitting the Tektronix exit (`ESC ETX`) and VT52 ANSI exit
(`ESC <`), then resets the terminal. Both exits are required even after one
switch command because either optional emulator can ignore that command. This
avoids treating a RIS ignored by VT52 or Tektronix mode as a safe redraw.

Automatic prediction is enabled only for recognized VT/xterm-style `TERM`
families and assumes the conventional terminal mode state at a normal shell
application boundary—the same starting state tmux expects. Crush emits no
terminal normalization at startup. Unknown/custom terminals still receive the
full byte-transparent raw relay; use `CRUSH_PREDICT=off` for launchers that
intentionally hand applications an unusual inherited display state.

Resize handling never erases at pre-resize coordinates. Suspend and termination
pause input and attempt exact overlay cleanup for a bounded 100 ms; if the
physical terminal stays unwritable, Crush restores terminal ownership instead
of hanging, and a partial plain-text overlay may remain until the next
authoritative redraw.

For normal password prompts, the prompt/output barrier and an undrawn probe keep
secret input out of the overlay. A client-only wrapper cannot detect an
application that silently disables remote echo after a previously trusted
character stream. Set `CRUSH_PREDICT=off` before entering secrets into an
application with that unusual behavior.

## Build

Crush uses Rust 2024 and has a minimum supported Rust version of 1.85.

```sh
cargo +stable build --locked
cargo +stable test --all-targets --all-features --locked
cargo +stable clippy --all-targets --all-features --locked -- -D warnings
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes, especially
changes that touch terminal bytes, process creation, or prediction.

## Status and scope

Version 1 is a POSIX client for Linux and macOS. It improves perceived input
latency and avoids wrapper-induced output delay, but it cannot make bytes arrive
from a server sooner than OpenSSH does. Session roaming, reconnect/resume,
Windows/ConPTY, and an optional remote helper are intentionally deferred.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
