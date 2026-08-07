# Crush

**Crisp Remote Uninterrupted Shell** is a responsive remote terminal built on
SSH authentication and Mosh-style screen synchronization.

```sh
crush user@example.com
```

> [!WARNING]
> Crush is pre-1.0 software. Its executable name also conflicts with
> [Charmbracelet's Crush](https://github.com/charmbracelet/crush), so the
> installer never replaces an existing `crush` unless `--force` is supplied.

## Install

Crush supports macOS and Linux on x86-64 and ARM64:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | sh
```

The mobile transport needs Crush on the remote host too:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | ssh user@example.com 'sh -s'
```

Open a new terminal if the installer adds `~/.local/bin` to `PATH`, then connect:

```sh
crush user@example.com
```

See [Installing Crush](docs/installing.md) for upgrades, version pinning,
custom destinations, and release verification.

## Why it feels local

OpenSSH authenticates the connection and starts an unprivileged remote helper.
The live terminal then uses authenticated, encrypted UDP to exchange input and
the newest authoritative screen state.

- Printable input is painted immediately as an overwrite-only overlay.
- Existing prompt, tmux, and coding-agent text is never shifted to predict a key.
- Obsolete screen frames can be skipped instead of building an output queue.
- Authoritative frames confirm or replace predictions in one synchronized update.
- Input is independently sequenced and retransmitted while the client roams.

This keeps typing responsive during large redraws while preserving tmux panes,
coding-agent interfaces, terminal modes, and OSC 52 clipboard writes.

## SSH compatibility

Use Crush like SSH:

```sh
crush user@example.com
crush -i ~/.ssh/work_ed25519 -p 2222 user@example.com
```

Interactive login shells prefer the mobile transport. Commands, forwarding,
subsystems, unsupported option forms, an unavailable helper, or unreachable UDP
fall back to OpenSSH in the default `auto` mode. Existing SSH configuration,
keys, host verification, `ProxyJump`, `ProxyCommand`, and SSM bootstrap continue
to use the system `ssh` binary.

The first mobile version requires directly reachable IPv4 UDP. See
[Configuration](docs/configuration.md) and [Compatibility](docs/compatibility.md)
for transport controls, port ranges, current limits, and fallback behavior.

## Build and test

Crush uses Rust 2024 and supports Rust 1.85 or newer.

```sh
cargo +stable build --locked
cargo +stable test --all-targets --all-features --locked
cargo +stable clippy --all-targets --all-features --locked -- -D warnings
```

See [Contributing](CONTRIBUTING.md), [Architecture](docs/architecture.md),
[Testing](docs/testing.md), [Security](docs/security-model.md), and
[Releasing](docs/releasing.md).

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your
option.
