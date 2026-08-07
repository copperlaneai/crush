# Contributing to Crush

Crush optimizes a path where tiny correctness mistakes are visible and terminal
protocol mistakes can expose input or corrupt a session. Small, reviewable
changes with explicit invariants are preferred over broad rewrites.

## Before you start

- Discuss protocol changes, new dependencies, public environment variables, and
  platform-support changes in an issue first.
- Read [Architecture](docs/architecture.md), [Compatibility](docs/compatibility.md),
  and [Testing](docs/testing.md).
- Never add a reserved key, fabricated terminal reply, output batching timer,
  input re-encoding step, or code path where raw relay waits for prediction.
- Do not copy code from another project under an incompatible license. Record
  design inspiration and provenance in the pull request.

## Development setup

Install stable Rust plus Rust 1.85, a C toolchain, OpenSSH, and tmux. The default
toolchain is stable, while the branch must continue to build on the minimum
supported Rust version.

```sh
rustup toolchain install stable 1.85.0 --profile minimal
rustup component add rustfmt clippy --toolchain stable
cargo +stable build --locked
```

For dependency-policy checks, install `cargo-deny`. For shell changes, install
ShellCheck.

## Required checks

Run the checks that apply to your change before opening a pull request:

```sh
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets --all-features --locked -- -D warnings
cargo +stable test --all-targets --all-features --locked
cargo +1.85.0 check --all-targets --all-features --locked
cargo deny check --all-features
shellcheck install.sh scripts/*.sh
```

Changes to PTY setup, relay ordering, parsing, overlays, resize handling, or
signals also require the relevant transcript/property tests and a tmux
integration test. Include before/after benchmark data for performance claims.

## Testing principles

- Assert child-side input byte identity, not just visible output.
- Test control sequences split at every possible byte boundary.
- Treat prediction as untrusted: tests must prove that quiescent terminal state
  equals the no-prediction reference.
- Test failure paths, partial writes, queue saturation, resize interleavings,
  child signals, and terminal restoration.
- Reproduce tmux bugs over a real SSH PTY. A loopback command that starts tmux
  and immediately detaches is not sufficient coverage.

See [docs/testing.md](docs/testing.md) for release gates and fixture guidance.

## Commits and pull requests

Use focused [Conventional Commits](https://www.conventionalcommits.org/):

```text
type(scope): concise imperative description
```

Keep the subject under 72 characters and use one concern per commit. Pull
requests should state the invariant being changed, compatibility impact, tests,
and performance measurements where relevant. Never commit credentials,
production terminal captures, `.env` files, generated build output, or trace
files.

## Dependency policy

Dependencies must be actively maintained, necessary on the latency-sensitive
path, compatible with Rust 1.85, and licensed under an entry permitted by
`deny.toml`. Disable default features that are not needed. Explain why a new
parser, runtime, allocator, serializer, cryptography crate, or unsafe API is
required.

## Unsafe code

Keep unsafe code isolated around OS interfaces, document each safety invariant,
and test failure behavior. `unsafe` is never acceptable merely to avoid a copy
without measurement showing that the copy matters.

## Licensing contributions

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Crush is licensed under either Apache-2.0 or MIT, at the user's
option, without additional terms or conditions.
