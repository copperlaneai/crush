# Testing and release gates

Crush tests behavior at three boundaries: bytes presented to OpenSSH, bytes
presented to the physical terminal, and the final terminal state after temporary
prediction is gone. Visual spot checks alone are not sufficient.

## Pull-request checks

Every pull request must pass:

- rustfmt and Clippy with warnings denied;
- stable and Rust 1.85 builds with the lockfile;
- unit, integration, property, and documentation tests on Linux and macOS;
- dependency advisories, licenses, bans, and source policy; and
- ShellCheck plus installer smoke tests when shell/release files change.

Tests must not use public hosts or require developer SSH credentials. The
network-free PR suite uses nested local PTYs and synthetic SSH executables. The
nightly real-tmux smoke gate uses an ephemeral localhost key, disposable sshd,
and throwaway tmux server/socket.

## Behavioral layers

### Invocation compatibility

Compare Crush with plain SSH across option arity, non-UTF-8 arguments, config and
authentication prompts, ProxyJump, forwarding, agent forwarding, multiplexing,
remote commands, escape handling, EOF, signals, and child exit status. Assert
that uncertain and noninteractive forms direct-exec OpenSSH.

### Byte identity

A recording child receives arbitrary input, paste, terminal replies, mouse/focus
events, extended keys, and embedded NUL where the platform permits. Assert exact
byte identity and order. With prediction off, assert exact output identity and no
extra physical-terminal writes.

### Shadow and overlay equivalence

Tag remote writes separately from overlay writes and run both the Crush stream
and a no-prediction reference through an independent terminal emulator. After
remote quiescence or the stale-overlay deadline, require equality of:

- primary and alternate grids;
- cursor position, shape, and visibility;
- rendition, margins, modes, and wrap state; and
- observable scrollback/history.

Split every CSI, OSC, DCS, APC, PM, SOS, paste marker, UTF-8 sequence, and
synchronized-update region at every possible byte boundary. Property tests vary
chunking, malformed input, queue overflow, resize timing, and prediction
rollback. Fuzz targets exercise parsers and state transitions without writing to
a real terminal.

### Process lifecycle

Inject partial reads/writes, `EINTR`, backpressure, PTY close, child exit, parent
signal, stop/resume, panic, and rapid resize. Every path must restore termios,
close descriptors, reap the child, and preserve the expected status. Verify
exact zero-residue/cursor-restoring cleanup when a blocked writer becomes
writable, bounded fallback when it remains full, input/PTY-read quiescence while
settling, and the absence of old-coordinate erases after resize.

## Tmux matrix

Remote tmux is a release gate, not a best-effort compatibility test. At release
cut, pin the oldest supported tmux, representative distro versions, current
stable, and a known source commit. Run each in an isolated environment over a
real OpenSSH PTY.

Test physical → Crush → remote tmux, local tmux → Crush → remote tmux, and nested
remote tmux. Cover default/custom configs and prefixes; pane/window lifecycle;
copy/search/choose modes; command prompts and popups; attach/detach; paste;
mouse/focus; alternate screens; synchronized panes; extended keys; OSC/DCS
passthrough; queries/replies; rapid resize; and high-frequency status redraws.

Application fixtures include Bash, zsh, fish, Readline emacs/vi modes,
Vim/Neovim modes, no-echo prompts, and a coding-agent-style output flood in one
pane while typing in another. Compare child input, an independent emulator, and
tmux capture/history with the plain-SSH reference.

The intended release program runs the broad matrix and fuzzing. A release
candidate must complete a 24-hour tmux soak with zero terminal-state mismatch or
corruption.

The repository currently automates the byte-level tmux transcript suite and one
real OpenSSH attach/custom-`C-g`-prefix/detach smoke path. The rest of this
matrix remains a release requirement, not a claim about the pre-1.0 test suite.

## Performance gates

Measure on dedicated Linux x86-64 and Apple Silicon hosts with release builds,
at 0, 20, 80, 200, and 500 ms RTT and at 0% and 1% packet loss.

| Metric | Gate |
| --- | --- |
| Local input read → SSH PTY write during output flood | p99 ≤ 1 ms |
| Trusted printable input read → completed disposable overlay | p99 ≤ 8 ms |
| SSH PTY output read → physical write, added latency | p99 ≤ 2 ms |
| 1 GiB sustained output throughput | ≥ 95% of plain SSH/raw relay |
| PTY setup before SSH spawn | p95 ≤ 10 ms |
| RSS at 200×60 and through a 1 GiB stream | ≤ 32 MiB and bounded |
| Stripped release binary | ≤ 5 MiB |

CI benchmark output is diagnostic until run on a controlled host. A maintainer
must review and attach the dedicated-host report before a 1.0 release.

## Release acceptance

A release is blocked by any byte mismatch, unrecovered screen/cursor mismatch,
terminal-restoration failure, tmux corruption, secret-prompt speculative echo,
unbounded queue, performance-gate regression, unsupported dependency license,
unresolved advisory, unverifiable archive, or installer collision failure.
