# Testing and release gates

Crush tests four boundaries: SSH invocation, authenticated datagrams, remote
framebuffer state, and bytes presented to the physical terminal.

## Pull-request checks

Every pull request runs rustfmt, warning-denied Clippy, stable/MSRV builds,
locked unit and integration tests on Linux/macOS, dependency policy, and release
script checks. Public hosts and developer SSH credentials are forbidden in the
normal test suite.

## Mobile protocol layers

### Cryptography and framing

- Round-trip every packet kind and reject header/payload modification.
- Require unique nonce coordinates across kind/sequence/fragment spaces.
- Reject invalid markers, kinds, fragment coordinates, dimensions, codepoints,
  compressed lengths, cursors, and inconsistent assemblies.
- Reassemble reordered/duplicated fragments and cap incomplete generations.
- Deduplicate/reorder input without writing any byte twice to the PTY.

### Screen state

- Feed arbitrary terminal streams and resize sequences to the remote emulator.
- Encode/compress/decode independent states and require exact cell, cursor,
  mode, title, bell, prediction-policy, and input-ack equality.
- Compare changed-cell rendering with full rendering in an independent terminal
  model.
- Exercise primary/alternate screen, wide characters, color/rendition, mouse,
  focus, paste, application keys, Kitty keyboard flags, and terminal replies.

### Prediction

Prediction tests require these invariants:

- one printable key causes a local paint without waiting for a frame;
- every predicted cell uses an absolute coordinate;
- no frame contains ICH (`CSI @`) or relative-backspace cursor cleanup;
- occupied cells to the right retain their original coordinates;
- side-by-side tmux prediction stops at a physical row boundary, never addresses
  its divider or status row, and resumes from the remote continuation anchor;
- a pane-border change invalidates the old full-width prediction anchor;
- unrelated status frames do not roll pending typing backward;
- an echo-eligible frame whose authoritative cursor is still behind the local
  cursor retains the unresolved conditional suffix;
- a contradictory cell rolls back only after the authoritative cursor catches
  up and the contradiction remains stable for the settlement interval;
- matching authoritative cells consume the prediction without a visible erase;
- backspace conditionally overwrites only the erased cell with a blank;
- transport receipt does not expire a cell before delayed echo validation;
- simple left/right movement is conditional, while bracketed paste, release
  events, and unsupported input are not predicted;
- ordinary Kitty printable/space/backspace encodings are recognized; and
- raw/no-echo line editors remain eligible while common visible secret prompts
  disable prediction.

### End-to-end PTY

`tests/mobile.rs` launches the public Crush binary under a real local PTY. A
fake SSH executable performs `ssh -G` resolution and starts a real local
`crush --server`; the client then uses the production encrypted UDP path and a
second remote PTY. The fixture asserts local dim paint, authoritative shell
echo, exit status, stationary right-side text, and absence of insert-character
operations.

The optional real-tmux test runs the same topology with tmux between the helper
PTY and pane application:

```sh
CRUSH_RUN_MOBILE_TMUX_TESTS=1 \
CRUSH_TMUX_BIN="$(command -v tmux)" \
cargo test --test mobile --locked -- --nocapture
```

It attaches a real tmux client, types beside occupied same-row text, verifies
instant overwrite prediction, types at the final column of a side-by-side pane,
requires prediction to pause until tmux publishes the wrapped row without
addressing the divider, submits through the pane, detaches, and checks clean
status propagation.

Exercise authenticated ping/pong across the client's full 30-second silence
timeout with:

```sh
CRUSH_RUN_MOBILE_IDLE_TESTS=1 \
cargo test --test mobile mobile_helper_round_trip_is_local_and_never_inserts_same_row_text
```

## SSH fallback layers

The legacy tests remain release gates for hosts/invocations that cannot use
mobile transport:

- byte-exact OpenSSH argv/environment and passthrough classification;
- exact input/output ordering with prediction disabled;
- shadow/overlay equivalence across split ANSI/UTF-8 sequences;
- terminal cleanup, signal propagation, stop/resume, PTY hangup, resize, and
  backpressure; and
- existing local/remote tmux fixtures under xterm and Kitty synchronization.

Legacy fake-SSH tests set `CRUSH_TRANSPORT=ssh` explicitly so they do not
mistake the intentional helper probe for the relay invocation under test.

## Network fault matrix

Release candidates run mobile sessions at 0, 20, 80, 200, and 500 ms RTT with
0%, 1%, and burst packet loss, plus reordering and client address changes.
Validate that:

- no input byte is lost or duplicated;
- an incomplete old frame never blocks a complete newer frame;
- multiple complete frames already queued at the client produce one physical
  paint of the newest state rather than a sequence of stale paints;
- output rate adapts rather than growing a queue;
- endpoint migration requires an authenticated packet;
- reconnect notification begins promptly and screen state converges after
  recovery; and
- memory remains bounded at the maximum supported screen size.

## Tmux and coding-agent matrix

Remote tmux is a release gate. Cover maintained tmux versions, Bash/zsh/fish,
default/custom prefixes, panes/windows, copy/search/choose modes, prompts,
popups, attach/detach, mouse/focus, rapid resize, alternate-screen editors,
nested tmux, and no-echo prompts.

Coding-agent fixtures repaint input/status continuously and after every key.
Run with ordinary, modifyOtherKeys, and Kitty keyboard input. One fixture keeps
occupied placeholder/right-prompt text on the input row and verifies its cell
coordinates never move during prediction. Cursor-stability fixtures require
one-off deadline-snapshot coordinates to remain hidden, while repeated or quiet
coordinates become authoritative.

Before 1.0, run a 24-hour tmux + coding-output soak and compare periodic remote
framebuffer captures with an independent client model. Any unrecovered cell or
cursor mismatch blocks release.

## Performance gates

Measure release builds on dedicated Linux x86-64 and Apple Silicon hosts.

| Metric | Gate |
| --- | --- |
| Physical input read → UDP send | p99 ≤ 1 ms |
| Printable input read → completed local overwrite paint | p99 ≤ 4 ms |
| PTY output quiet/deadline → frame encryption send | p99 ≤ 20 ms |
| Complete frame receipt → changed-cell physical write | p99 ≤ 4 ms |
| Coding-agent stream display age at 80 ms RTT | p99 ≤ 1 RTT + 35 ms |
| Input loss/duplication under 1% packet loss | zero |
| RSS at 200×60 under continuous output | ≤ 48 MiB and bounded |
| Compressed unchanged 200×60 frame | ≤ 10 KiB |
| Stripped client/helper binary | ≤ 8 MiB |

`CRUSH_TRACE` exposes `mobile_local_paint.latency_us` and compressed frame sizes
without payload content. Diagnostic benchmark numbers from shared CI do not
replace a dedicated-host report.

## Release acceptance

A release is blocked by authentication bypass, nonce reuse with differing
plaintext, input loss/duplication, unrecovered screen mismatch, same-row cell
movement, backward cursor cleanup, secret-prompt prediction in covered cases,
terminal restoration failure, unbounded memory/queue growth, unsupported
dependency policy, or installer/release-verification failure.
