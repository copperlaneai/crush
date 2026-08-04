# Architecture

Crush is a local process wrapper around the user's OpenSSH executable. It is not
an SSH implementation and, in version 1, has no remote component.

## Invariants

The following invariants take precedence over prediction coverage:

1. Bytes read from the physical terminal are written to OpenSSH unchanged and
   in order.
2. During a running relay, bytes read from OpenSSH's PTY are queued for the
   physical terminal unchanged, exactly once, and without a batching timer.
3. Raw input does not wait for parsing, prediction, rendering, tracing, or remote
   output.
4. Lifecycle signals are handled before a simultaneously readable PTY. Absent
   such a transition, each readiness turn queues and attempts the physical
   write of raw output before bounded observer work.
5. A speculative overlay is removed before authoritative output is displayed.
6. Uncertainty disables prediction; it never changes the relay.
7. Crush reserves no terminal key and answers no terminal query.

These rules are the compatibility boundary. An optimization that violates one
of them is not suitable for Crush.

## Session selection

The invocation classifier examines SSH option shapes without interpreting SSH
configuration or contacting a server.

- Clearly interactive invocations enter the PTY relay.
- Non-TTY, forwarding-only, multiplex-control, configuration-printing,
  background, and uncertain invocations directly execute OpenSSH.
- Arguments remain operating-system strings; Crush does not normalize them to
  UTF-8.
- Crush does not call `ssh -G`, inject `-t`, or add network tuning.

`CRUSH_MODE=force` requires the PTY relay for an otherwise compatible local TTY,
but it cannot force unsafe prediction. `CRUSH_MODE=passthrough` always executes
OpenSSH directly.

## Interactive process topology

```text
physical terminal
  input ──> input relay ──> OpenSSH PTY
                  └──────> bounded prediction observer

OpenSSH PTY
  output ──> render arbiter ──> physical terminal
                  └──────> bounded shadow observer
```

OpenSSH owns authentication, configuration, host keys, encryption, proxying,
forwarding, network I/O, and its remote PTY request. Crush owns the local PTY,
raw-terminal guard, relay scheduling, resize propagation, terminal shadow, and
temporary local overlay.

The input relay is independent of output processing so a streamed build or
coding-agent response cannot starve a keystroke. Side observers use bounded,
best-effort queues. If they fall behind, Crush drops observation state and
continues the raw relay. Remote output enters a bounded, nonblocking physical
output FIFO and is drained immediately; PTY reads pause at the high-water mark,
so authoritative bytes are backpressured rather than dropped. Adjacent chunks
coalesce to keep allocation count bounded. Shadow parsing runs in bounded slices
only when the PTY is momentarily quiescent and physical output has drained. A
continuous stream that fills the shadow backlog resets the sidecar instead of
putting parsing ahead of the next remote write. With `CRUSH_PREDICT=off`, the
shadow and input-payload observation copies are not created; an enabled trace
receives only input count/timing metadata.

Only the render arbiter writes to physical stdout. This provides a narrow point
at which an old overlay can be removed immediately before new remote bytes are
written, without allowing the parser to hold up those bytes.

## Terminal shadow and prediction

The shadow terminal contains only committed remote output. Locally predicted
cells never enter it. Prediction has two independent trust dimensions:

- **Terminal trust:** parser ground state, active buffer, cursor, dimensions,
  rendition, wrapping, modes, and known underlying cells are coherent.
- **Echo confidence:** the current remote application has recently demonstrated
  an exact, linear echo at the expected cursor.

At the start of an epoch, Crush forwards one eligible printable byte without
drawing it. An exact authoritative echo promotes the epoch. Later eligible bytes
may be drawn as a plain disposable overlay while still being sent to OpenSSH
immediately. Overlay frames use only printable ASCII, backspace, and space, so
abandoning an unwritten suffix cannot strand the terminal inside a control
sequence.

The initial shadow assumes only the conventional VT application-entry modes that
tmux and other terminal programs themselves expect from a normal shell: insert,
newline, origin, horizontal-margin, protection, and synchronized-update modes
off; autowrap and cursor visibility on; full-height margins; and ASCII G0/G1.
Crush emits no startup normalization and never uses these assumptions after
skipped output or suspend/resume. A recreated shadow also treats the terminal's
parser grammar as unknown: bare RIS is not proof because VT52 and Tektronix
modes can interpret or ignore it as data. An observed Tektronix exit (`ESC ETX`)
followed by the VT52 ANSI-exit (`ESC <`) proves ANSI parsing from the unknown
state; only a following RIS resets that epoch. If Crush observed entry into one
specific foreign-grammar switch, both exits are still required: emulator builds
may ignore either optional switch, so the physical grammar is ambiguous. At
ordinary application entry, every physical cell, cursor position, and the
inherited rendition remain unknown until authoritative output supplies a
rendition reset followed by a full-screen erase and absolute cursor anchor (or
an equivalent known alternate-screen transition). A reset observed after an
erase cannot retroactively prove the erased cells' attributes. Every overlay
target must be a proven blank default cell. Unknown or mismatched display state
disables prediction. An ordinary login prompt—and some tmux startup frames—may
therefore remain raw-relay-only until a remote application performs a complete
safe redraw.

Version 1 predicts only single-cell printable ASCII appended within a line and
backspace confined to the unresolved suffix. Enter, Escape, control keys,
navigation, paste, mouse, focus, Unicode, resize, screen changes, contradiction,
or unexpected cursor motion end the epoch.

Before remote output, the arbiter restores the overlay's confirmed underlying
cells and terminal state, writes the remote bytes unchanged, advances the
shadow, reconciles acknowledgements, and redraws only a still-valid suffix. It
does not use terminal save/restore slots, change modes, scroll, wrap, or retain
and re-render the full screen.

## Tmux

Tmux remains a normal remote terminal application. Crush does not invoke tmux
control mode, inspect tmux configuration, rewrite the remote command, or install
a plugin.

Input protocols—including custom prefixes, bracketed paste, mouse, focus,
extended keys, and terminal query replies—remain opaque byte streams to the
relay. Output protocols—including OSC, DCS passthrough, alternate screens,
cursor style, and synchronized updates—also remain opaque to the relay while the
side parser tracks enough state to decide whether an overlay is safe.

Prefix/control sequences and tmux-owned modes reset prediction. Once an
authoritative redraw establishes a safe pane anchor, ordinary typing performs a
fresh probe and re-arms. Status-line redraws may preserve an epoch only when the
authoritative cursor and cells return to that same safe anchor.

See [ADR 0004](adr/0004-native-tmux-protocol.md) and
[Compatibility](compatibility.md#tmux).

## Terminal and process lifecycle

An interactive session performs these steps:

1. Capture termios and complete window size, including pixel dimensions.
2. Create a PTY and spawn OpenSSH with the slave as its controlling terminal.
3. Start relay workers, then place the physical terminal in raw mode under a
   restoration guard.
4. Forward resize events to the PTY. Since the physical emulator may already
   have reflowed, abandon old overlay coordinates without a destructive erase
   and wait for the application's authoritative redraw.
5. Before stop or termination, pause new input and try to finish the exact
   queued prefix plus the overlay erase. This cleanup waits at most 100 ms. If
   stdout remains unwritable, retain authoritative queue order, discard only
   stale synthetic suffixes, and continue terminal handoff; a partial plain-text
   overlay can remain visible until the shell or application redraws.
6. Mirror EOF, PTY hangup, child exit, stop/resume, and terminal signals.
7. Restore the physical terminal on every controlled exit and panic path, then
   preserve OpenSSH's status or terminating signal where the platform permits.

Threads are started only after process creation so the child side of `fork` or
`pre_exec` remains minimal and auditable.

## Diagnostics

Crush has no telemetry. An explicit `CRUSH_TRACE` file records bounded
metadata—timestamps, byte counts, queue pressure, state transitions, rollback
reasons, and session outcome. It must never record arguments, hostnames,
keystrokes, terminal bytes, query replies, or clipboard data. Files are created
with owner-only permissions and are never uploaded automatically. Formatting and
file writes run on a bounded, drop-on-full worker so diagnostics cannot hold up
the relay. Traces are best-effort diagnostics: queue pressure, an I/O failure, or
process teardown may omit events at the tail of a file.

## Deferred remote helper

A later opt-in helper may add authoritative input acknowledgements, remote screen
checkpoints, reconnection, roaming, and state synchronization. It must be launched
through authenticated OpenSSH, negotiate capabilities, and fall back to this
client-only architecture. It is not required for tmux correctness.
