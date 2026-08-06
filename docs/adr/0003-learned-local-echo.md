# ADR 0003: Use conservative learned local echo

- Status: superseded by ADR 0005 for the default transport
- Date: 2026-08-03

## Decision

Crush begins each prediction epoch with an undrawn probe and accelerates only
later single-cell printable ASCII after an exact remote echo proves a linear,
echoing context. Conservative predictions are plain, disposable overlays over
authoritative remote state.

An explicit `CRUSH_PREDICT=fast` override may skip that probe and begin with
trusted echo confidence at a conventional application-entry anchor. It exists
for users who prioritize first-keystroke latency and accept that a client-only
wrapper cannot protect no-echo secret input in this mode. Fast overlays are
faint, begin from input-read notification rather than PTY-write completion, and
remain visible across submit until authoritative output arrives. Incremental
updates retain the common prefix, and matching authoritative echoes overwrite
the faint prefix in one forward cursor pass instead of blanking and repainting
the complete prediction. A fast overlay hides the native cursor and reverses
the cell under the predicted cursor, making cursor position part of the composed
local frame. Fast mode may also cover printable dim placeholder
cells, including dim spaces between words, immediately following a recognized
TUI input marker. It retains those cells as reversible underlay; other occupied
cells remain ineligible. Remote output is briefly coalesced while an overlay is
pending, then applied to the shadow before rendering. Synchronized TUI redraws
receive the local composition before their terminator. Unsynchronized
cursor-addressed redraws, including tmux output after it consumes an inner
boundary, are wrapped with the composition in a new physical synchronized
update. Unrelated frames retain the local suffix; acknowledgements restore the
native cursor without displaying an intermediate cleanup position. Fast-mode
composition has no stale timer; elapsed wall time alone is not evidence that a
local prediction is wrong. Fast ASCII spans may also cross physical rows when
their underlay and final cursor remain inside the modeled screen. Right-edge
frames use absolute changed-cell placement inside a synchronized update for
every key rather than relying on terminal-specific relative backspace or
delayed-wrap semantics.

## Rationale

Blind local echo risks showing passwords, duplicating application output, and
misrepresenting modal editors or custom key bindings. Waiting for the first
confirmation sacrifices one key per epoch but allows a client-only implementation
to be useful without server installation or application knowledge.

## Consequences

- Already trusted text can feel local; first input after a mode change remains
  one round trip behind in conservative mode. Explicit fast mode predicts it.
- Unicode, complex editing, paste, navigation, and uncertain state are initially
  unpredicted.
- A later authenticated helper can widen prediction coverage without changing
  the raw relay contract.

This design remains the SSH fallback. The default mobile transport now uses an
authoritative remote framebuffer and overwrite-only prediction as described in
[ADR 0005](0005-mobile-state-sync.md).
