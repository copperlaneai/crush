# ADR 0003: Use conservative learned local echo

- Status: accepted
- Date: 2026-08-03

## Decision

Crush begins each prediction epoch with an undrawn probe and accelerates only
later single-cell printable ASCII after an exact remote echo proves a linear,
echoing context. Predictions are plain, disposable overlays over authoritative
remote state.

## Rationale

Blind local echo risks showing passwords, duplicating application output, and
misrepresenting modal editors or custom key bindings. Waiting for the first
confirmation sacrifices one key per epoch but allows a client-only implementation
to be useful without server installation or application knowledge.

## Consequences

- Already trusted text can feel local; first input after a mode change remains
  one round trip behind.
- Unicode, complex editing, paste, navigation, and uncertain state are initially
  unpredicted.
- A later authenticated helper can widen prediction coverage without changing
  the raw relay contract.
