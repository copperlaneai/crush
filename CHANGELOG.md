# Changelog

All notable changes to Crush will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Pause speculative input at physical row boundaries until the remote screen
  publishes its continuation anchor, preventing transient duplicated input rows
  when coding-agent widgets reflow inside tmux.

## [0.1.0] - 2026-08-06

### Added

- Rebuild interactive login shells around an SSH-bootstrapped, unprivileged
  remote helper and encrypted UDP screen-state synchronization. Add
  ChaCha20-Poly1305 datagrams, independently LZ4-compressed framebuffer states,
  bounded fragmentation/reassembly, sequenced and retransmitted input, endpoint
  migration, resize, remote terminal replies, changed-cell rendering, terminal
  input-mode synchronization, automatic SSH fallback, and metadata-only mobile
  latency tracing.
- Make mobile prediction unconditionally overwrite-only. Every speculative
  character paints one absolute cell and never shifts the remainder of a row,
  preventing insert-prediction movement around right prompts, tmux, and
  coding-agent decorations. Decode Kitty/modifyOtherKeys printable input,
  suppress bracketed-paste prediction, preserve pending typing through unrelated
  redraws, and use remote PTY/screen context to disable covered secret prompts.
- Compose mobile predictions into the candidate framebuffer before diffing,
  eliminating the old authoritative-paint/overlay-paint cycle during tmux and
  coding-agent redraws. Split immediate input receipt from delayed echo
  validation, allow raw/no-echo line editors such as zsh, and add conditional
  backspace, Enter, and left/right cursor predictions.
- Keep a conditional mobile cursor ahead while a busy coding agent has accepted
  input but has not yet repainted its input widget. A delayed echo acknowledgement
  now makes a prediction eligible for comparison rather than expiring it, and a
  stable contradiction is required before rollback. Drain each ready UDP burst
  and paint only its newest complete framebuffer so streaming agent output cannot
  rebuild a stale-frame display queue on the client.
- Infer side-by-side tmux pane rectangles from their continuous border cells and
  constrain predicted text, wrap, backspace, movement, and Enter to the active
  pane. Pane layout changes and post-Enter application transitions hand the
  cursor to the new authoritative layout atomically. Buffer explicit synchronized
  updates on the helper and stabilize the cursor in deadline snapshots of long,
  unsynchronized repaints so Codex startup and streaming output do not expose
  transient internal cursor positions.
- Add a production-path double-PTY integration test and an optional real-tmux
  mobile test that verifies instant dim echo, authoritative reconciliation,
  stationary occupied same-row text, detach/exit behavior, and the complete
  absence of insert-character operations.
- Establish the Rust project, byte-transparent OpenSSH relay contract,
  conservative prediction design, and release infrastructure.
- Install the exact matching remote helper automatically on the first mobile
  connection and synchronize older default helpers before bootstrap. Send the
  bundled installer through authenticated SSH while leaving custom helper paths,
  unknown executables, and failed SSH connections untouched.
- Add opt-in `CRUSH_PREDICT=fast` first-keystroke faint local echo, input-read
  rendering, incremental cursor motion, in-place matching-echo reconciliation,
  a reversed-cell software cursor, atomic Kitty/tmux cursor settlement, submit
  continuity, latency tracing, and delayed-echo coverage. Recognize dim prompt
  placeholders used by coding-agent TUIs so Codex and Claude Code can predict
  the first character without clobbering real application text, including spaces
  between placeholder words. Pending input survives unrelated and split agent
  redraws by being composed into their final frame. When tmux consumes an inner
  synchronization boundary, wrap its coalesced client repaint and the local
  composition in a new physical-terminal update. Authoritative acknowledgement
  replaces the software cursor directly, including when an agent repaints after
  every key.
- Coalesce already-readable PTY output into bounded 64 KiB terminal writes
  without delaying the first available byte when no prediction is pending.
  While a fast overlay is pending, use 16 ms quiet and 50 ms maximum coalescing
  so intermediate repaint cursor positions are never rendered.
- Validate synthetic fast frames at terminal-operation boundaries, retain each
  paint in one zeroized queue allocation, and drain it with one write. Resize
  or bounded lifecycle abandonment can finish a partially accepted SGR/cursor
  control and restore the native cursor without cutting an escape sequence in
  half.
- Keep fast-mode composition pending until authoritative output or a real
  terminal/input transition arrives; timer expiry can no longer manufacture a
  cursor rollback during a network stall.
- Carry fast-mode ASCII and its software cursor across physical row boundaries.
  Use absolute cell diffs inside a synchronized paint for every key, never a
  relative backspace, so ordinary typing and terminal delayed-wrap behavior
  cannot make the cursor jump backward. Cover the path through real tmux with
  both xterm CSI and Kitty DCS synchronization. Feed local keys, unrelated agent
  repaints, and acknowledgement frames to an independent terminal one byte at a
  time and require its visible cursor never to reverse.
- Forward a newly read key to the SSH PTY in the same input-worker turn instead
  of waiting for another writable poll. Preserve fast-mode composition across
  temporary physical-terminal backpressure so a short output stall cannot
  schedule a visible erase/reappear cycle. Add continuous 2 ms coding-agent
  repaint coverage for both local-render and SSH-PTY-forward latency. Store
  ordinary input observations in a zeroized inline payload, removing the
  per-keystroke heap allocation from the common prediction path. Reuse two
  zeroized 64 KiB TUI frame buffers so continuous agent redraws do not allocate
  a fresh coalescing buffer for every physical paint.

[Unreleased]: https://github.com/copperlaneai/crush/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/copperlaneai/crush/releases/tag/v0.1.0
