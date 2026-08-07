# ADR 0005: Use SSH-bootstrapped mobile screen synchronization

- Status: accepted
- Date: 2026-08-05

## Context

Client-only prediction can make a plain shell feel local, but it cannot reliably
infer the final display of nested tmux, Codex, Claude Code, or another terminal
emulator. Reconciliation then exposes cursor rewinds or requires conservative
prediction gaps. An SSH byte stream also delivers every obsolete intermediate
coding-agent repaint in order.

A mobile transport can solve the broader problem with an unprivileged remote
helper, encrypted UDP, a synchronized screen model, and speculative local echo.
Insert-style prediction has an undesirable behavior: typing before existing
cells copies the remainder of the row right, so prediction must overwrite cells
without shifting the row.

## Decision

Interactive login shells prefer a new mobile transport:

- OpenSSH authenticates and launches `crush --server`.
- SSH carries an ephemeral session key and UDP port.
- ChaCha20-Poly1305 protects independently sequenced UDP packets.
- Input is ordered/retransmitted separately from screen state.
- The helper owns the remote PTY and terminal emulator.
- It sends bounded-rate, independently compressed visible framebuffer states.
- The client skips obsolete states and renders changed cell runs.
- Local prediction always overwrites absolute cells; insertion prediction is
  not implemented.
- Remote truth and conditional predictions are composed before one minimal
  display diff is generated.
- Immediate input receipt and delayed echo validation use distinct
  acknowledgements. Delayed acknowledgement establishes comparison eligibility;
  authoritative cursor progress and a short stable-mismatch interval establish
  whether an eligible prediction should settle or roll back.
- Tmux/full-screen raw mode is distinguished from ordinary no-echo prompts by
  remote screen context.
- Auto mode retains the existing OpenSSH relay when mobile prerequisites are
  unavailable.

## Consequences

- Tmux and coding-agent display state is authoritative rather than inferred.
- Continuous output does not require replaying every intermediate terminal byte.
- Existing same-row text never moves during prediction.
- Tmux or coding-agent status redraws do not repaint a stable prediction row.
- The remote host needs the Crush helper and directly reachable UDP.
- The mobile protocol, emulator, cryptography, and helper lifecycle add code and
  security surface.
- The first version synchronizes only visible state and does not resume after a
  local process restart.
- SSH forwarding, proxy paths, noninteractive operations, and remote commands
  continue to use OpenSSH behavior.
