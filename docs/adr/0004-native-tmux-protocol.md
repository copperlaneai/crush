# ADR 0004: Support tmux through its native terminal protocol

- Status: accepted
- Date: 2026-08-03

## Decision

Remote tmux is a first-class compatibility and acceleration target. Crush talks
to it through the same PTY byte stream as plain SSH and does not use tmux control
mode, a remote plugin, configuration injection, or remote command rewriting.

## Rationale

Tmux control mode changes the client protocol and omits output that tmux itself
generates for copy and choose modes. Making it the default would require Crush to
reimplement substantial tmux UI behavior and would no longer be a drop-in SSH
replacement.

Tmux also exercises the terminal protocols most likely to expose an incomplete
wrapper: bracketed paste, focus/mouse, alternate screens, cursor modes,
synchronized updates, terminal queries, and DCS passthrough. Byte transparency
addresses these at the correct layer.

## Consequences

- Tmux is a release-blocking integration matrix.
- Prefix/control interactions suspend prediction but are always forwarded raw;
  normal pane typing automatically re-arms after confirmation.
- Crush cannot know arbitrary tmux bindings before tmux processes them. It must
  repair speculative display promptly rather than intercepting or predicting the
  binding.
- Tmux correctness does not depend on the optional future remote helper.
