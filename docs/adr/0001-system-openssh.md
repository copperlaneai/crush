# ADR 0001: Delegate SSH to system OpenSSH

- Status: accepted
- Date: 2026-08-03

## Decision

Crush launches the user's OpenSSH binary and does not implement the SSH protocol.
It preserves arguments as operating-system strings and directly executes OpenSSH
for noninteractive or uncertain invocations.

## Rationale

OpenSSH already owns a large, security-sensitive compatibility surface:
configuration, authentication, host keys, agents, proxies, forwarding,
multiplexing, transports, and escape commands. Reimplementing or translating
that surface would weaken drop-in behavior and increase security risk without
addressing terminal feedback latency.

## Consequences

- Users retain existing SSH configuration and trust decisions.
- Crush cannot replace TCP behavior or make remote output arrive sooner.
- The classifier must fail passive and must not query SSH configuration to decide
  whether to wrap a session.
- A future helper must still bootstrap and authenticate through OpenSSH.
