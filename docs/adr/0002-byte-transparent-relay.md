# ADR 0002: Make the raw relay authoritative

- Status: accepted
- Date: 2026-08-03

## Decision

The input and output relays preserve raw bytes exactly once and in order. Parsing,
prediction, rendering, and tracing are bounded side observers and may never block
or transform the relay.

## Rationale

Terminal input libraries commonly decode and re-encode paste, focus, mouse, or
extended keys. Partial terminal renderers may consume queries, invent responses,
or lose newer OSC/DCS behavior. Those approaches are incompatible with a
drop-in SSH wrapper and are a major source of tmux corruption.

## Consequences

- Raw relay correctness is testable independently from prediction.
- Observer overflow disables acceleration rather than applying backpressure.
- The render arbiter may emit small overlay control sequences, but authoritative
  remote bytes are never replaced by a retained-frame renderer.
- Output throughput should remain close to plain SSH.
