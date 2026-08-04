## Summary

<!-- What changed, and why is this the smallest safe change? -->

## Invariants and compatibility

<!-- Which relay, PTY, prediction, tmux, security, or public-interface invariants
does this touch? State explicitly when none are affected. -->

## Validation

<!-- List exact tests, transcript/property cases, platforms, and tmux versions.
Include before/after measurements for performance claims. -->

## Checklist

- [ ] I preserved raw input/output ordering and did not add a reserved key,
      fabricated terminal reply, or output batching timer.
- [ ] Prediction uncertainty fails passive and cannot block either relay.
- [ ] I added regression tests for changed terminal/process behavior.
- [ ] I ran the relevant commands in `CONTRIBUTING.md`.
- [ ] I added no credentials, production captures, terminal payloads, or traces.
- [ ] I updated compatibility, security, architecture, or changelog documentation
      when the public contract changed.
