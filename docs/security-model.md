# Security model

Crush uses OpenSSH as its authentication and trust bootstrap. The mobile
transport adds a remote helper, encrypted UDP protocol, terminal emulator, and
local predictor to the attack surface.

## Trust boundaries

- The selected OpenSSH executable is trusted for configuration, host identity,
  authentication, and the confidentiality/integrity of bootstrap data.
- The local operating system, terminal, account, and Crush binary are trusted.
- `crush --server` runs on the authenticated remote account. A compromised
  remote account can already observe or alter its shell and terminal contents.
- Network peers, unauthenticated UDP packets, and terminal/application output
  are untrusted.

Crush does not make an untrusted remote shell safe. Screen cells, titles, and
terminal effects originate on that host and have the same general trust level
as output shown through SSH.

## Session bootstrap and UDP protection

The helper generates a fresh 256-bit random key and returns it through the
authenticated SSH channel with its selected UDP port. The predictable default
port range is not a credential; the key is never sent in UDP.

Each datagram is independently protected with ChaCha20-Poly1305. Its marker,
kind, sequence, and fragment coordinates are authenticated as associated data.
Packet kinds separate nonce spaces; retransmissions reuse a nonce only for the
same immutable packet. Authentication failure is discarded before parsing any
payload as input or screen state.

Sequence numbers provide input ordering and deduplication. The server accepts a
bounded future window and ignores already-applied input. Frame fragments and
advertised dimensions have explicit limits. The client retains only a few
recent assemblies, limiting unauthenticated and authenticated memory pressure.

A correctly authenticated packet may update the client's source address. This
enables roaming and also means possession of the session key is sufficient to
redirect the remote endpoint. The key is therefore treated like a session
credential and held in zeroizing storage where practical.

The current protocol does not provide forward secrecy independent of the
SSH-delivered session key, multi-party attachment, or recovery after key/process
loss.

## Speculative input and secrets

Local prediction can reveal a character on the physical screen before the
remote application displays it.

Kernel `ECHO` is not a reliable secret signal: zsh line editing, tmux, and TUIs
all disable it while drawing ordinary input themselves. Crush permits
prediction in both primary- and alternate-screen line editors unless the
current input row contains a common `password`, `passphrase`, `secret`, `token`,
or `login:` shape.

This handles normal password prompts and preserves tmux/coding-agent latency,
but it is a heuristic for nested applications. A disguised or blank secret
prompt inside a full-screen program can still receive a temporary local echo.
Use `CRUSH_PREDICT=off` before unusual secret-entry workflows. Prediction-off
still uses state synchronization and does not slow input delivery.

Bracketed-paste contents, ambiguous controls, unsupported Kitty events, and
non-ASCII text are not predicted. Simple left/right cursor motion is predicted
conditionally. Pending printable text is not logged by the metadata trace.

## Screen protocol and terminal effects

The helper parses PTY output into a bounded visible framebuffer. The client
validates dimensions, codepoints, compressed size, fragment counts, cursor
coordinates, and exact payload length before rendering. It generates its own
bounded cursor/style sequences instead of forwarding arbitrary network bytes as
terminal controls.

Titles and bells remain remote-controlled terminal effects. Control bytes are
removed from title text before producing OSC title output. Clipboard and color
queries are answered by the helper with constrained values; arbitrary remote
clipboard payload synchronization is not implemented in the first protocol.

The legacy SSH relay intentionally remains byte-transparent and therefore has
the same terminal-escape exposure as plain SSH.

## Overwrite prediction integrity

Speculative cells are never written back to the authoritative framebuffer. The
client clones the newest remote state, applies absolute cell replacements to
that candidate, and computes one minimal diff from the previously displayed
candidate. It never emits an insert-character operation or copies the remainder
of a row. An unrelated remote redraw therefore cannot erase and repaint the
prediction row.

Transport receipt and screen validation use separate acknowledgements. A key is
not judged merely because it reached the PTY; a delayed echo acknowledgement
makes the resulting screen eligible for conditional confirmation or correction.
Predictions never become remote input beyond the original exact bytes sent.

## Process and terminal lifecycle

The helper PTY and local physical terminal use scoped descriptors and termios
guards. Controlled client exit resets cursor, mouse, focus, paste,
alternate-screen, application-key, and Kitty keyboard modes before restoring
the original terminal settings. The helper sends SIGHUP to its owned shell
process group on abnormal teardown.

The SSH bootstrap remains a lifecycle parent in this version. Closing the local
client terminates that bootstrap and helper. A helper with no authenticated
client packet for ten minutes exits rather than retaining an unbounded orphan.

Crush installs signal flags for termination and resize. Job-control suspend and
resume for the mobile path require additional hardening before 1.0; the SSH
fallback retains its more complete process-group lifecycle implementation.

## Availability and resource exhaustion

Remote output can change continuously. The server sends bounded-rate latest
state, expands its interval when acknowledgements lag, and retries the latest
state. It does not queue every application frame. Input has its own packets and
retransmission queue, so output congestion does not place input behind screen
bytes.

Authenticated peers can still consume CPU by producing high-entropy full-screen
changes, forcing compression and fragmentation. Visible cells, fragments,
assemblies, reordered input, and pending input all have fixed limits. These are
session availability controls, not protection against a compromised remote
account exhausting its own resources.

## Configuration and executable confusion

`CRUSH_SSH` and `CRUSH_SERVER` intentionally select executables. Protect them,
`PATH`, shell startup files, and SSH configuration as credentials. Local Crush
rejects `CRUSH_SSH` resolving back to itself. The remote helper command is
interpreted by the SSH remote shell; paths containing shell metacharacters must
be treated as shell input and should be avoided.

Another popular application also uses the executable name `crush`. The
installer refuses every existing destination unless `--force` is explicit and
never executes an existing file to identify it.

## Diagnostics

There is no telemetry. `CRUSH_TRACE` is local and opt-in. The destination must
be a regular, user-owned, non-symlink file inaccessible to group/other users.
Mobile trace events contain frame numbers, compressed sizes, byte counts, and
local paint latency—not hostnames, keys, packet payloads, terminal cells, or
keystrokes.

## Out of scope

- Compromise of OpenSSH, an endpoint OS/account, terminal, shell, release
  account, or distribution infrastructure.
- Traffic analysis and endpoint metadata leakage.
- Perfect secret-prompt detection inside arbitrary nested full-screen apps.
- Harm caused by content the authenticated remote account is already authorized
  to display or execute.

Report vulnerabilities according to [SECURITY.md](../SECURITY.md).
