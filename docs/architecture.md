# Architecture

Crush has two interactive transports and a direct-OpenSSH compatibility path.
The default `auto` policy prefers the mobile transport for login shells and
falls back to the SSH relay when its prerequisites are unavailable.

## Session selection

```text
                         ┌─ noninteractive/uncertain ─> exec OpenSSH
crush argv ─> classifier ┤
                         └─ interactive login shell
                              ├─ mobile helper available ─> state sync
                              └─ otherwise ───────────────> SSH PTY relay
```

Forwarding, subsystems, remote commands without the mobile contract,
multiplex-control operations, configuration queries, and non-TTY callers retain
OpenSSH semantics. `CRUSH_TRANSPORT=mobile` makes helper failure explicit;
`CRUSH_TRANSPORT=ssh` bypasses mobile bootstrap.

## Mobile process topology

```text
local                                                   remote

physical terminal                                       login shell / tmux / TUI
  │ input                                                      │
  ├─> overwrite predictor                                      │ PTY output
  └─> sequenced encrypted UDP ────────────────> crush --server ─┤
                                                               │
changed-cell renderer <─ compressed framebuffer snapshots <────┘

OpenSSH ── authentication + one-time key/bootstrap ──> crush --server
```

OpenSSH still owns user configuration, host aliases, host-key verification,
authentication, agent use, and helper launch. The helper is an unprivileged
process running as the authenticated user. SSH transports the ephemeral session
key; interactive terminal traffic does not remain behind SSH's ordered byte
stream after bootstrap.

### Bootstrap

1. The client starts OpenSSH with the original login-shell arguments and the
   configured helper command followed by `--server`.
2. The helper binds the first available IPv4 UDP port in the configured range
   (`60000:61000` by default) and generates a random 256-bit key.
3. It returns `CRUSH/1 <port> <hex-key>` through the authenticated SSH channel.
4. The client resolves the effective `Hostname` with `ssh -G`, sends terminal
   dimensions and Crush's stable `xterm-256color` emulator baseline in an
   authenticated UDP hello, and enters raw mode.
5. The helper forks into a new session without placing the key in arguments or
   environment, redirects the inherited standard descriptors to `/dev/null`,
   and lets the SSH bootstrap close.
6. The detached helper allocates a PTY and launches the remote login shell while
   all terminal traffic uses UDP. A later TCP/SSH failure cannot end a healthy
   mobile session.

`ProxyJump` and `ProxyCommand` currently make direct UDP ineligible. Auto mode
terminates the attempted helper and starts the ordinary SSH relay.

## Datagram protocol

Every packet has a small authenticated header containing protocol marker,
packet kind, sequence number, and fragment coordinates. Payloads use
ChaCha20-Poly1305 with the SSH-bootstrapped session key. Packet kinds occupy
independent nonce/sequence spaces. A retransmission reuses a nonce only with the
same authenticated bytes.

Datagrams are capped at 1200 bytes to avoid ordinary path-MTU fragmentation.
Screen states larger than one datagram are split into bounded authenticated
fragments. The client keeps only a small window of recent incomplete states;
completing a newer state discards older assemblies.

Input packets have monotonically increasing sequence numbers. The helper
deduplicates, buffers a bounded out-of-order window, and writes them to the PTY
in order. The latest accepted input sequence is carried in screen states.
Unacknowledged input is retransmitted without blocking newer screen packets.

A valid packet received from a new source address migrates the server's client
endpoint. This permits IP/interface roaming while both Crush processes remain
alive. Authentication prevents an off-path host from redirecting the session.

## Authoritative screen synchronization

The helper feeds PTY output into a full terminal emulator. It also returns
terminal-generated replies (such as device-status and size responses) to the
remote PTY, rather than forwarding queries across a latency-sensitive byte
stream.

At 4 ms output quiet or a 16 ms frame deadline, the helper captures:

- visible rows and columns;
- Unicode base character, foreground/background color, and rendition flags for
  each cell;
- cursor position and visibility;
- terminal input modes, title, and bell state;
- latest accepted input sequence;
- a deliberately delayed echo-validation sequence; and
- whether the current screen context permits speculative echo.

States are LZ4-compressed independently. Under acknowledgement backlog the frame
interval expands to 33 ms, and unacknowledged latest state is retried. Because a
state does not depend on every preceding frame, the client can skip obsolete
coding-agent paints and display the newest complete screen.

The client first composes remote truth and every still-valid conditional cell
into one candidate framebuffer. It compares that candidate with the previously
displayed candidate and emits only changed cell runs, plus terminal mode
changes, inside one synchronized update. The first state and
size/alternate-screen transitions receive a full repaint.

## Overwrite-only local prediction

Mosh's default predictor models shell insertion by shifting the remainder of a
row right. That makes right prompts, tmux decorations, and coding-agent text move
temporarily. Mosh's `--predict-overwrite` avoids it.

Crush has no insert-style prediction. Every eligible character:

1. is assigned an absolute `(row, column)` from the last authoritative cursor;
2. overwrites only that physical cell in faint style;
3. advances the displayed cursor to the next absolute cell; and
4. remains a conditional replacement outside the authoritative framebuffer.

The renderer never emits ICH (`CSI @`) or relative-backspace cleanup. It applies
predictions before diffing, so an unrelated authoritative update never touches
the predicted row. Matching authoritative cells require at most a rendition
change from faint to normal, with the cursor staying at the composed location.

When the cursor is inside side-by-side tmux panes, Crush identifies continuous
vertical border segments in the authoritative framebuffer. Their columns and
vertical extent define the editable pane rectangle: wrapping returns to that
pane's left edge, never the terminal's left edge, and prediction stops before a
divider or status row. A changed border layout starts a new prediction epoch.

Remote output does not invalidate pending printable text merely because an
unrelated status frame moved the authoritative cursor. Transport receipt is
acknowledged immediately for retransmission, while a separate 50 ms delayed echo
acknowledgement makes a conditional cell eligible for validation. It is not
evidence that the application has repainted the input widget. If the
authoritative cursor is still behind the predicted cursor, Crush retains the
conditional suffix. It relinquishes the local cursor only after authoritative
state reaches the same cell; a contradictory eligible cell must then remain
stable for 250 ms before rollback. This is essential for coding agents that
repaint status content before processing every key. Enter and simple left/right
movement receive conditional cursor predictions; paste and ambiguous controls
are barriers. Enter additionally hands control to the first echo-eligible remote
state, since launching a full-screen application need not pass through the
shell's predicted next-row cursor.

The helper's terminal parser buffers explicit synchronized updates until their
end marker. For a long tmux repaint without such markers, deadline frames may
advance content but publish a new cursor only after it repeats or the output
stream becomes quiet. This prevents internal repaint coordinates from appearing
as user-visible cursor teleports while preserving bounded streaming progress.

Kitty keyboard and xterm modifyOtherKeys printable sequences are decoded for
visual prediction while their original bytes remain the only input sent to the
server. Release events are ignored, and bracketed-paste payloads are never
predicted.

### Echo safety under tmux

Zsh line editing, tmux, and full-screen programs intentionally disable kernel
echo and implement their input widgets in terminal output, so the PTY `ECHO` bit
cannot classify secrets. Primary- and alternate-screen contexts may predict
unless the current row contains a common password, passphrase, secret, token, or
login prompt shape.

This is safer than a client-only fast predictor and preserves tmux performance,
but it is not proof against an intentionally disguised secret prompt. Set
`CRUSH_PREDICT=off` for unusual secret-entry applications.

## Terminal mode synchronization

The authoritative state drives local application-cursor, application-keypad,
mouse reporting, focus reporting, bracketed paste, SGR mouse, alternate screen,
cursor visibility, and Kitty keyboard flags. The client resets these modes and
restores termios on controlled exit.

Cell snapshots currently omit combining-mark and OSC 8 hyperlink metadata.
Their base characters are retained. Adding these fields is a protocol-versioned
extension, not a reason to infer screen state on the client.

## SSH fallback

The legacy transport remains a byte-transparent OpenSSH PTY relay with an
optional client-side terminal shadow and disposable local overlay. It preserves
ProxyJump, ProxyCommand, existing network paths, remote commands with explicit
TTY allocation, and hosts without the helper. It cannot skip streamed bytes or
know nested tmux/TUI state as reliably as the mobile transport.

## Resource bounds

- UDP datagrams: 1200 bytes.
- Frame fragments: bounded protocol window.
- Visible cells: 100,000 per frame.
- Incomplete client frames: three recent generations.
- Reordered input: 64 packets.
- Pending client input: 256 packets.
- Remote output read: 64 KiB per turn.
- Helper idle timeout: ten minutes without an authenticated client packet.

Malformed, unauthenticated, replayed, oversized, or out-of-window packets are
discarded or terminate only the affected mobile session. They never become
terminal input.
