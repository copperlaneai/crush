# Security model

Crush is a local terminal and process wrapper. Its primary security goal is to
preserve OpenSSH's boundary while ensuring that latency optimizations cannot
expose secret input or change the byte stream.

## Trusted components

- The user-selected OpenSSH executable is trusted for SSH protocol security,
  authentication, configuration, host verification, encryption, and transport.
- The local operating system, terminal emulator, shell environment, and user
  account are trusted to the same degree as they are for plain SSH.
- Release users trust GitHub's release infrastructure and, when signature
  verification is used, the Sigstore identity bound to the release workflow.

The remote host and every byte it emits are untrusted. Crush does not sanitize
terminal control sequences; doing so would break byte transparency. Users must
apply the same caution to untrusted remote output that they apply under SSH.

## Protected assets

- Keystrokes, especially passwords and other input entered while remote echo is
  disabled.
- SSH arguments, hostnames, configuration paths, and environment.
- Terminal contents, clipboard transfers, query replies, and application data.
- Local terminal settings and process control state.
- The exact input/output order and OpenSSH exit result.

## Threats and controls

### Secret speculative echo

A predictor could display password input before learning that remote echo is
disabled. Crush starts each epoch with an undrawn probe and predicts only after
an exact remote echo proves a safe linear context. Mode changes, Enter, Escape,
control input, cursor movement, contradiction, or timeout reset that confidence,
so ordinary password prompts begin cold and remain undrawn.

A client-only wrapper cannot observe a remote application which disables echo
silently, without a prompt, barrier, cursor change, or other output after a
previously trusted echo. In that unusual transition, a printable character can
appear speculatively until authoritative output disagrees or the prediction
expires. Use `CRUSH_PREDICT=off` when entering secrets into an application with
that behavior. An authenticated remote helper carrying termios/echo state would
be required for an absolute guarantee across silent transitions.

Unresolved input is held only as long as needed for comparison. Pending input,
prediction observer events, stack read buffers, renderer frames, and overlay
capacity use best-effort zeroization on reset and drop. With prediction off,
trace-only input observations contain counts and timing metadata rather than a
copy of the input bytes.

### Terminal-protocol confusion

Incomplete or unfamiliar CSI/OSC/DCS sequences can desynchronize a partial
emulator. Parsing is incremental across arbitrary read boundaries. The relay
does not depend on parser results, and the overlay is disabled unless the parser
is in a known ground state with a safe cursor and underlying cells. At initial
application entry, Crush assumes only conventional VT mode and ASCII-charset
defaults already required by tmux; it sends no normalization bytes. The initial
screen, cursor, and rendition are explicitly unknown, so cursor movement alone
cannot turn synthetic shadow defaults into safe overlay targets. A shadow
recreated after skipped output or suspend/resume assumes nothing, including
whether the terminal is using ANSI, VT52, or Tektronix parsing. Because foreign
grammars can ignore or reinterpret bare RIS, parser trust recovers from an
unknown state only after observed Tektronix and VT52 exits (`ESC ETX`, `ESC <`)
and a following RIS. Both exits remain necessary after a specific switch because
optional terminal features may ignore that switch and leave a different grammar
possible. Incomplete UTF-8, opaque DCS/APC, unknown display modes, and unknown
OSC protocols taint or invalidate the model until an authoritative convergence
sequence. A full-screen erase proves default blank cells only when default
rendition was already known; a reset emitted after the erase does not reclassify
those earlier cells.

Crush never fabricates DA, DSR, color, clipboard, or keyboard-protocol replies.
Remote queries reach the physical terminal and terminal replies reach OpenSSH.

### Input interception or transformation

Semantic input libraries can combine, normalize, or discard bytes. Crush relays
raw bytes before sending a best-effort observation to prediction. It reserves no
key, performs no line-ending normalization, and preserves paste delimiters,
focus/mouse events, extended keys, and tmux prefixes.

### Output starvation and memory exhaustion

Remote output can be arbitrarily fast. Input has an independent relay path;
physical output, prediction, shadow parsing, and trace queues are bounded.
During a running relay, authoritative output is never dropped: PTY reads pause
at the output high-water mark until the physical terminal drains.
Provenance-tagged queue segments let resize and lifecycle cleanup discard only
stale synthetic suffixes without reordering retained authoritative bytes.
Observer work is time-sliced or moved to a drop-on-full worker; observer
overflow disables prediction instead of blocking the relay or growing memory
without limit.

### Process and terminal lifecycle failures

Errors or signals could leave the user's terminal raw or spawn SSH with an unsafe
descriptor layout. PTY and terminal ownership use scoped guards. Process creation
keeps pre-exec work minimal, starts threads only afterward, closes unintended
descriptors, and forwards window size. Scoped drops cover unwind paths;
automated PTY tests exercise restoration across normal exit, launch errors,
signals, stop/resume, PTY hangup, and input/output backpressure.

Lifecycle signal handling pauses the input relay and stops PTY reads before
settling a visible overlay. If stdout accepts output within the 100 ms handoff
deadline, Crush completes the exact applied frame prefix and its matching erase
before restoring terminal ownership. A permanently unwritable terminal makes
both exact visual cleanup and bounded handoff impossible; Crush chooses bounded
termios/file-flag restoration, abandons only unwritten synthetic bytes, and may
leave a transient plain-text residue. A resize never erases at stale coordinates
and instead relies on the authoritative application redraw. Process termination
can necessarily leave an unwritable authoritative tail undisplayed, just as any
terminal process can when its output device stops accepting bytes.

### Executable confusion

`CRUSH_SSH` can intentionally select a binary; otherwise resolution follows the
user's `PATH`. Crush rejects a resolution that points back to itself. Users must
protect `PATH` and `CRUSH_SSH` as they protect SSH aliases and shell startup
files.

The installer has an additional name-confusion risk because another popular
program is also named `crush`. It never executes a preexisting destination to
identify it. Every existing target, including an older Crush installation, is
refused unless the user supplies `--force`; directories are always refused.

### Diagnostics disclosure

There is no telemetry. `CRUSH_TRACE` is explicit and local. Its destination must
be a regular file owned by the current user with no group/other permissions;
symlinks, FIFOs, devices, foreign owners, and broadly readable existing files
are rejected. Trace schemas permit only timings, counters, state transitions, queue
pressure, prediction rollback categories, and outcomes. They prohibit argv,
environment values, hostnames, input content, terminal payloads, query replies,
and clipboard data.
Trace delivery is best effort and a file may omit its final queued events; the
relay never waits for diagnostic I/O.

### Release substitution

Release archives, `SHA256SUMS`, SBOMs, and installer source are published from a
tagged workflow. Archives receive GitHub build-provenance attestations and
Sigstore keyless bundles. The installer checks SHA-256 and, when Cosign is
available, authenticates the checksum manifest to the exact repository workflow
identity. Users who require publisher authentication should perform the manual
verification in [releasing.md](releasing.md#verify-a-release) before execution.

## Out of scope

- Compromise of OpenSSH, the operating system, local terminal, shell, account,
  remote host, GitHub account, or Sigstore infrastructure.
- Harmful terminal escape sequences emitted by an untrusted server; plain SSH
  exposes the terminal to the same bytes.
- Traffic analysis, endpoint compromise, or secrets already present in process
  arguments/environment outside Crush.
- Guarantees for an unsupported build, modified binary, or overridden SSH
  executable.

Report suspected vulnerabilities according to [SECURITY.md](../SECURITY.md).
