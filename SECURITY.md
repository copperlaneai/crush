# Security policy

Crush sits between a user's terminal and OpenSSH. Bugs involving terminal
restoration, secret input, command-line preservation, child-process setup, or
terminal control sequences can therefore have security consequences even when
they are not conventional memory-safety issues.

## Reporting a vulnerability

Please use the repository's **Security** tab and open a private security
advisory. Do not disclose a suspected vulnerability in a public issue, pull
request, discussion, trace, or terminal recording.

Include, when available:

- the Crush version and installation source;
- operating system, architecture, terminal, shell, OpenSSH version, and tmux
  version;
- the smallest safe reproduction;
- whether the issue can expose input, alter bytes sent to SSH, leave the local
  terminal in an unsafe state, or execute a different binary; and
- metadata-only diagnostics produced with `CRUSH_TRACE`, after reviewing them
  for sensitive paths.

Do not include passwords, private keys, hostnames, complete SSH configuration,
terminal payloads, or production recordings. We will acknowledge a complete
report as soon as maintainers are available, coordinate a fix and disclosure,
and credit reporters who want public recognition.

## Supported versions

Until 1.0, only the newest released version receives security fixes. After 1.0,
this table will list supported release lines explicitly.

| Version | Supported |
| --- | --- |
| Latest pre-1.0 release | Yes |
| Older pre-1.0 releases | No |

## Security boundaries

- Crush delegates authentication, host-key verification, encryption, proxying,
  and network transport to the selected OpenSSH client.
- Crush does not make an untrusted SSH server safe. A server can emit arbitrary
  terminal control sequences, just as it can under plain SSH.
- Prediction starts cold after ordinary prompt/output barriers and must not
  speculate before an exact echo establishes a trusted epoch. A client-only
  wrapper cannot detect a silent remote echo-mode transition; use
  `CRUSH_PREDICT=off` for secret entry in applications with that behavior.
- Diagnostic traces must never contain arguments, hostnames, keystrokes,
  terminal payload bytes, clipboard contents, or terminal query responses.
- The installer authenticates release identity only when its Sigstore check is
  performed. SHA-256 alone detects corruption but does not establish publisher
  identity.

The full threat model is in [docs/security-model.md](docs/security-model.md).
