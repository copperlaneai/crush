# Configuring Crush

Crush accepts ordinary SSH arguments without consuming them:

```sh
crush user@example.com
crush -i ~/.ssh/work_ed25519 user@example.com
crush -p 2222 user@example.com
```

Crush-specific settings use environment variables. They are removed before any
SSH or remote shell process starts.

| Variable | Values | Purpose |
| --- | --- | --- |
| `CRUSH_TRANSPORT` | `auto`, `mobile`, `ssh` | Prefer mobile with fallback, require mobile, or use the SSH relay. |
| `CRUSH_SERVER` | remote command/path | Select a manually managed helper; defaults to the automatically managed `$HOME/.local/bin/crush`. |
| `CRUSH_PORT` | port or `FIRST:LAST` | Select the UDP port range; defaults to `60000:61000`. |
| `CRUSH_SSH` | executable path | Select the local OpenSSH client. |
| `CRUSH_MODE` | `auto`, `passthrough`, `force` | Classify normally, execute SSH directly, or require an interactive wrapper. |
| `CRUSH_PREDICT` | `auto`, `fast`, `off` | Use normal prediction, force first-key SSH-relay prediction, or disable it. |
| `CRUSH_TRACE` | file path | Write private timing and state metadata without terminal or key contents. |
| `CRUSH_ACTION` | `version`, `doctor` | Run a local diagnostic action. |

Examples:

```sh
CRUSH_TRANSPORT=mobile crush user@example.com
CRUSH_TRANSPORT=ssh CRUSH_PREDICT=off crush user@example.com
CRUSH_SERVER='$HOME/bin/crush' crush user@example.com
CRUSH_PORT=60000 crush user@example.com
```

The mobile transport supports interactive login shells over directly reachable
IPv4 UDP. OpenSSH may bootstrap through `ProxyJump`, `ProxyCommand`, or SSM when
the client has an independent UDP route to the resolved host. Firewalls and
security groups must allow the configured UDP range.

Setting `CRUSH_SERVER` disables automatic installation and version management
because Crush cannot safely assume ownership of a custom path or command.

See [Compatibility](compatibility.md) for fallback behavior and current limits.
