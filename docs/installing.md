# Installing Crush

Crush release binaries support macOS and Linux on x86-64 and ARM64. Windows is
supported through WSL; native ConPTY support remains deferred. The Linux
installer selects a static musl binary so it does not depend on the host's
glibc version.

## Quick install

Install the latest release:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | sh
```

On Windows 10 or 11 with WSL installed, run this from PowerShell:

```powershell
& ([scriptblock]::Create((irm 'https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.ps1')))
```

The PowerShell installer installs the matching Linux binary in the default WSL
distribution, creates launcher files under
`%LOCALAPPDATA%\Programs\Crush\bin`, and adds that directory to the user
`PATH`. Open a new terminal afterward. Choose a non-default distribution by
downloading the installer first:

```powershell
irm https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.ps1 -OutFile crush-installer.ps1
.\crush-installer.ps1 -Distribution Ubuntu-24.04
```

The Windows launcher runs Crush and OpenSSH inside that distribution, so it
uses the distribution's home directory, SSH configuration, keys, and agent.
Pass Linux paths to options such as `-i`.

On macOS, Linux, and inside WSL, the default binary destination is
`~/.local/bin/crush`. When that directory is not on `PATH`, the POSIX installer
adds the standard PATH entry to the startup file for zsh, bash, fish, or the
current POSIX shell. Open a new terminal afterward.

Confirm the installed version:

```sh
crush --version
```

## First connection

Connect normally after installing Crush locally:

```sh
crush user@example.com
```

On the first mobile connection, Crush sends its bundled installer through the
authenticated SSH session. The remote host downloads and verifies the exact
release used by the client, then installs the helper at
`~/.local/bin/crush` without root. Crush retries the connection automatically.

This setup needs outbound access to GitHub Releases and the installer's standard
POSIX command-line tools on the remote host. If automatic setup is unavailable,
install the matching helper manually:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | ssh user@example.com 'sh -s'
```

## Upgrade

Replacement is explicit locally because another project also ships a binary
named `crush`. Upgrade an installation you recognize with:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | sh -s -- --force
```

The next connection automatically upgrades the default remote helper to the
local version. For a custom helper path or a host without release access,
upgrade it manually:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | ssh user@example.com 'sh -s -- --force'
```

## Options

Download the installer when you want to inspect it before execution:

```sh
curl -fsSLO https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh
less crush-installer.sh
sh crush-installer.sh
```

Pin a release:

```sh
sh crush-installer.sh --version 0.1.0
```

Choose a destination or leave shell startup files unchanged:

```sh
sh crush-installer.sh --dir "$HOME/bin"
sh crush-installer.sh --no-modify-path
```

Run `sh crush-installer.sh --help` for the complete option list.

On Windows, run `.\crush-installer.ps1 -Help`. Its `-Version`, `-Force`, and
`-NoModifyPath` options mirror the POSIX installer; `-Distribution` selects a
WSL distribution and `-InstallDir` selects the Windows launcher directory.
`-NoModifyPath` leaves both the Windows user PATH and WSL shell startup files
unchanged.

## Verification

The installer downloads the selected archive and `SHA256SUMS` from the same
immutable GitHub release and rejects a checksum mismatch. When Cosign is
available, it also authenticates the checksum manifest against the Crush
release workflow's Sigstore identity.

For fully manual verification, including GitHub build provenance, see
[Releasing Crush](releasing.md#verify-a-release).
