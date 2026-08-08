[CmdletBinding()]
param(
    [ValidatePattern('^(latest|v?[0-9]+\.[0-9]+\.[0-9]+)$')]
    [string] $Version = 'latest',

    [string] $Distribution,

    [string] $InstallDir,

    [switch] $Force,

    [switch] $NoModifyPath,

    [switch] $Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
    @'
Install Crisp Remote Uninterrupted Shell for Windows through WSL.

Usage: install.ps1 [OPTIONS]

Options:
  -Version VERSION          Install an exact version (for example, 0.1.0 or v0.1.0)
  -Distribution NAME        Install into this WSL distribution (default: WSL default)
  -InstallDir DIRECTORY     Windows launcher directory
                            (default: %LOCALAPPDATA%\Programs\Crush\bin)
  -Force                    Replace existing Windows launcher files
  -NoModifyPath             Do not add the launcher directory to the user PATH
  -Help                     Show this help

The PowerShell installer delegates archive verification and optional Sigstore
verification to the signed POSIX installer inside WSL, then creates a Windows
PATH launcher.
'@
}

function Fail([string] $Message) {
    throw "crush installer: $Message"
}

function Get-WslDistributions {
    $output = @(& $script:WslProgram --list --quiet 2>$null)
    if ($LASTEXITCODE -ne 0) {
        Fail 'could not list WSL distributions; install WSL with wsl --install'
    }

    @(
        $output |
            ForEach-Object { ($_ -replace "`0", '').Trim() } |
            Where-Object { $_.Length -ne 0 }
    )
}

function Get-DefaultWslDistribution([string[]] $Installed) {
    $registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    try {
        $defaultId = (Get-ItemProperty -LiteralPath $registryPath).DefaultDistribution
        $name = (Get-ItemProperty -LiteralPath (Join-Path $registryPath $defaultId)).DistributionName
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            return $name
        }
    }
    catch {
        # Older WSL versions may not expose the default distribution registry value.
    }

    if ($Installed.Count -ne 0) {
        return $Installed[0]
    }
    Fail 'no WSL distribution is installed; install one with wsl --install'
}

function Resolve-WslDistribution([string] $Requested) {
    $installed = @(Get-WslDistributions)
    if ($installed.Count -eq 0) {
        Fail 'no WSL distribution is installed; install one with wsl --install'
    }

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        $Requested = Get-DefaultWslDistribution $installed
    }

    $match = @($installed | Where-Object { $_ -ieq $Requested })
    if ($match.Count -ne 1) {
        Fail "WSL distribution '$Requested' is not installed"
    }
    if ($match[0].IndexOfAny([char[]]@("`r", "`n")) -ne -1) {
        Fail 'the WSL distribution name contains unsupported characters'
    }
    $match[0]
}

function Test-PathEntry([string] $PathValue, [string] $Entry) {
    $separators = [char[]]@('\', '/')
    $normalizedEntry = $Entry.TrimEnd($separators)
    foreach ($candidate in $PathValue -split ';') {
        if ($candidate.Trim().TrimEnd($separators) -ieq $normalizedEntry) {
            return $true
        }
    }
    $false
}

function Add-UserPath([string] $Directory) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) {
        $userPath = ''
    }
    if (-not (Test-PathEntry $userPath $Directory)) {
        $updated = if ($userPath.Length -eq 0) {
            $Directory
        }
        else {
            "$($userPath.TrimEnd(';'));$Directory"
        }
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    }
    if (-not (Test-PathEntry $env:Path $Directory)) {
        $env:Path = "$($env:Path.TrimEnd(';'));$Directory"
    }
}

function Quote-PowerShellLiteral([string] $Value) {
    "'$($Value.Replace("'", "''"))'"
}

function Install-WindowsLaunchers(
    [string] $Directory,
    [string] $WslDistribution,
    [bool] $AllowReplacement
) {
    $directoryInfo = [IO.Directory]::CreateDirectory($Directory)
    $Directory = $directoryInfo.FullName

    $powershellLauncher = Join-Path $Directory 'crush-launcher.ps1'
    $cmdLauncher = Join-Path $Directory 'crush.cmd'
    foreach ($destination in @($powershellLauncher, $cmdLauncher)) {
        if ((Test-Path -LiteralPath $destination) -and -not $AllowReplacement) {
            Fail "$destination already exists; use -Force to replace it"
        }
        if ((Test-Path -LiteralPath $destination -PathType Container)) {
            Fail "$destination is a directory; refusing to replace it"
        }
    }

    $distributionLiteral = Quote-PowerShellLiteral $WslDistribution
    $powershellContents = @"
`$distribution = $distributionLiteral
`$wslArguments = @(
    '--distribution', `$distribution,
    '--exec', 'sh', '-c',
    'exec "`$HOME/.local/bin/crush" "`$@"', 'sh'
) + `$args
`$wslProgram = Join-Path `$env:SystemRoot 'System32\wsl.exe'
if (-not (Test-Path -LiteralPath `$wslProgram -PathType Leaf)) {
    Write-Error 'crush: WSL is unavailable'
    exit 125
}
& `$wslProgram @wslArguments
exit `$LASTEXITCODE
"@
    $cmdContents = @'
@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0crush-launcher.ps1" %*
exit /b %ERRORLEVEL%
'@
    $cmdContents = $cmdContents.Replace("`r`n", "`n").Replace("`n", "`r`n")

    $staging = Join-Path $Directory ('.crush-install-' + [Guid]::NewGuid().ToString('N'))
    [void] [IO.Directory]::CreateDirectory($staging)
    try {
        $stagedPowerShell = Join-Path $staging 'crush-launcher.ps1'
        $stagedCmd = Join-Path $staging 'crush.cmd'
        [IO.File]::WriteAllText($stagedPowerShell, $powershellContents, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($stagedCmd, $cmdContents, [Text.ASCIIEncoding]::new())

        Move-Item -LiteralPath $stagedPowerShell -Destination $powershellLauncher -Force:$AllowReplacement
        try {
            Move-Item -LiteralPath $stagedCmd -Destination $cmdLauncher -Force:$AllowReplacement
        }
        catch {
            Remove-Item -LiteralPath $powershellLauncher -Force -ErrorAction SilentlyContinue
            throw
        }
    }
    finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }

    $Directory
}

if ($Help) {
    Show-Usage
    return
}

if ($env:OS -ne 'Windows_NT') {
    Fail 'this installer must run on Windows'
}
if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
    Fail 'SystemRoot is not set'
}
$script:WslProgram = Join-Path $env:SystemRoot 'System32\wsl.exe'
if (-not (Test-Path -LiteralPath $script:WslProgram -PathType Leaf)) {
    Fail 'WSL is required; install it with wsl --install and restart Windows'
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Fail 'LOCALAPPDATA is not set; pass -InstallDir DIRECTORY'
    }
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Crush\bin'
}
if ((Test-Path -LiteralPath $InstallDir) -and
    -not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    Fail "launcher directory is not a directory: $InstallDir"
}

$selectedDistribution = Resolve-WslDistribution $Distribution
$launcherPaths = @(
    (Join-Path $InstallDir 'crush-launcher.ps1'),
    (Join-Path $InstallDir 'crush.cmd')
)
foreach ($destination in $launcherPaths) {
    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        Fail "$destination already exists; use -Force to replace it"
    }
    if ((Test-Path -LiteralPath $destination -PathType Container)) {
        Fail "$destination is a directory; refusing to replace it"
    }
}

$posixArguments = @()
if ($Version -ne 'latest') {
    $posixArguments += @('--version', $Version)
}
if ($Force) {
    $posixArguments += '--force'
}
if ($NoModifyPath) {
    $posixArguments += '--no-modify-path'
}
$installerUrl = if ($Version -eq 'latest') {
    'https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh'
}
else {
    $normalizedVersion = $Version.TrimStart('v')
    "https://github.com/copperlaneai/crush/releases/download/v$normalizedVersion/crush-installer.sh"
}
$downloadAndInstall = (@'
set -eu
installer_url=$1
shift
command -v curl >/dev/null 2>&1 || {
    printf 'crush installer: required WSL command not found: curl\n' >&2
    exit 1
}
temporary_file=$(mktemp "${TMPDIR:-/tmp}/crush-windows-install.XXXXXX")
trap 'rm -f "$temporary_file"' EXIT HUP INT TERM
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --retry-delay 1 \
    --output "$temporary_file" \
    "$installer_url"
sh "$temporary_file" "$@"
'@).Replace("`r", '')
$wslArguments = @(
    '--distribution', $selectedDistribution,
    '--exec', 'sh', '-c', $downloadAndInstall, 'sh', $installerUrl
) + $posixArguments

Write-Host "crush installer: installing into WSL distribution $selectedDistribution"
& $script:WslProgram @wslArguments
if ($LASTEXITCODE -ne 0) {
    Fail "WSL installation exited with code $LASTEXITCODE"
}

$resolvedInstallDir = Install-WindowsLaunchers $InstallDir $selectedDistribution ([bool] $Force)
if (-not $NoModifyPath) {
    Add-UserPath $resolvedInstallDir
    Write-Host "crush installer: added $resolvedInstallDir to the user PATH"
}

Write-Host "crush installer: installed Windows launcher for $selectedDistribution"
Write-Host 'crush installer: run crush user@example.com from a new terminal'
