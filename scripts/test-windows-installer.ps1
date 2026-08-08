[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) {
        throw "windows installer test: $Message"
    }
}

function Read-MockInvocation([string] $Path, [int] $Index) {
    $lines = @(Get-Content -LiteralPath $Path)
    Assert-True ($Index -lt $lines.Count) "mock WSL invocation $Index is missing"
    @(
        $lines[$Index].Split('|') |
            ForEach-Object {
                [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
            }
    )
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repositoryRoot 'install.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('crush-windows-installer-' + [Guid]::NewGuid().ToString('N'))
$mockDirectory = Join-Path $testRoot 'System32'
$installDirectory = Join-Path $testRoot 'install'
$logPath = Join-Path $testRoot 'wsl-invocations'
[void] [IO.Directory]::CreateDirectory($mockDirectory)
$originalSystemRoot = $null

try {
    $mockSource = @'
using System;
using System.IO;
using System.Linq;
using System.Text;

public static class MockWsl
{
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--list" && args[1] == "--quiet")
        {
            Console.WriteLine("Crush-Test");
            return 0;
        }

        string logPath = Environment.GetEnvironmentVariable("CRUSH_TEST_WSL_LOG");
        if (String.IsNullOrEmpty(logPath))
        {
            Console.Error.WriteLine("CRUSH_TEST_WSL_LOG is not set");
            return 2;
        }
        string encoded = String.Join(
            "|",
            args.Select(value => Convert.ToBase64String(Encoding.UTF8.GetBytes(value)))
        );
        File.AppendAllText(logPath, encoded + Environment.NewLine);
        return 0;
    }
}
'@
    $mockWsl = Join-Path $mockDirectory 'wsl.exe'
    Add-Type -TypeDefinition $mockSource -Language CSharp `
        -OutputAssembly $mockWsl -OutputType ConsoleApplication

    $originalSystemRoot = $env:SystemRoot
    $env:SystemRoot = $testRoot
    $env:CRUSH_TEST_WSL_LOG = $logPath

    $help = & $installer -Help | Out-String
    Assert-True ($help -match 'Install Crisp Remote Uninterrupted Shell') 'help text is incomplete'

    & $installer -Version 9.8.7 -Distribution Crush-Test `
        -InstallDir $installDirectory -NoModifyPath
    $cmdLauncher = Join-Path $installDirectory 'crush.cmd'
    $powershellLauncher = Join-Path $installDirectory 'crush-launcher.ps1'
    Assert-True (Test-Path -LiteralPath $cmdLauncher -PathType Leaf) 'crush.cmd was not created'
    Assert-True (Test-Path -LiteralPath $powershellLauncher -PathType Leaf) `
        'PowerShell launcher was not created'

    $cmdContents = Get-Content -LiteralPath $cmdLauncher -Raw
    Assert-True ($cmdContents -match 'crush-launcher\.ps1') 'cmd launcher does not call PowerShell'
    $powershellContents = Get-Content -LiteralPath $powershellLauncher -Raw
    Assert-True ($powershellContents -match "'Crush-Test'") 'launcher did not pin the WSL distribution'
    Assert-True ($powershellContents -match '\$HOME/\.local/bin/crush') `
        'launcher does not use the installed WSL binary'

    $firstInvocation = @(Read-MockInvocation $logPath 0)
    Assert-True ($firstInvocation -contains '--distribution') 'WSL distribution option is missing'
    Assert-True ($firstInvocation -contains 'Crush-Test') 'selected WSL distribution is missing'
    Assert-True (
        $firstInvocation -contains `
            'https://github.com/copperlaneai/crush/releases/download/v9.8.7/crush-installer.sh'
    ) 'pinned installer URL is missing'
    Assert-True ($firstInvocation -contains '--version') 'POSIX version option is missing'
    Assert-True ($firstInvocation -contains '9.8.7') 'POSIX version value is missing'
    Assert-True ($firstInvocation -contains '--no-modify-path') `
        '-NoModifyPath was not forwarded to the POSIX installer'

    $collisionFailed = $false
    try {
        & $installer -Version 9.8.7 -Distribution Crush-Test `
            -InstallDir $installDirectory -NoModifyPath
    }
    catch {
        $collisionFailed = $true
    }
    Assert-True $collisionFailed 'installer replaced an existing launcher without -Force'
    Assert-True (@(Get-Content -LiteralPath $logPath).Count -eq 1) `
        'collision handling modified WSL before refusing the install'

    & $installer -Version 9.8.7 -Distribution Crush-Test `
        -InstallDir $installDirectory -NoModifyPath -Force
    $forcedInvocation = @(Read-MockInvocation $logPath 1)
    Assert-True ($forcedInvocation -contains '--force') '-Force was not forwarded to POSIX installer'

    Write-Host 'windows installer tests passed'
}
finally {
    if ($null -ne $originalSystemRoot) {
        $env:SystemRoot = $originalSystemRoot
    }
    else {
        Remove-Item Env:SystemRoot -ErrorAction SilentlyContinue
    }
    Remove-Item Env:CRUSH_TEST_WSL_LOG -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
