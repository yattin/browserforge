$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Candidates = @()
if ($env:BROWSERFORGE_BIN) { $Candidates += $env:BROWSERFORGE_BIN }
$Candidates += (Join-Path $ScriptDir "..\..\..\bin\browserforge.exe")
$Candidates += (Join-Path $ScriptDir "..\..\..\..\bin\browserforge.exe")
if ($env:LOCALAPPDATA) {
    $Candidates += (Join-Path $env:LOCALAPPDATA "BrowserForge\bin\browserforge.exe")
}

$Exe = $Candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $Exe) {
    $Cmd = Get-Command browserforge -ErrorAction SilentlyContinue
    if ($Cmd) { $Exe = $Cmd.Source }
}
if (-not $Exe) {
    throw "browserforge.exe not found. Build with build.ps1, install to %LOCALAPPDATA%\BrowserForge\bin, or set BROWSERFORGE_BIN."
}

& $Exe @args
exit $LASTEXITCODE
