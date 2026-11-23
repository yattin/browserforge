param(
    [switch]$SelfTest,
    [switch]$Clean,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

# Locate Go toolchain (system PATH, GO_BIN env, or project-local .toolchain)
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    $Candidates = @()
    if ($env:GO_BIN) { $Candidates += $env:GO_BIN }
    $Candidates += (Join-Path $ProjectRoot ".toolchain\go\bin")
    $FoundGo = $Candidates | Where-Object { $_ -and (Test-Path (Join-Path $_ "go.exe")) } | Select-Object -First 1
    if ($FoundGo) {
        $env:PATH = "$FoundGo;$env:PATH"
    } else {
        throw "Go toolchain not found in PATH (or set GO_BIN)."
    }
}

$env:CGO_ENABLED = "0"
$LdFlags = "-s -w"
if ($Version) {
    $LdFlags = "$LdFlags -X browserforge/internal/common.AppVersion=$Version"
}

$GuiLdFlags = "$LdFlags -H=windowsgui"

$BinDir = Join-Path $ProjectRoot "bin"
if ($Clean -and (Test-Path $BinDir)) {
    Remove-Item -Recurse -Force $BinDir
}
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Write-Host "[1/4] Building BrowserForge CLI (bin\browserforge.exe)..." -ForegroundColor Cyan
go build -trimpath -ldflags $LdFlags -o (Join-Path $BinDir "browserforge.exe") ./cmd/browserforge
if ($LASTEXITCODE -ne 0) { throw "Failed building browserforge.exe" }

Write-Host "[2/4] Building BrowserForge Silent Foreground Daemon (bin\browserforge-daemon.exe)..." -ForegroundColor Cyan
go build -trimpath -ldflags $GuiLdFlags -o (Join-Path $BinDir "browserforge-daemon.exe") ./cmd/browserforge-daemon
if ($LASTEXITCODE -ne 0) { throw "Failed building browserforge-daemon.exe" }

Write-Host "[3/4] Syncing companion AI Agent Skill (.agents\skills\browserforge)..." -ForegroundColor Cyan
$SkillSrcDir   = Join-Path $ProjectRoot "skills\browserforge"
$AgentSkillDir = Join-Path $ProjectRoot ".agents\skills\browserforge"
if (Test-Path (Join-Path $SkillSrcDir "SKILL.md")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $AgentSkillDir "scripts") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $AgentSkillDir "references") | Out-Null
    Copy-Item -Force (Join-Path $SkillSrcDir "SKILL.md") (Join-Path $AgentSkillDir "SKILL.md")
    if (Test-Path (Join-Path $SkillSrcDir "scripts\browserforge-cli.ps1")) {
        Copy-Item -Force (Join-Path $SkillSrcDir "scripts\browserforge-cli.ps1") (Join-Path $AgentSkillDir "scripts\browserforge-cli.ps1")
    }
    if (Test-Path (Join-Path $SkillSrcDir "references\cli-reference.md")) {
        Copy-Item -Force (Join-Path $SkillSrcDir "references\cli-reference.md") (Join-Path $AgentSkillDir "references\cli-reference.md")
    }
}

Write-Host "`nCompiled Artifacts:" -ForegroundColor Green
Get-ChildItem $BinDir -Filter *.exe | Select-Object Name, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}} | Format-Table -AutoSize

if ($SelfTest) {
    Write-Host "[3/3] Running BrowserForge End-to-End & Security Self-Test Suite..." -ForegroundColor Yellow
    & (Join-Path $BinDir "browserforge.exe") selftest
    if ($LASTEXITCODE -ne 0) {
        throw "Self-test suite failed with exit code $LASTEXITCODE"
    }
}
