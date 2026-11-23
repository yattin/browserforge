# BrowserForge

Standalone, zero-dependency Go CLI for managing isolated anti-detect browser environments, `beryl-v1` deterministic fingerprints, per-profile authenticated proxy forwarders, and native CDP automation.

## Features

- **Single Static Binary (`CGO_ENABLED=0`)**: 100% Go standard library — no Node.js, Electron, or external Go modules.
- **Native `beryl-v1` Fingerprint Engine**: Deterministic HMAC-SHA256 generation, ECMA-262 canonical JSON SHA-256 checksums, `0444` read-only file locking, and a 9-rule anti-detect consistency validator.
- **Per-Profile Isolated Proxy Forwarder**: Built-in `browserforge _forwarder` subprocess supporting `http`, `https`, and `socks5` (RFC 1929 auth + remote DNS resolution) with `stdin`-only credential passing, socket-level SSRF protection (`127.0.0.0/8`, `::1`, `169.254.0.0/16`, LAN blocks), `64 KiB` handshake cap, and automatic browser-PID lifetime watchdog.
- **Native RFC 6455 CDP Automation**: `tabs`, `open`, `snapshot`, `click`, `type` (React/Vue compatible), `eval`, `screenshot`, and `cookies` (redacted by default).
- **Encrypted Credential Storage**: Windows DPAPI (`CurrentUser` scope) on Windows; `0600` local key + AES-256-GCM on non-Windows platforms.

## Build & Self-Test

```powershell
.\build.ps1 -Clean -SelfTest
```

## Quick Start

```powershell
# Inspect host hardware and discovered browser kernels
.\bin\browserforge.exe doctor --json

# Optionally point to a Beryl Chromium kernel executable
.\bin\browserforge.exe kernel set D:\path\to\beryl\chrome.exe

# Add an upstream proxy (password read from environment variable)
$env:PROXY_PASS = "secret"
.\bin\browserforge.exe proxy add --name us-east --url http://user@proxy.example.com:8080 --pass-env PROXY_PASS

# Create & validate an isolated profile
.\bin\browserforge.exe profile create --name shop-01 --timezone America/New_York --lang en-US,en --proxy us-east
.\bin\browserforge.exe profile validate shop-01

# Launch, automate via CDP, and stop cleanly
.\bin\browserforge.exe start shop-01
.\bin\browserforge.exe cdp open shop-01 https://example.com
.\bin\browserforge.exe cdp snapshot shop-01
.\bin\browserforge.exe cdp screenshot shop-01 --out page.png
.\bin\browserforge.exe stop shop-01
```
