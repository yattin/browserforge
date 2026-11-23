---
name: browserforge
description: Operate the standalone BrowserForge Go CLI and foreground tray daemon for isolated anti-detect browser profiles, beryl-v1 fingerprint generation and validation, encrypted proxy management, and live CDP webpage automation (open, navigate, wait, snapshot, trusted Bezier click, type, scroll, hover, press, eval, html, screenshot, pdf, cookies export/import, console, network).
---

# BrowserForge CLI Skill

Use this skill to manage isolated anti-detect browser profiles and drive live pages via `browserforge.exe` + the optional foreground system-tray daemon `browserforge-daemon.exe` (pure Go, zero external dependencies).

## Locating the Binary

Use the helper wrapper `scripts/browserforge-cli.ps1` which resolves `BROWSERFORGE_BIN`, `bin\browserforge.exe`, `%LOCALAPPDATA%\BrowserForge\bin\browserforge.exe`, or `PATH` automatically:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/browserforge-cli.ps1 doctor --json
```

## Standard Workflow

1. **Inspect Environment, Kernels & Foreground Daemon**:
   - Run `doctor --json` to verify host hardware, discovered kernels (Beryl / Chrome / Edge), and whether the foreground tray daemon is online (`daemon.running`).
   - If a specific Beryl kernel is needed, run `kernel set <path-to-chrome.exe>`.
   - **Visible Foreground Windows (Human-in-the-Loop)**: When `browserforge-daemon.exe` is running in the user's interactive Windows desktop (visible as the green **B** icon in the system tray), `browserforge start <name> --url <url>` automatically delegates (`via_daemon: true`) so headed browsers pop directly onto the user's physical desktop and survive shell exits. Double-clicking the tray icon opens the local status panel. If the daemon is stopped, tell the user to run `%LOCALAPPDATA%\BrowserForge\bin\browserforge-daemon.exe` (or use `--headless` / `--direct` for headless automation).
2. **Manage Proxies (Optional)**:
   - Single proxy: `proxy add --name <n> --url <scheme://host:port> --user <u> --pass-env <VAR>`
   - Bulk import + concurrent check: `proxy import --prefix s5 --check proxies.txt --json`
   - Single probe: `proxy check <name> --json`
   - Safe removal: `proxy remove <name>` blocks if referenced by a profile (pass `--force` to unbind and delete).
3. **Create, Clone & Validate Profile**:
   - Auto-align timezone & locale with proxy: `profile create --name <name> --proxy <proxy> --sync-proxy --json`
   - Clone with fresh fingerprint seed: `profile clone --name <new> <src> --json`
   - Validate 9 anti-detect rules: `profile validate <name> --json`
4. **Launch & Automate via CDP**:
   - `start <name> [--url https://...] [--headless] [--direct] --json` (`--url` accepts only `http://`, `https://`, or `about:blank`).
   - Navigation & tabs: `cdp open`, `cdp navigate`, `cdp tabs`, `cdp close-tab`.
   - Waiting & reading: `cdp wait --selector/--text/--url`, `cdp snapshot`, `cdp html`, `cdp eval`.
   - **Humanized Interaction**: `cdp click` and `cdp hover` dispatch hardware-level trusted `Input.dispatchMouseEvent` (`event.isTrusted === true`) along a cubic Bezier trajectory with randomized inner-box landing, randomized dwell time, and continuous cross-command cursor coordinates persisted in `runtime.json`. Prefer `cdp click` directly (no redundant `cdp hover` beforehand) and prefer clicking links on-page over raw `cdp navigate` on anti-bot sites. Also available: `cdp type`, `cdp press --key Enter`, `cdp scroll`.
   - Media & cookies: `cdp screenshot --out`, `cdp pdf --out`, `cdp cookies` (redacted by default; `--include-values` only when explicitly requested), `cdp export-cookies`, `cdp set-cookies`.
   - Real-time observability (Beryl-safe `Runtime.enable` & `Network.enable`): `cdp console --duration 5s`, `cdp network --duration 5s --filter api`.
5. **Cleanup**:
   - `stop <name>` or `stop --all`, then verify zero remaining processes with `ps --json`.
   - Manage daemon lifecycle via `daemon status --json` or `daemon stop` (or `Exit Daemon` from the tray menu).

## Detailed Reference

For the full command & flag matrix, read [references/cli-reference.md](references/cli-reference.md).
