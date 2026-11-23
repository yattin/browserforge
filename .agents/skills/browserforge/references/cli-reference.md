# BrowserForge CLI Reference

## Global Flags & Argument Order

- `--data-dir <dir>` — Override state directory (default `%LOCALAPPDATA%\BrowserForge` or `BROWSERFORGE_DATA_DIR`).
- `--json` — Emit machine-readable JSON output.
- Subcommand flags may be placed before or after positional arguments (e.g. `start vn-temu --url https://example.com` or `profile update vn-temu --timezone Asia/Tokyo`).

## Commands

| Command | Description |
| --- | --- |
| `version` | Print binary version |
| `doctor` | Inspect host OS/CPU/RAM/GPU, foreground daemon status, store counts, and discovered kernels |
| `kernel list` | List all discovered kernels (`*` marks active default) |
| `kernel set <path>` | Persist default browser kernel executable |
| `profile list` | List profiles and running status |
| `profile create --name <n> [--template <t>] [--timezone <tz>] [--lang <csv>] [--proxy <p>] [--sync-proxy]` | Create isolated profile + locked `beryl-v1` `fingerprint.json` (`--sync-proxy` auto-aligns timezone & locale with proxy exit IP; rejects duplicate names) |
| `profile show <id\|name>` | Show profile metadata, fingerprint details, and runtime state |
| `profile update [--timezone <tz>] [--lang <csv>] [--proxy <p\|none>] <id\|name>` | Update editable fields and recompute `beryl-v1` checksum |
| `profile validate <id\|name>` | Run 9-rule anti-detect consistency check |
| `profile reset-fp <id\|name>` | Regenerate fingerprint with a fresh 256-bit seed |
| `profile clone --name <new> [--proxy <p>] <src>` | Clone profile settings with a fresh UUID and 256-bit seed |
| `profile delete <id\|name>` | Stop instance and delete isolated profile directory |
| `proxy list` | List proxies (passwords never printed) |
| `proxy add --url <scheme://host:port> [--name <n>] [--user <u>] [--pass-env <ENV>]` | Store encrypted upstream proxy (`http`/`https`/`socks5`; rejects duplicate names) |
| `proxy import [--prefix <p>] [--check] <file>` | Bulk-import `scheme://user:pass@host:port` list with auto-incrementing unique names & optional concurrent probe |
| `proxy check <id\|name> [--probe-url <url>]` | Probe tunnel latency, exit IP, country, and timezone |
| `proxy remove [--force] <id\|name>` | Delete saved proxy (blocks if bound to profiles unless `--force` is passed to unbind) |
| `start <id\|name> [--headless] [--url <url>] [--kernel <exe>] [--direct]` | Start proxy forwarder and isolated browser (auto-delegates to foreground tray daemon when online; `--url` allows only `http`/`https`/`about:blank`) |
| `stop <id\|name \| --all>` | Terminate browser and proxy forwarder processes |
| `ps` | List active browser and proxy processes |
| `daemon start \| status \| stop` | Run or manage the foreground GUI launcher daemon (`browserforge-daemon.exe` runs silently with Windows system tray icon + local status panel) |
| `cdp tabs <profile>` | List open page tabs |
| `cdp open <profile> <url>` | Open a new tab and wait for load completion |
| `cdp navigate <profile> [--tab <id>] <url>` | Navigate existing tab and wait for load completion |
| `cdp close-tab <profile> [--tab <id>]` | Close a tab |
| `cdp wait <profile> [--selector <css>] [--text <str>] [--url <sub...>] [--timeout 15s]` | Wait for DOM selector, text, or URL condition |
| `cdp snapshot <profile> [--tab <id>]` | Extract page text and interactive DOM elements |
| `cdp click <profile> [--tab <id>] (--selector <css> \| --text <label>)` | Hardware-level trusted click (`Input.dispatchMouseEvent`, cubic Bezier approach, continuous cursor from `runtime.json`, randomized landing & dwell) |
| `cdp type <profile> [--tab <id>] --selector <css> --text <val> [--submit]` | Hardware-level trusted typing (Bezier click focus, Ctrl+A/Backspace clear, randomized per-key `Input.dispatchKeyEvent`/`insertText`, hardware Enter on `--submit`) |
| `cdp scroll <profile> [--y <px> \| --to-bottom \| --selector <css>]` | Scroll viewport or element into view |
| `cdp hover <profile> --selector <css>` | Hardware-level humanized Bezier mouse hover over element |
| `cdp press <profile> --key <Enter\|Escape\|Tab\|...>` | Dispatch hardware keyDown/keyUp event |
| `cdp eval <profile> [--tab <id>] <js>` | Evaluate JS expression (`awaitPromise` enabled) |
| `cdp html <profile> [--selector <css>] [--out <file>]` | Dump page or element outerHTML |
| `cdp screenshot <profile> [--tab <id>] --out <file.png>` | Capture PNG screenshot |
| `cdp pdf <profile> [--tab <id>] --out <file.pdf>` | Print current page to PDF |
| `cdp cookies <profile> [--tab <id>] [--include-values]` | List cookies (values redacted by default) |
| `cdp export-cookies <profile> [--tab <id>] --out <file.json>` | Export cookies to 0600 JSON file |
| `cdp set-cookies <profile> [--tab <id>] --file <file.json>` | Import cookies from JSON file |
| `cdp console <profile> [--duration 5s]` | Capture `console.*` logs and uncaught exceptions via `Runtime.enable` |
| `cdp network <profile> [--duration 5s] [--filter <substr>]` | Capture HTTP requests, status codes & failures via `Network.enable` |
| `selftest [--with-browser]` | Run built-in security & integration regression suite |
