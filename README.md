# Hortense

```text
╻ ╻┏━┓┏━┓╺┳╸┏━╸┏┓╻┏━┓┏━╸
┣━┫┃ ┃┣┳┛ ┃ ┣╸ ┃┗┫┗━┓┣╸ 
╹ ╹┗━┛╹┗╸ ╹ ┗━╸╹ ╹┗━┛┗━╸
```

Windows interview-integrity research tool. Detects screen-capture exclusion, suspicious overlays, known process signatures, microphone capture during interview apps, outbound AI API connections, and PC-to-phone stealth relay listeners.

Hortense looks for the Win32 traces behind interview-assist overlays: `WDA_EXCLUDEFROMCAPTURE`, screen-share invisible windows, click-through overlays, microphone capture, helper-owned WebView2 audio, local TCP relay listeners (Interview Man / Weather Tracker class), and process trees tied to tools like Cluely, Parakeet, and LinkJobAI. Interview Man is the standard ghost-relay product; Weather Tracker is its generic white-label build. The point is simple: compare what the call can see with what Windows knows is actually on the machine.

**Platform:** Windows only (CLI). Build from source; no prebuilt trust required.

## Detection coverage

| Signal | Status | What it means |
|--------|--------|---------------|
| Display affinity (`WDA_EXCLUDEFROMCAPTURE`, `WDA_MONITOR`) | Live | Windows hidden from screen capture but visible on the monitor |
| Overlay heuristics | Live | Layered, topmost, click-through windows covering real screen |
| Process signatures | Live | Name, path, install-tree roots, child processes |
| Microphone correlation | Live | Mic capture during an interview call, including WebView2 audio when ancestry points back to a suspicious host |
| Network correlation | Live | Connections to the AI endpoints in `configs/signatures.yml` |
| Stealth relay (PC-to-phone link) | Live | TCP listeners and intranet peers during interview sessions, with Authenticode/path trust tiers and lifecycle in `watch` |
| Allowlist suppression | Live | Zoom, Teams, Chrome and system processes excluded by design |
| Capture-path discrepancy | Planned | DXGI duplication against a deeper per-window read |
| Browser/test attestation | Planned | Local companion verifies meeting app, test browser, and capture path agree |
| Relay / API piggybacking | Partial | Direct model endpoints are live; relay piggybacking on trusted hosts is planned for v0.4 |
| UDP / QUIC network paths | Planned | UDP owner tables, DNS/ETW history, and rolling timing buffers for short-lived sockets |
| GPU scanout / vendor APIs | Boundary only | No vendor/kernel framebuffer access; future discrepancy checks can catch visible effects |
| Kernel-level evasion | Boundary only | No kernel agent; user-mode checks can still flag capture/window mismatches |
| Second device (phone, laptop, earpiece) | Out of scope | Outside the endpoint boundary; no local scanner has a sensor there |

## Detection results

Three commercial interview tools, tested on a real machine.

| Signal | Parakeet | Cluely | LinkJobAI |
|--------|----------|--------|-----------|
| Display affinity | Caught | Caught (undetectable mode on) | Caught |
| Overlay heuristics | Caught | Not flagged | Caught |
| Process / path / tree | Caught | Caught | Caught |
| Microphone | Caught | Caught | Caught through WebView2 ancestry |
| Network | Not observed | Not observed | Not observed |

### Parakeet

**Verdict:** Caught as `pmodule.exe`: display affinity, overlay behavior, process signature, and microphone capture.

![Parakeet detected by Hortense](docs/img/parakeet-scan.png)

### Cluely

**Verdict:** Caught in undetectable mode: display affinity, process signature, and microphone capture. With undetectable mode off, the window behaved more like a normal app, but process and microphone evidence still held.

![Cluely detected by Hortense](docs/img/cluely-scan.png)

### LinkJobAI

**Verdict:** Caught as `Lynccontainer.exe`: display affinity, overlay behavior, process signature, and WebView2-owned microphone capture attributed back to the host tree.

![LinkJobAI detected by Hortense](docs/img/linkjobai-scan.jpg)

The network row stayed quiet across these runs. That is not an HTTPS excuse; it is the relay problem. See [The network shell game](THREAT_MODEL.md#the-network-shell-game).

Screenshots show raw local `hortense scan` evidence from the three runs. Cluely, Parakeet, and LinkJobAI are third-party products; Hortense is independent research and is not affiliated with them.

## Build requirements

- Windows 10 2004+ (for `WDA_EXCLUDEFROMCAPTURE` detection)
- Python 3.10+
- Rust toolchain via [`rustup`](https://rustup.rs/)
- Visual Studio Build Tools 2022 with the "Desktop development with C++" workload for the default MSVC Rust target
- `maturin` for building the Rust extension
- For GNU target: `$env:CARGO_HTTP_CHECK_REVOKE = "false"` if crates.io SSL revocation fails on your network

## Build from source

```powershell
cd Hortense
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install maturin
rustup default stable-msvc
maturin develop --release
hortense scan
```

For development tests:

```powershell
pip install -e ".[dev]"
python -m pytest tests
```

## CLI commands

| Command | Purpose |
|---------|---------|
| `hortense scan` | One-shot human-readable report |
| `hortense scan --json` | JSON findings array |
| `hortense scan --no-color` | Plain terminal output (no ANSI severity colors) |
| `hortense check --json` | Exit code 1 on high-severity hits |
| `hortense watch` | Background poll; append JSONL to `.hortense/events.jsonl` and print new hits live |
| `hortense watch --quiet` | JSONL only; suppress live terminal output |
| `hortense watch --interval 1 --jsonl path\to\events.jsonl` | Custom poll interval and log path |

## Configuration

Edit [`configs/signatures.yml`](configs/signatures.yml) for process names, path hints, install-tree roots, allowlists, and network domains. All commands accept `--signatures path\to\signatures.yml`.

## Threat model

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for what Hortense catches, misses, and what comes next.

## FAQ

### Does Hortense detect Cluely undetectable mode?

In these runs, yes. Cluely undetectable mode set display affinity, and Hortense caught it with `GetWindowDisplayAffinity`. With undetectable mode off, the affinity signal quieted down, but process and microphone signals still fired.

### Does Hortense detect Parakeet-style hidden overlays?

In the tested run, yes. Hortense caught Parakeet through display affinity, overlay behavior, process signature, and microphone capture. The process appeared as `pmodule.exe` in the scan output.

### What is `WDA_EXCLUDEFROMCAPTURE`?

It is a Windows display-affinity flag that can make a visible window disappear from common screen-capture paths. That is useful for legitimate protected content, and useful for interview-assist overlays trying to vanish from a screen share.

### Is this proctoring software?

No. Hortense is a local research scanner. It reports what this Windows machine exposes: windows, process paths, microphone ownership, and network metadata. It does not ship a remote proctoring service.

## Note on the name

Sernine is the name Arsène wore the day he met Hortense. The same name I wear here. The version of me that shows up when something is finally worth protecting.

In the stories, Hortense is the one person Lupin loved without an angle. No mark, no heist, nothing to lift. That is the part I kept. Hortense is built to stand with the people on the wrong end of a lie, not the ones telling it.

## License

[Apache-2.0](LICENSE)
