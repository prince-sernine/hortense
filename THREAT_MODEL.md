# Threat model

I will say the quiet part first. The data-structure ritual stopped making sense the day the job itself started running on AI. Asking someone to invert a tree from memory, then handing them the same AI on day one, is theater. The questions are stupid and unfair but they are not the real problem.

The cheating is. It corrodes trust, it demoralizes the people who play it straight, and it hands companies a reason to drag everyone back into a room for an offsite interview just to feel certain again. One quiet overlay, and remote hiring takes the fall.

What is strange is the silence around it. The internet is generous with guides on how to vanish from a screen share and nearly mute on how the trick works or how to catch it. Hortense is the first stroke of a larger painting. The overlay game can be understood, and it can be stopped.

Build it yourself. Never run a stranger's binary.

## What Hortense catches

Hortense runs six scans and reads them together. Display affinity on visible windows: `WDA_EXCLUDEFROMCAPTURE` and `WDA_MONITOR`. Overlay heuristics for layered, topmost, click-through windows that cover the real screen. A process walk across name and path signatures, install-tree roots, and children spawned from a flagged parent. It records microphone ownership when a non-allowlisted process holds capture, then asks what else belongs to that product before raising its voice. It reads connections to the AI endpoints in `configs/signatures.yml`, the IPv4 TCP owner table for suspicious local listeners and LAN peers, and the PC-to-phone relay shape used by InterviewMan and its generic Weather Tracker build. Corroboration decides how loudly each one speaks.

It is deliberate about silence. Known interview apps and trusted install paths sit on an allowlist, so a video call using your microphone is never mistaken for evidence. System processes too. That restraint took real work, and it matters. A tool that cries wolf is a tool no one runs twice.

That same restraint is a known soft spot. A cheat that lives entirely inside an allowlisted browser tab hides in good company. A browser process alone does not prove a call is happening, so browser-call confidence is planned work instead of a cheap process-name guess.

No single signal decides anything. They corroborate. That is the design.

## How Hortense deduces

The commercial cheats above do not need miracle tech. They lean on ordinary Windows behavior: hide a window from capture, float an overlay, grab the mic through a helper, call a model, or relay answers to a phone.

Hortense does not start with a verdict. It starts with facts Windows can name: affinity, overlay, process, microphone, network, relay.

Then it asks who owns them. Each finding gets a `product_key`, usually the install root or process tree behind it. That matters because real tools split themselves across helpers. A relay listener, a WebView2 audio process, and a renamed UI can still belong to one product.

Then it asks what else belongs to the same product. Relay plus overlay plus microphone is a stack, not three unrelated noises. Trust comes after that. Cheat signatures in `configs/signatures.yml` win first. Signed consumer software can quiet relay noise only when Authenticode, path, and the hybrid catalog agree. A costume is not trust. A known name still has to prove its signer.

`scan` returns the fused snapshot. `watch` turns it into a session board: what appeared, what partly cleared, and when a whole product cluster went `[CLEARED]`. The TUI keeps recent activity in view. JSONL and `--no-dashboard` keep the full trail.

PRE-CALL is not empty air. Process, overlay, display-affinity, known-app anomaly, microphone, relay, and impersonation can all matter before a meeting app opens.

Microphone is evidence, not a verdict. Alone, a recorder, OBS, a game, or another ordinary capture holder stays quiet in the pre-call watch path. Paired with a cheat signature, hidden-window evidence, overlay behavior, a relay, or a modified known app, it raises product confidence because the stack is now speaking.

Relay follows the same discipline. On a modified app or a cheat-shaped stack, it stays visible and clears only when the port or app actually stops. Closing a meeting never fake-clears a listener that is still open. A bare, unattributed listener stays call-context and pauses quietly when the call ends.

A modified build wearing a trusted app name is worth naming, but it is not called cheating unless the rest of the stack starts talking. A process name that renders blank in the terminal is still a process on disk. Hortense keeps the raw path and shows a readable alias when the name is Unicode misdirection, not an honest rename.

Evidence follows the product, not the PID. Helpers, detached spawns, and second roots under the same install path land in one cluster. A pathless orphan gets its own `pid:` slot. While a cluster is live, the board shows a main pid, a live process count, and a capped pid line. When the cluster clears, `[CLEARED]` and JSONL carry the full session PID set, including respawns.

Corroboration beats costume. A stolen cert might quiet relay; it does not quiet affinity, overlay, microphone, and community signatures together. A phone in your lap, kernel tampering, and cheats that never touch this OS stay outside the boundary, and Hortense says so plainly.

## What the lab showed

I expected compositor tricks and GPU sleight of hand. What I found was plainer: display affinity and unsubtle overlays. Hortense caught them in the field runs, along with the AppData install paths and the audio pipelines they leave behind.

I ran Hortense against popular tools because real products leave real evidence.

Parakeet showed up as `pmodule.exe`: affinity, overlay, process, microphone. Cluely with undetectable mode on tripped display affinity; with it off, the window behaved more like a normal app, but the process and microphone trail still held. LinkJobAI showed up as `Lynccontainer.exe`: affinity, overlay, process, and WebView2 audio ancestry.

InterviewMan and its Weather Tracker generic build added the relay shape. In standard mode the stack was plain: affinity, overlay, process/tree, relay listener, microphone. In their stealth phone-relay mode, the dashboard still had to open first. Hortense caught affinity and overlay at startup; when the app hid itself, those window-facing signals cleared, but the process and local listener remained.

The pattern matters. Not one magic signal. A chain Windows could still name.

Renaming the binary defeats exactly one check. The install folder stays. The affinity flag still reads. The microphone capture continues. The outbound connection still resolves. Hortense catches the rest on path, tree, audio, and network. The marketing promises invisibility. Task Manager disagrees.

Past that is not a better overlay. It is bespoke endpoint tradecraft: no affinity flag, no known path, no microphone ownership, no local model traffic, nothing on disk with a name worth remembering. At that point the problem has left interview cheating and entered the neighborhood antivirus vendors spend their lives in. Hortense is not weakened by drawing that line.

## Where Hortense goes quiet

Hortense only knows the interview machine. A phone in your lap, a second laptop beside you, an earpiece, a friend feeding lines over a call: none of that lives in the Windows API. If the cheat never touches this operating system, there is nothing for Hortense to ask.

A second monitor looks like a loophole: share the clean display, keep the assist on the other one. That is still the same host. An overlay on a display you are not sharing is still a window on this machine, and Hortense can still see it. The boundary is another device, not another monitor.

A virtual machine or a remote desktop is its own world. If the meeting, browser, and cheat all live inside that guest or remote box, this installation cannot see in. If the candidate shares the guest but runs the cheat on the host, the problem changes shape: the interviewer is no longer seeing the real meeting surface, and the missing local meeting/browser becomes its own tell. Hortense sees the machine it runs on. Not the universe.

## Move and counter-move

GPU and compositor evasion get most of the noise, so read the problem as a straight exchange. Each row is a move in the capture game and the honest answer Hortense has, or will have, for it.

| What a cheat does | How Hortense answers | Status |
|-------------------|----------------------|--------|
| Sets `WDA_EXCLUDEFROMCAPTURE` so the window drops out of capture | Queries `GetWindowDisplayAffinity` on every visible window | Live |
| Runs a layered, topmost, transparent overlay without the flag | Scores overlay style and screen coverage | Live |
| Hides in a known tool, renamed or relocated | Matches name, path, install tree, and child processes | Live |
| Obfuscates the executable name with invisible or misleading Unicode so logs and Task Manager look blank | Install-path and process-tree matching still land; Hortense keeps the raw path and renders a readable label instead of an empty `.exe` | Live |
| Lives entirely inside an allowlisted browser tab | Browser/test attestation, capture-path checks, browser call confidence, and correlation outside process name alone | Planned |
| Pipes audio out through the interview machine | Collects microphone ownership when present, attributes helper audio through ancestry, and lets product-stack confidence decide the severity | Live |
| Moves audio capture into WebView2 or another helper process | Attributes the audio owner through parent process and install-tree ancestry before judging the host | Live |
| Calls a model over the network | Watches connections to known AI endpoints | Live |
| Runs a local TCP relay for a phone or second device during the call | Scans IPv4 listeners and RFC1918/CGNAT peers; Authenticode publisher, path trust tiers, and correlation with overlay/process/anomaly evidence decide whether a listener stays visible off-call or reads as call-context | Live |
| Moves network traffic to QUIC, UDP, or short-lived relay sockets | UDP owner tables, DNS/ETW history, and rolling timing buffers | Planned |
| Hides the payload in an NTFS alternate data stream or leans on 8.3 short paths to look blank in casual tooling | Path and tree matching cover most host-binary cases today; dedicated stream and short-name sensors are planned | Planned |
| Uses a DirectComposition or D3D layer that slips past simple heuristics | Compares standard duplication against a deeper per-window read | Planned |
| Spoofs the affinity flag so the query itself lies | The same discrepancy check: what capture sees against what the window shows | Planned |
| Reads the GPU scanout beneath DWM through a vendor or kernel path | No vendor hook or kernel driver; compare visible surface, capture path, and window truth at the boundary | Boundary only |
| Drops below user mode to tamper with what Win32 reports | No kernel arms race; catch the mismatch where the shared capture and local window state disagree | Boundary only |
| Moves the cheat to a phone or a second machine | Outside the endpoint boundary; no local scanner has a sensor on another device | Out of scope |

The cheap moves at the top are where the commercial tools actually live. The expensive ones at the bottom are real, but they cost the kind of effort most paying users never spend. Hortense raises that cost. On its own, it does not close the problem.

Helper processes are part of that bargain. WebView2 is not guilty by itself; half the desktop wears it now. The question is who it serves. If the audio service traces back to a hidden-window host or a known install tree, the costume stops being interesting and the ancestry starts talking.

## The network shell game

The cleanest network trick is to look boring.

Today Hortense reads the Windows IPv4 TCP owner table while a native meeting app is open: process, remote IP, remote port, active socket. It resolves the AI domains in `configs/signatures.yml` and looks for a process on this machine talking to one of them. A tool that calls `api.openai.com` in the open is not subtle. It leaves its address on the desk.

The PC-to-phone relay is a different costume with the same goal. InterviewMan is the standard build. Weather Tracker is the generic white-label build. Both listen on a local port and accept connections from a phone on the same Wi-Fi. The direct AI endpoint is no longer the obvious clue.

Their stealth mode is not magic. The app dashboard opens, the candidate selects stealth, and the window-facing evidence can go quiet after startup. That still leaves a Windows process and a local webserver waiting for the phone. In a real interview, the user usually needs to know the server is alive and reachable before trusting the phone flow, so the dashboard open is part of the practical shape.

Hortense watches for that shape: a non-trusted process binding a listener, especially on all interfaces, plus established peers on RFC1918 or CGNAT ranges. Cheat signatures fire first; Authenticode and the hybrid trust catalog keep Zoom, Teams, Spotify, and other signed consumer apps from being mistaken for a relay when the tiers agree. Corroboration then sets the volume: a listener on a modified app or a cheat-shaped stack stays visible on its own weight, while a lone, unattributed listener is read as call-context and only surfaces around a live meeting. If the same product also carries overlay, mic, process, or affinity evidence, the stack still speaks. In `watch` mode, each signal follows the product cluster, so the terminal shows appeared, partial cleared, and `[CLEARED]` instead of spamming the same static finding every poll.

The better lie moves the address, not the act. It sends the request through a relay, a SaaS endpoint, a CDN edge, or a vendor backend. It uses QUIC over UDP instead of TCP. It opens a socket for half a breath and closes it between polls. TLS keeps the payload sealed, as it should. The mistake is thinking the payload was the only evidence.

The destination is only the address on the envelope. It is not the whole letter, and it is not the hand that mailed it.

That is where the next work lives.

- **Process lineage.** Not just who owns the socket, but who owns the parent, the helper, and the install tree. Cheats can borrow a clean destination. Borrowing a clean ancestry is harder.
- **UDP and QUIC ownership.** TCP is not the whole network anymore. UDP owner tables and UDP/443 correlation close the first obvious escape hatch.
- **DNS and ETW history.** DNS cache, DNS ETW, and TCP/UDP event streams can remember what polling missed: a model domain resolved, a relay contacted, a socket opened for a second and vanished.
- **TLS-adjacent fingerprints.** The tunnel stays closed, but the handshake still has edges: SNI when present, ALPN, certificate chain, issuer, network owner. With packet or ETW visibility, JA3/JA4-style client fingerprints become fair game. A real client and a script wearing its route do not always shake hands the same way.
- **Burst timing.** Voice input, outbound burst, response-sized inbound burst, overlay update. One packet is noise. The sequence, lined up against microphone ownership and window activity, is not.
- **Destination reputation.** ASN, certificate owner, domain age, and process identity can disagree with the costume. A CDN is not guilty. A strange process reaching through one during a live coding question is a smaller room.

There is a hard boundary. If a vendor owns the relay, terminates TLS there, and forwards server-side, the final hop never appears on this machine. Hortense should not pretend it does. The point is to narrow the room until the lie has fewer places to stand.

## What it could become

Hortense is a CLI today. The useful thing inside it is not the command; it is the local attestation primitive.

A browser test can ask only what the browser can see. A local companion can answer the rest: meeting app present, test browser present, capture path sane, no hidden overlay sitting outside the share. That is the seam the cheat depends on.

The platform-shaped version is session attestation. Before the interview starts, the machine proves the boring things: the expected meeting surface exists, the expected browser exists, the local scan is clean, and the capture path has not started lying. No kernel. No rootkit. No theater of total control.

That platform could justify signals a standalone CLI should not casually collect: clipboard movement, input focus, screen OCR, and other session-local context. Those belong behind explicit consent, a narrow interview window, and a clear stop point. Hortense starts as a scanner, not a landlord.

The overlay game works because the interview stack is split in half: the browser sees one room, the operating system knows another. Put a small honest witness at that boundary, and the trick stops being cheap.

## Trust

`maturin develop --release`. Read the Rust. Run `hortense scan`. No opaque binaries, and nothing here asks for faith.
