# Threat model

I will say the quiet part first. The data-structure ritual stopped making sense the day the job itself started running on AI. Asking someone to invert a tree from memory, then handing them the same AI on day one, is theater. The questions are stupid and unfair but they are not the real problem.

The cheating is. It corrodes trust, it demoralizes the people who play it straight, and it hands companies a reason to drag everyone back into a room for an offsite interview just to feel certain again. One quiet overlay, and remote hiring takes the fall.

What is strange is the silence around it. The internet is generous with guides on how to vanish from a screen share and nearly mute on how the trick works or how to catch it. Hortense is the first stroke of a larger painting. The overlay game can be understood, and it can be stopped.

Build it yourself. Never run a stranger's binary.

## What Hortense catches

Hortense runs five scans and reads them together. Display affinity on visible windows, `WDA_EXCLUDEFROMCAPTURE` and `WDA_MONITOR`. Overlay heuristics for layered, topmost, click-through windows that cover real screen. A process walk across name and path signatures, install-tree roots, and children spawned from a flagged parent. While Zoom, Teams, or Chrome is in a call, it notes which process holds the microphone and which opens connections to the AI endpoints in `configs/signatures.yml`.

It is deliberate about silence. Known interview apps and trusted install paths sit on an allowlist, so a video call using your microphone is never mistaken for evidence. System processes too. That restraint took real work, and it matters. A tool that cries wolf is a tool no one runs twice.

That same restraint is a known soft spot. A cheat that lives entirely inside an allowlisted browser tab hides in good company, which is why affinity, overlay, and network have to carry the weight when the process list looks innocent.

No single signal decides anything. They corroborate. That is the design.

## What the lab showed

I expected compositor tricks and GPU sleight of hand. What I found was plainer: display affinity and unsubtle overlays. Hortense caught them in the field runs, along with the AppData install paths and the audio pipelines they leave behind.

I ran Hortense against two popular tools because real products leave real evidence. Parakeet showed up as `pmodule.exe`: affinity, overlay, process, microphone. Cluely with undetectable mode on tripped display affinity; with it off, the window behaved more like a normal app, but the process and microphone trail still held.

Renaming the binary defeats exactly one check. The install folder stays. The affinity flag still reads. The microphone capture continues. The outbound connection still resolves. Hortense catches the rest on path, tree, audio, and network. The marketing promises invisibility. Task Manager disagrees.

Past that is not a better overlay. It is bespoke endpoint tradecraft: no affinity flag, no known path, no microphone ownership, no local model traffic, nothing on disk with a name worth remembering. At that point the problem has left interview cheating and entered the neighborhood antivirus vendors spend their lives in. Hortense is not weakened by drawing that line.

## Where Hortense goes quiet

Hortense only knows the interview machine. A phone in your lap, a second laptop beside you, an earpiece, a friend feeding lines over a call: none of that lives in the Windows API. If the cheat never touches this operating system, there is nothing for Hortense to ask.

A second monitor is a different matter. An overlay on the display you are not sharing is still a window on this machine, and Hortense can still see it. The boundary is another device, not another monitor.

A virtual machine or a remote desktop is its own world. If the meeting, browser, and cheat all live inside that guest or remote box, this installation cannot see in. If the candidate shares the guest but runs the cheat on the host, the problem changes shape: the interviewer is no longer seeing the real meeting surface, and the missing local meeting/browser becomes its own tell. Hortense sees the machine it runs on. Not the universe.

## Move and counter-move

GPU and compositor evasion get most of the noise, so read the problem as a straight exchange. Each row is a move in the capture game and the honest answer Hortense has, or will have, for it.

| What a cheat does | How Hortense answers | Status |
|-------------------|----------------------|--------|
| Sets `WDA_EXCLUDEFROMCAPTURE` so the window drops out of capture | Queries `GetWindowDisplayAffinity` on every visible window | Live |
| Runs a layered, topmost, transparent overlay without the flag | Scores overlay style and screen coverage | Live |
| Hides in a known tool, renamed or relocated | Matches name, path, install tree, and child processes | Live |
| Lives entirely inside an allowlisted browser tab | Browser/test attestation, capture-path checks, and correlation outside process name alone | Planned |
| Pipes audio out during the call | Correlates microphone ownership with an active interview | Live |
| Calls a model over the network | Watches connections to known AI endpoints | Live |
| Moves network traffic to QUIC, UDP, or short-lived relay sockets | UDP owner tables, DNS/ETW history, and rolling timing buffers | Planned |
| Uses a DirectComposition or D3D layer that slips past simple heuristics | Compares standard duplication against a deeper per-window read | Planned (v0.2) |
| Spoofs the affinity flag so the query itself lies | The same discrepancy check: what capture sees against what the window shows | Planned (v0.2) |
| Reads the GPU scanout beneath DWM through a vendor or kernel path | No vendor hook or kernel driver; compare visible surface, capture path, and window truth at the boundary | Boundary only |
| Drops below user mode to tamper with what Win32 reports | No kernel arms race; catch the mismatch where the shared capture and local window state disagree | Boundary only |
| Moves the cheat to a phone or a second machine | Outside the endpoint boundary; no local scanner has a sensor on another device | Out of scope |

The cheap moves at the top are where the commercial tools actually live. The expensive ones at the bottom are real, but they cost the kind of effort most paying users never spend. Hortense raises that cost. On its own, it does not close the problem.

## The network shell game

The cleanest network trick is to look boring.

Today Hortense reads the Windows IPv4 TCP owner table while an interview app is active: process, remote IP, remote port, active socket. It resolves the AI domains in `configs/signatures.yml` and looks for a process on this machine talking to one of them. A tool that calls `api.openai.com` in the open is not subtle. It leaves its address on the desk.

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

Some signals belong only there, behind consent and a clear session boundary: clipboard movement, input focus, screen OCR, the kind of context a standalone CLI should not casually collect. The line matters. Hortense starts as a scanner, not a landlord.

The overlay game works because the interview stack is split in half: the browser sees one room, the operating system knows another. Put a small honest witness at that boundary, and the trick stops being cheap.

## Trust

`maturin develop --release`. Read the Rust. Run `hortense scan`. No opaque binaries, and nothing here asks for faith.
