# AirClip — Product Specification

Version 1.0 · Status: Approved for Phase 1 build · Owner: Bernhard (NARRION LLC)

## 1. Problem statement

Millions of people carry an iPhone and work on a Windows PC. Moving a URL, verification code, address, or paragraph between the two requires emailing yourself, messaging yourself, or a third-party file-share app — every single time. Apple's Universal Clipboard solves this inside its ecosystem only; Apple's DMA-mandated iPhone↔Windows solution won't ship until fall 2027 at the earliest and may be EU-only. Existing third-party options require a self-hosted server, a cloud account, a subscription, or manual share codes. There is no zero-setup, no-account, privacy-clean product for the single most common cross-device action.

## 2. Goals

1. **Sub-second iPhone→PC text transfer** measured copy-to-paste-able: ≤ 1.0 s p50, ≤ 2.5 s p95 on the same Wi-Fi network.
2. **Time-to-first-beam under 2 minutes** from installing both apps (pairing included), with no account creation and no settings required.
3. **PC→iPhone retrieval in ≤ 3 taps** from inside any text field (switch keyboard → tap clip), with clip visible in ≤ 700 ms of keyboard appearing + tap.
4. **Zero data exfiltration**: no packet ever leaves the local network; verifiable by packet capture; no analytics SDKs; App Privacy label shows "Data Not Collected."
5. **Portfolio quality**: repo demonstrates shared Rust core + UniFFI + native shells, ≥ 80% test coverage on `airclip-core`, CI green on every commit.

## 3. Non-goals (v1)

- **No cloud relay / off-LAN sync.** Changes the trust model and the pitch. Tailscale users get off-LAN for free anyway (mDNS won't traverse, but manual IP entry will — P1).
- **No Android, no macOS, no Linux.** The wedge is iPhone+Windows; other platforms have adequate solutions. Protocol is platform-neutral so ports remain possible.
- **No clipboard *history* manager on Windows.** Win+V exists. We stage the latest N clips for iPhone pull, not a full manager UI.
- **No images/files in Phase 1.** Framing supports them (type field + chunking reserved) but implementation is Phase 3. Cutting this halves iOS complexity.
- **No multi-PC fan-out in Phase 1.** One iPhone ↔ one PC. Protocol supports multiple pairings; UI for it is Phase 3.
- **No automatic background sync on iOS.** Not a product decision — a platform impossibility. Design embraces it rather than fighting it.

## 4. Target users

- **Primary**: "Ecosystem straddlers" — iPhone owners on Windows PCs (work-issued or gaming/dev rigs). Tech-comfortable but not self-hosters.
- **Secondary**: Developers/power users who currently use LocalSend/Pushbullet for this and hate the friction.
- **Anti-persona**: Users wanting cross-network cloud sync — direct them to Pushbullet/ClipCascade.

## 5. User stories

P0:
- As an iPhone user, I want to copy text and press the Action Button so that it's on my PC clipboard before I even look up at the monitor.
- As an iPhone user, I want to pair by scanning a QR code on my PC so that setup requires no accounts, IPs, or ports.
- As a PC user, I want a toast when a clip arrives so that I know it worked without it stealing focus.
- As an iPhone user, I want to tap a clip from my PC inside any text field so that codes/URLs from my PC flow into iPhone apps.
- As a privacy-conscious user, I want proof nothing leaves my network so that I can trust it with passwords and personal data.

P1:
- As a Back Tap user, I want double-tap-back to send my clipboard so that I don't consume my Action Button.
- As a user with flaky Wi-Fi, I want a clear "PC not reachable" failure state with retry so that silent drops never happen.
- As a returning user, I want the last 5 clips visible in the iPhone app so that I can re-send or copy them locally.

## 6. Requirements

### P0 — Phase 1 ships with all of these

| ID | Requirement | Acceptance criteria |
|---|---|---|
| R1 | QR pairing with key exchange | Given tray "Pair new iPhone" shows QR; when iPhone scans; then both devices show identical 4-emoji SAS; on confirm, pairing persists across restarts on both sides. |
| R2 | mDNS discovery | Given both on same network; when iPhone app foregrounds; then paired PC is found in ≤ 1.5 s without any user input; when PC absent, UI shows unreachable state in ≤ 3 s. |
| R3 | iPhone→PC send via App Intent | Given paired + reachable; when the "Beam Clipboard" intent runs (Action Button/Back Tap/Shortcuts/Control Center); then PC clipboard contains the text and a toast appears; total latency ≤ 1 s p50. Intent runs without opening the app UI. |
| R4 | iPhone→PC send via app + share sheet | In-app "Beam" button and a Share Extension accepting text/URLs produce the same result as R3. |
| R5 | Windows clipboard staging | When user copies text on PC; then agent stages it (latest 5, text/URL only, ≤ 256 KB each) for iPhone pull; staged clips are held in memory only, never written to disk. |
| R6 | PC→iPhone pull via keyboard extension | Given AirClip keyboard active in a text field; when user taps the fetch row; then PC's staged clips appear ≤ 700 ms; tapping one inserts its text at the cursor. Keyboard requests *no* Full Access beyond what's required for LAN fetch (Open Access required — copy in UI explains why, see IOS-PLATFORM-NOTES §5). |
| R7 | E2E encryption | All post-handshake frames are ChaCha20-Poly1305 AEAD; identity keys in Keychain/DPAPI; packet capture during transfer shows no plaintext (test: send known string, grep pcap). |
| R8 | Windows tray agent UX | Tray icon with status (paired/reachable/idle), Pair, Pause, Launch-at-startup toggle, Quit. Installer ≤ 6 MB, no runtime deps, winget-ready manifest. |
| R9 | Failure states | Unreachable PC → iPhone shows actionable error (notification if intent-triggered, inline if in-app). No silent failures anywhere. |

### P1 — fast follow

- R10: Manual host:port fallback entry (enables Tailscale/other-subnet use).
- R11: Clip history (last 5) in iPhone app with re-send / local copy.
- R12: PC toast click = "copied" flash; PC hotkey (default Ctrl+Alt+V) to re-request most recent iPhone clip announcement.
- R13: Wake-on-LAN packet option when PC unreachable.

### P2 — architectural insurance (design for, don't build)

- Images (`public.png`/`public.jpeg`) and files via chunked frames — frame header already carries `content_type` and chunk fields.
- Multi-device pairing table with per-device keys — pairing store is already keyed by device ID.
- macOS agent — core is platform-free; only the shell is new.

## 7. Success metrics

Leading (first 30 days post-App Store): activation = % of installs completing pairing (target ≥ 60%); D7 retention of ≥ 3 beams/week (target ≥ 35%); intent-send p50 latency from telemetry-free local timing shown in a debug screen (no analytics — measured in TestFlight feedback + own use).
Lagging: App Store rating ≥ 4.5; GitHub stars as portfolio signal (target 500 in 90 days, driven by the Apple-2027 news hook); zero privacy-related review flags.

## 8. Open questions

- **(Blocking, product)** Keyboard "Allow Full Access" requirement: Apple requires Open Access for network calls from keyboards. Copy and first-run explainer must be nailed before Phase 2 build — draft in IOS-PLATFORM-NOTES §5. Decide: is keyboard pull Phase 1 or Phase 2? *Current call: build R6 in Phase 1 behind a feature flag; ship App Store v1 with it if review passes, without it if rejected.*
- **(Non-blocking, eng)** Control Center control (iOS 18+ `ControlWidget`) vs. relying on Action Button mapping to a Shortcut — build both, measure which demos better.
- **(Non-blocking, legal)** Trademark and App Store availability check on "AirClip" before submission — "Air"-prefixed names sit close to Apple's mark family (AirDrop, AirPlay, AirTag), so verify with counsel and have "ClipBeam" as fallback.

## 9. Timeline

- **Phase 1 (~2 weeks of sessions)**: core + pairing + iPhone→PC + Windows agent + keyboard pull behind flag. TestFlight.
- **Phase 2 (~1 week)**: polish, failure states, R10–R12, App Store submission.
- **Phase 3**: images/files, multi-PC.
- **Phase 4 (only if pulled by users)**: optional self-hosted relay for off-LAN — separate opt-in trust model.
- External clock: Apple's own solution lands fall 2027 (dev beta) / ~2028 public, likely EU-only. AirClip's window is now through at least mid-2027, and globally beyond that.
