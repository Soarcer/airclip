# Phase 1 Build Plan

Goal: pair once, beam text iPhone→PC in < 1 s via Action Button, pull PC clips from the iPhone keyboard. TestFlight-ready.

Tasks are sized for one Claude Code session each (~0.5–2 h focused). **File scope** is listed so parallel sessions don't collide. Dependency graph:

```
T-01 ─┬─ T-02 ── T-03 ─┬─ T-04 ── T-05 ─┬─ T-10 (win server)
      │                │                ├─ T-11..13 (win shell)   ── T-14
      │                │                └─ T-06 (ffi) ── T-07..09 (iOS)  ─┘
      └─ (CI: T-00 anytime after T-01)
```

Lanes after T-05: **Lane A** = Windows (T-10→T-13), **Lane B** = iOS (T-06→T-09). Run in parallel sessions.

---

## T-00 · CI pipeline
**Scope:** `.github/workflows/ci.yml`
GitHub Actions: `cargo fmt --check`, `clippy -D warnings`, `cargo test -p airclip-core` on ubuntu + windows runners; bindings-freshness check (regenerate FFI bindings, `git diff --exit-code apps/ios/Generated`).
**Accept:** CI green on main; a PR with a failing test blocks.

## T-01 · Workspace + frame codec
**Scope:** `Cargo.toml`, `crates/airclip-core/{Cargo.toml, src/lib.rs, src/frame.rs, src/error.rs}`
Complete PROTOCOL §5: tokio `Encoder/Decoder` around the existing `Frame` codec, plus fuzz target.
**Accept:** round-trip tests for every frame type; malformed magic/oversize/truncated inputs rejected; fuzz target compiles (`fuzz/fuzz_targets/frame.rs`).

## T-02 · Crypto module
**Scope:** `src/crypto.rs` (+ uncomment crypto deps in `crates/airclip-core/Cargo.toml`)
Identity keygen (x25519-dalek), BLAKE3 device_id, keyed-MAC helpers, HKDF per PROTOCOL §6.2, `AeadChannel` (per-direction counters, strict monotonic verify, zeroize on drop), SAS emoji mapping (fixed 64-emoji table, 6-bit indices).
**Accept:** KAT vectors pinned in tests (generate once, commit); nonce monotonicity property test; SAS vector test (`digest 0xDEADBEEF → expected 4 emoji`); zero clipboard-content logging enforced by lint script in CI.

## T-03 · Pairing state machine
**Scope:** `src/pairing.rs`
Sans-io FSM per PROTOCOL §7: QR URL parse/build (`airclip://pair?...`), token TTL/single-use, PAIR_REQ/ACK/CONFIRM transitions for both roles, SAS derivation, MAC verify, `PairingRecord` (de)serialization.
**Accept:** table-driven tests: happy path both roles; expired token; reused token; MITM ephemeral swap yields differing SAS on the two sides; CONFIRM with bad MAC rejected.

## T-04 · Session (handshake + traffic)
**Scope:** `src/session.rs`, `src/stage.rs`
HELLO/HELLO_ACK per PROTOCOL §6.1 (sans-io FSM + tokio driver), CLIP_PUSH/ACK, STAGE_LIST/GET/ITEM, PING/PONG, idle timeout, ERROR emission. `StageRing` with depth 5, 256 KiB cap, preview truncation (char-boundary safe, 120 chars).
**Accept:** `tests/loopback.rs` passes: pair → handshake → push text (assert PC-side event) → stage 6 items (assert eviction) → LIST returns previews newest-first → GET returns body; replayed frame (counter reuse) closes session; HELLO with stale ts rejected.

## T-05 · Discovery
**Scope:** `src/discovery.rs`
`Discovery` trait (`advertise`, `browse → stream of PeerHint`). `mdns-sd` implementation behind `feature = "mdns"` (used by Windows; iOS uses NWBrowser natively and feeds hints via FFI). TXT record build/parse per PROTOCOL §4.
**Accept:** unit tests for TXT encode/parse; two in-process instances discover each other on CI linux runner (skip-if-no-multicast guard).

## T-06 · FFI surface
**Scope:** `src/ffi.rs`, `uniffi.toml`, `scripts/gen-ios-bindings.sh`
UniFFI exports: `CoreHandle::new(role, keystore_callbacks)`, commands (`start_pairing(qr)`, `confirm_sas`, `beam_text_await(text, timeout_ms) -> BeamResult`, `fetch_stage_list_await`, `fetch_stage_item_await(id)`, `add_peer_hint(host, port)`), `CoreEvent` callback interface, keystore callback trait (Swift implements Keychain; Windows implements DPAPI directly in Rust, bypassing FFI).
**Accept:** bindings generate cleanly; Swift smoke target compiles in CI (macOS runner, sim arch); no internal types leak (review checklist in PR).

---

### Lane A — Windows agent

## T-10 · Server + keystore + simulate-peer
**Scope:** `apps/windows/src/{main.rs, server.rs, keystore.rs}`
Tokio accept loop → core sessions; DPAPI identity + pairing store; `--simulate-peer` flag drives a phone-role core in-process (pair with fixed token, beam a string, pull stages) for end-to-end manual testing without an iPhone.
**Accept:** `cargo run -p airclip-windows -- --simulate-peer` prints a full successful pair+beam+pull transcript on a Windows machine.

## T-11 · Clipboard integration
**Scope:** `apps/windows/src/clipboard.rs`
`AddClipboardFormatListener` watcher on a message-only window; own-write suppression via sequence-number bookkeeping; UTF-16⇄UTF-8; contended-clipboard retry (5×50 ms); wire watcher→`StageRing`, CLIP_PUSH→clipboard set.
**Accept:** cfg(windows) tests: set→read round-trip; watcher does not re-stage own writes (loop test); manual: copy in Notepad appears in simulate-peer stage list.

## T-12 · Tray, toasts, autostart
**Scope:** `apps/windows/src/{tray.rs, toast.rs}`
Tray icon with dynamic status (idle/paired/reachable), menu: Pair new iPhone, Pause beaming, Start with Windows, Quit. Toast on clip arrival with 40-char preview. Single-instance mutex.
**Accept:** manual checklist run recorded in PR: all menu items function; pause drops incoming CLIP_PUSH with ERROR 5; toast appears without focus steal.

## T-13 · Pairing window + installer
**Scope:** `apps/windows/src/pairing_window.rs`, `wix/`, `winget/`
egui window: QR (PROTOCOL §7.1 URL incl. all viable local addresses), then 4-emoji SAS display, success state. `cargo-wix` MSI: installs, firewall inbound rule for the binary, AUMID registration, optional autostart. Draft winget manifest.
**Accept:** fresh Windows VM: MSI installs → pair with simulate-peer QR flow → beam works; uninstall removes firewall rule.

### Lane B — iOS

## T-07 · App shell + pairing
**Scope:** `apps/ios/AirClip/*`
SwiftUI: Home (status card, Beam button, last-5 list stub), Pair (VisionKit/AVFoundation QR scan → `start_pairing` → SAS screen → confirm), Settings (device name, unpair). Keychain keystore callbacks (access group `group.com.narrion.airclip`). Local-network pre-prompt explainer → NWBrowser browse feeding `add_peer_hint`. Info.plist: `NSBonjourServices` = `_airclip._tcp`, `NSLocalNetworkUsageDescription`, camera usage.
**Accept:** manual: pair against real Windows agent; SAS emojis match; relaunch retains pairing; airplane-mode shows unreachable state ≤ 3 s.

## T-08 · Beam paths: App Intent, Control Center, share ext
**Scope:** `apps/ios/AirClipSendIntent/*`, `apps/ios/AirClipShare/*`, intent registration in app
"Beam Clipboard" AppIntent (background mode): `detectedPatterns` empty-check → read pasteboard → `beam_text_await(2000)` → result snippet ✓/✗ with reason; failure also posts a local notification when run headless. ControlWidget (iOS 18 gate) wrapping the same intent. Share extension for text/URL with progress + ACK dismissal.
**Accept:** manual matrix: Action Button beam < 1 s wall-clock to PC toast (film it — this is the demo clip); Back Tap path; Shortcuts "Always Allow" paste flow documented with screenshots in `docs/onboarding/`; PC-off beam surfaces error notification.

## T-09 · Keyboard extension (feature-flagged)
**Scope:** `apps/ios/AirClipKeyboard/*`
Open-access keyboard: chip row UI, tap-to-fetch STAGE_LIST (≤ 700 ms budget: connect 500 ms cap, current-thread runtime, cancel on disappear), tap chip → STAGE_GET → `insertText`. Full-access explainer empty state with Settings deep link. Globe-key handling, dark mode, memory audit ≤ 40 MB peak.
**Accept:** manual: copy URL on PC → open Messages on iPhone → switch keyboard → tap → URL inserted, ≤ 3 taps total; secure-field behavior documented; Instruments memory capture attached to PR.

---

## T-14 · Integration pass + TestFlight
**Scope:** repo-wide (single session, no parallel work)
Full two-device matrix: pair/unpair/re-pair, beam under weak RSSI, PC sleep/wake, phone Wi-Fi drop mid-beam, 256 KiB max clip, emoji/CJK/RTL text, rapid double-beam. Latency measurements logged into `docs/PERF.md` (p50/p95 over 30 beams). Fix pass. Archive → TestFlight internal build; App Review notes drafted from IOS-PLATFORM-NOTES §7.
**Accept:** all SPEC P0 acceptance criteria checked off in this file; TestFlight build installable; demo video recorded.

---

## Checklist mirror (tick as merged)

- [x] T-00 CI — fmt/clippy/tests on ubuntu+windows, core built for both iOS targets,
      fuzz smoke run, content-logging lint, self-activating bindings-freshness gate
- [x] T-01 frame codec — tokio codec + fuzz target + proptests
- [x] T-02 crypto — RFC 7748/5869/8439 KATs pinned, SAS vectors, nonce property tests
- [x] T-03 pairing FSM — QR round-trip, token TTL/reuse, MITM SAS divergence, MAC verify
- [x] T-04 session + stage — loopback harness green end to end
- [x] T-05 discovery — TXT codec + two in-process instances discovering over real mDNS
- [x] T-06 FFI — CoreHandle + commands + CoreEvent/Keystore callbacks; bindings
      generated and checked in; CI regenerates, diffs, and typechecks them for the sim
- [~] T-07 iOS app + pairing — code complete and **building for the simulator in CI**
      (XcodeGen spec, Keychain store, NWBrowser discovery, Home/Pair/Settings).
      Acceptance is manual and still owed: pair against the real Windows agent, confirm
      the SAS matches, relaunch retains pairing, airplane mode shows unreachable ≤ 3 s.
      All four need a device — see the Mac-access notes in apps/ios/README.md.
- [ ] T-08 beam paths
- [ ] T-09 keyboard (flagged)
- [x] T-10 win server + sim-peer — verified: `--simulate-peer` completes pair+beam+pull
- [x] T-11 win clipboard — watcher + setter, own-write suppression, UTF-16 round trip
- [x] T-12 tray/toasts — icon, menu, pause/autostart toggles, live status tooltip,
      single-instance mutex, WinRT toasts with XML escaping
- [x] T-13 pairing window + MSI — eframe QR/SAS/success window, WiX MSI (firewall rule,
      AUMID, optional autostart), winget manifests. MSI not yet built on a clean VM.
- [ ] T-14 integration + TestFlight
