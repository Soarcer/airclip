# AirClip Architecture

## 1. Shape of the system

One Rust core, two thin shells. Everything protocol-shaped lives in `airclip-core`; platforms contribute only clipboard access, UI, keystores, and lifecycle glue.

```
                    ┌───────────────────────────────────────┐
                    │            airclip-core (Rust)         │
                    │  frame codec · crypto · handshake ·    │
                    │  pairing FSM · session · stage ring ·  │
                    │  discovery trait · event stream        │
                    └───────┬───────────────────┬───────────┘
                     UniFFI │                   │ plain Rust
             ┌──────────────┴─────┐   ┌─────────┴──────────────┐
             │  iOS (Swift)       │   │  Windows agent (Rust)  │
             │  App / Intent ext /│   │  tray-icon · clipboard │
             │  Keyboard ext /    │   │  listener · toasts ·   │
             │  Share ext         │   │  mDNS register · DPAPI │
             └────────────────────┘   └────────────────────────┘
```

## 2. Workspace layout

```
Cargo.toml                     # [workspace] members = crates/*, apps/windows
crates/airclip-core/
  src/
    lib.rs                     # public surface + re-exports
    frame.rs                   # magic/type/len codec, tokio codec impl
    crypto.rs                  # identity keys, HKDF, AEAD channel, SAS
    pairing.rs                 # pairing state machine (pure, sans-io)
    session.rs                 # handshake + encrypted session (sans-io core, tokio driver)
    stage.rs                   # staged-clip ring buffer (PC role)
    discovery.rs               # Discovery trait + mDNS impl (mdns-sd), feature-gated
    ffi.rs                     # UniFFI exports ONLY
    error.rs
  tests/loopback.rs            # two sessions over in-memory duplex
  uniffi.toml
apps/windows/
  src/
    main.rs                    # tray app entry, tokio runtime
    clipboard.rs               # AddClipboardFormatListener watcher + setter
    tray.rs                    # tray-icon menu, status
    toast.rs                   # WinRT toast notifications
    keystore.rs                # DPAPI seal/unseal
    server.rs                  # TCP accept loop → core sessions
    pairing_window.rs          # QR window (egui, see ADR-6)
apps/ios/
  AirClip/                     # SwiftUI app target
  AirClipSendIntent/           # App Intents extension ("Beam Clipboard")
  AirClipKeyboard/             # keyboard extension (Phase 1 behind flag)
  AirClipShare/                # share extension
  Generated/                   # UniFFI Swift bindings (checked in per release)
scripts/gen-ios-bindings.sh
```

## 3. Core design rules

- **Sans-io protocol logic.** `pairing.rs` and the handshake half of `session.rs` are pure state machines: `fn on_frame(&mut self, Frame) -> Vec<Action>`. Transport driving (tokio TCP on both platforms via FFI-owned runtime) is separate. This is what makes the loopback test harness and high coverage cheap.
- **Event stream out, commands in.** The FFI surface is: create `CoreHandle`, issue commands (`beam_text`, `start_pairing(qr_url)`, `fetch_stage_list`, …), receive `CoreEvent`s over a callback interface (`ClipArrived`, `PairingSas(emoji: Vec<String>)`, `PeerUnreachable`, `StageList(items)`, …). Swift never sees frames or keys.
- **Two roles, one crate.** `Role::Phone` (dials, pulls stages) vs `Role::Pc` (listens, stages clips). Compiled into both shells; role picked at init. Keeps protocol evolution in one place and lets the Windows agent's `--simulate-peer` reuse the phone role for testing.
- **No global singletons.** Everything hangs off `CoreHandle`; iOS extensions create short-lived handles with tight budgets.

## 4. Threading / async

- Core internally owns a small tokio runtime (2 worker threads on desktop, current-thread on iOS extensions). FFI commands are non-blocking; results arrive as events.
- iOS: the App Intent path must complete inside the intent's lifetime — `beam_text` exposes an async-completing FFI variant (`beam_text_await(timeout_ms)`) returning a result enum so the intent can report success/failure to Shortcuts UI.
- Keyboard extension: current-thread runtime, hard 500 ms connect budget, everything cancellable on `viewWillDisappear`.

## 5. Windows agent specifics

- Clipboard watch: message-only HWND + `AddClipboardFormatListener`; on `WM_CLIPBOARDUPDATE`, read `CF_UNICODETEXT` (skip if own write — tag with `GetClipboardSequenceNumber` bookkeeping to avoid loops), push into core's stage ring.
- Clipboard write on CLIP_PUSH: open/empty/set with retry loop (clipboard is contended; 5 × 50 ms backoff).
- Toasts via `windows` crate WinRT `ToastNotificationManager`; AUMID registered by installer.
- Single instance via named mutex. Autostart via `HKCU\...\Run` toggle.
- Distribution: `cargo-wix` MSI + winget manifest; binary target ≤ 6 MB (strip + LTO + `opt-level="z"` where hot paths allow).

## 6. iOS specifics

- App target: SwiftUI. Screens: Home (status, last clips, Beam button), Pair (camera + SAS), Settings. Local Network permission primed with a pre-prompt explainer before first mDNS browse.
- Send intent extension: `AppIntent` "Beam Clipboard" — `supportedModes: .background`, reads `UIPasteboard.general` (this triggers the paste-permission chip; user sets "Allow Always" for the Shortcut once), calls `beam_text_await`. Donated so it appears in Spotlight/Action Button picker. Control Center `ControlWidget` wraps the same intent.
- Keyboard extension: `RequestsOpenAccess = YES` (required for network). UI = single row of staged-clip chips + refresh. Direct `textDocumentProxy.insertText` — never touches the pasteboard, which both avoids the iOS paste banner and is genuinely more private.
- Share extension: accepts `public.plain-text`/`public.url`, same beam path, closes on ACK.
- Keychain access group shared across app+extensions for identity/pairings: `group.com.narrion.airclip`.

## 7. UniFFI pipeline

Proc-macro UniFFI (`#[uniffi::export]`) — no UDL file. `scripts/gen-ios-bindings.sh`:
1. `cargo build -p airclip-core --release --features ffi --target aarch64-apple-ios` (+ sim target)
2. `uniffi-bindgen generate --library … --language swift --out-dir apps/ios/Generated`
3. `xcodebuild -create-xcframework` bundling both static libs → `apps/ios/AirClipCore.xcframework`
Bindings + xcframework are rebuilt whenever `ffi.rs` changes; CI job verifies bindings are current.

## 8. Testing strategy

| Layer | How |
|---|---|
| Frame codec | Unit: round-trip, fuzz malformed headers (`cargo-fuzz` target, CI smoke) |
| Crypto | Unit: KAT vectors for HKDF/AEAD, nonce-monotonicity property tests, SAS emoji mapping vectors |
| Pairing FSM | Table-driven state tests incl. MITM ephemeral-swap → SAS mismatch |
| Session | `tests/loopback.rs`: full handshake + push + stage pull over duplex; latency assertion |
| Windows integration | `--simulate-peer` manual harness; clipboard set/get behind `#[cfg(windows)]` tests |
| iOS | XCTest on the Swift wrapper against a loopback core; manual matrix in PHASE-1-TASKS T-14 |

## 9. Key decisions

See DECISIONS.md. Highlights: ADR-1 shared Rust core + UniFFI (portfolio goal + single protocol impl) · ADR-2 LAN-only, no relay (trust model is the product) · ADR-3 phone-always-dials (iOS background listening impossible; simplifies NAT/firewall story to one inbound rule on the PC) · ADR-4 mDNS over UDP broadcast · ADR-5 CBOR over protobuf/JSON (no schema toolchain, compact, `serde`-native) · ADR-6 pairing QR window in egui to keep the agent dependency-light.
