# AirClip

**Universal Clipboard for iPhone + Windows. No account. No cloud. No server.**

Copy on your iPhone, paste on your PC in under a second. Pull your PC's clipboard onto your iPhone from any text field. Everything stays on your LAN, end-to-end encrypted with keys that never leave your devices.

> Apple has committed to iPhone↔Windows clipboard sync under the EU DMA — but not until fall 2027, in a developer beta, likely EU-only. AirClip ships now, everywhere.

## Why this exists

- iOS forbids background clipboard access. Every third-party "clipboard sync" app on iOS is either foreground-only, cloud-relayed, account-gated, or all three.
- Microsoft Phone Link supports iPhone for notifications/messages/files — but not clipboard.
- Self-hosted tools (ClipCascade, SyncClipboard) work but require running a server. Not mass-market.
- AirClip's bet: you can't beat the iOS foreground restriction, so you design *around* it — make the foreground moment take zero perceived time (Action Button → sent) and make receiving ambient (custom keyboard shows your PC's clip in-line).

## How it works

```
┌─────────────┐         mDNS discovery          ┌──────────────────┐
│   iPhone    │ ◄──────────────────────────────►│   Windows tray    │
│  (SwiftUI + │      TCP :49517, length-        │  (Rust, ~3 MB,    │
│  Rust core) │      framed, ChaCha20-Poly1305  │  no runtime)      │
└─────────────┘ ◄──────────────────────────────►└──────────────────┘
       ▲                                                  ▲
  Action Button /                                 clipboard listener +
  Back Tap / keyboard ext                         toast + auto-stage
```

- **Pair once**: Windows tray shows a QR code; iPhone scans it. X25519 key exchange, SAS emoji verification, done forever.
- **iPhone → PC**: Copy anything → press the Action Button (or Back Tap, or Control Center control). An App Intent reads the clipboard and beams it. Your PC clipboard updates instantly with a quiet toast.
- **PC → iPhone**: The Windows agent stages every copy. On iPhone, switch to the AirClip keyboard in any text field — the top row shows your PC's latest clips, fetched live over LAN. One tap inserts.

## Project layout

```
airclip/
├── CLAUDE.md                  # Instructions for Claude Code sessions
├── Cargo.toml                 # Rust workspace
├── crates/
│   └── airclip-core/          # Shared protocol, crypto, discovery, session (Rust + UniFFI)
├── apps/
│   ├── windows/               # Windows tray agent (Rust, tray-icon + windows-rs)
│   └── ios/                   # SwiftUI app + App Intents extension + keyboard extension
└── docs/
    ├── SPEC.md                # Product spec / PRD
    ├── PROTOCOL.md            # Wire protocol, pairing, crypto — normative
    ├── ARCHITECTURE.md        # System design, crate/module layout, threading
    ├── IOS-PLATFORM-NOTES.md  # Every iOS restriction that shapes this design
    ├── DECISIONS.md           # ADRs
    └── PHASE-1-TASKS.md       # Sequenced build plan with acceptance criteria
```

## Status

Phase 1 in development. See `docs/PHASE-1-TASKS.md` for the sequenced plan.

| Area | State |
|---|---|
| Protocol core — framing, crypto, pairing, session, discovery | **done** (T-01–T-05) |
| Windows agent — server, keystore, clipboard, tray, installer | **done** (T-10–T-13) |
| CI | **done** (T-00) |
| iOS — FFI surface, app, beam paths, keyboard | not started (T-06–T-09) |

The Windows side works end to end today: pair, beam iPhone→PC, and pull staged clips,
all verifiable without an iPhone via `--simulate-peer` below.

## Building

```bash
# Core + Windows agent (from repo root)
cargo build --workspace

# Tests: protocol core, then the whole workspace
cargo test -p airclip-core
cargo test --workspace

# Required clean before commit
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# iOS: generate UniFFI bindings + xcframework (macOS or the CI macOS runner)
./scripts/gen-ios-bindings.sh
```

## Trying it without an iPhone

The agent can drive itself: `--simulate-peer` runs the *phone* role from the same
`airclip-core` code the real app will use, so this exercises the actual protocol rather
than a mock.

```bash
# Terminal 1 — start the agent and open a pairing window
cargo run -p airclip-windows -- --pair

# Terminal 2 — paste the printed airclip:// URL
cargo run -p airclip-windows -- --simulate-peer "airclip://pair?v=1&..."
```

Expect a full transcript — `PAIR_REQ → PAIR_ACK → SAS → PAIR_CONFIRM`, then
`HELLO → HELLO_ACK`, a `CLIP_PUSH`, and a staged pull — after which the beamed text is
on your Windows clipboard. The four SAS emoji printed by both sides must match.

## License

MIT
