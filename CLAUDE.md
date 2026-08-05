# CLAUDE.md — AirClip

Instructions for Claude Code working in this repository. Read this fully before making changes.

## What this project is

AirClip is a LAN-only, E2E-encrypted clipboard bridge between iPhone and Windows. No accounts, no cloud, no server. A shared Rust core (`crates/airclip-core`) implements protocol, crypto, discovery, and session state; thin platform shells (Windows tray agent in Rust, iOS app in SwiftUI) consume it. The iOS side is constrained by platform rules documented in `docs/IOS-PLATFORM-NOTES.md` — **read that file before touching anything iOS-related**. Several "obvious" designs are impossible on iOS and the current design exists because of those constraints.

## Source-of-truth documents

| Question | Document |
|---|---|
| What are we building and why | `docs/SPEC.md` |
| Bytes on the wire, crypto, pairing | `docs/PROTOCOL.md` (normative — code must match it) |
| Module layout, threading, data flow | `docs/ARCHITECTURE.md` |
| Why iOS can't do X | `docs/IOS-PLATFORM-NOTES.md` |
| Why we chose X over Y | `docs/DECISIONS.md` |
| What to build next | `docs/PHASE-1-TASKS.md` |

If code and `PROTOCOL.md` disagree, the protocol doc wins. If a change requires deviating from the protocol doc, update the doc **in the same commit** and bump the protocol version if the wire format changes.

## Hard rules

1. **No cloud, no accounts, no telemetry.** Never add a dependency that phones home. Never add analytics. This is the product's core promise.
2. **No plaintext clipboard data on the wire, ever.** Everything after `HELLO` is inside the AEAD channel. Pairing payloads (QR) contain public keys only, never secrets that would compromise past sessions.
3. **Crypto: use `x25519-dalek` / `chacha20poly1305` / `blake3` / `hkdf` as specified in PROTOCOL.md. Never hand-roll primitives. Never reuse nonces — the nonce scheme in PROTOCOL.md §6.3 is counter-based per direction; preserve it.**
4. **Clipboard content is never logged.** Log lengths, types, and hashes (first 8 hex chars of BLAKE3) only. This applies to debug builds too.
5. **`airclip-core` must stay platform-free.** No `windows`, no `objc`, no UI. Platform integration lives in `apps/`. Core compiles for `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `x86_64-pc-windows-msvc`.
6. **UniFFI boundary is `src/ffi.rs` only.** Keep the exported surface minimal — sessions, events, and byte payloads. Don't leak internal types across FFI.
7. **iOS extensions have tight memory limits** (keyboard ≈ 60 MB, intents ≈ ~30–60 MB). Anything running in an extension must avoid loading large buffers; stream and cap payloads per SPEC limits.

## Working style

- The maintainer is a 30-year full-stack dev. Be terse in code comments. No tutorial-style comments. Comment *why*, not *what*.
- Small, reviewable commits. Conventional commits format: `feat(core): ...`, `fix(win): ...`, `docs: ...`.
- Every protocol-relevant change needs a test in `airclip-core`. Frame codec, crypto round-trips, and pairing state machine all have test modules — extend them, don't skip them.
- Multiple Claude Code sessions may run in parallel on this repo. **Stay inside your assigned task's file scope** (tasks in PHASE-1-TASKS.md list their file scope). If you must touch a file outside scope, note it prominently in your summary.
- When a task is done, update its checkbox in `docs/PHASE-1-TASKS.md` in the same commit.

## Build & test commands

```bash
cargo build --workspace                 # core + windows agent
cargo test -p airclip-core              # protocol/crypto/session tests
cargo clippy --workspace -- -D warnings # required clean before commit
cargo fmt --all                         # required before commit

# iOS bindings regen (run after changing src/ffi.rs):
./scripts/gen-ios-bindings.sh           # see ARCHITECTURE.md §7
```

Windows agent can be built and unit-tested on any host; clipboard/tray integration tests require Windows (cfg-gated `#[cfg(windows)]`). iOS builds happen in Xcode on the maintainer's Mac — Claude Code prepares Swift sources and bindings; do not attempt to run `xcodebuild` unless on macOS.

Toolchain note: the crypto dependencies are commented out in `crates/airclip-core/Cargo.toml` until T-02; they require rustup ≥ 1.85 (edition2024 in `zeroize_derive`/`cpufeatures`). T-02 uncomments them.

## Testing without two devices

- `airclip-core` has a loopback harness: `tests/loopback.rs` spins up two `Session`s over an in-memory duplex transport. Use it for any protocol change.
- `apps/windows` has `--simulate-peer` flag: runs a fake iPhone peer in-process for manual testing of tray flows.

## Things you will be tempted to do — don't

- Don't add a relay server "just as a fallback." Out of scope until Phase 4, and it changes the trust model (see DECISIONS.md ADR-2).
- Don't switch discovery to UDP broadcast. mDNS was chosen deliberately (ADR-4); iOS local-network permission covers both, and mDNS gives us named services and interface handling for free.
- Don't use `NSUserDefaults`/plist for keys on iOS or DPAPI-unprotected files on Windows. Identity keys: iOS Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), Windows DPAPI per-user.
- Don't make the keyboard extension open network connections at load time. It fetches on explicit user tap only (App Review risk + latency budget, see IOS-PLATFORM-NOTES.md §5).
- Don't expand clipboard type support beyond `public.utf8-plain-text` + `public.url` in Phase 1.
