# Architecture Decision Records

Format: context → decision → consequences. Newest last. Amend by superseding, not editing.

## ADR-1: Shared Rust core with UniFFI bindings

**Context.** Two platforms need identical protocol, crypto, and state-machine behavior. Duplicating crypto in Swift + Rust doubles the attack surface and guarantees drift. This is also explicitly a portfolio project — the repo should demonstrate a modern cross-platform architecture.
**Decision.** One `airclip-core` Rust crate: framing, crypto, pairing, session, staging. UniFFI proc-macro bindings for Swift; Windows agent consumes the crate natively.
**Consequences.** Single protocol implementation, loopback-testable to high coverage. Cost: xcframework build pipeline and an FFI boundary to keep disciplined (events out, commands in). Accepted.

## ADR-2: LAN-only. No relay, no cloud, no account.

**Context.** Every incumbent either requires a server (ClipCascade), an account/subscription (Pushbullet), or is cloud-synced (Windows clipboard sync, which doesn't reach iPhone anyway). Privacy is the differentiator and the marketing story; goal #1 in SPEC is a verifiable "nothing leaves your network."
**Decision.** v1 has no off-LAN path. Manual host:port entry (P1) lets VPN/Tailscale users bridge networks themselves without changing our trust model.
**Consequences.** "Doesn't work at the coffee shop when PC is at home" — acceptable; that's not the core use case (same desk, two devices). Relay revisited only as opt-in self-hosted Phase 4 if demanded.

## ADR-3: iPhone always initiates connections

**Context.** iOS cannot run a background listener; the PC can trivially run one. Bidirectional dialing doubles firewall/NAT surface and handshake code paths.
**Decision.** Single direction of dialing: phone → PC. PC never connects to the phone. PC→iPhone content moves by phone-initiated pull (stage list/get).
**Consequences.** One inbound firewall rule (installer adds it), one server loop, simpler session code. Real-time PC→phone push is impossible — by iOS rules it effectively was anyway; the keyboard-pull UX turns this constraint into a feature.

## ADR-4: mDNS/DNS-SD discovery (not UDP broadcast, not static IP)

**Context.** Zero-config discovery on consumer Wi-Fi. LocalSend-style UDP multicast works but hand-rolls what DNS-SD standardizes; iOS's local-network permission gates both equally; Windows 10+ has native mDNS.
**Decision.** `_airclip._tcp` DNS-SD via `mdns-sd` crate on Windows, `NWBrowser` on iOS. mDNS treated as unauthenticated hint; auth is the handshake.
**Consequences.** Named services, IPv6 for free, multi-interface handled by the stack. Known failure mode: AP client isolation / mDNS-filtered networks → covered by P1 manual host:port fallback with a diagnostic hint in the error UI.

## ADR-5: CBOR payloads (not protobuf, not JSON)

**Context.** Payloads are small maps with binary fields (keys, bodies). JSON forces base64 (+33% and allocations). Protobuf brings a schema toolchain into both a Rust crate and review burden for a hand-auditable protocol.
**Decision.** CBOR with integer keys via `ciborium`; schemas documented in PROTOCOL.md per frame type.
**Consequences.** Compact, `serde`-native, human-documentable. Discipline required: PROTOCOL.md is the schema authority; adding fields = new integer keys, never reuse.

## ADR-6: egui for the Windows pairing window; tray-first everything else

**Context.** The agent needs exactly one real window (QR + SAS display). Full GUI frameworks (Tauri/WinUI) explode binary size or toolchain complexity for one screen.
**Decision.** `tray-icon` + native menus for daily use; a single egui window for pairing; WinRT toasts for arrivals.
**Consequences.** ~3–6 MB binary, no webview, no runtime deps. egui look is non-native but the window is seen once per pairing. Revisit only if settings UI grows (Phase 3).

## ADR-7: Keyboard inserts text; never writes the pasteboard

**Context.** A "remote clipboard" could be surfaced by writing fetched content to `UIPasteboard` for the user to paste. That triggers iOS paste banners, adds a step, and leaves PC content lingering in the phone's pasteboard.
**Decision.** The keyboard fetches on tap and inserts directly at the cursor via `textDocumentProxy`.
**Consequences.** Fewer steps than Universal Clipboard for the "code from PC into phone app" case; no banners; content never persists on the phone. Limitation: secure text fields block custom keyboards (Apple-wide); FAQ documents the in-app fallback.

## ADR-8: Counter-based AEAD nonces over random nonces

**Context.** ChaCha20-Poly1305 nonce misuse is catastrophic; random 12-byte nonces are safe at our volumes but give no replay ordering.
**Decision.** Per-direction u64 counters as nonces, receiver enforces strict monotonicity (PROTOCOL §6.3). Fresh keys per session make reuse impossible across sessions.
**Consequences.** Replay protection falls out for free on ordered TCP; simple to test as a property. Requires re-handshake on any counter desync — sessions are cheap by design (ADR-3 + PROTOCOL §2 idle timeout).

## ADR-9: Product name "AirClip" (was ClipBeam)

**Context.** Working title was ClipBeam; maintainer selected AirClip for launch. "Air"-prefixed names sit close to Apple's mark family (AirDrop, AirPlay, AirTag).
**Decision.** Rename everything — crates, bundle IDs (`com.narrion.airclip`), mDNS service (`_airclip._tcp`), URL scheme (`airclip://`), wire magic (`ACP1`) — pre-launch, while nothing is shipped. Trademark clearance is an open SPEC item; "ClipBeam" retained as fallback name.
**Consequences.** Clean, consistent identifiers from day one; a rename after launch would have required protocol magic/service-type migration shims.
