# iOS Platform Notes

Every constraint here is load-bearing for the design. Read before proposing iOS changes. Verify current behavior against the target SDK at build time — Apple tightens these rules more often than it loosens them (until the DMA solution lands ~fall 2027, EU).

## 1. Clipboard access

- **No background clipboard reads. Period.** `UIPasteboard.general` is readable only by a foregrounded process (app, or an extension in its active window of execution). There is no entitlement, no background mode, no workaround. This is why AirClip has no "continuous sync" and why iPhone→PC is trigger-based.
- **Paste permission chip (iOS 16+):** first programmatic read shows "Allow Paste from <app>?" per source-app. For the Beam intent via Shortcuts, the user can set **Shortcuts → (i) → Allow "Paste" → Always**, making subsequent Action Button sends promptless. Onboarding must walk the user through this once — it's the difference between magic and nagware.
- `UIPasteboard.detectedPatterns` allows checking *whether* the clipboard has URLs/text without triggering the chip — use it to short-circuit "clipboard empty" errors before reading.
- **Writing** to the pasteboard is unrestricted from foreground app context. The keyboard extension deliberately never writes the pasteboard — it inserts text via `textDocumentProxy`, which avoids both the banner and any review ambiguity.

## 2. App Intents / Action Button / Back Tap

- An `AppIntent` with background mode runs without opening the app UI — this is the entire hero flow. It still counts as "your app" for the paste chip (see above).
- Action Button (15 Pro+) maps to a Shortcut; Back Tap (accessibility) can also run it — covers non-Pro devices. Control Center `ControlWidget` (iOS 18+) gives a third entry point sharing the same intent.
- Intent execution budget is short (seconds) and memory-capped. `beam_text_await` uses a 2 s network timeout and reports a typed failure so Shortcuts shows a real error instead of spinning.
- Intents can present a confirmation/result snippet — use it for the "✓ Beamed to SAMMAMISH-PC" flash.

## 3. Local network access

- First LAN unicast/mDNS use triggers the **Local Network permission** dialog. Requires `NSLocalNetworkUsageDescription` and `NSBonjourServices` = `_airclip._tcp` in Info.plist — missing the Bonjour entry silently breaks discovery.
- Pre-prompt in onboarding ("AirClip talks directly to your PC — nothing leaves your network") before triggering the system dialog; denial leaves the app dead and recovery UX (Settings deep link) must exist.
- Extensions inherit the app's grant on current iOS versions, but treat "permission denied" as a first-class state in every network path anyway.

## 4. Background execution (what little exists)

- No persistent sockets in background. Sessions are ephemeral by design (§2 of PROTOCOL: reconnect is one round trip + crypto, ~30–80 ms on LAN — don't fight iOS to keep sockets alive).
- `BGAppRefreshTask` is discretionary and useless for real-time; not used.
- Local Push Connectivity entitlement (`NEAppPushProvider`) allows a LAN-maintained connection for *notifications* — this is the only sanctioned "always-on LAN" mechanism. Restricted entitlement, hotel/enterprise-Wi-Fi intent, approval unlikely for a clipboard app. Parked: revisit for Phase 3 "PC pushed a clip" notifications. Do not architect around getting it.

## 5. Keyboard extension (the PC→iPhone pull)

- Network access from a keyboard requires **RequestsOpenAccess = YES** and the user enabling **Allow Full Access**. This is a scary toggle with a scary system warning. Mitigations, all mandatory:
  - In-keyboard empty-state copy: "Full Access lets AirClip reach your PC over your Wi-Fi. Nothing is typed, logged, or sent anywhere else. [Open Settings]".
  - Privacy policy + App Review notes state: no keylogging, no persistence of typed content, network use is LAN-fetch on explicit tap only.
  - Fetch happens **only on user tap** (refresh chip), never automatically on keyboard appearance — latency budget aside, auto-fetch on every keyboard load is an App Review and battery red flag.
- Memory ceiling ≈ 60 MB (jetsam). Current-thread runtime, no caching of bodies beyond the tapped item, previews only in the list (PROTOCOL §8.2 is designed for this).
- Keyboard cannot present the camera, so pairing always happens in the main app.
- Insertion via `textDocumentProxy.insertText(_:)`; secure text fields (`isSecureTextEntry`) suppress third-party keyboards entirely — document as FAQ ("why can't I use it in password fields": Apple blocks all custom keyboards there; workaround is in-app receive → system paste).

## 6. Share extension

- Accepts `public.plain-text` and `public.url` via `NSExtensionActivationRule`. Runs in-process UI, so it can show beam progress + ACK state. Same memory caution as other extensions; the share path caps payload at MAX_TEXT_CLIP before calling core.

## 7. App Review landmines (pre-submission checklist)

- Guideline 2.5.14 (pasteboard): we read only on explicit user action — state this in review notes.
- Full Access keyboard justification with exact copy of the in-keyboard explainer.
- Local Network usage description strings must be specific, not boilerplate.
- Encryption export compliance: standard AEAD → `ITSAppUsesNonExemptEncryption = NO` qualifies for the exemption, but file the annual self-classification report anyway.
- Privacy nutrition label: Data Not Collected (verify no dependency embeds analytics).
- Name clearance: "AirClip" sits near Apple's "Air"-family marks (AirDrop/AirPlay/AirTag) — have counsel sign off before submission (SPEC §8).

## 8. Device/OS floor

- iOS 17 minimum (App Intents maturity, keyboard/network behaviors verified there; iOS 18 unlocks ControlWidget which is feature-gated).
- Action Button is 15 Pro+; Back Tap covers iPhone 8+. Both are just triggers for the same Shortcut — no capability branching in code.
