# AirClip Wire Protocol v1

Status: **Normative.** Code must conform to this document. Wire-format changes require bumping `PROTOCOL_VERSION` and a compatibility note here.

## 1. Overview

AirClip devices communicate over TCP on the local network. One long-lived, mutually-authenticated, AEAD-encrypted session carries all traffic. Discovery is via mDNS/DNS-SD. Trust is established once via QR pairing (out-of-band public key exchange + short-authentication-string verification) and persisted.

Design priorities, in order: (1) no plaintext content on the wire, (2) no secrets in the QR/pairing payload, (3) sub-second small-payload latency, (4) forward secrecy per session, (5) implementable in an iOS extension's memory budget.

```
Pair (once):  QR(pk_pc, host, port, token) → TCP → PAIR_* frames → SAS confirm → stored pairing
Session (each connection): HELLO/HELLO_ACK (ephemeral X25519) → derive keys → encrypted frames
Traffic:      CLIP_PUSH (phone→pc), STAGE_LIST/STAGE_GET (phone pulls pc clips), PING/PONG
```

## 2. Constants

```
PROTOCOL_VERSION      = 1
DEFAULT_PORT          = 49517            # fixed default; actual port advertised via mDNS
MDNS_SERVICE          = "_airclip._tcp.local."
MAX_FRAME_LEN         = 1_048_576        # 1 MiB hard cap, Phase 1
MAX_TEXT_CLIP         = 262_144          # 256 KiB per SPEC R5
STAGE_DEPTH           = 5                # staged clips retained on PC
SESSION_IDLE_TIMEOUT  = 60 s             # either side may close after idle; reconnect is cheap
PING_INTERVAL         = 20 s             # only while a session is intentionally held open
```

## 3. Identities and key material

Each device has a long-term identity: an X25519 static keypair `(sk_id, pk_id)` generated at first launch.

- iOS: stored in Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, non-synchronizable (never iCloud).
- Windows: 32-byte seed sealed with DPAPI (`CryptProtectData`, per-user scope) at `%LOCALAPPDATA%\AirClip\identity.bin`.

`device_id = BLAKE3(pk_id)[0..16]` (16 bytes, hex-encoded where displayed). Human-readable device names ("Bernhard's iPhone", "SAMMAMISH-PC") travel in pairing frames and are display-only — never used for auth.

A **pairing record** stores: peer `device_id`, peer `pk_id`, peer display name, created-at, last-seen. Windows: DPAPI-sealed JSON next to identity. iOS: Keychain generic password item per pairing.

## 4. Discovery (mDNS/DNS-SD)

The Windows agent registers:

```
Service:  <device_id_hex>._airclip._tcp.local.
Port:     actual bound port (tries DEFAULT_PORT, else ephemeral)
TXT:      v=1  id=<device_id_hex>  nm=<display name, UTF-8 ≤ 32 bytes>
```

The iPhone browses for `_airclip._tcp` **only when it needs a connection** (app foreground, intent execution, keyboard fetch) — no continuous browsing. Resolution → connect to the first address that completes TCP within 800 ms (Happy-Eyeballs-lite across IPv4/IPv6/interfaces).

The iPhone matches discovered `id` TXT against its pairing records. Unknown IDs are ignored (no UI) except during pairing mode. mDNS data is unauthenticated and treated as a *hint only* — real authentication happens in the handshake (§6). A spoofed mDNS record can cause a connection attempt but cannot pass the handshake without `sk_id`.

Fallback (P1, R10): stored `host:port` attempted in parallel with mDNS after 1 s.

## 5. Framing

All traffic after TCP connect uses one frame format. Integers are little-endian.

```
┌────────────┬───────────┬──────────────┬───────────────────────────┐
│ magic (4)  │ type (1)  │ length (4)   │ payload (length bytes)    │
│ "ACP1"     │ u8        │ u32 ≤ 1 MiB  │ type-specific             │
└────────────┴───────────┴──────────────┴───────────────────────────┘
```

Frames with bad magic, unknown type (outside reserved ranges), or length > `MAX_FRAME_LEN` → immediate connection close. Payloads of encrypted frame types (≥ 0x20) are `nonce_ctr (8) ‖ AEAD ciphertext` — see §6.3. Payloads of handshake/pairing types (< 0x20) are plaintext **but contain no secrets**.

### Frame types

```
0x01 HELLO         plaintext   session handshake init
0x02 HELLO_ACK     plaintext   session handshake response
0x10 PAIR_REQ      plaintext   pairing: phone → pc
0x11 PAIR_ACK      plaintext   pairing: pc → phone
0x12 PAIR_CONFIRM  plaintext   pairing: phone → pc after SAS confirm
0x20 CLIP_PUSH     encrypted   clipboard content, either direction
0x21 CLIP_ACK      encrypted   receipt for a CLIP_PUSH
0x22 STAGE_LIST_REQ encrypted  phone asks pc for staged clip metadata
0x23 STAGE_LIST    encrypted   pc responds with metadata array
0x24 STAGE_GET     encrypted   phone requests one staged clip body
0x25 STAGE_ITEM    encrypted   pc sends the clip body
0x30 PING          encrypted   keepalive
0x31 PONG          encrypted   keepalive reply
0x3F ERROR         encrypted   error code + message, then close
0x40–0x4F          reserved    chunked transfer (Phase 3 files/images)
```

Inner payloads (after decryption where applicable) are **CBOR maps** with integer keys (compact, schema documented per-type below). `serde` + `ciborium` in the Rust core.

## 6. Session handshake and encryption

### 6.1 Handshake (Noise-style, static+ephemeral)

The initiator is always the iPhone (Windows never dials the phone — iOS can't listen in background anyway). Both sides already hold each other's static `pk_id` from pairing.

```
HELLO (phone→pc), CBOR:
  1: protocol_version (u8) = 1
  2: initiator_device_id (bytes16)
  3: eph_pk_i (bytes32)            # fresh X25519 ephemeral per session
  4: ts (u64, unix ms)             # replay window check, ±120 s
  5: mac (bytes32)                 # BLAKE3-keyed(k=ss_static, msg=fields 1..4 serialized)
       where ss_static = X25519(sk_id_phone, pk_id_pc)
```

"Fields 1..4 serialized" means: the CBOR map containing exactly keys 1–4, emitted in
ascending key order, encoded as it would be on the wire. The verifier rebuilds this map
from the parsed values rather than hashing the received bytes, so a re-ordered or
padded HELLO cannot alter what the MAC covers. (Pinned during T-02/T-04; the original
wording left the encoding ambiguous and the two sides would not have interoperated.)

The MAC proves the initiator holds the paired identity key without signatures. PC verifies `device_id` is paired, verifies MAC and timestamp window, else closes silently (no oracle).

```
HELLO_ACK (pc→phone), CBOR:
  1: eph_pk_r (bytes32)
  2: mac (bytes32)                 # BLAKE3-keyed(k=ss_static, msg=eph_pk_r ‖ eph_pk_i)
```

### 6.2 Key derivation

```
ss_ee   = X25519(eph_sk_local, eph_pk_remote)
ss_si   = X25519(sk_id_phone,  eph_pk_pc)     # phone side; mirrored on pc
ikm     = ss_ee ‖ ss_si ‖ ss_static
salt    = "airclip-v1" ‖ device_id_phone ‖ device_id_pc
k_p2c   = HKDF-SHA256(ikm, salt, info="p2c", 32)   # phone→pc key
k_c2p   = HKDF-SHA256(ikm, salt, info="c2p", 32)   # pc→phone key
```

Ephemerals are zeroized after derivation (`zeroize` crate). Compromise of a device later does not decrypt past sessions (forward secrecy via `ss_ee`).

### 6.3 AEAD framing

Cipher: ChaCha20-Poly1305 (IETF, 12-byte nonce). Each direction has an independent u64 counter starting at 0. Nonce = `4 zero bytes ‖ counter_le_u64`. The 8-byte `nonce_ctr` prefix travels in the frame; receivers **require strictly increasing counters** (anti-replay, no window — TCP is ordered). AAD = frame `type` byte ‖ `PROTOCOL_VERSION`. Counter overflow (never in practice) → close and re-handshake.

## 7. Pairing

Pairing bootstraps trust. It must survive a hostile LAN (coffee shop): a passive attacker learns only public keys; an active MITM is caught by the SAS check.

### 7.1 QR payload (displayed by Windows tray)

```
airclip://pair?v=1
  &id=<device_id_pc hex>
  &pk=<pk_id_pc base64url>
  &nm=<display name, urlencoded>
  &hosts=<comma list of ip:port, e.g. 192.168.4.20:49517,[fe80::..]:49517>
  &tok=<pair_token base64url, 16 random bytes>
```

`tok` scopes this QR to one pairing window (10 min TTL, single use) — it prevents drive-by `PAIR_REQ` from a device that never saw the QR. It is *not* an authentication secret for the channel; MITM resistance comes from SAS.

### 7.2 Flow

```
1. Phone scans QR → connects to first reachable host.
2. PAIR_REQ (phone→pc), CBOR:
     1: pair_token (bytes16)
     2: device_id_phone (bytes16)
     3: pk_id_phone (bytes32)
     4: display_name (tstr)
     5: eph_pk_i (bytes32)
3. PC validates token (unexpired, unused). PAIR_ACK (pc→phone):
     1: eph_pk_r (bytes32)
4. Both compute sas_input = X25519(eph) ‖ pk_id_phone ‖ pk_id_pc ‖ pair_token
   sas = BLAKE3(sas_input)[0..4] → mapped to 4 emoji from a fixed 64-emoji table
   (indices: 6 bits per emoji from the 32-bit digest = 4 × 6 bits, high bits first).
5. Both screens show the 4 emoji. User confirms match on the phone.
6. PAIR_CONFIRM (phone→pc): 1: mac = BLAKE3-keyed(k=X25519(sk_id_phone, pk_id_pc), msg=sas_input)
7. PC verifies mac (proves the phone owns pk_id_phone AND both saw the same SAS basis).
   Both persist pairing records. Tray + phone show success.
```

An MITM substituting ephemerals or identity keys produces mismatched emoji with probability
1 − 2⁻²⁴ per attempt; token TTL and single-use prevent retry farming.

The SAS carries **24 bits**, not 32: four emoji at 6 bits each consume only the top 24 bits
of the digest. That is deliberate and in line with comparable schemes — ZRTP's spoken SAS
and Bluetooth numeric comparison are both ≈20 bits — because the attacker must be an active
MITM *during* the pairing window and gets exactly one attempt: the token is single-use with
a 10-minute TTL, so a failed guess cannot be retried. Widening the SAS means either six
emoji (36 bits) or a 256-emoji table (32 bits); both were rejected for Phase 1, the latter
because 256 cross-platform-unambiguous emoji do not exist and near-duplicate glyphs would
degrade the human comparison this defence actually rests on.

### 7.3 Unpairing

Either side deletes its record locally (Settings/tray menu). No wire message needed — subsequent HELLOs fail MAC and are dropped. Phase 2 nicety: an encrypted `UNPAIR` notice for tidy UI on the peer.

## 8. Clipboard transfer

### 8.1 CLIP_PUSH (encrypted CBOR)

```
1: clip_id (bytes8)        # random; used in CLIP_ACK
2: content_type (u8)       # 1 = text/plain;charset=utf-8, 2 = url. 3–9 reserved (png, jpeg, file…)
3: body (bstr ≤ 256 KiB)
4: created_at (u64 ms)     # source-device copy time, display only
5: source_name (tstr)      # display only
```

Receiver behavior (PC): set clipboard via `SetClipboardData(CF_UNICODETEXT)` (convert UTF-8→UTF-16, also set `CFSTR_INLINE` URL format when type=2), fire toast "📋 from iPhone — <first 40 chars>". Reply `CLIP_ACK {1: clip_id, 2: status u8 (0=ok)}`. Phone treats missing ACK within 2 s as failure → R9 error surface.

Receiver behavior (iPhone, in-app receive path): write to `UIPasteboard.general` **only from foreground app context**, show confirmation. (Keyboard path never touches the pasteboard — it inserts text directly; see IOS-PLATFORM-NOTES §5.)

### 8.2 Staged pull (PC → iPhone)

PC maintains a ring of the last `STAGE_DEPTH` local copies (text/url only, each ≤ 256 KiB, in-memory only, cleared on Pause/Quit and optionally on lock — Phase 2 setting).

```
STAGE_LIST_REQ: {}
STAGE_LIST:     1: [ {1: stage_id bytes8, 2: content_type u8, 3: preview tstr ≤ 120 chars,
                      4: size u32, 5: copied_at u64} … ]   # newest first
STAGE_GET:      1: stage_id
STAGE_ITEM:     1: stage_id, 2: content_type, 3: body
```

Previews are pre-truncated on the PC so the keyboard extension can render the list without fetching bodies — one round trip to show the row, a second only when the user taps an item. Total keyboard budget: connect+handshake+LIST ≤ 700 ms on warm Wi-Fi.

## 9. Errors

`ERROR` frame: `{1: code u16, 2: msg tstr}` then close. Codes: 1 unsupported version · 2 not paired · 3 bad token · 4 frame too large · 5 rate limited · 6 internal. Rate limit: ≥ 20 unauthenticated connection attempts/min from one address → drop for 5 min (mitigates LAN spam).

## 10. Security model summary

| Threat | Mitigation |
|---|---|
| Passive LAN sniffing | AEAD on all content frames; handshake carries no secrets |
| Active MITM at pairing | SAS emoji comparison (32-bit), token TTL/single-use |
| Active MITM post-pairing | Static-key MACs in HELLO/HELLO_ACK; attacker lacks `sk_id` |
| Replay of frames | Strictly-increasing per-direction nonce counters; HELLO ts window |
| Evil twin mDNS record | mDNS is a hint only; handshake authenticates |
| Device theft | Keys sealed in Keychain/DPAPI; unpair from the other device stops nothing remotely (documented limitation — content requires *live* proximity anyway) |
| Malicious clipboard content | Receivers treat body as inert data; PC never auto-executes; URL type does not auto-open |

Explicit non-goals of the model: resisting a compromised paired device; hiding metadata (frame sizes/timing) from the LAN; off-LAN operation.
