//! Crypto per PROTOCOL.md §3, §6, §7.2. Normative doc wins over this file.
//!
//! Primitives are fixed by CLAUDE.md rule 3: x25519-dalek, ChaCha20-Poly1305, BLAKE3, HKDF.
//! Nothing here logs key material or plaintext — see rule 4.

use blake3::Hash;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::frame::FrameType;
use crate::{DeviceId, PROTOCOL_VERSION};

/// HKDF salt prefix, PROTOCOL §6.2.
const KDF_SALT_PREFIX: &[u8] = b"airclip-v1";

/// 64-emoji SAS table (PROTOCOL §7.2). **Order is protocol-normative** — reordering or
/// substituting entries silently breaks pairing against any other build. Single-codepoint
/// emoji only: no ZWJ sequences, no variation selectors, no skin tones, so every platform
/// renders the same glyph and the user comparison is meaningful.
pub const SAS_EMOJI: [&str; 64] = [
    // 0..16 — animals
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔",
    // 16..32 — fruit & veg
    "🍎", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍒", "🍑", "🥝", "🍍", "🥥", "🥑", "🍅", "🌽", "🥕",
    // 32..48 — sport & music
    "⚽", "🏀", "🏈", "⚾", "🎾", "🏐", "🎱", "🏓", "🥁", "🎸", "🎺", "🎻", "🎨", "🎯", "🎲", "🎳",
    // 48..64 — vehicles
    "🚗", "🚕", "🚙", "🚌", "🚑", "🚓", "🚚", "🚲", "🛵", "🚀", "🚁", "⛵", "🚂", "🚜", "🛴", "🚤",
];

/// A 32-byte X25519 public key.
pub type PublicKeyBytes = [u8; 32];

/// Long-term device identity (PROTOCOL §3). The secret never leaves this type except
/// via [`IdentityKeypair::secret_bytes`], which exists solely so the platform keystore
/// (Keychain / DPAPI) can seal it at rest.
///
/// `Clone` is deliberate: the Windows agent hands one identity to every concurrent
/// session task, and cloning the scalar is cheaper than threading lifetimes through
/// spawned futures. Both copies zeroize on drop.
#[derive(Clone)]
pub struct IdentityKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl IdentityKeypair {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| Error::Crypto)?;
        let kp = Self::from_seed(seed);
        seed.zeroize();
        Ok(kp)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> PublicKeyBytes {
        self.public.to_bytes()
    }

    /// Only for keystore sealing. Callers must not persist this unsealed.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn device_id(&self) -> DeviceId {
        device_id_from_pk(&self.public_bytes())
    }

    /// Raw X25519 with a peer public key.
    pub fn dh(&self, peer_pk: &PublicKeyBytes) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(
            self.secret
                .diffie_hellman(&PublicKey::from(*peer_pk))
                .to_bytes(),
        )
    }
}

impl std::fmt::Debug for IdentityKeypair {
    // Never render the secret, even in debug builds (CLAUDE.md rule 4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeypair")
            .field("device_id", &self.device_id().hex())
            .finish_non_exhaustive()
    }
}

/// Hex BLAKE3 of arbitrary content, for logging.
///
/// CLAUDE.md rule 4 permits logging a content *hash* but never content. Callers should
/// take the first 8 characters — enough to correlate two log lines, useless for
/// recovering a short clip.
pub fn content_digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// `device_id = BLAKE3(pk_id)[0..16]` (PROTOCOL §3).
pub fn device_id_from_pk(pk: &PublicKeyBytes) -> DeviceId {
    let digest = blake3::hash(pk);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    DeviceId(out)
}

/// Session-scoped ephemeral. Modelled as a `StaticSecret` rather than dalek's
/// `EphemeralSecret` because the handshake needs two DH operations from the same
/// scalar (PROTOCOL §6.2: `ss_ee` and `ss_si`), and `EphemeralSecret` is consumed by
/// the first. Lifetime is still one session; the value is zeroized on drop.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| Error::Crypto)?;
        let kp = Self::from_seed(seed);
        seed.zeroize();
        Ok(kp)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> PublicKeyBytes {
        self.public.to_bytes()
    }

    pub fn dh(&self, peer_pk: &PublicKeyBytes) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(
            self.secret
                .diffie_hellman(&PublicKey::from(*peer_pk))
                .to_bytes(),
        )
    }
}

/// BLAKE3 keyed MAC (PROTOCOL §6.1, §7.2 step 6).
pub fn keyed_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, msg).as_bytes()
}

/// Constant-time MAC verification. `blake3::Hash`'s `PartialEq` is documented as
/// constant-time, which is why the comparison goes through `Hash` rather than `[u8; 32]`.
pub fn verify_mac(key: &[u8; 32], msg: &[u8], tag: &[u8]) -> bool {
    let Ok(tag): std::result::Result<[u8; 32], _> = tag.try_into() else {
        return false;
    };
    blake3::keyed_hash(key, msg) == Hash::from(tag)
}

/// Directional session keys (PROTOCOL §6.2).
pub struct SessionKeys {
    pub p2c: Zeroizing<[u8; 32]>,
    pub c2p: Zeroizing<[u8; 32]>,
}

/// HKDF-SHA256 per PROTOCOL §6.2.
///
/// `ikm = ss_ee ‖ ss_si ‖ ss_static`, `salt = "airclip-v1" ‖ id_phone ‖ id_pc`.
/// Both roles must pass the device ids in the same order regardless of who is calling,
/// or the two sides derive different keys.
pub fn derive_session_keys(
    ss_ee: &[u8; 32],
    ss_si: &[u8; 32],
    ss_static: &[u8; 32],
    device_id_phone: &DeviceId,
    device_id_pc: &DeviceId,
) -> Result<SessionKeys> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(ss_ee);
    ikm.extend_from_slice(ss_si);
    ikm.extend_from_slice(ss_static);

    let mut salt = Vec::with_capacity(KDF_SALT_PREFIX.len() + 32);
    salt.extend_from_slice(KDF_SALT_PREFIX);
    salt.extend_from_slice(&device_id_phone.0);
    salt.extend_from_slice(&device_id_pc.0);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut p2c = Zeroizing::new([0u8; 32]);
    let mut c2p = Zeroizing::new([0u8; 32]);
    hk.expand(b"p2c", p2c.as_mut()).map_err(|_| Error::Crypto)?;
    hk.expand(b"c2p", c2p.as_mut()).map_err(|_| Error::Crypto)?;
    Ok(SessionKeys { p2c, c2p })
}

/// One direction of the AEAD channel: a key plus its counter.
struct Direction {
    key: Zeroizing<[u8; 32]>,
    /// Sender: next counter to use. Receiver: highest counter accepted so far.
    ctr: u64,
    seen_any: bool,
}

/// Encrypted channel over a frame stream (PROTOCOL §6.3).
///
/// Nonce is `4 zero bytes ‖ counter_le_u64`; the 8-byte counter is transmitted as the
/// payload prefix. AAD binds the frame type and protocol version, so a ciphertext cannot
/// be replayed under a different frame type.
pub struct AeadChannel {
    tx: Direction,
    rx: Direction,
}

impl AeadChannel {
    /// `tx_key` encrypts outbound frames, `rx_key` decrypts inbound ones. The Phone role
    /// passes `(p2c, c2p)`; the PC role passes `(c2p, p2c)`.
    pub fn new(tx_key: Zeroizing<[u8; 32]>, rx_key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            tx: Direction {
                key: tx_key,
                ctr: 0,
                seen_any: false,
            },
            rx: Direction {
                key: rx_key,
                ctr: 0,
                seen_any: false,
            },
        }
    }

    fn nonce_for(ctr: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&ctr.to_le_bytes());
        Nonce::from(n)
    }

    fn aad_for(ty: FrameType) -> [u8; 2] {
        [ty as u8, PROTOCOL_VERSION]
    }

    /// Encrypt `plaintext` for frame type `ty`, returning `nonce_ctr(8) ‖ ciphertext`.
    pub fn seal(&mut self, ty: FrameType, plaintext: &[u8]) -> Result<Vec<u8>> {
        debug_assert!(ty.is_encrypted(), "seal called on a plaintext frame type");
        let ctr = self.tx.ctr;
        let cipher = ChaCha20Poly1305::new(&Key::from(*self.tx.key));
        let aad = Self::aad_for(ty);
        let ct = cipher
            .encrypt(
                &Self::nonce_for(ctr),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;

        // Overflow is unreachable in practice; if it ever happens, force a re-handshake
        // rather than wrap the nonce (PROTOCOL §6.3).
        self.tx.ctr = ctr.checked_add(1).ok_or(Error::Crypto)?;

        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&ctr.to_le_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a `nonce_ctr(8) ‖ ciphertext` payload, enforcing strictly increasing
    /// counters (anti-replay).
    pub fn open(&mut self, ty: FrameType, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 8 {
            return Err(Error::Crypto);
        }
        let mut ctr_bytes = [0u8; 8];
        ctr_bytes.copy_from_slice(&payload[..8]);
        let ctr = u64::from_le_bytes(ctr_bytes);

        if self.rx.seen_any && ctr <= self.rx.ctr {
            // Replayed or reordered frame. Caller closes the session.
            return Err(Error::Crypto);
        }

        let cipher = ChaCha20Poly1305::new(&Key::from(*self.rx.key));
        let aad = Self::aad_for(ty);
        let pt = cipher
            .decrypt(
                &Self::nonce_for(ctr),
                Payload {
                    msg: &payload[8..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;

        // Only advance after authentication succeeds, so a forged frame cannot burn
        // counter space and wedge the channel.
        self.rx.ctr = ctr;
        self.rx.seen_any = true;
        Ok(pt)
    }
}

impl std::fmt::Debug for AeadChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadChannel")
            .field("tx_ctr", &self.tx.ctr)
            .field("rx_ctr", &self.rx.ctr)
            .finish_non_exhaustive()
    }
}

/// SAS basis, PROTOCOL §7.2 step 4:
/// `sas_input = X25519(eph) ‖ pk_id_phone ‖ pk_id_pc ‖ pair_token`.
pub fn sas_input(
    ss_eph: &[u8; 32],
    pk_id_phone: &PublicKeyBytes,
    pk_id_pc: &PublicKeyBytes,
    pair_token: &[u8; 16],
) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(32 + 32 + 32 + 16));
    v.extend_from_slice(ss_eph);
    v.extend_from_slice(pk_id_phone);
    v.extend_from_slice(pk_id_pc);
    v.extend_from_slice(pair_token);
    v
}

/// `sas = BLAKE3(sas_input)[0..4]`, read big-endian (PROTOCOL §7.2 step 4).
pub fn sas_digest(sas_input: &[u8]) -> u32 {
    let h = blake3::hash(sas_input);
    let b = h.as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Map a 32-bit SAS digest to 4 emoji: 6 bits each, high bits first.
///
/// Note this consumes only the top 24 bits of the digest — see the SAS strength note in
/// the module tests and `docs/PROTOCOL.md` §7.2.
pub fn sas_emoji(digest: u32) -> [&'static str; 4] {
    [
        SAS_EMOJI[((digest >> 26) & 0x3F) as usize],
        SAS_EMOJI[((digest >> 20) & 0x3F) as usize],
        SAS_EMOJI[((digest >> 14) & 0x3F) as usize],
        SAS_EMOJI[((digest >> 8) & 0x3F) as usize],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    // ---------------------------------------------------------------------
    // Known-answer tests against *published* vectors. These validate that our
    // wiring of each primitive matches the RFC, independent of our own code —
    // self-generated vectors would only prove we are consistently wrong.
    // ---------------------------------------------------------------------

    /// RFC 7748 §6.1 — X25519 Diffie-Hellman.
    #[test]
    fn kat_x25519_rfc7748() {
        let alice_sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_sk = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expect = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice = IdentityKeypair::from_seed(alice_sk);
        let bob = IdentityKeypair::from_seed(bob_sk);
        assert_eq!(alice.public_bytes(), alice_pk);
        assert_eq!(bob.public_bytes(), bob_pk);
        assert_eq!(*alice.dh(&bob_pk), expect);
        assert_eq!(*bob.dh(&alice_pk), expect);
    }

    /// RFC 5869 Test Case 1 — HKDF-SHA256.
    #[test]
    fn kat_hkdf_sha256_rfc5869() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expect = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = vec![0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, expect);
    }

    /// RFC 8439 §2.8.2 — AEAD_CHACHA20_POLY1305.
    #[test]
    fn kat_chacha20poly1305_rfc8439() {
        let key: [u8; 32] = (0x80u8..=0x9f).collect::<Vec<_>>().try_into().unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expect = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
        ).unwrap();

        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        let nonce = Nonce::try_from(&nonce[..]).unwrap();
        let ct = cipher
            .encrypt(&nonce, Payload { msg: pt, aad: &aad })
            .unwrap();
        assert_eq!(ct, expect, "ciphertext‖tag must match RFC 8439");
    }

    /// Official BLAKE3 vector for the empty input.
    #[test]
    fn kat_blake3_empty() {
        assert_eq!(
            blake3::hash(b"").to_hex().to_string(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    // ---------------------------------------------------------------------
    // Protocol-level behaviour
    // ---------------------------------------------------------------------

    #[test]
    fn device_id_is_truncated_blake3_of_pk() {
        let kp = IdentityKeypair::from_seed([7u8; 32]);
        let pk = kp.public_bytes();
        let full = blake3::hash(&pk);
        assert_eq!(kp.device_id().0, full.as_bytes()[..16]);
        assert_eq!(kp.device_id().hex().len(), 32);
    }

    #[test]
    fn both_roles_derive_identical_session_keys() {
        // Mirrors PROTOCOL §6.2 from each side's point of view.
        let phone = IdentityKeypair::from_seed([1u8; 32]);
        let pc = IdentityKeypair::from_seed([2u8; 32]);
        let eph_phone = EphemeralKeypair::from_seed([3u8; 32]);
        let eph_pc = EphemeralKeypair::from_seed([4u8; 32]);

        let id_phone = phone.device_id();
        let id_pc = pc.device_id();

        // Phone side.
        let ss_static_p = phone.dh(&pc.public_bytes());
        let ss_ee_p = eph_phone.dh(&eph_pc.public_bytes());
        let ss_si_p = phone.dh(&eph_pc.public_bytes());
        let ks_phone =
            derive_session_keys(&ss_ee_p, &ss_si_p, &ss_static_p, &id_phone, &id_pc).unwrap();

        // PC side — mirrored operations, same values.
        let ss_static_c = pc.dh(&phone.public_bytes());
        let ss_ee_c = eph_pc.dh(&eph_phone.public_bytes());
        let ss_si_c = eph_pc.dh(&phone.public_bytes());
        let ks_pc =
            derive_session_keys(&ss_ee_c, &ss_si_c, &ss_static_c, &id_phone, &id_pc).unwrap();

        assert_eq!(*ss_static_p, *ss_static_c);
        assert_eq!(*ss_ee_p, *ss_ee_c);
        assert_eq!(*ss_si_p, *ss_si_c, "ss_si must mirror across roles");
        assert_eq!(*ks_phone.p2c, *ks_pc.p2c);
        assert_eq!(*ks_phone.c2p, *ks_pc.c2p);
        assert_ne!(*ks_phone.p2c, *ks_phone.c2p, "directions must differ");
    }

    #[test]
    fn session_keys_change_with_any_input() {
        let base = derive_session_keys(
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &DeviceId([4; 16]),
            &DeviceId([5; 16]),
        )
        .unwrap();
        let diff_ee = derive_session_keys(
            &[9; 32],
            &[2; 32],
            &[3; 32],
            &DeviceId([4; 16]),
            &DeviceId([5; 16]),
        )
        .unwrap();
        let diff_id = derive_session_keys(
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &DeviceId([9; 16]),
            &DeviceId([5; 16]),
        )
        .unwrap();
        assert_ne!(*base.p2c, *diff_ee.p2c);
        assert_ne!(*base.p2c, *diff_id.p2c, "device ids are salt material");
    }

    fn channel_pair() -> (AeadChannel, AeadChannel) {
        let p2c = Zeroizing::new([0x11u8; 32]);
        let c2p = Zeroizing::new([0x22u8; 32]);
        (
            AeadChannel::new(p2c.clone(), c2p.clone()), // phone
            AeadChannel::new(c2p, p2c),                 // pc
        )
    }

    #[test]
    fn aead_round_trip() {
        let (mut phone, mut pc) = channel_pair();
        let sealed = phone.seal(FrameType::ClipPush, b"hello pc").unwrap();
        assert_eq!(&sealed[..8], &0u64.to_le_bytes(), "first counter is 0");
        let opened = pc.open(FrameType::ClipPush, &sealed).unwrap();
        assert_eq!(opened, b"hello pc");
    }

    #[test]
    fn aead_rejects_replay() {
        let (mut phone, mut pc) = channel_pair();
        let first = phone.seal(FrameType::ClipPush, b"a").unwrap();
        let second = phone.seal(FrameType::ClipPush, b"b").unwrap();

        pc.open(FrameType::ClipPush, &first).unwrap();
        pc.open(FrameType::ClipPush, &second).unwrap();
        // Replaying an already-accepted counter must fail.
        assert!(pc.open(FrameType::ClipPush, &first).is_err());
    }

    #[test]
    fn aead_rejects_wrong_frame_type() {
        // AAD binds the frame type, so a ClipPush ciphertext cannot masquerade as StageItem.
        let (mut phone, mut pc) = channel_pair();
        let sealed = phone.seal(FrameType::ClipPush, b"payload").unwrap();
        assert!(pc.open(FrameType::StageItem, &sealed).is_err());
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let (mut phone, mut pc) = channel_pair();
        let mut sealed = phone.seal(FrameType::ClipPush, b"payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(pc.open(FrameType::ClipPush, &sealed).is_err());
    }

    #[test]
    fn aead_rejects_short_payload() {
        let (_, mut pc) = channel_pair();
        assert!(pc.open(FrameType::ClipPush, &[0u8; 4]).is_err());
    }

    #[test]
    fn forged_frame_does_not_advance_receiver_counter() {
        let (mut phone, mut pc) = channel_pair();
        let good = phone.seal(FrameType::ClipPush, b"real").unwrap();

        // A forgery claiming counter 0 must fail *and* leave the channel able to
        // accept the genuine counter-0 frame afterwards.
        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        assert!(pc.open(FrameType::ClipPush, &forged).is_err());
        assert_eq!(pc.open(FrameType::ClipPush, &good).unwrap(), b"real");
    }

    #[test]
    fn nonce_layout_matches_protocol() {
        // 4 zero bytes ‖ counter_le_u64
        let n = AeadChannel::nonce_for(1);
        assert_eq!(&n[..4], &[0, 0, 0, 0]);
        assert_eq!(&n[4..], &1u64.to_le_bytes());
    }

    #[test]
    fn mac_verify_roundtrip_and_rejects_tamper() {
        let key = [0x5au8; 32];
        let tag = keyed_mac(&key, b"message");
        assert!(verify_mac(&key, b"message", &tag));
        assert!(!verify_mac(&key, b"other", &tag));
        assert!(!verify_mac(&[0u8; 32], b"message", &tag));
        assert!(
            !verify_mac(&key, b"message", &tag[..31]),
            "short tag rejected"
        );
    }

    // --- SAS ---

    /// T-02 acceptance: `digest 0xDEADBEEF → expected 4 emoji`.
    ///
    /// 0xDEADBEEF = 1101_1110_1010_1101_1011_1110_1110_1111
    /// 6-bit groups, high bits first: 110111=55, 101010=42, 110110=54, 111110=62.
    #[test]
    fn sas_vector_deadbeef() {
        assert_eq!(sas_emoji(0xDEAD_BEEF), ["🚲", "🎺", "🚚", "🛴"]);
    }

    #[test]
    fn sas_index_extraction_is_high_bits_first() {
        // Top 6 bits set, rest zero → first emoji is index 63, others index 0.
        assert_eq!(
            sas_emoji(0b111111 << 26),
            [SAS_EMOJI[63], SAS_EMOJI[0], SAS_EMOJI[0], SAS_EMOJI[0]]
        );
        assert_eq!(sas_emoji(0), [SAS_EMOJI[0]; 4]);
    }

    #[test]
    fn sas_table_is_64_unique_single_codepoint_emoji() {
        let mut seen = std::collections::HashSet::new();
        for e in SAS_EMOJI {
            assert!(seen.insert(e), "duplicate emoji in SAS table: {e}");
            assert_eq!(
                e.chars().count(),
                1,
                "SAS emoji must be single-codepoint (no ZWJ/variation selector): {e}"
            );
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn sas_matches_on_both_sides_and_differs_under_mitm() {
        let phone = IdentityKeypair::from_seed([1u8; 32]);
        let pc = IdentityKeypair::from_seed([2u8; 32]);
        let eph_phone = EphemeralKeypair::from_seed([3u8; 32]);
        let eph_pc = EphemeralKeypair::from_seed([4u8; 32]);
        let token = [0xABu8; 16];

        let ss_p = eph_phone.dh(&eph_pc.public_bytes());
        let ss_c = eph_pc.dh(&eph_phone.public_bytes());
        let sas_p = sas_emoji(sas_digest(&sas_input(
            &ss_p,
            &phone.public_bytes(),
            &pc.public_bytes(),
            &token,
        )));
        let sas_c = sas_emoji(sas_digest(&sas_input(
            &ss_c,
            &phone.public_bytes(),
            &pc.public_bytes(),
            &token,
        )));
        assert_eq!(sas_p, sas_c);

        // MITM swaps in its own ephemeral → different shared secret → different SAS.
        let mitm = EphemeralKeypair::from_seed([99u8; 32]);
        let ss_mitm = eph_phone.dh(&mitm.public_bytes());
        let sas_mitm = sas_emoji(sas_digest(&sas_input(
            &ss_mitm,
            &phone.public_bytes(),
            &pc.public_bytes(),
            &token,
        )));
        assert_ne!(sas_p, sas_mitm, "ephemeral swap must change the SAS");
    }

    // --- property tests ---
    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Counters must strictly increase; any counter at or below the high-water
            /// mark is rejected regardless of ciphertext validity.
            #[test]
            fn counters_are_strictly_increasing(n in 1usize..64) {
                let (mut phone, mut pc) = channel_pair();
                let mut sealed = Vec::new();
                for i in 0..n {
                    sealed.push(phone.seal(FrameType::ClipPush, &[i as u8]).unwrap());
                }
                for (i, s) in sealed.iter().enumerate() {
                    let ctr = u64::from_le_bytes(s[..8].try_into().unwrap());
                    prop_assert_eq!(ctr, i as u64);
                    prop_assert!(pc.open(FrameType::ClipPush, s).is_ok());
                }
                // Every previously accepted frame is now a replay.
                for s in &sealed {
                    prop_assert!(pc.open(FrameType::ClipPush, s).is_err());
                }
            }

            /// Round-trip holds for arbitrary payloads and encrypted frame types.
            #[test]
            fn seal_open_round_trips(
                payload in proptest::collection::vec(any::<u8>(), 0..2048),
                ty_idx in 0usize..6,
            ) {
                let tys = [
                    FrameType::ClipPush, FrameType::ClipAck, FrameType::StageList,
                    FrameType::StageGet, FrameType::StageItem, FrameType::Ping,
                ];
                let ty = tys[ty_idx];
                let (mut phone, mut pc) = channel_pair();
                let sealed = phone.seal(ty, &payload).unwrap();
                prop_assert_eq!(pc.open(ty, &sealed).unwrap(), payload);
            }

            /// Distinct digests should almost always give distinct emoji, and the
            /// mapping must never panic or index out of bounds.
            #[test]
            fn sas_emoji_total_and_in_range(d: u32) {
                let e = sas_emoji(d);
                for s in e {
                    prop_assert!(SAS_EMOJI.contains(&s));
                }
            }
        }
    }
}
