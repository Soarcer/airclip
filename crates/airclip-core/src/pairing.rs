//! Pairing state machine, PROTOCOL.md §7. Sans-io: `on_frame` returns actions, the
//! caller owns the socket and the clock (ARCHITECTURE §3).
//!
//! Threat model recap (PROTOCOL §7): a passive attacker on the LAN learns only public
//! keys; an active MITM is caught by the 4-emoji SAS comparison. The pair token is a
//! drive-by filter, not an authentication secret.

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::cbor::{MapBuilder, MapReader};
use crate::crypto::{self, device_id_from_pk, EphemeralKeypair, IdentityKeypair, PublicKeyBytes};
use crate::error::{Error, Result};
use crate::frame::{Frame, FrameType};
use crate::DeviceId;

/// Pair-token lifetime, PROTOCOL §7.1.
pub const PAIR_TOKEN_TTL_MS: u64 = 10 * 60 * 1000;
pub const QR_SCHEME: &str = "airclip";

// CBOR keys, PROTOCOL §7.2. Append-only (ADR-5).
mod key {
    pub const PAIR_TOKEN: u64 = 1;
    pub const DEVICE_ID: u64 = 2;
    pub const PK_ID: u64 = 3;
    pub const DISPLAY_NAME: u64 = 4;
    pub const EPH_PK: u64 = 5;
    // PAIR_ACK / PAIR_CONFIRM reuse key 1 for their single field.
    pub const ACK_EPH_PK: u64 = 1;
    pub const CONFIRM_MAC: u64 = 1;
}

/// A persisted pairing (PROTOCOL §3). Serialized as JSON inside the platform keystore:
/// DPAPI-sealed on Windows, a Keychain item on iOS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRecord {
    /// Hex, 32 chars.
    pub device_id: String,
    /// base64url, unpadded.
    pub public_key: String,
    pub display_name: String,
    pub created_at_ms: u64,
    pub last_seen_ms: u64,
}

impl PairingRecord {
    pub fn new(device_id: &DeviceId, pk: &PublicKeyBytes, name: &str, now_ms: u64) -> Self {
        Self {
            device_id: device_id.hex(),
            public_key: BASE64_URL_SAFE_NO_PAD.encode(pk),
            display_name: name.to_owned(),
            created_at_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }

    pub fn public_key_bytes(&self) -> Result<PublicKeyBytes> {
        let raw = BASE64_URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| Error::Cbor("pairing record: bad base64 public key".into()))?;
        raw.try_into()
            .map_err(|_| Error::Cbor("pairing record: public key must be 32 bytes".into()))
    }

    pub fn device_id_bytes(&self) -> Result<DeviceId> {
        let raw = hex::decode(&self.device_id)
            .map_err(|_| Error::Cbor("pairing record: bad hex device id".into()))?;
        let arr: [u8; 16] = raw
            .try_into()
            .map_err(|_| Error::Cbor("pairing record: device id must be 16 bytes".into()))?;
        Ok(DeviceId(arr))
    }
}

/// Parsed `airclip://pair?...` payload (PROTOCOL §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrPayload {
    pub version: u8,
    pub device_id: DeviceId,
    pub public_key: PublicKeyBytes,
    pub display_name: String,
    /// `ip:port` candidates, in the order the PC advertised them.
    pub hosts: Vec<String>,
    pub pair_token: [u8; 16],
}

impl QrPayload {
    pub fn to_url(&self) -> String {
        // Built by hand rather than via Url::parse so the field order matches
        // PROTOCOL §7.1 exactly — QR density is worth the small ugliness.
        let mut s = format!(
            "{QR_SCHEME}://pair?v={}&id={}&pk={}&nm={}&hosts={}&tok={}",
            self.version,
            self.device_id.hex(),
            BASE64_URL_SAFE_NO_PAD.encode(self.public_key),
            urlencode(&self.display_name),
            urlencode(&self.hosts.join(",")),
            BASE64_URL_SAFE_NO_PAD.encode(self.pair_token),
        );
        s.shrink_to_fit();
        s
    }

    pub fn parse(url: &str) -> Result<Self> {
        let u = Url::parse(url).map_err(|e| Error::Cbor(format!("bad QR url: {e}")))?;
        if u.scheme() != QR_SCHEME {
            return Err(Error::Cbor("QR url: wrong scheme".into()));
        }
        if u.host_str() != Some("pair") {
            return Err(Error::Cbor("QR url: expected airclip://pair".into()));
        }

        let mut version = None;
        let mut device_id = None;
        let mut public_key = None;
        let mut display_name = String::new();
        let mut hosts = Vec::new();
        let mut pair_token = None;

        for (k, v) in u.query_pairs() {
            match k.as_ref() {
                "v" => version = v.parse::<u8>().ok(),
                "id" => {
                    let raw = hex::decode(v.as_ref())
                        .map_err(|_| Error::Cbor("QR url: bad id hex".into()))?;
                    let arr: [u8; 16] = raw
                        .try_into()
                        .map_err(|_| Error::Cbor("QR url: id must be 16 bytes".into()))?;
                    device_id = Some(DeviceId(arr));
                }
                "pk" => {
                    let raw = BASE64_URL_SAFE_NO_PAD
                        .decode(v.as_ref())
                        .map_err(|_| Error::Cbor("QR url: bad pk base64".into()))?;
                    let arr: PublicKeyBytes = raw
                        .try_into()
                        .map_err(|_| Error::Cbor("QR url: pk must be 32 bytes".into()))?;
                    public_key = Some(arr);
                }
                "nm" => display_name = v.into_owned(),
                "hosts" => {
                    hosts = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_owned())
                        .collect()
                }
                "tok" => {
                    let raw = BASE64_URL_SAFE_NO_PAD
                        .decode(v.as_ref())
                        .map_err(|_| Error::Cbor("QR url: bad token base64".into()))?;
                    let arr: [u8; 16] = raw
                        .try_into()
                        .map_err(|_| Error::Cbor("QR url: token must be 16 bytes".into()))?;
                    pair_token = Some(arr);
                }
                _ => {} // forward-compatible: ignore unknown params
            }
        }

        let version = version.ok_or_else(|| Error::Cbor("QR url: missing v".into()))?;
        if version != crate::PROTOCOL_VERSION {
            return Err(Error::Cbor(format!(
                "QR url: unsupported version {version}"
            )));
        }
        let device_id = device_id.ok_or_else(|| Error::Cbor("QR url: missing id".into()))?;
        let public_key = public_key.ok_or_else(|| Error::Cbor("QR url: missing pk".into()))?;
        let pair_token = pair_token.ok_or_else(|| Error::Cbor("QR url: missing tok".into()))?;

        // The QR carries both; a mismatch means a malformed or tampered code.
        if device_id_from_pk(&public_key) != device_id {
            return Err(Error::Cbor("QR url: id does not match pk".into()));
        }

        Ok(Self {
            version,
            device_id,
            public_key,
            display_name,
            hosts,
            pair_token,
        })
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// What the caller must do next. The FSM never touches a socket itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingAction {
    Send(Frame),
    /// Show these emoji and ask the user to compare (PROTOCOL §7.2 step 5).
    ShowSas([&'static str; 4]),
    /// Pairing succeeded; persist this record.
    Completed(Box<PairingRecord>),
    /// Abort and close the connection.
    Failed(&'static str),
}

// ---------------------------------------------------------------------------
// PC role
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcState {
    AwaitingReq,
    AwaitingConfirm,
    Done,
    Failed,
}

/// PC side of pairing: displays the QR, validates the token, shows the SAS, verifies
/// the confirming MAC.
pub struct PcPairing<'a> {
    identity: &'a IdentityKeypair,
    display_name: String,
    hosts: Vec<String>,
    token: [u8; 16],
    issued_ms: u64,
    ttl_ms: u64,
    token_used: bool,
    state: PcState,
    eph: Option<EphemeralKeypair>,
    peer: Option<PeerHandshake>,
    sas_input: Option<Zeroizing<Vec<u8>>>,
}

struct PeerHandshake {
    device_id: DeviceId,
    pk: PublicKeyBytes,
    display_name: String,
}

impl<'a> PcPairing<'a> {
    pub fn new(
        identity: &'a IdentityKeypair,
        display_name: impl Into<String>,
        hosts: Vec<String>,
        now_ms: u64,
    ) -> Result<Self> {
        let mut token = [0u8; 16];
        getrandom::fill(&mut token).map_err(|_| Error::Crypto)?;
        Ok(Self {
            identity,
            display_name: display_name.into(),
            hosts,
            token,
            issued_ms: now_ms,
            ttl_ms: PAIR_TOKEN_TTL_MS,
            token_used: false,
            state: PcState::AwaitingReq,
            eph: None,
            peer: None,
            sas_input: None,
        })
    }

    /// Deterministic constructor for tests and `--simulate-peer` (T-10).
    pub fn with_token(
        identity: &'a IdentityKeypair,
        display_name: impl Into<String>,
        hosts: Vec<String>,
        token: [u8; 16],
        now_ms: u64,
    ) -> Self {
        Self {
            identity,
            display_name: display_name.into(),
            hosts,
            token,
            issued_ms: now_ms,
            ttl_ms: PAIR_TOKEN_TTL_MS,
            token_used: false,
            state: PcState::AwaitingReq,
            eph: None,
            peer: None,
            sas_input: None,
        }
    }

    pub fn qr_payload(&self) -> QrPayload {
        QrPayload {
            version: crate::PROTOCOL_VERSION,
            device_id: self.identity.device_id(),
            public_key: self.identity.public_bytes(),
            display_name: self.display_name.clone(),
            hosts: self.hosts.clone(),
            pair_token: self.token,
        }
    }

    pub fn qr_url(&self) -> String {
        self.qr_payload().to_url()
    }

    fn token_valid(&self, presented: &[u8; 16], now_ms: u64) -> Option<&'static str> {
        // Constant-time-ish compare is unnecessary here: the token is not a long-term
        // secret and a mismatch closes the connection either way (PROTOCOL §7.1).
        if presented != &self.token {
            return Some("bad pair token");
        }
        if self.token_used {
            return Some("pair token already used");
        }
        if now_ms.saturating_sub(self.issued_ms) > self.ttl_ms {
            return Some("pair token expired");
        }
        None
    }

    pub fn on_frame(&mut self, frame: &Frame, now_ms: u64) -> Vec<PairingAction> {
        match (self.state, frame.ty) {
            (PcState::AwaitingReq, FrameType::PairReq) => self.on_pair_req(frame, now_ms),
            (PcState::AwaitingConfirm, FrameType::PairConfirm) => self.on_confirm(frame, now_ms),
            _ => {
                self.state = PcState::Failed;
                vec![PairingAction::Failed("unexpected frame for pairing state")]
            }
        }
    }

    fn on_pair_req(&mut self, frame: &Frame, now_ms: u64) -> Vec<PairingAction> {
        let fail = |s: &mut Self, msg: &'static str| {
            s.state = PcState::Failed;
            vec![PairingAction::Failed(msg)]
        };

        let Ok(r) = MapReader::from_slice(&frame.payload) else {
            return fail(self, "malformed PAIR_REQ");
        };
        let (Ok(token), Ok(peer_id), Ok(peer_pk), Ok(eph_pk_i)) = (
            r.byte_array::<16>(key::PAIR_TOKEN),
            r.byte_array::<16>(key::DEVICE_ID),
            r.byte_array::<32>(key::PK_ID),
            r.byte_array::<32>(key::EPH_PK),
        ) else {
            return fail(self, "malformed PAIR_REQ fields");
        };
        let peer_name = r.text(key::DISPLAY_NAME).unwrap_or("iPhone").to_owned();

        if let Some(reason) = self.token_valid(&token, now_ms) {
            return fail(self, reason);
        }
        if device_id_from_pk(&peer_pk) != DeviceId(peer_id) {
            return fail(self, "PAIR_REQ device id does not match public key");
        }
        self.token_used = true;

        let Ok(eph) = EphemeralKeypair::generate() else {
            return fail(self, "ephemeral keygen failed");
        };

        // PROTOCOL §7.2 step 4.
        let ss_eph = eph.dh(&eph_pk_i);
        let sas_input = crypto::sas_input(
            &ss_eph,
            &peer_pk,
            &self.identity.public_bytes(),
            &self.token,
        );
        let sas = crypto::sas_emoji(crypto::sas_digest(&sas_input));

        let ack = MapBuilder::new()
            .bytes(key::ACK_EPH_PK, &eph.public_bytes())
            .to_vec();
        let Ok(ack) = ack else {
            return fail(self, "failed to encode PAIR_ACK");
        };

        self.eph = Some(eph);
        self.peer = Some(PeerHandshake {
            device_id: DeviceId(peer_id),
            pk: peer_pk,
            display_name: peer_name,
        });
        self.sas_input = Some(sas_input);
        self.state = PcState::AwaitingConfirm;

        vec![
            PairingAction::Send(Frame::new(FrameType::PairAck, ack)),
            PairingAction::ShowSas(sas),
        ]
    }

    fn on_confirm(&mut self, frame: &Frame, now_ms: u64) -> Vec<PairingAction> {
        let fail = |s: &mut Self, msg: &'static str| {
            s.state = PcState::Failed;
            vec![PairingAction::Failed(msg)]
        };

        let Ok(r) = MapReader::from_slice(&frame.payload) else {
            return fail(self, "malformed PAIR_CONFIRM");
        };
        let Ok(mac) = r.byte_array::<32>(key::CONFIRM_MAC) else {
            return fail(self, "malformed PAIR_CONFIRM mac");
        };
        let (Some(peer), Some(sas_input)) = (self.peer.as_ref(), self.sas_input.as_ref()) else {
            return fail(self, "confirm without request");
        };

        // k = X25519(sk_id_pc, pk_id_phone) — the mirror of the phone's computation.
        let k = self.identity.dh(&peer.pk);
        if !crypto::verify_mac(&k, sas_input, &mac) {
            return fail(self, "PAIR_CONFIRM mac mismatch");
        }

        let record = PairingRecord::new(&peer.device_id, &peer.pk, &peer.display_name, now_ms);
        self.state = PcState::Done;
        vec![PairingAction::Completed(Box::new(record))]
    }

    pub fn is_done(&self) -> bool {
        self.state == PcState::Done
    }
}

// ---------------------------------------------------------------------------
// Phone role
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhoneState {
    AwaitingAck,
    AwaitingUserConfirm,
    Done,
    Failed,
}

/// Phone side of pairing: scans the QR, sends PAIR_REQ, shows the SAS, and only after
/// the user confirms sends PAIR_CONFIRM.
pub struct PhonePairing<'a> {
    identity: &'a IdentityKeypair,
    display_name: String,
    qr: QrPayload,
    eph: EphemeralKeypair,
    state: PhoneState,
    sas_input: Option<Zeroizing<Vec<u8>>>,
}

impl<'a> PhonePairing<'a> {
    /// Build the initial PAIR_REQ. Returns the FSM plus the frame to send.
    pub fn start(
        identity: &'a IdentityKeypair,
        display_name: impl Into<String>,
        qr: QrPayload,
    ) -> Result<(Self, Frame)> {
        Self::start_with_ephemeral(identity, display_name, qr, EphemeralKeypair::generate()?)
    }

    /// Deterministic variant for tests.
    pub fn start_with_ephemeral(
        identity: &'a IdentityKeypair,
        display_name: impl Into<String>,
        qr: QrPayload,
        eph: EphemeralKeypair,
    ) -> Result<(Self, Frame)> {
        let display_name = display_name.into();
        let payload = MapBuilder::new()
            .bytes(key::PAIR_TOKEN, &qr.pair_token)
            .bytes(key::DEVICE_ID, &identity.device_id().0)
            .bytes(key::PK_ID, &identity.public_bytes())
            .text(key::DISPLAY_NAME, &display_name)
            .bytes(key::EPH_PK, &eph.public_bytes())
            .to_vec()?;

        let me = Self {
            identity,
            display_name,
            qr,
            eph,
            state: PhoneState::AwaitingAck,
            sas_input: None,
        };
        Ok((me, Frame::new(FrameType::PairReq, payload)))
    }

    pub fn on_frame(&mut self, frame: &Frame) -> Vec<PairingAction> {
        match (self.state, frame.ty) {
            (PhoneState::AwaitingAck, FrameType::PairAck) => self.on_ack(frame),
            _ => {
                self.state = PhoneState::Failed;
                vec![PairingAction::Failed("unexpected frame for pairing state")]
            }
        }
    }

    fn on_ack(&mut self, frame: &Frame) -> Vec<PairingAction> {
        let fail = |s: &mut Self, msg: &'static str| {
            s.state = PhoneState::Failed;
            vec![PairingAction::Failed(msg)]
        };

        let Ok(r) = MapReader::from_slice(&frame.payload) else {
            return fail(self, "malformed PAIR_ACK");
        };
        let Ok(eph_pk_r) = r.byte_array::<32>(key::ACK_EPH_PK) else {
            return fail(self, "malformed PAIR_ACK ephemeral key");
        };

        let ss_eph = self.eph.dh(&eph_pk_r);
        let sas_input = crypto::sas_input(
            &ss_eph,
            &self.identity.public_bytes(),
            &self.qr.public_key,
            &self.qr.pair_token,
        );
        let sas = crypto::sas_emoji(crypto::sas_digest(&sas_input));
        self.sas_input = Some(sas_input);
        self.state = PhoneState::AwaitingUserConfirm;
        vec![PairingAction::ShowSas(sas)]
    }

    /// The user tapped "they match". Only now does the confirming MAC go out —
    /// this is the step that makes the MITM check meaningful.
    pub fn confirm_sas(&mut self, now_ms: u64) -> Vec<PairingAction> {
        if self.state != PhoneState::AwaitingUserConfirm {
            return vec![PairingAction::Failed("confirm before SAS was shown")];
        }
        let Some(sas_input) = self.sas_input.as_ref() else {
            return vec![PairingAction::Failed("confirm without SAS basis")];
        };

        // k = X25519(sk_id_phone, pk_id_pc)
        let k = self.identity.dh(&self.qr.public_key);
        let mac = crypto::keyed_mac(&k, sas_input);
        let Ok(payload) = MapBuilder::new().bytes(key::CONFIRM_MAC, &mac).to_vec() else {
            self.state = PhoneState::Failed;
            return vec![PairingAction::Failed("failed to encode PAIR_CONFIRM")];
        };

        let record = PairingRecord::new(
            &self.qr.device_id,
            &self.qr.public_key,
            &self.qr.display_name,
            now_ms,
        );
        self.state = PhoneState::Done;
        vec![
            PairingAction::Send(Frame::new(FrameType::PairConfirm, payload)),
            PairingAction::Completed(Box::new(record)),
        ]
    }

    /// The user tapped "they don't match" — abort without sending anything.
    pub fn reject_sas(&mut self) -> Vec<PairingAction> {
        self.state = PhoneState::Failed;
        vec![PairingAction::Failed("user rejected SAS")]
    }

    pub fn is_done(&self) -> bool {
        self.state == PhoneState::Done
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    fn pc_identity() -> IdentityKeypair {
        IdentityKeypair::from_seed([0xC1; 32])
    }
    fn phone_identity() -> IdentityKeypair {
        IdentityKeypair::from_seed([0xF0; 32])
    }

    fn hosts() -> Vec<String> {
        vec!["192.168.4.20:49517".into(), "[fe80::1]:49517".into()]
    }

    /// Drives a full pair and returns (pc_actions, phone_record, pc_record).
    fn run_happy_path() -> (PairingRecord, PairingRecord) {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "SAMMAMISH-PC", hosts(), [0x5A; 16], NOW);

        let qr = QrPayload::parse(&pc.qr_url()).unwrap();
        let (mut phone, req) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "Bernhard's iPhone",
            qr,
            EphemeralKeypair::from_seed([0xE1; 32]),
        )
        .unwrap();

        // PC handles PAIR_REQ → PAIR_ACK + SAS
        let pc_actions = pc.on_frame(&req, NOW);
        let (ack, pc_sas) = match pc_actions.as_slice() {
            [PairingAction::Send(f), PairingAction::ShowSas(s)] => (f.clone(), *s),
            other => panic!("unexpected PC actions: {other:?}"),
        };

        // Phone handles PAIR_ACK → SAS
        let ph_actions = phone.on_frame(&ack);
        let ph_sas = match ph_actions.as_slice() {
            [PairingAction::ShowSas(s)] => *s,
            other => panic!("unexpected phone actions: {other:?}"),
        };
        assert_eq!(pc_sas, ph_sas, "both sides must show the same emoji");

        // User confirms → PAIR_CONFIRM
        let confirm_actions = phone.confirm_sas(NOW);
        let (confirm, phone_record) = match confirm_actions.as_slice() {
            [PairingAction::Send(f), PairingAction::Completed(r)] => (f.clone(), (**r).clone()),
            other => panic!("unexpected confirm actions: {other:?}"),
        };

        let pc_final = pc.on_frame(&confirm, NOW);
        let pc_record = match pc_final.as_slice() {
            [PairingAction::Completed(r)] => (**r).clone(),
            other => panic!("unexpected PC final actions: {other:?}"),
        };

        assert!(pc.is_done() && phone.is_done());
        (phone_record, pc_record)
    }

    #[test]
    fn happy_path_both_roles() {
        let (phone_record, pc_record) = run_happy_path();

        // Each side stored the *other* device.
        assert_eq!(phone_record.device_id, pc_identity().device_id().hex());
        assert_eq!(pc_record.device_id, phone_identity().device_id().hex());
        assert_eq!(phone_record.display_name, "SAMMAMISH-PC");
        assert_eq!(pc_record.display_name, "Bernhard's iPhone");
        assert_eq!(
            phone_record.public_key_bytes().unwrap(),
            pc_identity().public_bytes()
        );
        assert_eq!(
            pc_record.public_key_bytes().unwrap(),
            phone_identity().public_bytes()
        );
    }

    #[test]
    fn pairing_record_json_round_trip() {
        let (phone_record, _) = run_happy_path();
        let json = serde_json::to_string(&phone_record).unwrap();
        let back: PairingRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, phone_record);
        assert_eq!(back.device_id_bytes().unwrap(), pc_identity().device_id());
    }

    // --- QR payload ---

    #[test]
    fn qr_url_round_trips() {
        let pc_id = pc_identity();
        let pc = PcPairing::with_token(&pc_id, "Bernhard's PC (office)", hosts(), [0x11; 16], NOW);
        let url = pc.qr_url();
        assert!(url.starts_with("airclip://pair?v=1&"));
        let parsed = QrPayload::parse(&url).unwrap();
        assert_eq!(parsed, pc.qr_payload());
        assert_eq!(parsed.display_name, "Bernhard's PC (office)");
        assert_eq!(parsed.hosts, hosts());
    }

    #[test]
    fn qr_rejects_malformed_input() {
        let good = PcPairing::with_token(&pc_identity(), "PC", hosts(), [1; 16], NOW).qr_url();

        let cases: Vec<(String, &str)> = vec![
            ("https://pair?v=1".into(), "wrong scheme"),
            ("airclip://other?v=1".into(), "wrong host"),
            (good.replace("v=1", "v=2"), "unsupported version"),
            (good.replace("&tok=", "&xok="), "missing token"),
            (good.replace("&pk=", "&xk="), "missing pk"),
        ];
        for (url, why) in cases {
            assert!(QrPayload::parse(&url).is_err(), "should reject: {why}");
        }
    }

    #[test]
    fn qr_rejects_id_pk_mismatch() {
        // Swap in a different device id than the pk hashes to.
        let pc_id = pc_identity();
        let pc = PcPairing::with_token(&pc_id, "PC", hosts(), [1; 16], NOW);
        let mut p = pc.qr_payload();
        p.device_id = DeviceId([0xFF; 16]);
        assert!(QrPayload::parse(&p.to_url()).is_err());
    }

    #[test]
    fn qr_survives_unicode_and_reserved_chars_in_name() {
        let pc_id = pc_identity();
        let pc = PcPairing::with_token(&pc_id, "Büro-PC & Späß #1", hosts(), [1; 16], NOW);
        let parsed = QrPayload::parse(&pc.qr_url()).unwrap();
        assert_eq!(parsed.display_name, "Büro-PC & Späß #1");
    }

    // --- token rules (PROTOCOL §7.1) ---

    fn pair_req_with_token(ph_id: &IdentityKeypair, qr: &QrPayload, token: [u8; 16]) -> Frame {
        let mut qr = qr.clone();
        qr.pair_token = token;
        let (_, req) = PhonePairing::start_with_ephemeral(
            ph_id,
            "iPhone",
            qr,
            EphemeralKeypair::from_seed([0xE2; 32]),
        )
        .unwrap();
        req
    }

    #[test]
    fn rejects_wrong_token() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0xAA; 16], NOW);
        let qr = pc.qr_payload();
        let req = pair_req_with_token(&ph_id, &qr, [0xBB; 16]);
        assert!(matches!(
            pc.on_frame(&req, NOW).as_slice(),
            [PairingAction::Failed("bad pair token")]
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0xAA; 16], NOW);
        let qr = pc.qr_payload();
        let req = pair_req_with_token(&ph_id, &qr, [0xAA; 16]);
        let late = NOW + PAIR_TOKEN_TTL_MS + 1;
        assert!(matches!(
            pc.on_frame(&req, late).as_slice(),
            [PairingAction::Failed("pair token expired")]
        ));
    }

    #[test]
    fn token_is_accepted_at_the_ttl_boundary() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0xAA; 16], NOW);
        let qr = pc.qr_payload();
        let req = pair_req_with_token(&ph_id, &qr, [0xAA; 16]);
        let actions = pc.on_frame(&req, NOW + PAIR_TOKEN_TTL_MS);
        assert!(matches!(
            actions.as_slice(),
            [PairingAction::Send(_), PairingAction::ShowSas(_)]
        ));
    }

    #[test]
    fn rejects_reused_token() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0xAA; 16], NOW);
        let qr = pc.qr_payload();

        let first = pair_req_with_token(&ph_id, &qr, [0xAA; 16]);
        assert!(matches!(
            pc.on_frame(&first, NOW).as_slice(),
            [PairingAction::Send(_), PairingAction::ShowSas(_)]
        ));

        // A second PAIR_REQ on the same token must fail — but the FSM has already
        // advanced past AwaitingReq, so it fails on state, which is equally fatal.
        let second = pair_req_with_token(&ph_id, &qr, [0xAA; 16]);
        assert!(matches!(
            pc.on_frame(&second, NOW).as_slice(),
            [PairingAction::Failed(_)]
        ));
    }

    #[test]
    fn reused_token_rejected_on_a_fresh_connection() {
        // Models the real single-use rule: same PcPairing, token already burned,
        // FSM reset to awaiting a request (e.g. the first peer dropped).
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0xAA; 16], NOW);
        let qr = pc.qr_payload();
        pc.on_frame(&pair_req_with_token(&ph_id, &qr, [0xAA; 16]), NOW);

        pc.state = PcState::AwaitingReq; // fresh connection, token already used
        let again = pair_req_with_token(&ph_id, &qr, [0xAA; 16]);
        assert!(matches!(
            pc.on_frame(&again, NOW).as_slice(),
            [PairingAction::Failed("pair token already used")]
        ));
    }

    #[test]
    fn rejects_pair_req_whose_id_does_not_match_its_pk() {
        let pc_id = pc_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0xAA; 16], NOW);
        let ph_id = phone_identity();

        let payload = MapBuilder::new()
            .bytes(key::PAIR_TOKEN, &[0xAA; 16])
            .bytes(key::DEVICE_ID, &[0x00; 16]) // lie about the id
            .bytes(key::PK_ID, &ph_id.public_bytes())
            .text(key::DISPLAY_NAME, "iPhone")
            .bytes(key::EPH_PK, &[0x09; 32])
            .to_vec()
            .unwrap();

        assert!(matches!(
            pc.on_frame(&Frame::new(FrameType::PairReq, payload), NOW)
                .as_slice(),
            [PairingAction::Failed(
                "PAIR_REQ device id does not match public key"
            )]
        ));
    }

    // --- MITM / MAC ---

    #[test]
    fn mitm_ephemeral_swap_yields_different_sas_on_each_side() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0x5A; 16], NOW);
        let qr = QrPayload::parse(&pc.qr_url()).unwrap();

        let (mut phone, req) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "iPhone",
            qr,
            EphemeralKeypair::from_seed([0xE1; 32]),
        )
        .unwrap();

        // PC sees the genuine request and returns its own ephemeral.
        let pc_actions = pc.on_frame(&req, NOW);
        let pc_sas = match pc_actions.as_slice() {
            [PairingAction::Send(_), PairingAction::ShowSas(s)] => *s,
            other => panic!("unexpected: {other:?}"),
        };

        // An active MITM replaces the PAIR_ACK ephemeral with its own.
        let mitm = EphemeralKeypair::from_seed([0x99; 32]);
        let forged = Frame::new(
            FrameType::PairAck,
            MapBuilder::new()
                .bytes(key::ACK_EPH_PK, &mitm.public_bytes())
                .to_vec()
                .unwrap(),
        );
        let ph_sas = match phone.on_frame(&forged).as_slice() {
            [PairingAction::ShowSas(s)] => *s,
            other => panic!("unexpected: {other:?}"),
        };

        assert_ne!(
            pc_sas, ph_sas,
            "SAS must diverge when the ephemeral is swapped — this is the whole MITM defence"
        );
    }

    #[test]
    fn confirm_with_bad_mac_is_rejected() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0x5A; 16], NOW);
        let qr = QrPayload::parse(&pc.qr_url()).unwrap();
        let (mut phone, req) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "iPhone",
            qr,
            EphemeralKeypair::from_seed([0xE1; 32]),
        )
        .unwrap();

        let ack = match pc.on_frame(&req, NOW).as_slice() {
            [PairingAction::Send(f), _] => f.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        phone.on_frame(&ack);

        let bad = Frame::new(
            FrameType::PairConfirm,
            MapBuilder::new()
                .bytes(key::CONFIRM_MAC, &[0u8; 32])
                .to_vec()
                .unwrap(),
        );
        assert!(matches!(
            pc.on_frame(&bad, NOW).as_slice(),
            [PairingAction::Failed("PAIR_CONFIRM mac mismatch")]
        ));
        assert!(!pc.is_done());
    }

    #[test]
    fn confirm_from_a_different_identity_is_rejected() {
        // An attacker who saw the SAS basis still cannot produce the MAC without
        // the phone's identity key.
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let attacker = IdentityKeypair::from_seed([0xAB; 32]);

        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0x5A; 16], NOW);
        let qr = QrPayload::parse(&pc.qr_url()).unwrap();
        let (mut phone, req) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "iPhone",
            qr.clone(),
            EphemeralKeypair::from_seed([0xE1; 32]),
        )
        .unwrap();
        let ack = match pc.on_frame(&req, NOW).as_slice() {
            [PairingAction::Send(f), _] => f.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        phone.on_frame(&ack);

        // Forge a CONFIRM using the attacker's DH with the PC.
        let sas_input = phone.sas_input.clone().unwrap();
        let k = attacker.dh(&qr.public_key);
        let mac = crypto::keyed_mac(&k, &sas_input);
        let forged = Frame::new(
            FrameType::PairConfirm,
            MapBuilder::new()
                .bytes(key::CONFIRM_MAC, &mac)
                .to_vec()
                .unwrap(),
        );
        assert!(matches!(
            pc.on_frame(&forged, NOW).as_slice(),
            [PairingAction::Failed("PAIR_CONFIRM mac mismatch")]
        ));
    }

    // --- state machine discipline ---

    #[test]
    fn out_of_order_frames_fail_both_roles() {
        let pc_id = pc_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [1; 16], NOW);
        // CONFIRM before REQ
        let f = Frame::new(
            FrameType::PairConfirm,
            MapBuilder::new().bytes(1, &[0; 32]).to_vec().unwrap(),
        );
        assert!(matches!(
            pc.on_frame(&f, NOW).as_slice(),
            [PairingAction::Failed(_)]
        ));

        let ph_id = phone_identity();
        let qr = PcPairing::with_token(&pc_id, "PC", hosts(), [1; 16], NOW).qr_payload();
        let (mut phone, _) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "iPhone",
            qr,
            EphemeralKeypair::from_seed([3; 32]),
        )
        .unwrap();
        // REQ arriving at the phone is nonsense
        let f = Frame::new(FrameType::PairReq, vec![]);
        assert!(matches!(
            phone.on_frame(&f).as_slice(),
            [PairingAction::Failed(_)]
        ));
    }

    #[test]
    fn phone_cannot_confirm_before_seeing_sas() {
        let ph_id = phone_identity();
        let pc_id = pc_identity();
        let qr = PcPairing::with_token(&pc_id, "PC", hosts(), [1; 16], NOW).qr_payload();
        let (mut phone, _) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "iPhone",
            qr,
            EphemeralKeypair::from_seed([3; 32]),
        )
        .unwrap();
        assert!(matches!(
            phone.confirm_sas(NOW).as_slice(),
            [PairingAction::Failed("confirm before SAS was shown")]
        ));
    }

    #[test]
    fn user_rejecting_sas_sends_nothing() {
        let pc_id = pc_identity();
        let ph_id = phone_identity();
        let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [0x5A; 16], NOW);
        let qr = QrPayload::parse(&pc.qr_url()).unwrap();
        let (mut phone, req) = PhonePairing::start_with_ephemeral(
            &ph_id,
            "iPhone",
            qr,
            EphemeralKeypair::from_seed([0xE1; 32]),
        )
        .unwrap();
        let ack = match pc.on_frame(&req, NOW).as_slice() {
            [PairingAction::Send(f), _] => f.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        phone.on_frame(&ack);

        let actions = phone.reject_sas();
        assert!(matches!(actions.as_slice(), [PairingAction::Failed(_)]));
        assert!(!actions.iter().any(|a| matches!(a, PairingAction::Send(_))));
        assert!(!phone.is_done());
    }

    #[test]
    fn malformed_payloads_never_panic() {
        let pc_id = pc_identity();
        for bad in [
            vec![],
            vec![0xFF],
            vec![0xA1, 0x01],
            b"not cbor at all".to_vec(),
        ] {
            let mut pc = PcPairing::with_token(&pc_id, "PC", hosts(), [1; 16], NOW);
            let f = Frame::new(FrameType::PairReq, bad.clone());
            assert!(matches!(
                pc.on_frame(&f, NOW).as_slice(),
                [PairingAction::Failed(_)]
            ));

            let ph_id = phone_identity();
            let qr = PcPairing::with_token(&pc_id, "PC", hosts(), [1; 16], NOW).qr_payload();
            let (mut phone, _) = PhonePairing::start_with_ephemeral(
                &ph_id,
                "iPhone",
                qr,
                EphemeralKeypair::from_seed([3; 32]),
            )
            .unwrap();
            let f = Frame::new(FrameType::PairAck, bad);
            assert!(matches!(
                phone.on_frame(&f).as_slice(),
                [PairingAction::Failed(_)]
            ));
        }
    }
}
