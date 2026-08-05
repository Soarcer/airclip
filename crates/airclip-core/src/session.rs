//! Session handshake and encrypted traffic, PROTOCOL.md §6 and §8.
//!
//! Sans-io (ARCHITECTURE §3): `on_frame` returns actions, the caller owns the socket and
//! supplies the clock. The phone always initiates (ADR-3); the PC only ever answers.

use crate::cbor::{MapBuilder, MapReader};
use crate::crypto::{self, AeadChannel, EphemeralKeypair, IdentityKeypair, PublicKeyBytes};
use crate::error::{Error, Result, WireErrorCode};
use crate::frame::{Frame, FrameType};
use crate::stage::{StageMeta, StagedClip};
use crate::{ContentType, DeviceId, Role, MAX_TEXT_CLIP, PROTOCOL_VERSION};

/// HELLO timestamp acceptance window, PROTOCOL §6.1 (±120 s).
pub const HELLO_TS_WINDOW_MS: u64 = 120_000;
/// PROTOCOL §2.
pub const SESSION_IDLE_TIMEOUT_MS: u64 = 60_000;
pub const PING_INTERVAL_MS: u64 = 20_000;

// CBOR keys per PROTOCOL §6.1, §8.1, §8.2, §9. Append-only (ADR-5).
mod key {
    // HELLO
    pub const VERSION: u64 = 1;
    pub const INITIATOR_ID: u64 = 2;
    pub const EPH_PK_I: u64 = 3;
    pub const TS: u64 = 4;
    pub const HELLO_MAC: u64 = 5;
    // HELLO_ACK
    pub const EPH_PK_R: u64 = 1;
    pub const ACK_MAC: u64 = 2;
    // CLIP_PUSH
    pub const CLIP_ID: u64 = 1;
    pub const CONTENT_TYPE: u64 = 2;
    pub const BODY: u64 = 3;
    pub const CREATED_AT: u64 = 4;
    pub const SOURCE_NAME: u64 = 5;
    // CLIP_ACK
    pub const ACK_CLIP_ID: u64 = 1;
    pub const ACK_STATUS: u64 = 2;
    // STAGE_*
    pub const STAGE_ITEMS: u64 = 1;
    pub const STAGE_ID: u64 = 1;
    pub const STAGE_META_ID: u64 = 1;
    pub const STAGE_META_TYPE: u64 = 2;
    pub const STAGE_META_PREVIEW: u64 = 3;
    pub const STAGE_META_SIZE: u64 = 4;
    pub const STAGE_META_COPIED_AT: u64 = 5;
    pub const ITEM_ID: u64 = 1;
    pub const ITEM_TYPE: u64 = 2;
    pub const ITEM_BODY: u64 = 3;
    // ERROR
    pub const ERR_CODE: u64 = 1;
    pub const ERR_MSG: u64 = 2;
}

/// A paired peer's identity, as needed to authenticate a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerKey {
    pub device_id: DeviceId,
    pub public_key: PublicKeyBytes,
}

/// Things the application above the session cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Handshake finished; the channel is encrypted from here on.
    Established { peer: DeviceId },
    /// A clip arrived from the peer (PC: write to clipboard; phone: show it).
    ClipArrived {
        clip_id: [u8; 8],
        content_type: ContentType,
        body: Vec<u8>,
        source_name: String,
        created_at_ms: u64,
    },
    /// Our CLIP_PUSH was acknowledged.
    ClipAcked { clip_id: [u8; 8], status: u8 },
    /// PC role: the phone asked for the staged list. Reply via [`Session::send_stage_list`].
    StageListRequested,
    /// PC role: the phone asked for one body. Reply via [`Session::send_stage_item`].
    StageItemRequested { stage_id: [u8; 8] },
    /// Phone role: the staged list arrived.
    StageList(Vec<StageMeta>),
    /// Phone role: a staged body arrived.
    StageItem {
        stage_id: [u8; 8],
        content_type: ContentType,
        body: Vec<u8>,
    },
    /// Peer sent an ERROR frame; the connection is finished.
    PeerError { code: u16, msg: String },
}

/// Instructions for the transport driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    Send(Frame),
    Emit(SessionEvent),
    /// Close the connection. Any `Send` before this must still be flushed.
    Close(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Phone: HELLO sent, waiting for HELLO_ACK.
    AwaitingHelloAck,
    /// PC: waiting for HELLO.
    AwaitingHello,
    Established,
    Closed,
}

/// One connection's protocol state.
pub struct Session {
    role: Role,
    identity: IdentityKeypair,
    state: State,
    /// PC role: peers we will accept a handshake from.
    known_peers: Vec<PeerKey>,
    peer: Option<PeerKey>,
    eph: Option<EphemeralKeypair>,
    /// Phone role: our own HELLO ephemeral public key, needed to verify the ACK MAC.
    eph_pk_i: Option<PublicKeyBytes>,
    channel: Option<AeadChannel>,
    last_activity_ms: u64,
    /// Set by the PC agent's Pause menu item (T-12): reject inbound clips with ERROR 5.
    paused: bool,
}

impl Session {
    /// Phone role: build the HELLO frame that opens a session (PROTOCOL §6.1).
    pub fn start_phone(
        identity: IdentityKeypair,
        peer: PeerKey,
        now_ms: u64,
    ) -> Result<(Self, Frame)> {
        Self::start_phone_with_ephemeral(identity, peer, now_ms, EphemeralKeypair::generate()?)
    }

    /// Deterministic variant for tests and `--simulate-peer`.
    pub fn start_phone_with_ephemeral(
        identity: IdentityKeypair,
        peer: PeerKey,
        now_ms: u64,
        eph: EphemeralKeypair,
    ) -> Result<(Self, Frame)> {
        let ss_static = identity.dh(&peer.public_key);
        let eph_pk_i = eph.public_bytes();

        // MAC covers the canonical encoding of fields 1..4 — see `hello_mac_basis`.
        let basis = hello_mac_basis(&identity.device_id(), &eph_pk_i, now_ms)?;
        let mac = crypto::keyed_mac(&ss_static, &basis);

        let payload = MapBuilder::new()
            .u64(key::VERSION, PROTOCOL_VERSION as u64)
            .bytes(key::INITIATOR_ID, &identity.device_id().0)
            .bytes(key::EPH_PK_I, &eph_pk_i)
            .u64(key::TS, now_ms)
            .bytes(key::HELLO_MAC, &mac)
            .to_vec()?;

        let me = Self {
            role: Role::Phone,
            identity,
            state: State::AwaitingHelloAck,
            known_peers: vec![peer],
            peer: Some(peer),
            eph: Some(eph),
            eph_pk_i: Some(eph_pk_i),
            channel: None,
            last_activity_ms: now_ms,
            paused: false,
        };
        Ok((me, Frame::new(FrameType::Hello, payload)))
    }

    /// PC role: wait for a HELLO from any of `known_peers`.
    pub fn new_pc(identity: IdentityKeypair, known_peers: Vec<PeerKey>, now_ms: u64) -> Self {
        Self {
            role: Role::Pc,
            identity,
            state: State::AwaitingHello,
            known_peers,
            peer: None,
            eph: None,
            eph_pk_i: None,
            channel: None,
            last_activity_ms: now_ms,
            paused: false,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn peer(&self) -> Option<DeviceId> {
        self.peer.map(|p| p.device_id)
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// PROTOCOL §2: either side may close after `SESSION_IDLE_TIMEOUT`.
    pub fn is_idle(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_activity_ms) >= SESSION_IDLE_TIMEOUT_MS
    }

    // -----------------------------------------------------------------
    // Inbound
    // -----------------------------------------------------------------

    pub fn on_frame(&mut self, frame: &Frame, now_ms: u64) -> Vec<SessionAction> {
        if self.state == State::Closed {
            return vec![SessionAction::Close("frame after close")];
        }
        self.last_activity_ms = now_ms;

        match (self.state, frame.ty) {
            (State::AwaitingHello, FrameType::Hello) => self.on_hello(frame, now_ms),
            (State::AwaitingHelloAck, FrameType::HelloAck) => self.on_hello_ack(frame),
            (State::Established, _) if frame.ty.is_encrypted() => self.on_encrypted(frame, now_ms),
            _ => self.fail("unexpected frame for session state"),
        }
    }

    fn fail(&mut self, why: &'static str) -> Vec<SessionAction> {
        self.state = State::Closed;
        vec![SessionAction::Close(why)]
    }

    /// Emit an ERROR frame then close (PROTOCOL §9).
    fn wire_error(&mut self, code: WireErrorCode, msg: &'static str) -> Vec<SessionAction> {
        let payload = MapBuilder::new()
            .u64(key::ERR_CODE, code as u64)
            .text(key::ERR_MSG, msg)
            .to_vec()
            .unwrap_or_default();

        // ERROR is an encrypted frame type; before the handshake completes there is no
        // channel, and PROTOCOL §6.1 requires silent closure anyway ("no oracle").
        let mut out = Vec::new();
        if let Some(ch) = self.channel.as_mut() {
            if let Ok(sealed) = ch.seal(FrameType::Error, &payload) {
                out.push(SessionAction::Send(Frame::new(FrameType::Error, sealed)));
            }
        }
        self.state = State::Closed;
        out.push(SessionAction::Close(msg));
        out
    }

    fn on_hello(&mut self, frame: &Frame, now_ms: u64) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(&frame.payload) else {
            return self.fail("malformed HELLO");
        };
        let (Ok(version), Ok(id), Ok(eph_pk_i), Ok(ts), Ok(mac)) = (
            r.u64(key::VERSION),
            r.byte_array::<16>(key::INITIATOR_ID),
            r.byte_array::<32>(key::EPH_PK_I),
            r.u64(key::TS),
            r.byte_array::<32>(key::HELLO_MAC),
        ) else {
            return self.fail("malformed HELLO fields");
        };

        if version != PROTOCOL_VERSION as u64 {
            return self.wire_error(WireErrorCode::UnsupportedVersion, "unsupported version");
        }

        // Replay window, PROTOCOL §6.1. Absolute difference: a clock ahead of ours is
        // just as suspicious as one behind.
        let skew = ts.abs_diff(now_ms);
        if skew > HELLO_TS_WINDOW_MS {
            return self.fail("HELLO timestamp outside replay window");
        }

        let initiator = DeviceId(id);
        let Some(peer) = self
            .known_peers
            .iter()
            .find(|p| p.device_id == initiator)
            .copied()
        else {
            // PROTOCOL §6.1: close silently, do not reveal whether the id is known.
            return self.fail("HELLO from unpaired device");
        };

        let ss_static = self.identity.dh(&peer.public_key);
        let Ok(basis) = hello_mac_basis(&initiator, &eph_pk_i, ts) else {
            return self.fail("failed to rebuild HELLO mac basis");
        };
        if !crypto::verify_mac(&ss_static, &basis, &mac) {
            return self.fail("HELLO mac mismatch");
        }

        let Ok(eph) = EphemeralKeypair::generate() else {
            return self.fail("ephemeral keygen failed");
        };
        let eph_pk_r = eph.public_bytes();

        // ACK mac covers eph_pk_r ‖ eph_pk_i (PROTOCOL §6.1).
        let mut ack_basis = Vec::with_capacity(64);
        ack_basis.extend_from_slice(&eph_pk_r);
        ack_basis.extend_from_slice(&eph_pk_i);
        let ack_mac = crypto::keyed_mac(&ss_static, &ack_basis);

        // PROTOCOL §6.2, PC side: ss_si mirrors the phone's static⇄our-ephemeral DH.
        let ss_ee = eph.dh(&eph_pk_i);
        let ss_si = eph.dh(&peer.public_key);
        let keys = match crypto::derive_session_keys(
            &ss_ee,
            &ss_si,
            &ss_static,
            &initiator,
            &self.identity.device_id(),
        ) {
            Ok(k) => k,
            Err(_) => return self.fail("key derivation failed"),
        };

        let Ok(payload) = MapBuilder::new()
            .bytes(key::EPH_PK_R, &eph_pk_r)
            .bytes(key::ACK_MAC, &ack_mac)
            .to_vec()
        else {
            return self.fail("failed to encode HELLO_ACK");
        };

        // PC transmits on c2p and receives on p2c.
        self.channel = Some(AeadChannel::new(keys.c2p, keys.p2c));
        self.peer = Some(peer);
        self.eph = Some(eph);
        self.state = State::Established;

        vec![
            SessionAction::Send(Frame::new(FrameType::HelloAck, payload)),
            SessionAction::Emit(SessionEvent::Established { peer: initiator }),
        ]
    }

    fn on_hello_ack(&mut self, frame: &Frame) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(&frame.payload) else {
            return self.fail("malformed HELLO_ACK");
        };
        let (Ok(eph_pk_r), Ok(mac)) = (
            r.byte_array::<32>(key::EPH_PK_R),
            r.byte_array::<32>(key::ACK_MAC),
        ) else {
            return self.fail("malformed HELLO_ACK fields");
        };
        let (Some(peer), Some(eph), Some(eph_pk_i)) = (self.peer, self.eph.as_ref(), self.eph_pk_i)
        else {
            return self.fail("HELLO_ACK without pending handshake");
        };

        let ss_static = self.identity.dh(&peer.public_key);
        let mut ack_basis = Vec::with_capacity(64);
        ack_basis.extend_from_slice(&eph_pk_r);
        ack_basis.extend_from_slice(&eph_pk_i);
        if !crypto::verify_mac(&ss_static, &ack_basis, &mac) {
            // Proves the responder holds sk_id_pc — this is what stops an evil-twin
            // mDNS record from completing a session (PROTOCOL §10).
            return self.fail("HELLO_ACK mac mismatch");
        }

        // PROTOCOL §6.2, phone side.
        let ss_ee = eph.dh(&eph_pk_r);
        let ss_si = self.identity.dh(&eph_pk_r);
        let keys = match crypto::derive_session_keys(
            &ss_ee,
            &ss_si,
            &ss_static,
            &self.identity.device_id(),
            &peer.device_id,
        ) {
            Ok(k) => k,
            Err(_) => return self.fail("key derivation failed"),
        };

        // Phone transmits on p2c and receives on c2p.
        self.channel = Some(AeadChannel::new(keys.p2c, keys.c2p));
        self.state = State::Established;
        vec![SessionAction::Emit(SessionEvent::Established {
            peer: peer.device_id,
        })]
    }

    fn on_encrypted(&mut self, frame: &Frame, now_ms: u64) -> Vec<SessionAction> {
        let Some(ch) = self.channel.as_mut() else {
            return self.fail("encrypted frame before handshake");
        };
        let plain = match ch.open(frame.ty, &frame.payload) {
            Ok(p) => p,
            // Covers replay (counter reuse), tampering, and wrong-type reuse.
            Err(_) => return self.fail("AEAD open failed"),
        };

        match frame.ty {
            FrameType::ClipPush => self.on_clip_push(&plain, now_ms),
            FrameType::ClipAck => self.on_clip_ack(&plain),
            FrameType::StageListReq => vec![SessionAction::Emit(SessionEvent::StageListRequested)],
            FrameType::StageList => self.on_stage_list(&plain),
            FrameType::StageGet => self.on_stage_get(&plain),
            FrameType::StageItem => self.on_stage_item(&plain),
            FrameType::Ping => match self.seal_frame(FrameType::Pong, &[]) {
                Ok(f) => vec![SessionAction::Send(f)],
                Err(_) => self.fail("failed to seal PONG"),
            },
            FrameType::Pong => Vec::new(),
            FrameType::Error => self.on_error(&plain),
            _ => self.fail("unhandled encrypted frame type"),
        }
    }

    fn on_clip_push(&mut self, plain: &[u8], _now_ms: u64) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(plain) else {
            return self.fail("malformed CLIP_PUSH");
        };
        let (Ok(clip_id), Ok(ct), Ok(body)) = (
            r.byte_array::<8>(key::CLIP_ID),
            r.u64(key::CONTENT_TYPE),
            r.bytes(key::BODY).map(|b| b.to_vec()),
        ) else {
            return self.fail("malformed CLIP_PUSH fields");
        };
        let created_at_ms = r.u64(key::CREATED_AT).unwrap_or(0);
        let source_name = r.text(key::SOURCE_NAME).unwrap_or("").to_owned();

        if self.paused {
            return self.wire_error(WireErrorCode::RateLimited, "beaming paused");
        }
        if body.len() > MAX_TEXT_CLIP {
            return self.wire_error(WireErrorCode::FrameTooLarge, "clip exceeds MAX_TEXT_CLIP");
        }
        let Ok(content_type) = u8::try_from(ct)
            .map_err(|_| ())
            .and_then(|v| ContentType::try_from(v).map_err(|_| ()))
        else {
            return self.fail("unknown content type");
        };

        let ack = MapBuilder::new()
            .bytes(key::ACK_CLIP_ID, &clip_id)
            .u64(key::ACK_STATUS, 0)
            .to_vec();
        let Ok(ack) = ack else {
            return self.fail("failed to encode CLIP_ACK");
        };
        let ack_frame = match self.seal_frame(FrameType::ClipAck, &ack) {
            Ok(f) => f,
            Err(_) => return self.fail("failed to seal CLIP_ACK"),
        };

        vec![
            SessionAction::Emit(SessionEvent::ClipArrived {
                clip_id,
                content_type,
                body,
                source_name,
                created_at_ms,
            }),
            SessionAction::Send(ack_frame),
        ]
    }

    fn on_clip_ack(&mut self, plain: &[u8]) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(plain) else {
            return self.fail("malformed CLIP_ACK");
        };
        let Ok(clip_id) = r.byte_array::<8>(key::ACK_CLIP_ID) else {
            return self.fail("malformed CLIP_ACK id");
        };
        let status = r.u64(key::ACK_STATUS).unwrap_or(0) as u8;
        vec![SessionAction::Emit(SessionEvent::ClipAcked {
            clip_id,
            status,
        })]
    }

    fn on_stage_get(&mut self, plain: &[u8]) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(plain) else {
            return self.fail("malformed STAGE_GET");
        };
        let Ok(stage_id) = r.byte_array::<8>(key::STAGE_ID) else {
            return self.fail("malformed STAGE_GET id");
        };
        vec![SessionAction::Emit(SessionEvent::StageItemRequested {
            stage_id,
        })]
    }

    fn on_stage_list(&mut self, plain: &[u8]) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(plain) else {
            return self.fail("malformed STAGE_LIST");
        };
        let Ok(items) = r.array(key::STAGE_ITEMS) else {
            return self.fail("malformed STAGE_LIST array");
        };

        let mut out = Vec::with_capacity(items.len());
        for v in items {
            let Ok(m) = MapReader::from_value(v.clone()) else {
                return self.fail("malformed STAGE_LIST entry");
            };
            let (Ok(stage_id), Ok(ct), Ok(preview), Ok(size), Ok(copied_at_ms)) = (
                m.byte_array::<8>(key::STAGE_META_ID),
                m.u64(key::STAGE_META_TYPE),
                m.text(key::STAGE_META_PREVIEW).map(|s| s.to_owned()),
                m.u64(key::STAGE_META_SIZE),
                m.u64(key::STAGE_META_COPIED_AT),
            ) else {
                return self.fail("malformed STAGE_LIST entry fields");
            };
            let Ok(content_type) = u8::try_from(ct)
                .map_err(|_| ())
                .and_then(|v| ContentType::try_from(v).map_err(|_| ()))
            else {
                return self.fail("unknown content type in STAGE_LIST");
            };
            out.push(StageMeta {
                stage_id,
                content_type,
                preview,
                size: size as u32,
                copied_at_ms,
            });
        }
        vec![SessionAction::Emit(SessionEvent::StageList(out))]
    }

    fn on_stage_item(&mut self, plain: &[u8]) -> Vec<SessionAction> {
        let Ok(r) = MapReader::from_slice(plain) else {
            return self.fail("malformed STAGE_ITEM");
        };
        let (Ok(stage_id), Ok(ct), Ok(body)) = (
            r.byte_array::<8>(key::ITEM_ID),
            r.u64(key::ITEM_TYPE),
            r.bytes(key::ITEM_BODY).map(|b| b.to_vec()),
        ) else {
            return self.fail("malformed STAGE_ITEM fields");
        };
        let Ok(content_type) = u8::try_from(ct)
            .map_err(|_| ())
            .and_then(|v| ContentType::try_from(v).map_err(|_| ()))
        else {
            return self.fail("unknown content type in STAGE_ITEM");
        };
        vec![SessionAction::Emit(SessionEvent::StageItem {
            stage_id,
            content_type,
            body,
        })]
    }

    fn on_error(&mut self, plain: &[u8]) -> Vec<SessionAction> {
        let (code, msg) = MapReader::from_slice(plain)
            .map(|r| {
                (
                    r.u64(key::ERR_CODE).unwrap_or(0) as u16,
                    r.text(key::ERR_MSG).unwrap_or("").to_owned(),
                )
            })
            .unwrap_or((0, String::new()));
        self.state = State::Closed;
        vec![
            SessionAction::Emit(SessionEvent::PeerError { code, msg }),
            SessionAction::Close("peer sent ERROR"),
        ]
    }

    // -----------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------

    fn seal_frame(&mut self, ty: FrameType, plain: &[u8]) -> Result<Frame> {
        let ch = self.channel.as_mut().ok_or(Error::Crypto)?;
        Ok(Frame::new(ty, ch.seal(ty, plain)?))
    }

    /// Build a CLIP_PUSH. Returns the frame plus the generated clip id so the caller
    /// can match the eventual CLIP_ACK (PROTOCOL §8.1).
    pub fn push_clip(
        &mut self,
        content_type: ContentType,
        body: &[u8],
        source_name: &str,
        now_ms: u64,
    ) -> Result<(Frame, [u8; 8])> {
        if body.len() > MAX_TEXT_CLIP {
            return Err(Error::FrameTooLarge(body.len() as u32));
        }
        let mut clip_id = [0u8; 8];
        getrandom::fill(&mut clip_id).map_err(|_| Error::Crypto)?;
        let frame = self.push_clip_with_id(clip_id, content_type, body, source_name, now_ms)?;
        Ok((frame, clip_id))
    }

    /// Deterministic variant for tests and `--simulate-peer`.
    pub fn push_clip_with_id(
        &mut self,
        clip_id: [u8; 8],
        content_type: ContentType,
        body: &[u8],
        source_name: &str,
        now_ms: u64,
    ) -> Result<Frame> {
        let payload = MapBuilder::new()
            .bytes(key::CLIP_ID, &clip_id)
            .u64(key::CONTENT_TYPE, content_type as u64)
            .bytes(key::BODY, body)
            .u64(key::CREATED_AT, now_ms)
            .text(key::SOURCE_NAME, source_name)
            .to_vec()?;
        self.seal_frame(FrameType::ClipPush, &payload)
    }

    pub fn request_stage_list(&mut self) -> Result<Frame> {
        let payload = MapBuilder::new().to_vec()?;
        self.seal_frame(FrameType::StageListReq, &payload)
    }

    pub fn request_stage_item(&mut self, stage_id: &[u8; 8]) -> Result<Frame> {
        let payload = MapBuilder::new().bytes(key::STAGE_ID, stage_id).to_vec()?;
        self.seal_frame(FrameType::StageGet, &payload)
    }

    /// PC role: answer a [`SessionEvent::StageListRequested`].
    pub fn send_stage_list(&mut self, items: &[StageMeta]) -> Result<Frame> {
        let entries = items
            .iter()
            .map(|m| {
                MapBuilder::new()
                    .bytes(key::STAGE_META_ID, &m.stage_id)
                    .u64(key::STAGE_META_TYPE, m.content_type as u64)
                    .text(key::STAGE_META_PREVIEW, &m.preview)
                    .u64(key::STAGE_META_SIZE, m.size as u64)
                    .u64(key::STAGE_META_COPIED_AT, m.copied_at_ms)
                    .build()
            })
            .collect();
        let payload = MapBuilder::new()
            .array(key::STAGE_ITEMS, entries)
            .to_vec()?;
        self.seal_frame(FrameType::StageList, &payload)
    }

    /// PC role: answer a [`SessionEvent::StageItemRequested`].
    pub fn send_stage_item(&mut self, clip: &StagedClip) -> Result<Frame> {
        let payload = MapBuilder::new()
            .bytes(key::ITEM_ID, &clip.stage_id)
            .u64(key::ITEM_TYPE, clip.content_type as u64)
            .bytes(key::ITEM_BODY, &clip.body)
            .to_vec()?;
        self.seal_frame(FrameType::StageItem, &payload)
    }

    pub fn ping(&mut self) -> Result<Frame> {
        self.seal_frame(FrameType::Ping, &[])
    }
}

/// Canonical bytes the HELLO MAC covers.
///
/// PROTOCOL §6.1 says "fields 1..4 serialized" without pinning an encoding. We define it
/// as the CBOR map containing exactly keys 1–4 in ascending order — deterministic, and
/// re-derivable by the verifier from the parsed values. Documented in PROTOCOL.md §6.1.
fn hello_mac_basis(initiator: &DeviceId, eph_pk_i: &PublicKeyBytes, ts: u64) -> Result<Vec<u8>> {
    MapBuilder::new()
        .u64(key::VERSION, PROTOCOL_VERSION as u64)
        .bytes(key::INITIATOR_ID, &initiator.0)
        .bytes(key::EPH_PK_I, eph_pk_i)
        .u64(key::TS, ts)
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage::StageRing;

    const NOW: u64 = 1_700_000_000_000;

    fn identities() -> (IdentityKeypair, IdentityKeypair) {
        (
            IdentityKeypair::from_seed([0xF0; 32]),
            IdentityKeypair::from_seed([0xC1; 32]),
        )
    }

    fn peer_of(k: &IdentityKeypair) -> PeerKey {
        PeerKey {
            device_id: k.device_id(),
            public_key: k.public_bytes(),
        }
    }

    /// Drive both sides through the handshake. Returns established sessions.
    fn handshake() -> (Session, Session) {
        let (ph_id, pc_id) = identities();
        let (mut phone, hello) = Session::start_phone(ph_id.clone(), peer_of(&pc_id), NOW).unwrap();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);

        let acts = pc.on_frame(&hello, NOW);
        let ack = match acts.as_slice() {
            [SessionAction::Send(f), SessionAction::Emit(SessionEvent::Established { .. })] => {
                f.clone()
            }
            other => panic!("unexpected PC actions: {other:?}"),
        };
        let acts = phone.on_frame(&ack, NOW);
        assert!(matches!(
            acts.as_slice(),
            [SessionAction::Emit(SessionEvent::Established { .. })]
        ));
        assert!(phone.is_established() && pc.is_established());
        (phone, pc)
    }

    #[test]
    fn handshake_establishes_both_sides() {
        let (ph_id, pc_id) = identities();
        let (phone, pc) = handshake();
        assert_eq!(phone.peer(), Some(pc_id.device_id()));
        assert_eq!(pc.peer(), Some(ph_id.device_id()));
        assert_eq!(phone.role(), Role::Phone);
        assert_eq!(pc.role(), Role::Pc);
    }

    #[test]
    fn hello_with_stale_timestamp_is_rejected() {
        let (ph_id, pc_id) = identities();
        let (_, hello) = Session::start_phone(ph_id.clone(), peer_of(&pc_id), NOW).unwrap();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);

        let late = NOW + HELLO_TS_WINDOW_MS + 1;
        assert!(matches!(
            pc.on_frame(&hello, late).as_slice(),
            [SessionAction::Close(
                "HELLO timestamp outside replay window"
            )]
        ));
        assert!(pc.is_closed());
    }

    #[test]
    fn hello_from_the_future_is_also_rejected() {
        let (ph_id, pc_id) = identities();
        let future = NOW + HELLO_TS_WINDOW_MS + 5_000;
        let (_, hello) = Session::start_phone(ph_id.clone(), peer_of(&pc_id), future).unwrap();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);
        assert!(matches!(
            pc.on_frame(&hello, NOW).as_slice(),
            [SessionAction::Close(
                "HELLO timestamp outside replay window"
            )]
        ));
    }

    #[test]
    fn hello_at_window_edge_is_accepted() {
        let (ph_id, pc_id) = identities();
        let (_, hello) = Session::start_phone(ph_id.clone(), peer_of(&pc_id), NOW).unwrap();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);
        let edge = NOW + HELLO_TS_WINDOW_MS;
        assert!(matches!(
            pc.on_frame(&hello, edge).as_slice(),
            [SessionAction::Send(_), SessionAction::Emit(_)]
        ));
    }

    #[test]
    fn hello_from_unpaired_device_closes_silently() {
        let (ph_id, pc_id) = identities();
        let stranger = IdentityKeypair::from_seed([0x77; 32]);
        let (_, hello) = Session::start_phone(stranger, peer_of(&pc_id), NOW).unwrap();
        // PC only knows the real phone.
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);

        let acts = pc.on_frame(&hello, NOW);
        // No ERROR frame — PROTOCOL §6.1 forbids an oracle.
        assert!(matches!(acts.as_slice(), [SessionAction::Close(_)]));
        assert!(!acts.iter().any(|a| matches!(a, SessionAction::Send(_))));
    }

    #[test]
    fn hello_with_forged_mac_is_rejected() {
        let (ph_id, pc_id) = identities();
        let (_, hello) = Session::start_phone(ph_id.clone(), peer_of(&pc_id), NOW).unwrap();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);

        // Rebuild the HELLO with a garbage MAC but otherwise valid fields.
        let r = MapReader::from_slice(&hello.payload).unwrap();
        let forged = MapBuilder::new()
            .u64(key::VERSION, r.u64(key::VERSION).unwrap())
            .bytes(
                key::INITIATOR_ID,
                &r.byte_array::<16>(key::INITIATOR_ID).unwrap(),
            )
            .bytes(key::EPH_PK_I, &r.byte_array::<32>(key::EPH_PK_I).unwrap())
            .u64(key::TS, r.u64(key::TS).unwrap())
            .bytes(key::HELLO_MAC, &[0u8; 32])
            .to_vec()
            .unwrap();

        assert!(matches!(
            pc.on_frame(&Frame::new(FrameType::Hello, forged), NOW)
                .as_slice(),
            [SessionAction::Close("HELLO mac mismatch")]
        ));
    }

    #[test]
    fn hello_ack_with_forged_mac_is_rejected() {
        // An evil-twin PC that answers mDNS but lacks sk_id_pc cannot pass this.
        let (ph_id, pc_id) = identities();
        let (mut phone, _) = Session::start_phone(ph_id, peer_of(&pc_id), NOW).unwrap();
        let evil = EphemeralKeypair::from_seed([0x66; 32]);
        let forged = MapBuilder::new()
            .bytes(key::EPH_PK_R, &evil.public_bytes())
            .bytes(key::ACK_MAC, &[0u8; 32])
            .to_vec()
            .unwrap();
        assert!(matches!(
            phone
                .on_frame(&Frame::new(FrameType::HelloAck, forged), NOW)
                .as_slice(),
            [SessionAction::Close("HELLO_ACK mac mismatch")]
        ));
    }

    #[test]
    fn unsupported_version_gets_wire_error_semantics() {
        let (ph_id, pc_id) = identities();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);
        let payload = MapBuilder::new()
            .u64(key::VERSION, 99)
            .bytes(key::INITIATOR_ID, &ph_id.device_id().0)
            .bytes(key::EPH_PK_I, &[0u8; 32])
            .u64(key::TS, NOW)
            .bytes(key::HELLO_MAC, &[0u8; 32])
            .to_vec()
            .unwrap();
        let acts = pc.on_frame(&Frame::new(FrameType::Hello, payload), NOW);
        assert!(matches!(acts.last(), Some(SessionAction::Close(_))));
        assert!(pc.is_closed());
    }

    // --- traffic ---

    #[test]
    fn clip_push_round_trip_with_ack() {
        let (mut phone, mut pc) = handshake();
        let (push, clip_id) = phone
            .push_clip(
                ContentType::Text,
                b"hello from iPhone",
                "Bernhard's iPhone",
                NOW,
            )
            .unwrap();

        let acts = pc.on_frame(&push, NOW);
        let (arrived, ack) = match acts.as_slice() {
            [SessionAction::Emit(e), SessionAction::Send(f)] => (e.clone(), f.clone()),
            other => panic!("unexpected: {other:?}"),
        };
        match arrived {
            SessionEvent::ClipArrived {
                content_type,
                body,
                source_name,
                clip_id: got_id,
                ..
            } => {
                assert_eq!(content_type, ContentType::Text);
                assert_eq!(body, b"hello from iPhone");
                assert_eq!(source_name, "Bernhard's iPhone");
                assert_eq!(got_id, clip_id);
            }
            other => panic!("expected ClipArrived, got {other:?}"),
        }

        // Phone receives the ACK.
        assert!(matches!(
            phone.on_frame(&ack, NOW).as_slice(),
            [SessionAction::Emit(SessionEvent::ClipAcked {
                status: 0,
                ..
            })]
        ));
    }

    #[test]
    fn replayed_frame_closes_the_session() {
        // T-04 acceptance: counter reuse must terminate the session.
        let (mut phone, mut pc) = handshake();
        let (push, _) = phone
            .push_clip(ContentType::Text, b"once", "iPhone", NOW)
            .unwrap();
        assert!(pc
            .on_frame(&push, NOW)
            .iter()
            .any(|a| matches!(a, SessionAction::Emit(SessionEvent::ClipArrived { .. }))));

        assert!(matches!(
            pc.on_frame(&push, NOW).as_slice(),
            [SessionAction::Close("AEAD open failed")]
        ));
        assert!(pc.is_closed());
    }

    #[test]
    fn tampered_ciphertext_closes_the_session() {
        let (mut phone, mut pc) = handshake();
        let (mut push, _) = phone
            .push_clip(ContentType::Text, b"data", "iPhone", NOW)
            .unwrap();
        let last = push.payload.len() - 1;
        push.payload[last] ^= 0xFF;
        assert!(matches!(
            pc.on_frame(&push, NOW).as_slice(),
            [SessionAction::Close("AEAD open failed")]
        ));
    }

    #[test]
    fn paused_pc_rejects_clips_with_wire_error() {
        let (mut phone, mut pc) = handshake();
        pc.set_paused(true);
        let (push, _) = phone
            .push_clip(ContentType::Text, b"nope", "iPhone", NOW)
            .unwrap();

        let acts = pc.on_frame(&push, NOW);
        // ERROR frame out, then close (PROTOCOL §9 code 5).
        assert!(matches!(acts.first(), Some(SessionAction::Send(f)) if f.ty == FrameType::Error));
        assert!(matches!(acts.last(), Some(SessionAction::Close(_))));

        // The phone can still decrypt and surface it.
        let err = match acts.first() {
            Some(SessionAction::Send(f)) => f.clone(),
            _ => unreachable!(),
        };
        assert!(matches!(
            phone.on_frame(&err, NOW).as_slice(),
            [
                SessionAction::Emit(SessionEvent::PeerError { code: 5, .. }),
                SessionAction::Close(_)
            ]
        ));
    }

    #[test]
    fn oversize_clip_is_refused_by_sender_and_receiver() {
        let (mut phone, mut pc) = handshake();
        let too_big = vec![b'x'; MAX_TEXT_CLIP + 1];
        assert!(phone
            .push_clip(ContentType::Text, &too_big, "iPhone", NOW)
            .is_err());

        // And if a non-conforming client sends one anyway, the PC refuses it.
        let payload = MapBuilder::new()
            .bytes(key::CLIP_ID, &[1u8; 8])
            .u64(key::CONTENT_TYPE, ContentType::Text as u64)
            .bytes(key::BODY, &too_big)
            .u64(key::CREATED_AT, NOW)
            .text(key::SOURCE_NAME, "rogue")
            .to_vec()
            .unwrap();
        let frame = phone.seal_frame(FrameType::ClipPush, &payload).unwrap();
        let acts = pc.on_frame(&frame, NOW);
        assert!(matches!(acts.last(), Some(SessionAction::Close(_))));
    }

    #[test]
    fn unknown_content_type_closes_session() {
        let (mut phone, mut pc) = handshake();
        let payload = MapBuilder::new()
            .bytes(key::CLIP_ID, &[1u8; 8])
            .u64(key::CONTENT_TYPE, 42) // reserved / unimplemented
            .bytes(key::BODY, b"x")
            .u64(key::CREATED_AT, NOW)
            .text(key::SOURCE_NAME, "iPhone")
            .to_vec()
            .unwrap();
        let frame = phone.seal_frame(FrameType::ClipPush, &payload).unwrap();
        assert!(matches!(
            pc.on_frame(&frame, NOW).as_slice(),
            [SessionAction::Close("unknown content type")]
        ));
    }

    #[test]
    fn stage_pull_round_trip() {
        let (mut phone, mut pc) = handshake();
        let mut ring = StageRing::default();
        for i in 0..3u8 {
            ring.push_with_id(
                [i; 8],
                ContentType::Text,
                format!("clip {i}").into_bytes(),
                NOW + i as u64,
            )
            .unwrap();
        }

        // Phone asks for the list.
        let req = phone.request_stage_list().unwrap();
        assert!(matches!(
            pc.on_frame(&req, NOW).as_slice(),
            [SessionAction::Emit(SessionEvent::StageListRequested)]
        ));
        let list_frame = pc.send_stage_list(&ring.list()).unwrap();

        let list = match phone.on_frame(&list_frame, NOW).as_slice() {
            [SessionAction::Emit(SessionEvent::StageList(l))] => l.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].preview, "clip 2", "newest first");
        assert_eq!(list[0].stage_id, [2u8; 8]);

        // Phone fetches one body.
        let get = phone.request_stage_item(&list[0].stage_id).unwrap();
        let asked = match pc.on_frame(&get, NOW).as_slice() {
            [SessionAction::Emit(SessionEvent::StageItemRequested { stage_id })] => *stage_id,
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(asked, [2u8; 8]);

        let item_frame = pc.send_stage_item(ring.get(&asked).unwrap()).unwrap();
        match phone.on_frame(&item_frame, NOW).as_slice() {
            [SessionAction::Emit(SessionEvent::StageItem {
                stage_id,
                body,
                content_type,
            })] => {
                assert_eq!(*stage_id, [2u8; 8]);
                assert_eq!(body, b"clip 2");
                assert_eq!(*content_type, ContentType::Text);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let (mut phone, mut pc) = handshake();
        let ping = phone.ping().unwrap();
        let pong = match pc.on_frame(&ping, NOW).as_slice() {
            [SessionAction::Send(f)] => f.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(pong.ty, FrameType::Pong);
        // Pong itself produces no further actions.
        assert!(phone.on_frame(&pong, NOW).is_empty());
    }

    #[test]
    fn idle_timeout_tracks_last_activity() {
        let (mut phone, mut pc) = handshake();
        assert!(!pc.is_idle(NOW));
        assert!(pc.is_idle(NOW + SESSION_IDLE_TIMEOUT_MS));

        let ping = phone.ping().unwrap();
        pc.on_frame(&ping, NOW + 30_000);
        assert!(!pc.is_idle(NOW + 30_000 + SESSION_IDLE_TIMEOUT_MS - 1));
        assert!(pc.is_idle(NOW + 30_000 + SESSION_IDLE_TIMEOUT_MS));
    }

    #[test]
    fn plaintext_frame_after_handshake_is_rejected() {
        let (_, mut pc) = handshake();
        // A second HELLO on an established session is a protocol violation.
        assert!(matches!(
            pc.on_frame(&Frame::new(FrameType::Hello, vec![]), NOW)
                .as_slice(),
            [SessionAction::Close(_)]
        ));
    }

    #[test]
    fn encrypted_frame_before_handshake_is_rejected() {
        let (ph_id, pc_id) = identities();
        let mut pc = Session::new_pc(pc_id, vec![peer_of(&ph_id)], NOW);
        assert!(matches!(
            pc.on_frame(&Frame::new(FrameType::ClipPush, vec![0; 32]), NOW)
                .as_slice(),
            [SessionAction::Close(_)]
        ));
    }

    #[test]
    fn frames_after_close_are_refused() {
        let (_, mut pc) = handshake();
        pc.on_frame(&Frame::new(FrameType::Hello, vec![]), NOW);
        assert!(pc.is_closed());
        assert!(matches!(
            pc.on_frame(&Frame::new(FrameType::Ping, vec![]), NOW)
                .as_slice(),
            [SessionAction::Close("frame after close")]
        ));
    }

    #[test]
    fn malformed_encrypted_payloads_never_panic() {
        for bad in [vec![], vec![0xFF], vec![0xA1, 0x01], b"garbage".to_vec()] {
            let (mut phone, mut pc) = handshake();
            let frame = phone.seal_frame(FrameType::ClipPush, &bad).unwrap();
            let acts = pc.on_frame(&frame, NOW);
            assert!(matches!(acts.last(), Some(SessionAction::Close(_))));
        }
    }

    #[test]
    fn hello_mac_basis_is_stable() {
        // Guards against an accidental reordering that would break interop.
        let id = DeviceId([0xAB; 16]);
        let a = hello_mac_basis(&id, &[0x11; 32], 1234).unwrap();
        let b = hello_mac_basis(&id, &[0x11; 32], 1234).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, hello_mac_basis(&id, &[0x11; 32], 1235).unwrap());
        assert_ne!(a, hello_mac_basis(&id, &[0x12; 32], 1234).unwrap());
    }
}
