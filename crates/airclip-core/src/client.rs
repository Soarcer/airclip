//! Phone-role transport driver: the tokio half of ADR-3 (the phone always dials).
//!
//! `session.rs` is sans-io and decides *what* to send; this module owns sockets and
//! timeouts and decides *when*. Both the iOS FFI layer and the Windows `--simulate-peer`
//! harness drive the phone role through here, so there is one implementation of
//! "connect, handshake, do one thing, hang up" rather than two that can drift.
//!
//! Sessions are deliberately short-lived (IOS-PLATFORM-NOTES §4): iOS cannot hold a
//! socket in the background, so reconnecting per operation is the design, not a fallback.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::crypto::IdentityKeypair;
use crate::error::Error;
use crate::frame::{Frame, FrameCodec, FrameType};
use crate::pairing::{PairingAction, PairingRecord, PhonePairing, QrPayload};
use crate::session::{PeerKey, Session, SessionAction, SessionEvent};
use crate::stage::StageMeta;
use crate::ContentType;

/// Per-address TCP connect budget (PROTOCOL §4: first address to answer within 800 ms).
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
/// Default budget for a whole request/response exchange.
pub const DEFAULT_OP_TIMEOUT: Duration = Duration::from_millis(2_000);

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

type Wire = Framed<TcpStream, FrameCodec>;

/// Why an operation could not complete. Kept coarse: these map onto the user-facing
/// failure states SPEC R9 requires, and finer detail would only leak protocol internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// No candidate address accepted a connection in time.
    Unreachable,
    /// Connected, but the peer never finished the exchange in the allotted time.
    TimedOut,
    /// Handshake rejected — wrong keys, unpaired, or an impostor.
    Rejected(String),
    /// Payload exceeds MAX_TEXT_CLIP.
    TooLarge {
        max_bytes: u32,
    },
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "PC not reachable on this network"),
            Self::TimedOut => write!(f, "PC did not respond in time"),
            Self::Rejected(r) => write!(f, "rejected: {r}"),
            Self::TooLarge { max_bytes } => write!(f, "clip exceeds {max_bytes} bytes"),
            Self::Protocol(r) => write!(f, "protocol error: {r}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<Error> for ClientError {
    fn from(e: Error) -> Self {
        ClientError::Protocol(e.to_string())
    }
}

type ClientResult<T> = std::result::Result<T, ClientError>;

/// Race candidate addresses, returning the first TCP connection to complete.
///
/// Happy-Eyeballs-lite per PROTOCOL §4. Addresses are tried concurrently rather than
/// in series because a dead IPv6 literal otherwise burns the whole budget before the
/// working IPv4 address is even attempted — the common case on a dual-stack LAN.
pub async fn dial(addrs: &[SocketAddr], per_attempt: Duration) -> ClientResult<TcpStream> {
    if addrs.is_empty() {
        return Err(ClientError::Unreachable);
    }

    let mut attempts = futures_util::stream::FuturesUnordered::new();
    for addr in addrs.iter().copied() {
        attempts.push(async move {
            match tokio::time::timeout(per_attempt, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => Some(s),
                _ => None,
            }
        });
    }

    while let Some(result) = attempts.next().await {
        if let Some(stream) = result {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    Err(ClientError::Unreachable)
}

async fn recv_frame(wire: &mut Wire, budget: Duration) -> ClientResult<Frame> {
    match tokio::time::timeout(budget, wire.next()).await {
        Ok(Some(Ok(f))) => Ok(f),
        Ok(Some(Err(e))) => Err(ClientError::Protocol(e.to_string())),
        Ok(None) => Err(ClientError::Rejected("peer closed the connection".into())),
        Err(_) => Err(ClientError::TimedOut),
    }
}

async fn send_frame(wire: &mut Wire, frame: Frame) -> ClientResult<()> {
    wire.send(frame)
        .await
        .map_err(|e| ClientError::Protocol(e.to_string()))
}

/// An in-progress pairing: the SAS has been shown and we are waiting for the user.
///
/// Holding the live connection matters — PROTOCOL §7.2 step 6 sends PAIR_CONFIRM on the
/// same connection that produced the SAS, so the user's decision cannot be applied to a
/// different exchange.
pub struct PendingPairing {
    wire: Wire,
    record: PairingRecord,
    sas: [&'static str; 4],
    confirm_frame: Option<Frame>,
}

impl PendingPairing {
    pub fn sas(&self) -> [&'static str; 4] {
        self.sas
    }

    /// User confirmed the emoji match. Sends PAIR_CONFIRM and returns the record to store.
    pub async fn confirm(mut self) -> ClientResult<PairingRecord> {
        let Some(frame) = self.confirm_frame.take() else {
            return Err(ClientError::Protocol("nothing to confirm".into()));
        };
        send_frame(&mut self.wire, frame).await?;
        Ok(self.record)
    }
}

/// Begin pairing from a scanned QR payload.
///
/// Stops at the SAS: the whole point of PROTOCOL §7 is that a human compares the emoji
/// *before* anything is persisted, so this cannot complete without a second call.
pub async fn begin_pairing(
    identity: &IdentityKeypair,
    display_name: &str,
    qr: QrPayload,
    op_timeout: Duration,
) -> ClientResult<PendingPairing> {
    let addrs = resolve_hosts(&qr.hosts);
    let stream = dial(&addrs, CONNECT_TIMEOUT).await?;
    let mut wire = Framed::new(stream, FrameCodec);

    let (mut fsm, req) = PhonePairing::start(identity, display_name, qr)?;
    send_frame(&mut wire, req).await?;

    let ack = recv_frame(&mut wire, op_timeout).await?;
    if ack.ty != FrameType::PairAck {
        return Err(ClientError::Protocol(format!(
            "expected PAIR_ACK, got {:?}",
            ack.ty
        )));
    }

    let sas = match fsm.on_frame(&ack).as_slice() {
        [PairingAction::ShowSas(s)] => *s,
        [PairingAction::Failed(r)] => return Err(ClientError::Rejected((*r).into())),
        other => {
            return Err(ClientError::Protocol(format!(
                "unexpected pairing state: {other:?}"
            )))
        }
    };

    // Build (but do not send) the confirmation, so `confirm()` is a pure send.
    match fsm.confirm_sas(now_ms()).as_slice() {
        [PairingAction::Send(f), PairingAction::Completed(record)] => Ok(PendingPairing {
            wire,
            record: (**record).clone(),
            sas,
            confirm_frame: Some(f.clone()),
        }),
        other => Err(ClientError::Protocol(format!(
            "unexpected confirm state: {other:?}"
        ))),
    }
}

/// A live, handshaked session with the PC.
pub struct Connection {
    wire: Wire,
    session: Session,
    op_timeout: Duration,
}

impl Connection {
    /// Dial and complete the handshake (PROTOCOL §6.1).
    pub async fn open(
        identity: IdentityKeypair,
        peer: PeerKey,
        addrs: &[SocketAddr],
        op_timeout: Duration,
    ) -> ClientResult<Self> {
        let stream = dial(addrs, CONNECT_TIMEOUT).await?;
        let mut wire = Framed::new(stream, FrameCodec);

        let (mut session, hello) = Session::start_phone(identity, peer, now_ms())?;
        send_frame(&mut wire, hello).await?;

        let ack = recv_frame(&mut wire, op_timeout).await?;
        match session.on_frame(&ack, now_ms()).as_slice() {
            [SessionAction::Emit(SessionEvent::Established { .. })] => {}
            [SessionAction::Close(why)] => return Err(ClientError::Rejected((*why).into())),
            other => {
                return Err(ClientError::Protocol(format!(
                    "handshake failed: {other:?}"
                )));
            }
        }

        Ok(Self {
            wire,
            session,
            op_timeout,
        })
    }

    /// Push a clip and wait for its acknowledgement (PROTOCOL §8.1).
    ///
    /// The ACK is what makes this trustworthy: SPEC R9 forbids silent failure, so a beam
    /// is only "sent" once the PC has confirmed the clip id it received.
    pub async fn beam(
        &mut self,
        content_type: ContentType,
        body: &[u8],
        source_name: &str,
    ) -> ClientResult<[u8; 8]> {
        if body.len() > crate::MAX_TEXT_CLIP {
            return Err(ClientError::TooLarge {
                max_bytes: crate::MAX_TEXT_CLIP as u32,
            });
        }

        let (frame, clip_id) = self
            .session
            .push_clip(content_type, body, source_name, now_ms())?;
        send_frame(&mut self.wire, frame).await?;

        loop {
            let reply = recv_frame(&mut self.wire, self.op_timeout).await?;
            for action in self.session.on_frame(&reply, now_ms()) {
                match action {
                    SessionAction::Emit(SessionEvent::ClipAcked {
                        clip_id: got,
                        status,
                    }) => {
                        if got != clip_id {
                            continue; // ack for a different clip; keep waiting
                        }
                        return if status == 0 {
                            Ok(clip_id)
                        } else {
                            Err(ClientError::Rejected(format!(
                                "PC refused the clip (status {status})"
                            )))
                        };
                    }
                    SessionAction::Emit(SessionEvent::PeerError { code, msg }) => {
                        return Err(ClientError::Rejected(format!("{msg} (code {code})")));
                    }
                    SessionAction::Close(why) => return Err(ClientError::Rejected(why.into())),
                    _ => {}
                }
            }
        }
    }

    /// Fetch staged clip metadata (PROTOCOL §8.2). One round trip; previews only.
    pub async fn stage_list(&mut self) -> ClientResult<Vec<StageMeta>> {
        let req = self.session.request_stage_list()?;
        send_frame(&mut self.wire, req).await?;

        loop {
            let reply = recv_frame(&mut self.wire, self.op_timeout).await?;
            for action in self.session.on_frame(&reply, now_ms()) {
                match action {
                    SessionAction::Emit(SessionEvent::StageList(items)) => return Ok(items),
                    SessionAction::Emit(SessionEvent::PeerError { code, msg }) => {
                        return Err(ClientError::Rejected(format!("{msg} (code {code})")));
                    }
                    SessionAction::Close(why) => return Err(ClientError::Rejected(why.into())),
                    _ => {}
                }
            }
        }
    }

    /// Fetch one staged body by id.
    pub async fn stage_item(&mut self, stage_id: &[u8; 8]) -> ClientResult<(ContentType, Vec<u8>)> {
        let req = self.session.request_stage_item(stage_id)?;
        send_frame(&mut self.wire, req).await?;

        loop {
            let reply = recv_frame(&mut self.wire, self.op_timeout).await?;
            for action in self.session.on_frame(&reply, now_ms()) {
                match action {
                    SessionAction::Emit(SessionEvent::StageItem {
                        stage_id: got,
                        content_type,
                        body,
                    }) => {
                        if &got == stage_id {
                            return Ok((content_type, body));
                        }
                    }
                    // The PC answers an evicted id with an empty list rather than an error.
                    SessionAction::Emit(SessionEvent::StageList(_)) => {
                        return Err(ClientError::Rejected("clip no longer staged".into()));
                    }
                    SessionAction::Close(why) => return Err(ClientError::Rejected(why.into())),
                    _ => {}
                }
            }
        }
    }

    pub fn peer(&self) -> Option<crate::DeviceId> {
        self.session.peer()
    }
}

impl std::fmt::Debug for Connection {
    // Manual: never render the session, which owns key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.peer().map(|p| p.hex()))
            .finish_non_exhaustive()
    }
}

/// Parse `ip:port` strings, dropping any that do not resolve to a literal address.
///
/// Hostnames are deliberately unsupported: PROTOCOL §7.1 advertises literals, and a DNS
/// lookup here would be a silent way for traffic to leave the LAN.
pub fn resolve_hosts(hosts: &[String]) -> Vec<SocketAddr> {
    hosts.iter().filter_map(|h| h.parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::PcPairing;
    use crate::stage::StageRing;
    use tokio::net::TcpListener;

    fn phone_id() -> IdentityKeypair {
        IdentityKeypair::from_seed([0x0F; 32])
    }
    fn pc_id() -> IdentityKeypair {
        IdentityKeypair::from_seed([0x0C; 32])
    }
    fn peer_of(k: &IdentityKeypair) -> PeerKey {
        PeerKey {
            device_id: k.device_id(),
            public_key: k.public_bytes(),
        }
    }

    /// Minimal PC-role server: accepts one connection and drives it to completion.
    /// This is the real `Session`, not a mock, so the test exercises both roles.
    async fn spawn_pc(stage: Vec<(u8, &'static str)>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut ring = StageRing::default();
            for (id, text) in stage {
                ring.push_with_id([id; 8], ContentType::Text, text.as_bytes().to_vec(), 1)
                    .unwrap();
            }

            while let Ok((stream, _)) = listener.accept().await {
                let mut wire = Framed::new(stream, FrameCodec);
                let mut session = Session::new_pc(pc_id(), vec![peer_of(&phone_id())], now_ms());

                while let Some(Ok(frame)) = wire.next().await {
                    let mut closed = false;
                    for action in session.on_frame(&frame, now_ms()) {
                        match action {
                            SessionAction::Send(f) => {
                                let _ = wire.send(f).await;
                            }
                            SessionAction::Emit(SessionEvent::StageListRequested) => {
                                if let Ok(f) = session.send_stage_list(&ring.list()) {
                                    let _ = wire.send(f).await;
                                }
                            }
                            SessionAction::Emit(SessionEvent::StageItemRequested { stage_id }) => {
                                if let Some(c) = ring.get(&stage_id) {
                                    if let Ok(f) = session.send_stage_item(c) {
                                        let _ = wire.send(f).await;
                                    }
                                }
                            }
                            SessionAction::Close(_) => closed = true,
                            _ => {}
                        }
                    }
                    if closed {
                        break;
                    }
                }
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn beam_round_trips_over_tcp() {
        let (addr, _pc) = spawn_pc(vec![]).await;
        let mut conn = Connection::open(phone_id(), peer_of(&pc_id()), &[addr], DEFAULT_OP_TIMEOUT)
            .await
            .expect("handshake");

        let id = conn
            .beam(ContentType::Text, "hello 🚀".as_bytes(), "iPhone")
            .await
            .expect("beam");
        assert_ne!(id, [0u8; 8]);
        assert_eq!(conn.peer(), Some(pc_id().device_id()));
    }

    #[tokio::test]
    async fn stage_list_and_item_round_trip() {
        let (addr, _pc) = spawn_pc(vec![(1, "first"), (2, "second")]).await;
        let mut conn = Connection::open(phone_id(), peer_of(&pc_id()), &[addr], DEFAULT_OP_TIMEOUT)
            .await
            .unwrap();

        let list = conn.stage_list().await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].preview, "second", "newest first");

        let (ct, body) = conn.stage_item(&list[0].stage_id).await.unwrap();
        assert_eq!(ct, ContentType::Text);
        assert_eq!(body, b"second");
    }

    #[tokio::test]
    async fn oversize_clip_is_refused_before_the_wire() {
        let (addr, _pc) = spawn_pc(vec![]).await;
        let mut conn = Connection::open(phone_id(), peer_of(&pc_id()), &[addr], DEFAULT_OP_TIMEOUT)
            .await
            .unwrap();

        let too_big = vec![b'x'; crate::MAX_TEXT_CLIP + 1];
        assert!(matches!(
            conn.beam(ContentType::Text, &too_big, "iPhone").await,
            Err(ClientError::TooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn unreachable_when_nothing_is_listening() {
        // Port 1 on loopback: reliably closed, so this exercises the failure path
        // rather than depending on a timeout.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = Connection::open(phone_id(), peer_of(&pc_id()), &[addr], DEFAULT_OP_TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(err, ClientError::Unreachable);
    }

    #[tokio::test]
    async fn empty_address_list_is_unreachable() {
        let err = Connection::open(phone_id(), peer_of(&pc_id()), &[], DEFAULT_OP_TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(err, ClientError::Unreachable);
    }

    #[tokio::test]
    async fn dial_races_past_a_dead_address() {
        // A dead address listed first must not consume the budget — this is the
        // dual-stack case where an IPv6 literal is advertised but unroutable.
        let (good, _pc) = spawn_pc(vec![]).await;
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let started = std::time::Instant::now();
        let stream = dial(&[dead, good], CONNECT_TIMEOUT).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), good);
        assert!(
            started.elapsed() < CONNECT_TIMEOUT,
            "racing should beat the per-attempt budget"
        );
    }

    #[tokio::test]
    async fn handshake_rejected_for_unpaired_identity() {
        let (addr, _pc) = spawn_pc(vec![]).await;
        let stranger = IdentityKeypair::from_seed([0xAB; 32]);
        let err = Connection::open(stranger, peer_of(&pc_id()), &[addr], DEFAULT_OP_TIMEOUT)
            .await
            .unwrap_err();
        // The PC closes silently (PROTOCOL §6.1), so the client sees a closed connection.
        assert!(matches!(err, ClientError::Rejected(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn full_pairing_then_session_over_tcp() {
        // Mirrors what the iOS app does: pair on one connection, then open a session on
        // a fresh one using only what pairing persisted.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = [0x5A; 16];

        let pc_task = tokio::spawn(async move {
            // Connection 1: pairing.
            let (stream, _) = listener.accept().await.unwrap();
            let mut wire = Framed::new(stream, FrameCodec);
            let pc_identity = pc_id();
            let mut fsm = PcPairing::with_token(
                &pc_identity,
                "TEST-PC",
                vec![addr.to_string()],
                token,
                now_ms(),
            );
            while let Some(Ok(frame)) = wire.next().await {
                let mut done = false;
                for a in fsm.on_frame(&frame, now_ms()) {
                    match a {
                        PairingAction::Send(f) => {
                            let _ = wire.send(f).await;
                        }
                        PairingAction::Completed(_) => done = true,
                        PairingAction::Failed(r) => panic!("pairing failed: {r}"),
                        _ => {}
                    }
                }
                if done {
                    break;
                }
            }

            // Connection 2: session.
            let (stream, _) = listener.accept().await.unwrap();
            let mut wire = Framed::new(stream, FrameCodec);
            let mut session = Session::new_pc(pc_id(), vec![peer_of(&phone_id())], now_ms());
            while let Some(Ok(frame)) = wire.next().await {
                for a in session.on_frame(&frame, now_ms()) {
                    if let SessionAction::Send(f) = a {
                        let _ = wire.send(f).await;
                    }
                }
            }
        });

        let phone = phone_id();
        let qr = QrPayload {
            version: crate::PROTOCOL_VERSION,
            device_id: pc_id().device_id(),
            public_key: pc_id().public_bytes(),
            display_name: "TEST-PC".into(),
            hosts: vec![addr.to_string()],
            pair_token: token,
        };

        let pending = begin_pairing(&phone, "iPhone", qr, DEFAULT_OP_TIMEOUT)
            .await
            .expect("pairing starts");
        assert_eq!(pending.sas().len(), 4);
        let record = pending.confirm().await.expect("confirm");
        assert_eq!(record.display_name, "TEST-PC");

        // Now use only the persisted record, as the app would after a relaunch.
        let peer = PeerKey {
            device_id: record.device_id_bytes().unwrap(),
            public_key: record.public_key_bytes().unwrap(),
        };
        let mut conn = Connection::open(phone_id(), peer, &[addr], DEFAULT_OP_TIMEOUT)
            .await
            .expect("session opens from stored pairing");
        conn.beam(ContentType::Text, b"after pairing", "iPhone")
            .await
            .expect("beam");

        pc_task.abort();
    }

    #[test]
    fn resolve_hosts_drops_unparseable_and_hostnames() {
        let hosts = vec![
            "192.168.1.5:49517".to_string(),
            "[fe80::1]:49517".to_string(),
            "my-pc.local:49517".to_string(), // hostnames are not resolved on purpose
            "garbage".to_string(),
        ];
        let addrs = resolve_hosts(&hosts);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.iter().any(|a| a.is_ipv4()));
        assert!(addrs.iter().any(|a| a.is_ipv6()));
    }
}
