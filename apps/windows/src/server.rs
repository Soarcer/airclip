//! T-10 — TCP accept loop feeding `airclip-core` sessions.
//!
//! ADR-3: the PC only ever listens. One connection carries either a pairing exchange
//! (plaintext PAIR_* frames) or a session (HELLO then encrypted frames); the first frame
//! decides which.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use airclip_core::crypto::IdentityKeypair;
use airclip_core::frame::{Frame, FrameCodec, FrameType};
use airclip_core::pairing::{PairingAction, PairingRecord, PcPairing};
use airclip_core::session::{PeerKey, Session, SessionAction, SessionEvent};
use airclip_core::stage::StageRing;
use airclip_core::{ContentType, DEFAULT_PORT};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use crate::keystore::Keystore;

/// Unauthenticated connection attempts per address per minute (PROTOCOL §9 code 5).
const RATE_LIMIT_PER_MIN: u32 = 20;
const RATE_LIMIT_BAN_MS: u64 = 5 * 60 * 1000;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Things the agent's UI layer reacts to (tray status, toasts, pairing window).
#[derive(Debug, Clone)]
pub enum AgentEvent {
    PeerConnected {
        device_id: String,
    },
    PeerDisconnected {
        device_id: String,
    },
    /// A clip arrived and should be written to the Windows clipboard.
    ClipArrived {
        content_type: ContentType,
        body: Vec<u8>,
        source_name: String,
    },
    /// Pairing produced a SAS to display next to the QR.
    PairingSas([&'static str; 4]),
    Paired {
        record: Box<PairingRecord>,
    },
    PairingFailed {
        reason: String,
    },
}

/// Shared agent state. Cheap to clone; every connection task gets a handle.
#[derive(Clone)]
pub struct AgentState {
    pub identity: IdentityKeypair,
    pub display_name: String,
    pub stage: Arc<Mutex<StageRing>>,
    pub peers: Arc<Mutex<Vec<PairingRecord>>>,
    pub keystore: Arc<Keystore>,
    pub events: mpsc::UnboundedSender<AgentEvent>,
    /// Set by the tray's Pause item (T-12).
    pub paused: Arc<Mutex<bool>>,
    /// Active pairing token, present only while the pairing window is open.
    pub pairing: Arc<Mutex<Option<PairingOffer>>>,
    /// Port actually bound (may be ephemeral if 49517 was taken).
    port: Arc<Mutex<u16>>,
    /// Tray tooltip sink. Absent until the shell starts, and always absent off-Windows.
    #[cfg(windows)]
    tray: Arc<Mutex<Option<crate::tray::TrayHandle>>>,
    rate: Arc<Mutex<RateLimiter>>,
}

/// Tray tooltip sink that silently does nothing before the shell exists.
#[cfg(windows)]
pub struct TrayStatusSink(Option<crate::tray::TrayHandle>);

#[cfg(windows)]
impl TrayStatusSink {
    pub fn set_status(&self, status: crate::tray::Status, peer_name: Option<&str>) {
        if let Some(h) = &self.0 {
            h.set_status(status, peer_name);
        }
    }
}

/// A pairing window's token and the hosts printed into its QR.
#[derive(Debug, Clone)]
pub struct PairingOffer {
    pub token: [u8; 16],
    pub issued_ms: u64,
    pub hosts: Vec<String>,
}

impl AgentState {
    pub fn new(
        identity: IdentityKeypair,
        display_name: String,
        keystore: Arc<Keystore>,
        peers: Vec<PairingRecord>,
        events: mpsc::UnboundedSender<AgentEvent>,
    ) -> Self {
        Self {
            identity,
            display_name,
            stage: Arc::new(Mutex::new(StageRing::default())),
            peers: Arc::new(Mutex::new(peers)),
            keystore,
            events,
            paused: Arc::new(Mutex::new(false)),
            pairing: Arc::new(Mutex::new(None)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            #[cfg(windows)]
            tray: Arc::new(Mutex::new(None)),
            rate: Arc::new(Mutex::new(RateLimiter::default())),
        }
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.lock().unwrap()
    }

    /// Port the agent actually bound, so a later pairing window advertises the right one.
    pub fn listen_port(&self) -> u16 {
        *self.port.lock().unwrap()
    }

    pub fn set_listen_port(&self, port: u16) {
        *self.port.lock().unwrap() = port;
    }

    #[cfg(windows)]
    pub fn set_tray(&self, handle: crate::tray::TrayHandle) {
        *self.tray.lock().unwrap() = Some(handle);
    }

    /// Tooltip updater. Returns a no-op sink before the shell has started so callers
    /// never have to branch on whether the tray exists yet.
    #[cfg(windows)]
    pub fn tray(&self) -> TrayStatusSink {
        TrayStatusSink(self.tray.lock().unwrap().clone())
    }

    pub fn peer_keys(&self) -> Vec<PeerKey> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| {
                Some(PeerKey {
                    device_id: r.device_id_bytes().ok()?,
                    public_key: r.public_key_bytes().ok()?,
                })
            })
            .collect()
    }

    fn emit(&self, e: AgentEvent) {
        let _ = self.events.send(e);
    }
}

/// Per-source-address connection throttle (PROTOCOL §9).
#[derive(Default)]
struct RateLimiter {
    window_start_ms: HashMap<IpAddr, u64>,
    counts: HashMap<IpAddr, u32>,
    banned_until_ms: HashMap<IpAddr, u64>,
}

impl RateLimiter {
    fn allow(&mut self, ip: IpAddr, now: u64) -> bool {
        if let Some(&until) = self.banned_until_ms.get(&ip) {
            if now < until {
                return false;
            }
            self.banned_until_ms.remove(&ip);
        }
        let start = self.window_start_ms.entry(ip).or_insert(now);
        if now.saturating_sub(*start) >= 60_000 {
            *start = now;
            self.counts.insert(ip, 0);
        }
        let c = self.counts.entry(ip).or_insert(0);
        *c += 1;
        if *c > RATE_LIMIT_PER_MIN {
            self.banned_until_ms.insert(ip, now + RATE_LIMIT_BAN_MS);
            return false;
        }
        true
    }
}

/// Bind `DEFAULT_PORT`, falling back to an ephemeral port (PROTOCOL §4).
pub async fn bind() -> Result<TcpListener> {
    match TcpListener::bind(("0.0.0.0", DEFAULT_PORT)).await {
        Ok(l) => Ok(l),
        Err(e) => {
            tracing::warn!(port = DEFAULT_PORT, error = %e, "default port unavailable, using ephemeral");
            TcpListener::bind(("0.0.0.0", 0))
                .await
                .context("binding ephemeral port")
        }
    }
}

/// Accept loop. Runs until the listener errors unrecoverably.
pub async fn serve(listener: TcpListener, state: AgentState) -> Result<()> {
    let local = listener.local_addr()?;
    tracing::info!(%local, "listening");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };

        let allowed = state.rate.lock().unwrap().allow(peer_addr.ip(), now_ms());
        if !allowed {
            tracing::warn!(%peer_addr, "rate limited, dropping");
            continue;
        }

        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, st).await {
                tracing::debug!(%peer_addr, error = %e, "connection ended");
            }
        });
    }
}

/// One connection: either a pairing exchange or a session, decided by the first frame.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: AgentState,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let mut wire = Framed::new(stream, FrameCodec);

    let Some(first) = wire.next().await else {
        return Ok(()); // closed before sending anything
    };
    let first = first.context("decoding first frame")?;

    match first.ty {
        FrameType::PairReq => run_pairing(&mut wire, first, state).await,
        FrameType::Hello => run_session(&mut wire, first, state).await,
        other => {
            tracing::debug!(%peer_addr, ?other, "unexpected opening frame");
            Ok(())
        }
    }
}

async fn run_pairing(
    wire: &mut Framed<TcpStream, FrameCodec>,
    first: Frame,
    state: AgentState,
) -> Result<()> {
    let Some(offer) = state.pairing.lock().unwrap().clone() else {
        tracing::debug!("PAIR_REQ with no pairing window open");
        return Ok(());
    };

    let mut fsm = PcPairing::with_token(
        &state.identity,
        state.display_name.clone(),
        offer.hosts.clone(),
        offer.token,
        offer.issued_ms,
    );

    let mut frame = first;
    loop {
        for action in fsm.on_frame(&frame, now_ms()) {
            match action {
                PairingAction::Send(f) => wire.send(f).await?,
                PairingAction::ShowSas(sas) => state.emit(AgentEvent::PairingSas(sas)),
                PairingAction::Completed(record) => {
                    let all = state.keystore.upsert_pairing((*record).clone())?;
                    *state.peers.lock().unwrap() = all;
                    // Token is single-use: close the window as soon as it succeeds.
                    *state.pairing.lock().unwrap() = None;
                    tracing::info!(device_id = %record.device_id, "paired");
                    state.emit(AgentEvent::Paired { record });
                    return Ok(());
                }
                PairingAction::Failed(reason) => {
                    tracing::warn!(reason, "pairing failed");
                    state.emit(AgentEvent::PairingFailed {
                        reason: reason.to_string(),
                    });
                    return Ok(());
                }
            }
        }
        let Some(next) = wire.next().await else {
            return Ok(());
        };
        frame = next.context("decoding pairing frame")?;
    }
}

async fn run_session(
    wire: &mut Framed<TcpStream, FrameCodec>,
    first: Frame,
    state: AgentState,
) -> Result<()> {
    let mut session = Session::new_pc(state.identity.clone(), state.peer_keys(), now_ms());
    session.set_paused(state.is_paused());

    let mut connected_id: Option<String> = None;
    let mut frame = first;

    loop {
        // Pause can be toggled from the tray mid-session.
        session.set_paused(state.is_paused());

        for action in session.on_frame(&frame, now_ms()) {
            match action {
                SessionAction::Send(f) => wire.send(f).await?,
                SessionAction::Emit(event) => {
                    if let Some(reply) =
                        handle_event(event, &mut session, &state, &mut connected_id)?
                    {
                        wire.send(reply).await?;
                    }
                }
                SessionAction::Close(why) => {
                    tracing::debug!(why, "closing session");
                    if let Some(id) = connected_id.take() {
                        state.emit(AgentEvent::PeerDisconnected { device_id: id });
                    }
                    return Ok(());
                }
            }
        }

        let next = tokio::time::timeout(
            std::time::Duration::from_millis(airclip_core::session::SESSION_IDLE_TIMEOUT_MS),
            wire.next(),
        )
        .await;

        frame = match next {
            Ok(Some(f)) => f.context("decoding session frame")?,
            // Peer closed, or idle timeout elapsed (PROTOCOL §2).
            Ok(None) | Err(_) => {
                if let Some(id) = connected_id.take() {
                    state.emit(AgentEvent::PeerDisconnected { device_id: id });
                }
                return Ok(());
            }
        };
    }
}

/// Translate a core event into agent-level effects, optionally producing a reply frame.
fn handle_event(
    event: SessionEvent,
    session: &mut Session,
    state: &AgentState,
    connected_id: &mut Option<String>,
) -> Result<Option<Frame>> {
    match event {
        SessionEvent::Established { peer } => {
            let id = peer.hex();
            tracing::info!(device_id = %id, "session established");
            *connected_id = Some(id.clone());
            state.emit(AgentEvent::PeerConnected { device_id: id });
            Ok(None)
        }
        SessionEvent::ClipArrived {
            content_type,
            body,
            source_name,
            ..
        } => {
            // Length and type only — never the content (CLAUDE.md rule 4).
            tracing::info!(
                bytes = body.len(),
                ?content_type,
                hash = %short_hash(&body),
                "clip arrived"
            );
            state.emit(AgentEvent::ClipArrived {
                content_type,
                body,
                source_name,
            });
            Ok(None)
        }
        SessionEvent::StageListRequested => {
            let items = state.stage.lock().unwrap().list();
            Ok(Some(session.send_stage_list(&items)?))
        }
        SessionEvent::StageItemRequested { stage_id } => {
            let clip = state.stage.lock().unwrap().get(&stage_id).cloned();
            match clip {
                Some(c) => Ok(Some(session.send_stage_item(&c)?)),
                None => {
                    // Evicted between LIST and GET; an empty list is a benign answer.
                    tracing::debug!("STAGE_GET for an evicted id");
                    Ok(Some(session.send_stage_list(&[])?))
                }
            }
        }
        SessionEvent::PeerError { code, msg } => {
            tracing::warn!(code, %msg, "peer reported an error");
            Ok(None)
        }
        SessionEvent::ClipAcked { .. }
        | SessionEvent::StageList(_)
        | SessionEvent::StageItem { .. } => Ok(None), // phone-role events
    }
}

/// First 8 hex of BLAKE3 — the only content-derived value allowed in logs.
pub fn short_hash(bytes: &[u8]) -> String {
    blake3_hex8(bytes)
}

fn blake3_hex8(bytes: &[u8]) -> String {
    let h = airclip_core::crypto::content_digest(bytes);
    h[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_bans_after_threshold() {
        let mut rl = RateLimiter::default();
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        for i in 0..RATE_LIMIT_PER_MIN {
            assert!(rl.allow(ip, 1000), "attempt {i} should be allowed");
        }
        assert!(!rl.allow(ip, 1000), "threshold+1 must be refused");
        // Still banned inside the ban window.
        assert!(!rl.allow(ip, 1000 + RATE_LIMIT_BAN_MS - 1));
        // Released afterwards.
        assert!(rl.allow(ip, 1000 + RATE_LIMIT_BAN_MS + 1));
    }

    #[test]
    fn rate_limiter_is_per_address() {
        let mut rl = RateLimiter::default();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..=RATE_LIMIT_PER_MIN {
            rl.allow(a, 0);
        }
        assert!(!rl.allow(a, 0));
        assert!(rl.allow(b, 0), "a different address is unaffected");
    }

    #[test]
    fn rate_limiter_window_rolls_over() {
        let mut rl = RateLimiter::default();
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        for _ in 0..RATE_LIMIT_PER_MIN {
            assert!(rl.allow(ip, 0));
        }
        // A minute later the window resets.
        assert!(rl.allow(ip, 60_001));
    }
}
