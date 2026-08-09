//! T-06 — the UniFFI boundary. **This is the only file Swift sees** (CLAUDE.md rule 6).
//!
//! Shape per ARCHITECTURE §3: commands in, events out. Swift never touches frames, keys,
//! sessions or sockets — only strings, byte payloads and plain enums.
//!
//! Every command blocks until it completes or times out. That is deliberate: the App
//! Intent path must finish inside the intent's lifetime (ARCHITECTURE §4), and a
//! callback-based API would make "did my beam actually land?" unanswerable at the moment
//! Shortcuts needs to render a result.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::client::{self, ClientError, Connection, PendingPairing};
use crate::crypto::IdentityKeypair;
use crate::pairing::{PairingRecord, QrPayload};
use crate::session::PeerKey;
use crate::ContentType;

/// Clipboard payload kind on the wire (PROTOCOL §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiContentType {
    Text,
    Url,
}

impl From<ContentType> for FfiContentType {
    fn from(c: ContentType) -> Self {
        match c {
            ContentType::Text => Self::Text,
            ContentType::Url => Self::Url,
        }
    }
}

impl From<FfiContentType> for ContentType {
    fn from(c: FfiContentType) -> Self {
        match c {
            FfiContentType::Text => Self::Text,
            FfiContentType::Url => Self::Url,
        }
    }
}

/// One staged clip's metadata — enough to render a keyboard chip without fetching bodies.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiStageItem {
    /// Hex-encoded opaque id; pass back verbatim to fetch the body.
    pub stage_id: String,
    pub content_type: FfiContentType,
    pub preview: String,
    pub size: u32,
    pub copied_at_ms: u64,
}

/// A stored pairing, for the Settings screen.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPeer {
    pub device_id: String,
    pub display_name: String,
    pub paired_at_ms: u64,
}

/// Failure modes worth distinguishing in the UI (SPEC R9: no silent failures).
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    #[error("not paired with a PC yet")]
    NotPaired,
    #[error("your PC isn't reachable on this network")]
    Unreachable,
    #[error("your PC didn't respond in time")]
    TimedOut,
    #[error("this clip is too large to send")]
    TooLarge,
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    Internal(String),
}

impl From<ClientError> for FfiError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Unreachable => Self::Unreachable,
            ClientError::TimedOut => Self::TimedOut,
            ClientError::TooLarge { .. } => Self::TooLarge,
            ClientError::Rejected(r) => Self::Rejected(r),
            ClientError::Protocol(r) => Self::Internal(r),
        }
    }
}

/// Outcome of a beam.
///
/// Non-throwing on purpose: the App Intent always has to render *something* to Shortcuts,
/// and a thrown error there degrades into a generic system failure message.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum BeamResult {
    Sent { clip_id: String },
    NotPaired,
    Unreachable,
    TimedOut,
    TooLarge { max_bytes: u32 },
    Failed { reason: String },
}

/// Events pushed to the app. Kept small — anything a command can return synchronously
/// is returned, not emitted.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum CoreEvent {
    /// Show these four emoji and ask the user to compare with the PC (PROTOCOL §7.2).
    PairingSas {
        emoji: Vec<String>,
    },
    Paired {
        device_id: String,
        display_name: String,
    },
    PairingFailed {
        reason: String,
    },
    PeerUnreachable,
}

/// Implemented in Swift over the Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
/// non-synchronizable) and shared with the extensions via the app group.
///
/// The core never chooses *where* secrets live; that is a platform decision, and on
/// Windows the equivalent is DPAPI called directly in Rust, bypassing FFI entirely.
#[uniffi::export(callback_interface)]
pub trait KeystoreDelegate: Send + Sync {
    /// 32-byte identity seed, or None on first launch.
    fn load_identity_seed(&self) -> Option<Vec<u8>>;
    fn store_identity_seed(&self, seed: Vec<u8>);
    /// Pairing records as a JSON array, or None if never paired.
    fn load_pairings(&self) -> Option<String>;
    fn store_pairings(&self, json: String);
}

/// Implemented in Swift to receive [`CoreEvent`]s.
#[uniffi::export(callback_interface)]
pub trait CoreEventListener: Send + Sync {
    fn on_event(&self, event: CoreEvent);
}

struct CoreState {
    identity: IdentityKeypair,
    peers: Vec<PairingRecord>,
    /// Addresses fed in from NWBrowser (iOS does its own discovery — ADR-4).
    hints: Vec<std::net::SocketAddr>,
    /// Live pairing exchange, waiting on the user's emoji comparison.
    pending: Option<PendingPairing>,
    /// Addresses carried by the QR we are pairing against.
    ///
    /// Promoted to `hints` on success so the first beam works immediately. Without this
    /// a user can pair (pairing dials the QR's hosts directly) and then have every beam
    /// fail as unreachable while mDNS is still settling — a confusing first run for
    /// something that just visibly worked.
    pending_hosts: Vec<std::net::SocketAddr>,
}

/// The one object Swift holds. Owns the runtime and all mutable state.
#[derive(uniffi::Object)]
pub struct CoreHandle {
    state: Mutex<CoreState>,
    keystore: Box<dyn KeystoreDelegate>,
    listener: Box<dyn CoreEventListener>,
    runtime: tokio::runtime::Runtime,
}

#[uniffi::export]
impl CoreHandle {
    /// Load or create the device identity and restore any stored pairings.
    #[uniffi::constructor]
    pub fn new(
        keystore: Box<dyn KeystoreDelegate>,
        listener: Box<dyn CoreEventListener>,
    ) -> Result<Arc<Self>, FfiError> {
        // Current-thread, per ARCHITECTURE §4: extensions are memory-capped
        // (IOS-PLATFORM-NOTES §5 — the keyboard gets ~60 MB) and spawning a worker pool
        // to run one short request at a time is pure overhead. `block_on` takes &self
        // and is safe to call from any thread; concurrent callers serialise rather than
        // racing, which is the behaviour we want anyway.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| FfiError::Internal(e.to_string()))?;

        let identity = match keystore.load_identity_seed() {
            Some(seed) if seed.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&seed);
                IdentityKeypair::from_seed(arr)
            }
            _ => {
                let id =
                    IdentityKeypair::generate().map_err(|e| FfiError::Internal(e.to_string()))?;
                keystore.store_identity_seed(id.secret_bytes().to_vec());
                id
            }
        };

        let peers: Vec<PairingRecord> = keystore
            .load_pairings()
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();

        Ok(Arc::new(Self {
            state: Mutex::new(CoreState {
                identity,
                peers,
                hints: Vec::new(),
                pending: None,
                pending_hosts: Vec::new(),
            }),
            keystore,
            listener,
            runtime,
        }))
    }

    /// This device's id (PROTOCOL §3), hex-encoded. Display and diagnostics only.
    pub fn device_id(&self) -> String {
        self.state.lock().unwrap().identity.device_id().hex()
    }

    pub fn is_paired(&self) -> bool {
        !self.state.lock().unwrap().peers.is_empty()
    }

    pub fn peers(&self) -> Vec<FfiPeer> {
        self.state
            .lock()
            .unwrap()
            .peers
            .iter()
            .map(|p| FfiPeer {
                device_id: p.device_id.clone(),
                display_name: p.display_name.clone(),
                paired_at_ms: p.created_at_ms,
            })
            .collect()
    }

    /// Feed an address discovered by NWBrowser, or entered manually (SPEC R10).
    ///
    /// mDNS results are hints only and are never trusted for identity — the handshake
    /// is what authenticates (PROTOCOL §4).
    pub fn add_peer_hint(&self, host: String, port: u16) {
        let Ok(ip) = host.parse::<std::net::IpAddr>() else {
            return; // literals only; a DNS lookup here could leave the LAN
        };
        let addr = std::net::SocketAddr::new(ip, port);
        let mut st = self.state.lock().unwrap();
        if !st.hints.contains(&addr) {
            st.hints.push(addr);
        }
    }

    pub fn clear_peer_hints(&self) {
        self.state.lock().unwrap().hints.clear();
    }

    /// Scan result from the pairing QR. Emits `PairingSas` once both sides agree on the
    /// basis; nothing is stored until [`Self::confirm_sas`].
    pub fn start_pairing(&self, qr_url: String, display_name: String) -> Result<(), FfiError> {
        let qr = QrPayload::parse(&qr_url).map_err(|e| FfiError::Rejected(e.to_string()))?;
        let qr_hosts = client::resolve_hosts(&qr.hosts);

        let identity = {
            let mut st = self.state.lock().unwrap();
            st.pending_hosts = qr_hosts;
            st.identity.clone()
        };

        let pending = self
            .runtime
            .block_on(client::begin_pairing(
                &identity,
                &display_name,
                qr,
                client::DEFAULT_OP_TIMEOUT,
            ))
            .map_err(|e| {
                if matches!(e, ClientError::Unreachable) {
                    self.listener.on_event(CoreEvent::PeerUnreachable);
                }
                let reason = e.to_string();
                self.listener.on_event(CoreEvent::PairingFailed {
                    reason: reason.clone(),
                });
                FfiError::from(e)
            })?;

        let emoji = pending.sas().iter().map(|s| (*s).to_string()).collect();
        self.state.lock().unwrap().pending = Some(pending);
        self.listener.on_event(CoreEvent::PairingSas { emoji });
        Ok(())
    }

    /// The user confirmed the emoji match. Sends PAIR_CONFIRM and persists the pairing.
    pub fn confirm_sas(&self) -> Result<(), FfiError> {
        let pending = self
            .state
            .lock()
            .unwrap()
            .pending
            .take()
            .ok_or(FfiError::Internal("no pairing in progress".into()))?;

        let record = self
            .runtime
            .block_on(pending.confirm())
            .map_err(FfiError::from)?;

        let (device_id, display_name) = (record.device_id.clone(), record.display_name.clone());
        {
            let mut st = self.state.lock().unwrap();
            st.peers.retain(|p| p.device_id != record.device_id);
            st.peers.push(record);
            if let Ok(json) = serde_json::to_string(&st.peers) {
                self.keystore.store_pairings(json);
            }
            // The QR's addresses are known-good — we just completed a pairing over them.
            for addr in std::mem::take(&mut st.pending_hosts) {
                if !st.hints.contains(&addr) {
                    st.hints.push(addr);
                }
            }
        }
        self.listener.on_event(CoreEvent::Paired {
            device_id,
            display_name,
        });
        Ok(())
    }

    /// The user rejected the emoji. Drops the connection without sending anything.
    pub fn cancel_pairing(&self) {
        let mut st = self.state.lock().unwrap();
        st.pending = None;
        st.pending_hosts.clear();
    }

    pub fn forget_peer(&self, device_id: String) {
        let mut st = self.state.lock().unwrap();
        st.peers.retain(|p| p.device_id != device_id);
        if let Ok(json) = serde_json::to_string(&st.peers) {
            self.keystore.store_pairings(json);
        }
    }

    /// Beam text to the paired PC and wait for its acknowledgement.
    ///
    /// This is the hero path (SPEC R3): Action Button → intent → here → PC clipboard.
    pub fn beam_text_await(&self, text: String, timeout_ms: u32) -> BeamResult {
        let (identity, peer, addrs) = match self.connection_params() {
            Ok(v) => v,
            Err(_) => return BeamResult::NotPaired,
        };
        let timeout = Duration::from_millis(timeout_ms.max(250) as u64);
        // Classify here rather than in the app: the wire type drives how the PC pastes
        // it (PROTOCOL §8.1), so the decision belongs next to the protocol.
        let content_type = classify(&text);

        let result = self.runtime.block_on(async move {
            let mut conn = Connection::open(identity, peer, &addrs, timeout).await?;
            conn.beam(content_type, text.as_bytes(), "iPhone").await
        });

        match result {
            Ok(clip_id) => BeamResult::Sent {
                clip_id: hex::encode(clip_id),
            },
            Err(ClientError::Unreachable) => {
                self.listener.on_event(CoreEvent::PeerUnreachable);
                BeamResult::Unreachable
            }
            Err(ClientError::TimedOut) => BeamResult::TimedOut,
            Err(ClientError::TooLarge { max_bytes }) => BeamResult::TooLarge { max_bytes },
            Err(e) => BeamResult::Failed {
                reason: e.to_string(),
            },
        }
    }

    /// Fetch staged clip metadata for the keyboard's chip row (SPEC R6).
    ///
    /// One round trip, previews only — the ≤700 ms budget in PROTOCOL §8.2 does not
    /// survive fetching bodies up front.
    pub fn fetch_stage_list_await(&self, timeout_ms: u32) -> Result<Vec<FfiStageItem>, FfiError> {
        let (identity, peer, addrs) = self.connection_params()?;
        let timeout = Duration::from_millis(timeout_ms.max(250) as u64);

        let items = self
            .runtime
            .block_on(async move {
                let mut conn = Connection::open(identity, peer, &addrs, timeout).await?;
                conn.stage_list().await
            })
            .map_err(FfiError::from)?;

        Ok(items
            .into_iter()
            .map(|m| FfiStageItem {
                stage_id: hex::encode(m.stage_id),
                content_type: m.content_type.into(),
                preview: m.preview,
                size: m.size,
                copied_at_ms: m.copied_at_ms,
            })
            .collect())
    }

    /// Fetch one staged body, for insertion at the cursor (ADR-7 — never the pasteboard).
    pub fn fetch_stage_item_await(
        &self,
        stage_id: String,
        timeout_ms: u32,
    ) -> Result<String, FfiError> {
        let raw = hex::decode(&stage_id)
            .ok()
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .ok_or(FfiError::Internal("malformed stage id".into()))?;

        let (identity, peer, addrs) = self.connection_params()?;
        let timeout = Duration::from_millis(timeout_ms.max(250) as u64);

        let (_ct, body) = self
            .runtime
            .block_on(async move {
                let mut conn = Connection::open(identity, peer, &addrs, timeout).await?;
                conn.stage_item(&raw).await
            })
            .map_err(FfiError::from)?;

        // Phase 1 is text and URLs only, so lossy conversion cannot lose real data —
        // and returning a String keeps `insertText` a one-liner in Swift.
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

impl CoreHandle {
    /// Gather what a connection needs, or fail early if unpaired / undiscovered.
    fn connection_params(
        &self,
    ) -> Result<(IdentityKeypair, PeerKey, Vec<std::net::SocketAddr>), FfiError> {
        let st = self.state.lock().unwrap();
        let record = st.peers.first().ok_or(FfiError::NotPaired)?;
        let peer = PeerKey {
            device_id: record
                .device_id_bytes()
                .map_err(|e| FfiError::Internal(e.to_string()))?,
            public_key: record
                .public_key_bytes()
                .map_err(|e| FfiError::Internal(e.to_string()))?,
        };
        if st.hints.is_empty() {
            return Err(FfiError::Unreachable);
        }
        Ok((st.identity.clone(), peer, st.hints.clone()))
    }
}

/// Tag text as a URL when it is *only* a URL (PROTOCOL §8.1).
fn classify(text: &str) -> ContentType {
    let t = text.trim();
    if !t.contains(char::is_whitespace) && (t.starts_with("http://") || t.starts_with("https://")) {
        ContentType::Url
    } else {
        ContentType::Text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// In-memory stand-in for the Keychain.
    #[derive(Default)]
    struct MemKeystore {
        seed: StdMutex<Option<Vec<u8>>>,
        pairings: StdMutex<Option<String>>,
    }

    impl KeystoreDelegate for MemKeystore {
        fn load_identity_seed(&self) -> Option<Vec<u8>> {
            self.seed.lock().unwrap().clone()
        }
        fn store_identity_seed(&self, seed: Vec<u8>) {
            *self.seed.lock().unwrap() = Some(seed);
        }
        fn load_pairings(&self) -> Option<String> {
            self.pairings.lock().unwrap().clone()
        }
        fn store_pairings(&self, json: String) {
            *self.pairings.lock().unwrap() = Some(json);
        }
    }

    #[derive(Default)]
    struct RecordingListener {
        events: StdMutex<Vec<String>>,
    }

    impl CoreEventListener for RecordingListener {
        fn on_event(&self, event: CoreEvent) {
            self.events.lock().unwrap().push(format!("{event:?}"));
        }
    }

    fn handle() -> Arc<CoreHandle> {
        CoreHandle::new(
            Box::new(MemKeystore::default()),
            Box::new(RecordingListener::default()),
        )
        .unwrap()
    }

    #[test]
    fn identity_is_generated_once_and_reused() {
        let ks = Arc::new(MemKeystore::default());
        let first = {
            struct Shared(Arc<MemKeystore>);
            impl KeystoreDelegate for Shared {
                fn load_identity_seed(&self) -> Option<Vec<u8>> {
                    self.0.load_identity_seed()
                }
                fn store_identity_seed(&self, s: Vec<u8>) {
                    self.0.store_identity_seed(s)
                }
                fn load_pairings(&self) -> Option<String> {
                    self.0.load_pairings()
                }
                fn store_pairings(&self, j: String) {
                    self.0.store_pairings(j)
                }
            }
            let h = CoreHandle::new(
                Box::new(Shared(ks.clone())),
                Box::new(RecordingListener::default()),
            )
            .unwrap();
            let id = h.device_id();

            // A second handle over the same keystore must recover the same identity,
            // which is what makes a pairing survive an app relaunch.
            let h2 = CoreHandle::new(
                Box::new(Shared(ks.clone())),
                Box::new(RecordingListener::default()),
            )
            .unwrap();
            assert_eq!(h2.device_id(), id);
            id
        };
        assert_eq!(first.len(), 32, "device id is 16 bytes hex-encoded");
    }

    #[test]
    fn unpaired_handle_reports_not_paired() {
        let h = handle();
        assert!(!h.is_paired());
        assert!(h.peers().is_empty());
        assert!(matches!(
            h.beam_text_await("hi".into(), 500),
            BeamResult::NotPaired
        ));
        assert!(matches!(
            h.fetch_stage_list_await(500),
            Err(FfiError::NotPaired)
        ));
    }

    #[test]
    fn peer_hints_reject_hostnames_and_dedupe() {
        let h = handle();
        h.add_peer_hint("192.168.1.9".into(), 49517);
        h.add_peer_hint("192.168.1.9".into(), 49517); // duplicate
        h.add_peer_hint("my-pc.local".into(), 49517); // hostname: must be ignored
        assert_eq!(h.state.lock().unwrap().hints.len(), 1);

        h.clear_peer_hints();
        assert!(h.state.lock().unwrap().hints.is_empty());
    }

    #[test]
    fn malformed_qr_is_rejected_without_panicking() {
        let h = handle();
        for bad in ["", "not a url", "https://pair?v=1", "airclip://pair?v=9"] {
            assert!(h.start_pairing(bad.into(), "iPhone".into()).is_err());
        }
    }

    #[test]
    fn confirm_without_pairing_is_an_error() {
        let h = handle();
        assert!(matches!(h.confirm_sas(), Err(FfiError::Internal(_))));
    }

    #[test]
    fn malformed_stage_id_is_rejected() {
        let h = handle();
        assert!(h.fetch_stage_item_await("zz".into(), 500).is_err());
        assert!(
            h.fetch_stage_item_await("aabb".into(), 500).is_err(),
            "wrong width"
        );
    }

    #[test]
    fn content_classification_matches_the_agent() {
        assert_eq!(classify("https://example.com"), ContentType::Url);
        assert_eq!(classify("see https://x.com now"), ContentType::Text);
        assert_eq!(classify("plain text"), ContentType::Text);
    }

    #[test]
    fn forget_peer_persists_through_the_keystore() {
        let h = handle();
        {
            let mut st = h.state.lock().unwrap();
            st.peers.push(PairingRecord {
                device_id: "aa".repeat(16),
                public_key: "x".into(),
                display_name: "PC".into(),
                created_at_ms: 1,
                last_seen_ms: 1,
            });
        }
        assert!(h.is_paired());
        h.forget_peer("aa".repeat(16));
        assert!(!h.is_paired());
    }
}
