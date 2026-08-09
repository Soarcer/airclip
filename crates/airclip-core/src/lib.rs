//! airclip-core — shared protocol, crypto, and session logic.
//!
//! Platform-free by rule (see CLAUDE.md #5). Normative spec: docs/PROTOCOL.md.
//! Modules are stubs pending tasks T-01..T-06 in docs/PHASE-1-TASKS.md.

pub mod cbor;
pub mod client;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod frame;
pub mod pairing;
pub mod session;
pub mod stage;

#[cfg(feature = "ffi")]
pub mod ffi;

// UniFFI's proc-macro mode needs this once per crate to emit the scaffolding that the
// generated Swift links against.
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
// pub mod discovery;   // T-05
// #[cfg(feature = "ffi")]
// pub mod ffi;         // T-06

/// PROTOCOL.md §2 — change requires a protocol doc amendment.
pub const PROTOCOL_VERSION: u8 = 1;
pub const DEFAULT_PORT: u16 = 49_517;
pub const MDNS_SERVICE: &str = "_airclip._tcp.local.";
pub const MAX_FRAME_LEN: u32 = 1_048_576;
pub const MAX_TEXT_CLIP: usize = 262_144;
pub const STAGE_DEPTH: usize = 5;

/// Which end of the protocol this instance plays. PROTOCOL.md / ADR-3:
/// the phone always dials; the PC always listens and stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Phone,
    Pc,
}

/// 16-byte truncated BLAKE3 of the identity public key (PROTOCOL.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Clipboard content type on the wire (PROTOCOL.md §8.1). 3..=9 reserved for Phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Text = 1,
    Url = 2,
}

impl TryFrom<u8> for ContentType {
    type Error = error::Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Text),
            2 => Ok(Self::Url),
            _ => Err(error::Error::UnknownContentType(v)),
        }
    }
}
