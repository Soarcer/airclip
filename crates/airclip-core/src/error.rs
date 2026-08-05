use thiserror::Error;

/// Wire error codes per PROTOCOL.md §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum WireErrorCode {
    UnsupportedVersion = 1,
    NotPaired = 2,
    BadToken = 3,
    FrameTooLarge = 4,
    RateLimited = 5,
    Internal = 6,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("bad frame magic")]
    BadMagic,
    #[error("frame length {0} exceeds MAX_FRAME_LEN")]
    FrameTooLarge(u32),
    #[error("unknown frame type {0:#04x}")]
    UnknownFrameType(u8),
    #[error("unknown content type {0}")]
    UnknownContentType(u8),
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("crypto failure")] // deliberately unspecific; never leak which check failed
    Crypto,
    #[error("peer sent wire error {code:?}: {msg}")]
    Peer { code: u16, msg: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
