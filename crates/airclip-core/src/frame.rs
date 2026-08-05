//! Frame codec per PROTOCOL.md §5: "ACP1" ‖ type u8 ‖ len u32le ‖ payload.

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::{Error, Result};
use crate::MAX_FRAME_LEN;

pub const MAGIC: [u8; 4] = *b"ACP1";
pub const HEADER_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    HelloAck = 0x02,
    PairReq = 0x10,
    PairAck = 0x11,
    PairConfirm = 0x12,
    ClipPush = 0x20,
    ClipAck = 0x21,
    StageListReq = 0x22,
    StageList = 0x23,
    StageGet = 0x24,
    StageItem = 0x25,
    Ping = 0x30,
    Pong = 0x31,
    Error = 0x3F,
}

impl FrameType {
    /// Encrypted frame types carry `nonce_ctr(8) ‖ AEAD ct` payloads (PROTOCOL §5).
    pub fn is_encrypted(self) -> bool {
        (self as u8) >= 0x20
    }

    /// All types, for exhaustive tests. Update when the protocol gains a frame.
    pub const ALL: [FrameType; 14] = [
        FrameType::Hello,
        FrameType::HelloAck,
        FrameType::PairReq,
        FrameType::PairAck,
        FrameType::PairConfirm,
        FrameType::ClipPush,
        FrameType::ClipAck,
        FrameType::StageListReq,
        FrameType::StageList,
        FrameType::StageGet,
        FrameType::StageItem,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Error,
    ];
}

impl TryFrom<u8> for FrameType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        use FrameType::*;
        Ok(match v {
            0x01 => Hello,
            0x02 => HelloAck,
            0x10 => PairReq,
            0x11 => PairAck,
            0x12 => PairConfirm,
            0x20 => ClipPush,
            0x21 => ClipAck,
            0x22 => StageListReq,
            0x23 => StageList,
            0x24 => StageGet,
            0x25 => StageItem,
            0x30 => Ping,
            0x31 => Pong,
            0x3F => Error,
            // 0x40..=0x4F are reserved for Phase 3 chunked transfer. Phase 1 has no
            // handler, and PROTOCOL §5 says unhandled types close the connection —
            // so they are rejected here rather than silently skipped.
            other => return Err(crate::error::Error::UnknownFrameType(other)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(ty: FrameType, payload: Vec<u8>) -> Self {
        Self { ty, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.ty as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse one complete frame from `buf`. Returns frame + bytes consumed,
    /// or Ok(None) if more bytes are needed. Errors are fatal to the connection.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>> {
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }
        if buf[0..4] != MAGIC {
            return Err(Error::BadMagic);
        }
        let ty = FrameType::try_from(buf[4])?;
        let len = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if len > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge(len));
        }
        let total = HEADER_LEN + len as usize;
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some((
            Frame {
                ty,
                payload: buf[HEADER_LEN..total].to_vec(),
            },
            total,
        )))
    }
}

/// Tokio codec driving `Frame` over a stream. Header is validated before the body is
/// buffered, so an oversize `length` is rejected without allocating for it.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }
        if src[0..4] != MAGIC {
            return Err(Error::BadMagic);
        }
        let ty = FrameType::try_from(src[4])?;
        let len = u32::from_le_bytes([src[5], src[6], src[7], src[8]]);
        if len > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge(len));
        }
        let total = HEADER_LEN + len as usize;
        if src.len() < total {
            // Hint the exact remainder so the transport reads it in one go.
            src.reserve(total - src.len());
            return Ok(None);
        }
        src.advance(HEADER_LEN);
        let payload = src.split_to(len as usize).to_vec();
        Ok(Some(Frame { ty, payload }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<()> {
        let len = item.payload.len();
        if len > MAX_FRAME_LEN as usize {
            return Err(Error::FrameTooLarge(len as u32));
        }
        dst.reserve(HEADER_LEN + len);
        dst.put_slice(&MAGIC);
        dst.put_u8(item.ty as u8);
        dst.put_u32_le(len as u32);
        dst.put_slice(&item.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_util::codec::FramedRead;

    #[test]
    fn round_trip_all_types() {
        for ty in FrameType::ALL {
            let f = Frame {
                ty,
                payload: vec![0xAB; 33],
            };
            let enc = f.encode();
            let (dec, used) = Frame::decode(&enc).unwrap().unwrap();
            assert_eq!(used, enc.len());
            assert_eq!(dec, f);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut enc = Frame {
            ty: FrameType::Ping,
            payload: vec![],
        }
        .encode();
        enc[0] = b'X';
        assert!(matches!(Frame::decode(&enc), Err(Error::BadMagic)));
    }

    #[test]
    fn rejects_oversize_length() {
        let mut enc = Frame {
            ty: FrameType::Ping,
            payload: vec![],
        }
        .encode();
        enc[5..9].copy_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        assert!(matches!(Frame::decode(&enc), Err(Error::FrameTooLarge(_))));
    }

    #[test]
    fn partial_input_needs_more() {
        let enc = Frame {
            ty: FrameType::Ping,
            payload: vec![1, 2, 3],
        }
        .encode();
        assert!(Frame::decode(&enc[..enc.len() - 1]).unwrap().is_none());
        assert!(Frame::decode(&enc[..4]).unwrap().is_none());
    }

    #[test]
    fn encrypted_type_classification() {
        assert!(!FrameType::Hello.is_encrypted());
        assert!(!FrameType::PairConfirm.is_encrypted());
        assert!(FrameType::ClipPush.is_encrypted());
        assert!(FrameType::Error.is_encrypted());
    }

    #[test]
    fn reserved_chunk_range_rejected_in_phase1() {
        for b in 0x40u8..=0x4F {
            assert!(matches!(
                FrameType::try_from(b),
                Err(Error::UnknownFrameType(_))
            ));
        }
    }

    // --- codec ---

    #[test]
    fn codec_round_trip_all_types() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        for ty in FrameType::ALL {
            let f = Frame::new(ty, vec![0x5A; 7]);
            codec.encode(f.clone(), &mut buf).unwrap();
            let got = codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(got, f);
            assert!(buf.is_empty(), "codec left trailing bytes");
        }
    }

    #[test]
    fn codec_decodes_back_to_back_frames() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        codec
            .encode(Frame::new(FrameType::Ping, vec![]), &mut buf)
            .unwrap();
        codec
            .encode(Frame::new(FrameType::ClipPush, vec![9; 20]), &mut buf)
            .unwrap();

        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().ty, FrameType::Ping);
        let second = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(second.ty, FrameType::ClipPush);
        assert_eq!(second.payload.len(), 20);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn codec_waits_for_full_payload() {
        let mut codec = FrameCodec;
        let full = Frame::new(FrameType::StageItem, vec![7; 64]).encode();
        let mut buf = BytesMut::new();

        // Feed one byte at a time; nothing decodes until the final byte arrives.
        for b in &full[..full.len() - 1] {
            buf.extend_from_slice(&[*b]);
            assert!(codec.decode(&mut buf).unwrap().is_none());
        }
        buf.extend_from_slice(&[full[full.len() - 1]]);
        let f = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(f.payload.len(), 64);
    }

    #[test]
    fn codec_rejects_oversize_header_without_buffering_body() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&[FrameType::ClipPush as u8]);
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        assert!(matches!(
            codec.decode(&mut buf),
            Err(Error::FrameTooLarge(_))
        ));
    }

    #[test]
    fn codec_encode_rejects_oversize_payload() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        let too_big = Frame::new(FrameType::ClipPush, vec![0; MAX_FRAME_LEN as usize + 1]);
        assert!(matches!(
            codec.encode(too_big, &mut buf),
            Err(Error::FrameTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn framed_read_over_async_stream() {
        let mut wire = Vec::new();
        for ty in FrameType::ALL {
            wire.extend_from_slice(&Frame::new(ty, vec![1, 2, 3]).encode());
        }
        let mut framed = FramedRead::new(&wire[..], FrameCodec);
        for ty in FrameType::ALL {
            let f = framed.next().await.unwrap().unwrap();
            assert_eq!(f.ty, ty);
            assert_eq!(f.payload, vec![1, 2, 3]);
        }
        assert!(framed.next().await.is_none());
    }

    #[tokio::test]
    async fn framed_write_then_read_duplex() {
        let (client, server) = tokio::io::duplex(4096);
        let mut tx = tokio_util::codec::FramedWrite::new(client, FrameCodec);
        let mut rx = FramedRead::new(server, FrameCodec);

        tx.send(Frame::new(FrameType::ClipPush, b"hello".to_vec()))
            .await
            .unwrap();
        let got = rx.next().await.unwrap().unwrap();
        assert_eq!(got.ty, FrameType::ClipPush);
        assert_eq!(got.payload, b"hello");
    }

    /// A truncated stream must surface as a decode error, not a silent short frame.
    #[tokio::test]
    async fn framed_read_rejects_truncated_tail() {
        let full = Frame::new(FrameType::ClipPush, vec![3; 40]).encode();
        let truncated = &full[..full.len() - 5];
        let mut framed = FramedRead::new(truncated, FrameCodec);
        let err = framed.next().await.unwrap();
        assert!(err.is_err(), "truncated frame should error at EOF");
    }

    // --- property tests ---
    //
    // These mirror fuzz/fuzz_targets/frame.rs, which needs Linux + nightly (libFuzzer
    // does not build on MSVC). Keeping the same invariants as proptest means the
    // decoder's no-panic guarantee is actually verified on a Windows dev box.
    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Arbitrary bytes must never panic the decoder — error or None only.
            #[test]
            fn decode_never_panics(data: Vec<u8>) {
                let _ = Frame::decode(&data);

                let mut codec = FrameCodec;
                let mut buf = BytesMut::from(&data[..]);
                while let Ok(Some(_)) = codec.decode(&mut buf) {}
            }

            /// Bytes that happen to carry a valid header must not desync the stream.
            #[test]
            fn decode_never_panics_on_valid_header_prefix(
                ty_byte in 0u8..=0xFF,
                len in 0u32..2048,
                tail: Vec<u8>,
            ) {
                let mut data = Vec::new();
                data.extend_from_slice(&MAGIC);
                data.push(ty_byte);
                data.extend_from_slice(&len.to_le_bytes());
                data.extend_from_slice(&tail);

                let mut codec = FrameCodec;
                let mut buf = BytesMut::from(&data[..]);
                while let Ok(Some(_)) = codec.decode(&mut buf) {}
            }

            /// Any frame the codec accepts must re-encode to the identical bytes.
            #[test]
            fn encode_decode_round_trips(
                idx in 0usize..FrameType::ALL.len(),
                payload in proptest::collection::vec(any::<u8>(), 0..4096),
            ) {
                let f = Frame::new(FrameType::ALL[idx], payload);
                let mut codec = FrameCodec;
                let mut buf = BytesMut::new();
                codec.encode(f.clone(), &mut buf).unwrap();

                let wire = buf.clone();
                let manual = f.encode();
                let got = codec.decode(&mut buf).unwrap().unwrap();
                prop_assert_eq!(&got, &f);
                prop_assert!(buf.is_empty());
                prop_assert_eq!(wire.as_ref(), manual.as_slice());
            }

            /// Splitting the stream at an arbitrary point must not change the result:
            /// the decoder has to be resumable at any byte boundary.
            #[test]
            fn arbitrary_split_point_is_resumable(
                idx in 0usize..FrameType::ALL.len(),
                payload in proptest::collection::vec(any::<u8>(), 0..512),
                split_pct in 0usize..=100,
            ) {
                let f = Frame::new(FrameType::ALL[idx], payload);
                let wire = f.encode();
                let split = wire.len() * split_pct / 100;

                let mut codec = FrameCodec;
                let mut buf = BytesMut::from(&wire[..split]);
                if split < wire.len() {
                    prop_assert!(codec.decode(&mut buf).unwrap().is_none());
                }
                buf.extend_from_slice(&wire[split..]);
                let got = codec.decode(&mut buf).unwrap().unwrap();
                prop_assert_eq!(got, f);
            }
        }
    }
}
