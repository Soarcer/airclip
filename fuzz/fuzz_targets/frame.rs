#![no_main]
//! T-01 fuzz target: the frame decoder must never panic on hostile input.
//!
//! Build/run on Linux nightly (libFuzzer is not usable on MSVC):
//!   cargo +nightly fuzz run frame
//! CI runs a short smoke job on the ubuntu runner (T-00).

use airclip_core::frame::{Frame, FrameCodec};
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    // One-shot parse: any outcome is acceptable except a panic.
    let _ = Frame::decode(data);

    // Streaming parse: feed everything, then drain. Also exercises the
    // advance/split_to bookkeeping that the one-shot path doesn't touch.
    let mut codec = FrameCodec;
    let mut buf = BytesMut::from(data);
    while let Ok(Some(frame)) = codec.decode(&mut buf) {
        // Re-encoding a decoded frame must round-trip identically.
        let re = frame.encode();
        match Frame::decode(&re) {
            Ok(Some((again, _))) => assert_eq!(again, frame),
            other => panic!("re-encode failed to round-trip: {other:?}"),
        }
    }
});
