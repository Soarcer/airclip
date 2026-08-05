//! T-04 acceptance harness (ARCHITECTURE §8): two `Session`s talking over an in-memory
//! duplex, through the real frame codec. This is the test that proves pairing, the
//! handshake, and both traffic directions actually interoperate — the unit tests only
//! prove each half in isolation.

use std::time::{Duration, Instant};

use airclip_core::crypto::IdentityKeypair;
use airclip_core::frame::{Frame, FrameCodec, FrameType};
use airclip_core::pairing::{PairingAction, PairingRecord, PcPairing, PhonePairing, QrPayload};
use airclip_core::session::{PeerKey, Session, SessionAction, SessionEvent, HELLO_TS_WINDOW_MS};
use airclip_core::stage::StageRing;
use airclip_core::ContentType;
use futures_util::{SinkExt, StreamExt};
use tokio::io::DuplexStream;
use tokio_util::codec::Framed;

const NOW: u64 = 1_700_000_000_000;
type Wire = Framed<DuplexStream, FrameCodec>;

fn wire_pair() -> (Wire, Wire) {
    let (a, b) = tokio::io::duplex(1 << 20);
    (Framed::new(a, FrameCodec), Framed::new(b, FrameCodec))
}

async fn send(w: &mut Wire, f: Frame) {
    w.send(f).await.expect("send frame");
}

async fn recv(w: &mut Wire) -> Frame {
    w.next().await.expect("stream open").expect("decode frame")
}

fn peer_key(k: &IdentityKeypair) -> PeerKey {
    PeerKey {
        device_id: k.device_id(),
        public_key: k.public_bytes(),
    }
}

fn peer_key_from_record(r: &PairingRecord) -> PeerKey {
    PeerKey {
        device_id: r.device_id_bytes().unwrap(),
        public_key: r.public_key_bytes().unwrap(),
    }
}

/// Run the full QR pairing exchange over the wire. Returns each side's stored record.
async fn pair_over_wire(
    phone_id: &IdentityKeypair,
    pc_id: &IdentityKeypair,
    phone_w: &mut Wire,
    pc_w: &mut Wire,
) -> (PairingRecord, PairingRecord) {
    let mut pc = PcPairing::with_token(
        pc_id,
        "SAMMAMISH-PC",
        vec!["127.0.0.1:49517".into()],
        [0x5A; 16],
        NOW,
    );
    let qr = QrPayload::parse(&pc.qr_url()).expect("QR parses");

    let (mut phone, req) = PhonePairing::start(phone_id, "Bernhard's iPhone", qr).unwrap();
    send(phone_w, req).await;

    // PC: PAIR_REQ → PAIR_ACK + SAS
    let got = recv(pc_w).await;
    assert_eq!(got.ty, FrameType::PairReq);
    let pc_actions = pc.on_frame(&got, NOW);
    let (ack, pc_sas) = match pc_actions.as_slice() {
        [PairingAction::Send(f), PairingAction::ShowSas(s)] => (f.clone(), *s),
        other => panic!("unexpected PC pairing actions: {other:?}"),
    };
    send(pc_w, ack).await;

    // Phone: PAIR_ACK → SAS
    let got = recv(phone_w).await;
    assert_eq!(got.ty, FrameType::PairAck);
    let phone_sas = match phone.on_frame(&got).as_slice() {
        [PairingAction::ShowSas(s)] => *s,
        other => panic!("unexpected phone pairing actions: {other:?}"),
    };
    assert_eq!(pc_sas, phone_sas, "both screens must show identical emoji");

    // User confirms.
    let (confirm, phone_record) = match phone.confirm_sas(NOW).as_slice() {
        [PairingAction::Send(f), PairingAction::Completed(r)] => (f.clone(), (**r).clone()),
        other => panic!("unexpected confirm actions: {other:?}"),
    };
    send(phone_w, confirm).await;

    let got = recv(pc_w).await;
    assert_eq!(got.ty, FrameType::PairConfirm);
    let pc_record = match pc.on_frame(&got, NOW).as_slice() {
        [PairingAction::Completed(r)] => (**r).clone(),
        other => panic!("unexpected PC confirm actions: {other:?}"),
    };

    (phone_record, pc_record)
}

/// Establish an encrypted session over the wire from existing pairings.
async fn handshake_over_wire(
    phone_id: &IdentityKeypair,
    pc_id: &IdentityKeypair,
    phone_peer: PeerKey,
    pc_peer: PeerKey,
    phone_w: &mut Wire,
    pc_w: &mut Wire,
    now_ms: u64,
) -> (Session, Session) {
    let (mut phone, hello) = Session::start_phone(phone_id.clone(), phone_peer, now_ms).unwrap();
    let mut pc = Session::new_pc(pc_id.clone(), vec![pc_peer], now_ms);

    send(phone_w, hello).await;
    let got = recv(pc_w).await;
    assert_eq!(got.ty, FrameType::Hello);
    let ack = match pc.on_frame(&got, now_ms).as_slice() {
        [SessionAction::Send(f), SessionAction::Emit(SessionEvent::Established { .. })] => {
            f.clone()
        }
        other => panic!("unexpected PC handshake actions: {other:?}"),
    };
    send(pc_w, ack).await;

    let got = recv(phone_w).await;
    assert_eq!(got.ty, FrameType::HelloAck);
    assert!(matches!(
        phone.on_frame(&got, now_ms).as_slice(),
        [SessionAction::Emit(SessionEvent::Established { .. })]
    ));

    (phone, pc)
}

/// The headline flow: pair, handshake, beam a clip, pull the staged list.
#[tokio::test]
async fn full_pair_handshake_beam_and_stage_pull() {
    let started = Instant::now();

    let phone_id = IdentityKeypair::from_seed([0xF0; 32]);
    let pc_id = IdentityKeypair::from_seed([0xC1; 32]);
    let (mut phone_w, mut pc_w) = wire_pair();

    // --- pair ---
    let (phone_record, pc_record) =
        pair_over_wire(&phone_id, &pc_id, &mut phone_w, &mut pc_w).await;
    assert_eq!(phone_record.display_name, "SAMMAMISH-PC");
    assert_eq!(pc_record.display_name, "Bernhard's iPhone");
    // Each side must have stored the other's real identity key.
    assert_eq!(peer_key_from_record(&phone_record), peer_key(&pc_id));
    assert_eq!(peer_key_from_record(&pc_record), peer_key(&phone_id));

    // --- handshake, using only what pairing persisted ---
    let (mut phone, mut pc) = handshake_over_wire(
        &phone_id,
        &pc_id,
        peer_key_from_record(&phone_record),
        peer_key_from_record(&pc_record),
        &mut phone_w,
        &mut pc_w,
        NOW,
    )
    .await;

    // --- iPhone → PC beam (SPEC R3) ---
    let (push, clip_id) = phone
        .push_clip(
            ContentType::Text,
            "hello 🚀 from iPhone".as_bytes(),
            "Bernhard's iPhone",
            NOW,
        )
        .unwrap();
    send(&mut phone_w, push).await;

    let got = recv(&mut pc_w).await;
    let acts = pc.on_frame(&got, NOW);
    let ack = match acts.as_slice() {
        [SessionAction::Emit(SessionEvent::ClipArrived {
            body,
            source_name,
            clip_id: id,
            ..
        }), SessionAction::Send(f)] => {
            assert_eq!(body, "hello 🚀 from iPhone".as_bytes());
            assert_eq!(source_name, "Bernhard's iPhone");
            assert_eq!(*id, clip_id);
            f.clone()
        }
        other => panic!("unexpected PC traffic actions: {other:?}"),
    };
    send(&mut pc_w, ack).await;

    let got = recv(&mut phone_w).await;
    assert!(matches!(
        phone.on_frame(&got, NOW).as_slice(),
        [SessionAction::Emit(SessionEvent::ClipAcked {
            status: 0,
            ..
        })]
    ));

    // --- PC → iPhone staged pull (SPEC R6) ---
    // Stage 6 into a depth-5 ring: the oldest must be evicted.
    let mut ring = StageRing::default();
    for i in 0..6u8 {
        ring.push_with_id(
            [i; 8],
            ContentType::Text,
            format!("staged clip {i}").into_bytes(),
            NOW + i as u64,
        )
        .unwrap();
    }
    assert_eq!(ring.len(), 5, "depth-5 ring must evict the oldest of 6");

    send(&mut phone_w, phone.request_stage_list().unwrap()).await;
    let got = recv(&mut pc_w).await;
    assert!(matches!(
        pc.on_frame(&got, NOW).as_slice(),
        [SessionAction::Emit(SessionEvent::StageListRequested)]
    ));
    send(&mut pc_w, pc.send_stage_list(&ring.list()).unwrap()).await;

    let got = recv(&mut phone_w).await;
    let list = match phone.on_frame(&got, NOW).as_slice() {
        [SessionAction::Emit(SessionEvent::StageList(l))] => l.clone(),
        other => panic!("unexpected phone stage actions: {other:?}"),
    };
    assert_eq!(list.len(), 5);
    assert_eq!(list[0].preview, "staged clip 5", "newest first");
    assert_eq!(list[4].preview, "staged clip 1", "oldest surviving entry");
    assert!(
        !list.iter().any(|m| m.preview == "staged clip 0"),
        "evicted clip must not appear"
    );

    // Fetch one body.
    send(
        &mut phone_w,
        phone.request_stage_item(&list[0].stage_id).unwrap(),
    )
    .await;
    let got = recv(&mut pc_w).await;
    let asked = match pc.on_frame(&got, NOW).as_slice() {
        [SessionAction::Emit(SessionEvent::StageItemRequested { stage_id })] => *stage_id,
        other => panic!("unexpected: {other:?}"),
    };
    send(
        &mut pc_w,
        pc.send_stage_item(ring.get(&asked).unwrap()).unwrap(),
    )
    .await;

    let got = recv(&mut phone_w).await;
    match phone.on_frame(&got, NOW).as_slice() {
        [SessionAction::Emit(SessionEvent::StageItem { body, stage_id, .. })] => {
            assert_eq!(*stage_id, [5u8; 8]);
            assert_eq!(body, b"staged clip 5");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Guards against a stray sleep creeping into the hot path; the real latency budget
    // (SPEC goal 1) is measured on device in T-14.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "loopback flow took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn replayed_frame_closes_the_session() {
    let phone_id = IdentityKeypair::from_seed([0x01; 32]);
    let pc_id = IdentityKeypair::from_seed([0x02; 32]);
    let (mut phone_w, mut pc_w) = wire_pair();

    let (mut phone, mut pc) = handshake_over_wire(
        &phone_id,
        &pc_id,
        peer_key(&pc_id),
        peer_key(&phone_id),
        &mut phone_w,
        &mut pc_w,
        NOW,
    )
    .await;

    let (push, _) = phone
        .push_clip(ContentType::Text, b"only once", "iPhone", NOW)
        .unwrap();

    // Deliver it twice, as a LAN attacker replaying a captured frame would.
    send(&mut phone_w, push.clone()).await;
    let got = recv(&mut pc_w).await;
    assert!(pc
        .on_frame(&got, NOW)
        .iter()
        .any(|a| matches!(a, SessionAction::Emit(SessionEvent::ClipArrived { .. }))));

    send(&mut phone_w, push).await;
    let got = recv(&mut pc_w).await;
    assert!(matches!(
        pc.on_frame(&got, NOW).as_slice(),
        [SessionAction::Close(_)]
    ));
    assert!(pc.is_closed(), "counter reuse must terminate the session");
}

#[tokio::test]
async fn hello_with_stale_timestamp_is_rejected_over_the_wire() {
    let phone_id = IdentityKeypair::from_seed([0x03; 32]);
    let pc_id = IdentityKeypair::from_seed([0x04; 32]);
    let (mut phone_w, mut pc_w) = wire_pair();

    let (_, hello) = Session::start_phone(phone_id.clone(), peer_key(&pc_id), NOW).unwrap();
    send(&mut phone_w, hello).await;

    // PC's clock is far ahead of the HELLO timestamp.
    let mut pc = Session::new_pc(pc_id, vec![peer_key(&phone_id)], NOW);
    let got = recv(&mut pc_w).await;
    let late = NOW + HELLO_TS_WINDOW_MS + 1;
    assert!(matches!(
        pc.on_frame(&got, late).as_slice(),
        [SessionAction::Close(_)]
    ));
    assert!(pc.is_closed());
}

#[tokio::test]
async fn unpaired_device_cannot_establish_a_session() {
    let real_phone = IdentityKeypair::from_seed([0x05; 32]);
    let attacker = IdentityKeypair::from_seed([0xAA; 32]);
    let pc_id = IdentityKeypair::from_seed([0x06; 32]);
    let (mut phone_w, mut pc_w) = wire_pair();

    // Attacker knows the PC's public key (it is in the QR / mDNS) but was never paired.
    let (_, hello) = Session::start_phone(attacker, peer_key(&pc_id), NOW).unwrap();
    send(&mut phone_w, hello).await;

    let mut pc = Session::new_pc(pc_id, vec![peer_key(&real_phone)], NOW);
    let got = recv(&mut pc_w).await;
    let acts = pc.on_frame(&got, NOW);

    assert!(matches!(acts.as_slice(), [SessionAction::Close(_)]));
    assert!(
        !acts.iter().any(|a| matches!(a, SessionAction::Send(_))),
        "must close silently — PROTOCOL §6.1 forbids an oracle"
    );
}

/// A session survives many sequential clips; counters keep advancing.
#[tokio::test]
async fn sustained_traffic_keeps_counters_monotonic() {
    let phone_id = IdentityKeypair::from_seed([0x07; 32]);
    let pc_id = IdentityKeypair::from_seed([0x08; 32]);
    let (mut phone_w, mut pc_w) = wire_pair();

    let (mut phone, mut pc) = handshake_over_wire(
        &phone_id,
        &pc_id,
        peer_key(&pc_id),
        peer_key(&phone_id),
        &mut phone_w,
        &mut pc_w,
        NOW,
    )
    .await;

    for i in 0..50u32 {
        let body = format!("clip number {i}");
        let (push, _) = phone
            .push_clip(ContentType::Text, body.as_bytes(), "iPhone", NOW + i as u64)
            .unwrap();
        send(&mut phone_w, push).await;

        let got = recv(&mut pc_w).await;
        let acts = pc.on_frame(&got, NOW + i as u64);
        let ack = match acts.as_slice() {
            [SessionAction::Emit(SessionEvent::ClipArrived { body: b, .. }), SessionAction::Send(f)] =>
            {
                assert_eq!(b, body.as_bytes());
                f.clone()
            }
            other => panic!("iteration {i}: unexpected {other:?}"),
        };
        send(&mut pc_w, ack).await;
        let got = recv(&mut phone_w).await;
        assert!(matches!(
            phone.on_frame(&got, NOW).as_slice(),
            [SessionAction::Emit(SessionEvent::ClipAcked { .. })]
        ));
    }
    assert!(phone.is_established() && pc.is_established());
}

/// A 256 KiB clip — the SPEC R5 maximum — must survive the round trip intact.
#[tokio::test]
async fn max_size_clip_round_trips() {
    let phone_id = IdentityKeypair::from_seed([0x09; 32]);
    let pc_id = IdentityKeypair::from_seed([0x0A; 32]);
    let (mut phone_w, mut pc_w) = wire_pair();

    let (mut phone, mut pc) = handshake_over_wire(
        &phone_id,
        &pc_id,
        peer_key(&pc_id),
        peer_key(&phone_id),
        &mut phone_w,
        &mut pc_w,
        NOW,
    )
    .await;

    let body = vec![b'x'; airclip_core::MAX_TEXT_CLIP];
    let (push, _) = phone
        .push_clip(ContentType::Text, &body, "iPhone", NOW)
        .unwrap();
    send(&mut phone_w, push).await;

    let got = recv(&mut pc_w).await;
    match pc.on_frame(&got, NOW).as_slice() {
        [SessionAction::Emit(SessionEvent::ClipArrived { body: b, .. }), SessionAction::Send(_)] => {
            assert_eq!(b.len(), airclip_core::MAX_TEXT_CLIP);
            assert_eq!(b, &body);
        }
        other => panic!("unexpected: {other:?}"),
    }
}
