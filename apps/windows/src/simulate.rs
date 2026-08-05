//! T-10 — `--simulate-peer`: an in-process phone-role core so the whole PC path can be
//! exercised end to end without an iPhone.
//!
//! Reuses `Role::Phone` from `airclip-core` (ADR: two roles, one crate), so this exercises
//! the same code the real phone will run — not a mock.

use std::time::Duration;

use airclip_core::crypto::IdentityKeypair;
use airclip_core::frame::{Frame, FrameCodec, FrameType};
use airclip_core::pairing::{PairingAction, PairingRecord, PhonePairing, QrPayload};
use airclip_core::session::{PeerKey, Session, SessionAction, SessionEvent};
use airclip_core::ContentType;
use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::server::now_ms;

type Wire = Framed<TcpStream, FrameCodec>;

async fn connect(host: &str) -> Result<Wire> {
    let stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(host))
        .await
        .with_context(|| format!("timed out connecting to {host}"))?
        .with_context(|| format!("connecting to {host}"))?;
    stream.set_nodelay(true).ok();
    Ok(Framed::new(stream, FrameCodec))
}

async fn expect_frame(wire: &mut Wire, ty: FrameType) -> Result<Frame> {
    let Some(f) = wire.next().await else {
        bail!("connection closed while waiting for {ty:?}");
    };
    let f = f.context("decoding frame")?;
    if f.ty != ty {
        bail!("expected {ty:?}, got {:?}", f.ty);
    }
    Ok(f)
}

/// Run pair → handshake → beam → stage pull against a running agent, printing a
/// transcript. This is the T-10 acceptance check.
pub async fn run(qr_url: &str) -> Result<()> {
    let qr = QrPayload::parse(qr_url).context("parsing the pairing URL")?;
    println!("── AirClip simulated peer ──");
    println!("PC          : {} ({})", qr.display_name, qr.device_id.hex());
    println!("hosts       : {}", qr.hosts.join(", "));

    let phone_id = IdentityKeypair::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("phone id    : {}", phone_id.device_id().hex());

    let host = qr
        .hosts
        .first()
        .cloned()
        .context("QR carried no host addresses")?;

    // --- pairing ---
    let mut wire = connect(&host).await?;
    let (mut fsm, req) = PhonePairing::start(&phone_id, "Simulated iPhone", qr.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    wire.send(req).await?;
    println!("→ PAIR_REQ");

    let ack = expect_frame(&mut wire, FrameType::PairAck).await?;
    println!("← PAIR_ACK");
    let sas = match fsm.on_frame(&ack).as_slice() {
        [PairingAction::ShowSas(s)] => *s,
        other => bail!("unexpected pairing actions: {other:?}"),
    };
    println!("  SAS       : {}", sas.join(" "));
    println!("  (compare with the pairing window — they must match)");

    let pc_record: PairingRecord = match fsm.confirm_sas(now_ms()).as_slice() {
        [PairingAction::Send(f), PairingAction::Completed(r)] => {
            wire.send(f.clone()).await?;
            println!("→ PAIR_CONFIRM");
            (**r).clone()
        }
        other => bail!("unexpected confirm actions: {other:?}"),
    };
    println!("✓ paired with {}", pc_record.display_name);
    drop(wire);

    // --- session on a fresh connection, exactly like the real phone ---
    let mut wire = connect(&host).await?;
    let peer = PeerKey {
        device_id: pc_record
            .device_id_bytes()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        public_key: pc_record
            .public_key_bytes()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    let (mut session, hello) = Session::start_phone(phone_id.clone(), peer, now_ms())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    wire.send(hello).await?;
    println!("→ HELLO");

    let ack = expect_frame(&mut wire, FrameType::HelloAck).await?;
    println!("← HELLO_ACK");
    match session.on_frame(&ack, now_ms()).as_slice() {
        [SessionAction::Emit(SessionEvent::Established { peer })] => {
            println!("✓ session established with {}", peer.hex());
        }
        other => bail!("handshake failed: {other:?}"),
    }

    // --- beam a clip to the PC (SPEC R3) ---
    let text = "Beamed by --simulate-peer 🚀";
    let (push, _) = session
        .push_clip(
            ContentType::Text,
            text.as_bytes(),
            "Simulated iPhone",
            now_ms(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    wire.send(push).await?;
    println!("→ CLIP_PUSH ({} bytes)", text.len());

    let ack = expect_frame(&mut wire, FrameType::ClipAck).await?;
    match session.on_frame(&ack, now_ms()).as_slice() {
        [SessionAction::Emit(SessionEvent::ClipAcked { status: 0, .. })] => {
            println!("← CLIP_ACK ok — check your Windows clipboard");
        }
        other => bail!("clip was not acknowledged: {other:?}"),
    }

    // --- pull the PC's staged clips (SPEC R6) ---
    wire.send(
        session
            .request_stage_list()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .await?;
    println!("→ STAGE_LIST_REQ");

    let list_frame = expect_frame(&mut wire, FrameType::StageList).await?;
    let items = match session.on_frame(&list_frame, now_ms()).as_slice() {
        [SessionAction::Emit(SessionEvent::StageList(items))] => items.clone(),
        other => bail!("unexpected stage list actions: {other:?}"),
    };
    println!("← STAGE_LIST ({} staged)", items.len());
    for (i, m) in items.iter().enumerate() {
        println!("   [{i}] {:?} {}B  {}", m.content_type, m.size, m.preview);
    }

    if let Some(first) = items.first() {
        wire.send(
            session
                .request_stage_item(&first.stage_id)
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .await?;
        println!("→ STAGE_GET");
        let item = expect_frame(&mut wire, FrameType::StageItem).await?;
        match session.on_frame(&item, now_ms()).as_slice() {
            [SessionAction::Emit(SessionEvent::StageItem { body, .. })] => {
                println!("← STAGE_ITEM ({} bytes)", body.len());
                println!("   body: {}", String::from_utf8_lossy(body));
            }
            other => bail!("unexpected stage item actions: {other:?}"),
        }
    } else {
        println!("   (copy something on the PC first to see staged clips)");
    }

    println!("── transcript complete: pair + beam + pull all succeeded ──");
    Ok(())
}
