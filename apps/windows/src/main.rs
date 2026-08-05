//! AirClip Windows tray agent (SPEC R8, ARCHITECTURE §5).
//!
//! `--simulate-peer <qr-url>` runs an in-process phone-role core against a running agent
//! for end-to-end testing without an iPhone (docs/PHASE-1-TASKS.md T-10).

mod clipboard;
mod keystore;
mod pairing_window;
mod server;
mod simulate;
mod toast;
mod tray;

use std::sync::Arc;

use airclip_core::discovery::{Discovery, MdnsDiscovery};
use anyhow::Result;
use tokio::sync::mpsc;

use crate::keystore::Keystore;
use crate::server::{AgentEvent, AgentState, PairingOffer};

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Agent,
    /// Drive a full pair+beam+pull transcript against a running agent.
    SimulatePeer {
        qr_url: String,
    },
    /// Open pairing mode and print the QR URL.
    Pair,
    Help,
}

fn classify_args(args: &[String]) -> Mode {
    match args.first().map(String::as_str) {
        Some("--simulate-peer") => match args.get(1) {
            Some(url) => Mode::SimulatePeer {
                qr_url: url.clone(),
            },
            None => Mode::Help,
        },
        Some("--pair") => Mode::Pair,
        None => Mode::Agent,
        _ => Mode::Help,
    }
}

fn print_help() {
    println!(
        "airclip-windows {}\n\n\
         USAGE:\n  \
         airclip-windows                      run the tray agent\n  \
         airclip-windows --pair               open pairing mode and print the QR URL\n  \
         airclip-windows --simulate-peer URL  act as a phone against a running agent\n  \
         airclip-windows --help\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2) // ARCHITECTURE §4: traffic is tiny
        .enable_all()
        .build()?;

    match classify_args(&args) {
        Mode::Help => {
            print_help();
            Ok(())
        }
        Mode::SimulatePeer { qr_url } => runtime.block_on(simulate::run(&qr_url)),
        Mode::Pair => run_agent(&runtime, true),
        Mode::Agent => run_agent(&runtime, false),
    }
}

/// Start the agent, then hand the **main thread** to the tray/window shell.
///
/// The split matters on Windows: eframe must run on the main thread, so the async work
/// lives on the runtime and the tray pumps its own message loop on a worker (tray.rs).
fn run_agent(runtime: &tokio::runtime::Runtime, open_pairing: bool) -> Result<()> {
    // Held for the whole process: a second launch must not fight over the port. Binding
    // it here rather than inside setup keeps the mutex alive for the agent's lifetime.
    #[cfg(windows)]
    let _instance = match tray::SingleInstance::acquire()? {
        Some(i) => i,
        None => {
            tracing::info!("another AirClip instance is already running; exiting");
            return Ok(());
        }
    };

    // Tooltip channel is created here so the async event pump can update tray status
    // while the tray itself lives on its own thread.
    let (tip_tx, tip_rx) = std::sync::mpsc::channel::<String>();

    let started = runtime.block_on(start_services(open_pairing, tip_tx))?;
    runtime.spawn(server::serve(started.listener, started.state.clone()));

    #[cfg(windows)]
    {
        run_shell(started.state, started.pairing_view, open_pairing, tip_rx)
    }
    #[cfg(not(windows))]
    {
        // No tray or window off-Windows; just keep the server alive.
        let _ = (&started.state, &started.pairing_view, open_pairing, tip_rx);
        runtime.block_on(std::future::pending::<()>());
        Ok(())
    }
}

/// Everything the shell needs once async setup has finished.
struct Started {
    state: AgentState,
    listener: tokio::net::TcpListener,
    pairing_view: pairing_window::SharedView,
}

/// The tray/window shell. Owns the main thread and blocks until Quit.
#[cfg(windows)]
fn run_shell(
    state: AgentState,
    pairing_view: pairing_window::SharedView,
    open_now: bool,
    tip_rx: std::sync::mpsc::Receiver<String>,
) -> Result<()> {
    let commands = match tray::spawn_tray(state.is_paused(), tray::is_autostart_enabled(), tip_rx) {
        Ok(v) => v,
        Err(e) => {
            // A missing notification area shouldn't kill the agent — it still serves
            // sessions headlessly, which is exactly what --simulate-peer needs.
            tracing::warn!(error = %e, "tray unavailable; running headless");
            std::thread::park();
            return Ok(());
        }
    };

    let idle_status = if state.peers.lock().unwrap().is_empty() {
        tray::Status::Unpaired
    } else {
        tray::Status::Idle
    };
    state.tray().set_status(idle_status, None);

    if open_now {
        pairing_window::run(pairing_view.clone())?;
    }

    for cmd in commands {
        match cmd {
            tray::TrayCommand::OpenPairing => {
                let port = state.listen_port();
                match open_pairing_window(&state, port) {
                    Ok(url) => {
                        *pairing_view.lock().unwrap() = pairing_window::PairingView::ShowQr { url };
                        // Blocks on the main thread until the user closes the window.
                        if let Err(e) = pairing_window::run(pairing_view.clone()) {
                            tracing::warn!(error = %e, "pairing window failed");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "cannot start pairing"),
                }
            }
            tray::TrayCommand::SetPaused(p) => {
                *state.paused.lock().unwrap() = p;
                tracing::info!(paused = p, "beaming pause toggled");
                state
                    .tray()
                    .set_status(if p { tray::Status::Paused } else { idle_status }, None);
            }
            tray::TrayCommand::SetAutostart(on) => {
                if let Err(e) = tray::set_autostart(on) {
                    tracing::warn!(error = %e, "autostart toggle failed");
                }
            }
            tray::TrayCommand::Quit => {
                tracing::info!("quit requested from tray");
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn start_services(
    open_pairing: bool,
    tip_tx: std::sync::mpsc::Sender<String>,
) -> Result<Started> {
    let keystore = Arc::new(Keystore::open()?);
    let identity = keystore.load_or_create_identity()?;
    let peers = keystore.load_pairings().unwrap_or_default();
    let display_name = hostname();

    tracing::info!(
        device_id = %identity.device_id().hex(),
        name = %display_name,
        paired = peers.len(),
        "airclip agent starting"
    );

    let listener = server::bind().await?;
    let port = listener.local_addr()?.port();

    let (tx, mut rx) = mpsc::unbounded_channel::<AgentEvent>();
    let state = AgentState::new(
        identity.clone(),
        display_name.clone(),
        keystore.clone(),
        peers,
        tx,
    );
    state.set_listen_port(port);
    #[cfg(windows)]
    state.set_tray(tray::TrayHandle::new(tip_tx));
    #[cfg(not(windows))]
    let _ = tip_tx;

    // mDNS advertisement (PROTOCOL §4). Failure is non-fatal: the pairing QR carries
    // explicit hosts, and manual host entry (R10) does not need discovery either.
    let mdns = match MdnsDiscovery::new() {
        Ok(mut d) => match d.advertise(&identity.device_id(), &display_name, port) {
            Ok(()) => {
                tracing::info!(port, "advertising _airclip._tcp");
                Some(d)
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS advertise failed; discovery unavailable");
                None
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "mDNS unavailable; discovery disabled");
            None
        }
    };

    let pairing_view: pairing_window::SharedView =
        Arc::new(std::sync::Mutex::new(pairing_window::PairingView::ShowQr {
            url: String::new(),
        }));

    if open_pairing {
        let url = open_pairing_window(&state, port)?;
        println!("\nPairing URL (valid 10 minutes):\n{url}\n");
        println!("Run this in another terminal to simulate an iPhone:");
        println!("  cargo run -p airclip-windows -- --simulate-peer \"{url}\"\n");
        *pairing_view.lock().unwrap() = pairing_window::PairingView::ShowQr { url };
    }

    // Clipboard watcher → stage ring (SPEC R5).
    #[cfg(windows)]
    {
        let stage = state.stage.clone();
        match clipboard::spawn_watcher(clipboard::OwnWriteGuard::default()) {
            Ok(watch_rx) => {
                std::thread::spawn(move || {
                    for ev in watch_rx {
                        let mut ring = stage.lock().unwrap();
                        match ring.push(ev.content_type, ev.body, server::now_ms()) {
                            Ok(_) => tracing::debug!(staged = ring.len(), "staged local clip"),
                            Err(e) => tracing::debug!(error = %e, "clip not staged"),
                        }
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "clipboard watcher unavailable"),
        }
    }

    // Event pump: apply core events to the Windows shell, and mirror pairing progress
    // into the window's shared view.
    let view_for_events = pairing_view.clone();
    let state_for_events = state.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            #[cfg(windows)]
            match &event {
                AgentEvent::PeerConnected { .. } => state_for_events
                    .tray()
                    .set_status(tray::Status::Connected, None),
                AgentEvent::PeerDisconnected { .. } => {
                    let s = if state_for_events.is_paused() {
                        tray::Status::Paused
                    } else {
                        tray::Status::Idle
                    };
                    state_for_events.tray().set_status(s, None);
                }
                _ => {}
            }
            match &event {
                AgentEvent::PairingSas(emoji) => {
                    *view_for_events.lock().unwrap() =
                        pairing_window::PairingView::CompareSas { emoji: *emoji };
                }
                AgentEvent::Paired { record } => {
                    *view_for_events.lock().unwrap() = pairing_window::PairingView::Success {
                        device_name: record.display_name.clone(),
                    };
                }
                AgentEvent::PairingFailed { reason } => {
                    *view_for_events.lock().unwrap() = pairing_window::PairingView::Failed {
                        reason: reason.clone(),
                    };
                }
                _ => {}
            }
            handle_agent_event(event);
        }
    });

    // mDNS registration lives as long as the process; dropping it here would
    // immediately withdraw the advertisement.
    std::mem::forget(mdns);

    Ok(Started {
        state,
        listener,
        pairing_view,
    })
}

fn handle_agent_event(event: AgentEvent) {
    match event {
        AgentEvent::ClipArrived {
            body,
            source_name,
            content_type,
        } => {
            // Phase 1 writes both Text and Url as CF_UNICODETEXT; PROTOCOL §8.1 also
            // wants CFSTR_INETURL set for Url, which lands with the richer paste work.
            tracing::debug!(?content_type, "writing clip to clipboard");
            let text = String::from_utf8_lossy(&body).into_owned();
            #[cfg(windows)]
            {
                match clipboard::set_text(&text, &clipboard::OwnWriteGuard::default()) {
                    Ok(_) => tracing::info!(bytes = body.len(), "clipboard updated"),
                    Err(e) => tracing::warn!(error = %e, "failed to set clipboard"),
                }
                let preview = toast::toast_preview(&text);
                if let Err(e) = toast::show_clip_arrived(&preview, &source_name) {
                    tracing::debug!(error = %e, "toast failed (AUMID not registered?)");
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (&text, &source_name);
                tracing::info!(
                    bytes = body.len(),
                    "clip received (no clipboard on this platform)"
                );
            }
        }
        AgentEvent::PairingSas(emoji) => {
            println!(
                "\n  Pairing code: {}\n  Confirm on your iPhone that these match.\n",
                emoji.join(" ")
            );
        }
        AgentEvent::Paired { record } => println!("✓ Paired with {}", record.display_name),
        AgentEvent::PairingFailed { reason } => println!("✗ Pairing failed: {reason}"),
        AgentEvent::PeerConnected { device_id } => tracing::info!(%device_id, "peer connected"),
        AgentEvent::PeerDisconnected { device_id } => {
            tracing::info!(%device_id, "peer disconnected")
        }
    }
}

/// Open a 10-minute pairing window and return the QR URL (PROTOCOL §7.1).
fn open_pairing_window(state: &AgentState, port: u16) -> Result<String> {
    let mut token = [0u8; 16];
    getrandom::fill(&mut token).map_err(|_| anyhow::anyhow!("rng failure"))?;
    let hosts = pairing_window::local_hosts(port);
    if hosts.is_empty() {
        anyhow::bail!("no usable network interface — connect to Wi-Fi and retry");
    }

    let url = pairing_window::pairing_url(
        &state.identity.device_id(),
        &state.identity.public_bytes(),
        &state.display_name,
        hosts.clone(),
        token,
    );

    *state.pairing.lock().unwrap() = Some(PairingOffer {
        token,
        issued_ms: server::now_ms(),
        hosts,
    });
    Ok(url)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Windows PC".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_args_runs_the_agent() {
        assert_eq!(classify_args(&args(&[])), Mode::Agent);
    }

    #[test]
    fn pair_flag_is_recognised() {
        assert_eq!(classify_args(&args(&["--pair"])), Mode::Pair);
    }

    #[test]
    fn simulate_peer_requires_a_url() {
        assert_eq!(
            classify_args(&args(&["--simulate-peer", "airclip://pair?v=1"])),
            Mode::SimulatePeer {
                qr_url: "airclip://pair?v=1".into()
            }
        );
        // Missing URL falls back to help rather than panicking on a missing index.
        assert_eq!(classify_args(&args(&["--simulate-peer"])), Mode::Help);
    }

    #[test]
    fn unknown_flags_show_help() {
        assert_eq!(classify_args(&args(&["--nope"])), Mode::Help);
        assert_eq!(classify_args(&args(&["--help"])), Mode::Help);
    }

    #[test]
    fn hostname_always_returns_something() {
        assert!(!hostname().is_empty());
    }
}
