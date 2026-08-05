//! T-13 — pairing window (ADR-6: one egui window, everything else is tray-only).
//!
//! Shows the QR from PROTOCOL §7.1, then the 4-emoji SAS, then a success state. The
//! window is the only GUI in the product, so it stays deliberately plain.
//!
//! Runs on the **main** thread: winit/eframe requires it on Windows, which is why the
//! tray pumps its own message loop on a worker thread instead (see tray.rs).
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use airclip_core::DeviceId;
use anyhow::Result;
use qrcode::QrCode;

/// Local addresses to advertise in the QR, best-first.
///
/// Ordering matters: the phone dials the first address that answers, so a private LAN
/// address must come before link-local, and loopback is useless to a phone.
pub fn local_hosts(port: u16) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            match iface.ip() {
                std::net::IpAddr::V4(ip) => {
                    // Skip APIPA: 169.254/16 means DHCP failed, nothing will reach us.
                    if ip.is_link_local() {
                        continue;
                    }
                    v4.push(format!("{ip}:{port}"));
                }
                std::net::IpAddr::V6(ip) => {
                    // Bracketed per RFC 3986 so `host:port` parsing stays unambiguous.
                    v6.push(format!("[{ip}]:{port}"));
                }
            }
        }
    }
    v4.extend(v6);
    v4
}

/// QR modules as a row-major boolean grid, for rendering into any UI toolkit.
pub struct QrGrid {
    pub size: usize,
    pub dark: Vec<bool>,
}

impl QrGrid {
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.size + x]
    }
}

/// Encode the pairing URL as a QR grid.
pub fn qr_grid(url: &str) -> Result<QrGrid> {
    let code = QrCode::new(url.as_bytes())?;
    let colors = code.to_colors();
    let size = code.width();
    Ok(QrGrid {
        size,
        dark: colors
            .into_iter()
            .map(|c| c == qrcode::types::Color::Dark)
            .collect(),
    })
}

/// What the pairing window is currently showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingView {
    /// Waiting for the phone to scan.
    ShowQr {
        url: String,
    },
    /// Both sides computed a SAS; the user compares them.
    CompareSas {
        emoji: [&'static str; 4],
    },
    Success {
        device_name: String,
    },
    Failed {
        reason: String,
    },
}

/// Human-readable instruction for each stage, kept out of the render loop so it is testable.
pub fn instruction(view: &PairingView) -> String {
    match view {
        PairingView::ShowQr { .. } => "Open AirClip on your iPhone and scan this code.".into(),
        PairingView::CompareSas { .. } => {
            "Check these match what your iPhone shows, then confirm on the phone.".into()
        }
        PairingView::Success { device_name } => format!("Paired with {device_name}."),
        PairingView::Failed { reason } => format!("Pairing failed: {reason}"),
    }
}

/// The QR payload for a pairing window (PROTOCOL §7.1).
pub fn pairing_url(
    device_id: &DeviceId,
    public_key: &[u8; 32],
    display_name: &str,
    hosts: Vec<String>,
    token: [u8; 16],
) -> String {
    airclip_core::pairing::QrPayload {
        version: airclip_core::PROTOCOL_VERSION,
        device_id: *device_id,
        public_key: *public_key,
        display_name: display_name.to_owned(),
        hosts,
        pair_token: token,
    }
    .to_url()
}

/// Shared cell the server task writes progress into and the window polls each frame.
pub type SharedView = Arc<Mutex<PairingView>>;

/// Render the QR grid as an egui texture.
///
/// Nearest-neighbour scaling with an integer module size: QR codes must not be
/// interpolated, or the scanner sees blurred module edges and fails to lock on.
fn qr_texture(ctx: &egui::Context, grid: &QrGrid) -> egui::TextureHandle {
    const QUIET: usize = 4; // quiet zone, required by the QR spec
    let dim = grid.size + QUIET * 2;
    let mut pixels = vec![egui::Color32::WHITE; dim * dim];
    for y in 0..grid.size {
        for x in 0..grid.size {
            if grid.is_dark(x, y) {
                pixels[(y + QUIET) * dim + (x + QUIET)] = egui::Color32::BLACK;
            }
        }
    }
    let image = egui::ColorImage {
        size: [dim, dim],
        pixels,
        source_size: egui::vec2(dim as f32, dim as f32),
    };
    ctx.load_texture("airclip-qr", image, egui::TextureOptions::NEAREST)
}

struct PairingApp {
    view: SharedView,
    qr: Option<egui::TextureHandle>,
    last_url: String,
}

impl eframe::App for PairingApp {
    // eframe 0.35 hands the root `Ui` directly; there is no `update`/CentralPanel step.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Pairing progress is driven from the server task on another thread, so repaint
        // on a timer rather than waiting for input events.
        ctx.request_repaint_after(std::time::Duration::from_millis(200));
        let view = self.view.lock().unwrap().clone();

        ui.vertical_centered(|ui| {
            ui.add_space(12.0);
            ui.heading("Pair your iPhone");
            ui.add_space(4.0);
            ui.label(instruction(&view));
            ui.add_space(12.0);

            match &view {
                PairingView::ShowQr { url } => {
                    if self.qr.is_none() || self.last_url != *url {
                        if let Ok(grid) = qr_grid(url) {
                            self.qr = Some(qr_texture(&ctx, &grid));
                            self.last_url = url.clone();
                        }
                    }
                    if let Some(tex) = &self.qr {
                        ui.image((tex.id(), egui::vec2(280.0, 280.0)));
                    }
                    ui.add_space(8.0);
                    if ui.button("Copy pairing link").clicked() {
                        ctx.copy_text(url.clone());
                    }
                }
                PairingView::CompareSas { emoji } => {
                    ui.label(egui::RichText::new(emoji.join("   ")).size(56.0));
                    ui.add_space(8.0);
                    ui.label("If they differ, cancel — someone may be intercepting.");
                }
                PairingView::Success { device_name } => {
                    ui.label(
                        egui::RichText::new("✓")
                            .size(64.0)
                            .color(egui::Color32::from_rgb(40, 160, 70)),
                    );
                    ui.label(format!("{device_name} is paired."));
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
                PairingView::Failed { reason } => {
                    ui.label(
                        egui::RichText::new("✗")
                            .size(64.0)
                            .color(egui::Color32::from_rgb(190, 60, 60)),
                    );
                    ui.label(reason.clone());
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        });
    }
}

/// Open the pairing window. Blocks until the user closes it, so it must run on the
/// main thread.
pub fn run(view: SharedView) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([380.0, 520.0])
            .with_resizable(false)
            .with_title("AirClip — Pair your iPhone"),
        ..Default::default()
    };

    eframe::run_native(
        "AirClip Pairing",
        options,
        Box::new(|_cc| {
            Ok(Box::new(PairingApp {
                view,
                qr: None,
                last_url: String::new(),
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("pairing window: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use airclip_core::crypto::IdentityKeypair;
    use airclip_core::pairing::QrPayload;

    #[test]
    fn qr_grid_is_square_and_scannable_size() {
        let g = qr_grid("airclip://pair?v=1&id=aa").unwrap();
        assert_eq!(g.dark.len(), g.size * g.size);
        assert!(g.size >= 21, "smallest QR version is 21 modules");
        // Finder pattern: top-left module is always dark.
        assert!(g.is_dark(0, 0));
    }

    #[test]
    fn qr_encodes_a_full_pairing_url() {
        let id = IdentityKeypair::from_seed([9u8; 32]);
        let url = pairing_url(
            &id.device_id(),
            &id.public_bytes(),
            "SAMMAMISH-PC",
            vec!["192.168.4.20:49517".into(), "[fe80::1]:49517".into()],
            [0x5A; 16],
        );
        // The generated URL must survive a round trip through the parser the phone uses.
        let parsed = QrPayload::parse(&url).unwrap();
        assert_eq!(parsed.device_id, id.device_id());
        assert_eq!(parsed.hosts.len(), 2);
        // And it must actually fit in a QR code.
        assert!(qr_grid(&url).is_ok(), "pairing URL must be QR-encodable");
    }

    #[test]
    fn local_hosts_are_formatted_for_the_wire() {
        for h in local_hosts(49517) {
            assert!(h.ends_with(":49517"), "host must carry the port: {h}");
            assert!(!h.starts_with("127."), "loopback is useless to a phone");
            assert!(!h.starts_with("169.254."), "APIPA address advertised: {h}");
            if h.contains("::") {
                assert!(h.starts_with('['), "IPv6 must be bracketed: {h}");
            }
            // Every advertised host must parse as a SocketAddr.
            assert!(
                h.parse::<std::net::SocketAddr>().is_ok(),
                "unparseable host: {h}"
            );
        }
    }

    #[test]
    fn instructions_cover_every_view() {
        assert!(instruction(&PairingView::ShowQr { url: "x".into() }).contains("scan"));
        assert!(instruction(&PairingView::CompareSas {
            emoji: ["🚀", "🐶", "🍎", "⚽"]
        })
        .contains("match"));
        assert_eq!(
            instruction(&PairingView::Success {
                device_name: "iPhone".into()
            }),
            "Paired with iPhone."
        );
        assert!(instruction(&PairingView::Failed {
            reason: "bad token".into()
        })
        .contains("bad token"));
    }
}
