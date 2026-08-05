//! T-12 — tray icon, menu, autostart, single-instance (SPEC R8).
//!
//! Menu: Pair new iPhone · Pause beaming · Start with Windows · Quit.
//! Autostart is the `HKCU\...\Run` value "AirClip"; single-instance is a named mutex so a
//! second launch (e.g. from the Start menu) exits instead of fighting over the port.
//!
//! Threading: the tray owns its own thread and pumps a Win32 message loop there. Windows
//! message loops are per-thread, so this leaves the *main* thread free for the eframe
//! pairing window (T-13) — which needs to be the main thread on Windows.

/// Agent status shown in the tray tooltip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No pairing exists yet.
    Unpaired,
    /// Paired but no phone currently connected.
    Idle,
    /// A phone is connected right now.
    Connected,
    /// Beaming paused by the user.
    Paused,
}

impl Status {
    pub fn tooltip(self, peer_name: Option<&str>) -> String {
        match self {
            Status::Unpaired => "AirClip — not paired".into(),
            Status::Idle => match peer_name {
                Some(n) => format!("AirClip — paired with {n}"),
                None => "AirClip — paired".into(),
            },
            Status::Connected => match peer_name {
                Some(n) => format!("AirClip — {n} connected"),
                None => "AirClip — connected".into(),
            },
            Status::Paused => "AirClip — paused".into(),
        }
    }
}

/// Registry value name under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
pub const AUTOSTART_VALUE: &str = "AirClip";
pub const AUTOSTART_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Named mutex for single-instance detection.
pub const SINGLE_INSTANCE_MUTEX: &str = "Global\\AirClipSingleInstance";

/// What the user asked the tray to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    OpenPairing,
    SetPaused(bool),
    SetAutostart(bool),
    Quit,
}

/// 32×32 RGBA tray icon, generated rather than shipped as a file so the binary has no
/// asset dependency (SPEC R8: no runtime deps).
///
/// A rounded blue tile with a lighter "clip" bar through it — legible at 16×16 in the
/// notification area, which is the only size that matters.
pub fn icon_rgba() -> (Vec<u8>, u32, u32) {
    const S: i32 = 32;
    let mut px = vec![0u8; (S * S * 4) as usize];
    let (cx, cy) = (15.5f32, 15.5f32);

    for y in 0..S {
        for x in 0..S {
            let i = ((y * S + x) * 4) as usize;
            // Rounded square: Chebyshev distance with corner rounding.
            let dx = (x as f32 - cx).abs();
            let dy = (y as f32 - cy).abs();
            let inside =
                dx <= 14.0 && dy <= 14.0 && (dx - 10.0).max(0.0).hypot((dy - 10.0).max(0.0)) <= 4.0;
            if !inside {
                continue;
            }
            // Clip bar: a diagonal band of lighter pixels.
            let band = (x - y).abs() <= 3 || (x + y - 31).abs() <= 3;
            let (r, g, b) = if band { (150, 200, 255) } else { (10, 90, 200) };
            px[i] = r;
            px[i + 1] = g;
            px[i + 2] = b;
            px[i + 3] = 255;
        }
    }
    (px, S as u32, S as u32)
}

#[cfg(windows)]
pub use win::{is_autostart_enabled, set_autostart, spawn_tray, SingleInstance, TrayHandle};

#[cfg(windows)]
mod win {
    use super::*;
    use std::sync::mpsc;

    use anyhow::{bail, Result};
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, TranslateMessage, MSG,
    };

    /// Holds the single-instance mutex for the process lifetime.
    pub struct SingleInstance(HANDLE);

    impl SingleInstance {
        /// Returns `None` if another instance already holds the mutex.
        pub fn acquire() -> Result<Option<Self>> {
            Self::acquire_named(SINGLE_INSTANCE_MUTEX)
        }

        /// Named variant. Tests must not use the production name: a real agent running
        /// on the same machine would otherwise make them fail.
        pub fn acquire_named(name: &str) -> Result<Option<Self>> {
            // SAFETY: name is a valid NUL-terminated wide string for the call's duration.
            let handle = unsafe { CreateMutexW(None, true, &HSTRING::from(name))? };
            // SAFETY: GetLastError has no preconditions, but must be read immediately
            // after the call whose error state we care about.
            let already =
                unsafe { windows::Win32::Foundation::GetLastError() } == ERROR_ALREADY_EXISTS;
            if already {
                // SAFETY: handle is valid and owned here.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Ok(None);
            }
            Ok(Some(Self(handle)))
        }
    }

    impl Drop for SingleInstance {
        fn drop(&mut self) {
            // SAFETY: handle is valid and owned by this struct.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn run_key() -> Result<windows_registry::Key> {
        Ok(windows_registry::CURRENT_USER.create(AUTOSTART_KEY)?)
    }

    pub fn is_autostart_enabled() -> bool {
        run_key()
            .and_then(|k| Ok(k.get_string(AUTOSTART_VALUE)?))
            .is_ok()
    }

    pub fn set_autostart(enabled: bool) -> Result<()> {
        let key = run_key()?;
        if enabled {
            let exe = std::env::current_exe()?;
            let Some(exe) = exe.to_str() else {
                bail!("executable path is not valid UTF-8");
            };
            // Quoted: Program Files paths contain spaces.
            key.set_string(AUTOSTART_VALUE, format!("\"{exe}\""))?;
        } else {
            let _ = key.remove_value(AUTOSTART_VALUE);
        }
        Ok(())
    }

    /// Sends tooltip updates to the tray thread. Cloneable so the async event pump can
    /// reflect connection state without owning the tray.
    #[derive(Clone)]
    pub struct TrayHandle {
        tooltip: mpsc::Sender<String>,
    }

    impl TrayHandle {
        pub fn new(tooltip: mpsc::Sender<String>) -> Self {
            Self { tooltip }
        }
        pub fn set_status(&self, status: Status, peer_name: Option<&str>) {
            let _ = self.tooltip.send(status.tooltip(peer_name));
        }
    }

    /// Start the tray on its own thread, consuming tooltip updates from `tip_rx`.
    ///
    /// The tray icon *and* its message loop must live on the same thread — Win32
    /// delivers notification-area callbacks to the creating thread's message queue.
    pub fn spawn_tray(
        initial_paused: bool,
        initial_autostart: bool,
        tip_rx: mpsc::Receiver<String>,
    ) -> Result<mpsc::Receiver<TrayCommand>> {
        let (cmd_tx, cmd_rx) = mpsc::channel::<TrayCommand>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        std::thread::Builder::new()
            .name("tray".into())
            .spawn(move || {
                let (rgba, w, h) = icon_rgba();
                let icon = match Icon::from_rgba(rgba, w, h) {
                    Ok(i) => i,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow::anyhow!("tray icon: {e}")));
                        return;
                    }
                };

                let menu = Menu::new();
                let pair = MenuItem::new("Pair new iPhone…", true, None);
                let pause = CheckMenuItem::new("Pause beaming", true, initial_paused, None);
                let autostart =
                    CheckMenuItem::new("Start with Windows", true, initial_autostart, None);
                let quit = MenuItem::new("Quit AirClip", true, None);

                let (pair_id, pause_id, autostart_id, quit_id) = (
                    pair.id().clone(),
                    pause.id().clone(),
                    autostart.id().clone(),
                    quit.id().clone(),
                );

                let build = (|| -> Result<_> {
                    menu.append(&pair)?;
                    menu.append(&PredefinedMenuItem::separator())?;
                    menu.append(&pause)?;
                    menu.append(&autostart)?;
                    menu.append(&PredefinedMenuItem::separator())?;
                    menu.append(&quit)?;
                    Ok(TrayIconBuilder::new()
                        .with_menu(Box::new(menu))
                        .with_tooltip(Status::Unpaired.tooltip(None))
                        .with_icon(icon)
                        .build()?)
                })();

                let tray = match build {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));

                // Menu events arrive on a global channel; translate to commands.
                let menu_rx = MenuEvent::receiver();
                let mut paused = initial_paused;
                let mut autostart_on = initial_autostart;

                // SAFETY: standard message pump on the thread that owns the tray icon.
                let mut msg = MSG::default();
                loop {
                    // Drain any pending menu/tooltip work before blocking again.
                    while let Ok(ev) = menu_rx.try_recv() {
                        let cmd = classify_menu_event(
                            &ev.id,
                            &pair_id,
                            &pause_id,
                            &autostart_id,
                            &quit_id,
                            &mut paused,
                            &mut autostart_on,
                        );
                        if let Some(cmd) = cmd {
                            let quitting = cmd == TrayCommand::Quit;
                            if cmd_tx.send(cmd).is_err() || quitting {
                                return;
                            }
                        }
                    }
                    while let Ok(tip) = tip_rx.try_recv() {
                        let _ = tray.set_tooltip(Some(tip));
                    }

                    // GetMessageW blocks until Windows has something; menu clicks always
                    // generate one, so the drains above run promptly.
                    let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                    if !got.as_bool() {
                        return;
                    }
                    unsafe {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            })?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(cmd_rx),
            Ok(Err(e)) => Err(e),
            Err(_) => bail!("tray thread died during startup"),
        }
    }

    /// Pure mapping from a clicked menu id to a command; separated so it is testable
    /// without a desktop session.
    fn classify_menu_event(
        clicked: &MenuId,
        pair: &MenuId,
        pause: &MenuId,
        autostart: &MenuId,
        quit: &MenuId,
        paused_state: &mut bool,
        autostart_state: &mut bool,
    ) -> Option<TrayCommand> {
        if clicked == pair {
            Some(TrayCommand::OpenPairing)
        } else if clicked == pause {
            *paused_state = !*paused_state;
            Some(TrayCommand::SetPaused(*paused_state))
        } else if clicked == autostart {
            *autostart_state = !*autostart_state;
            Some(TrayCommand::SetAutostart(*autostart_state))
        } else if clicked == quit {
            Some(TrayCommand::Quit)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tooltips_describe_each_state() {
        assert_eq!(Status::Unpaired.tooltip(None), "AirClip — not paired");
        assert_eq!(
            Status::Idle.tooltip(Some("Bernhard's iPhone")),
            "AirClip — paired with Bernhard's iPhone"
        );
        assert_eq!(
            Status::Connected.tooltip(Some("Bernhard's iPhone")),
            "AirClip — Bernhard's iPhone connected"
        );
        assert_eq!(Status::Paused.tooltip(Some("x")), "AirClip — paused");
        // Missing peer name must not produce a dangling "with".
        assert_eq!(Status::Idle.tooltip(None), "AirClip — paired");
    }

    #[test]
    fn icon_is_well_formed_rgba() {
        let (px, w, h) = icon_rgba();
        assert_eq!((w, h), (32, 32));
        assert_eq!(px.len(), (w * h * 4) as usize);
        // Must have both transparent corners and opaque body, or it renders as a blob.
        assert!(px.chunks(4).any(|p| p[3] == 0), "no transparent pixels");
        assert!(px.chunks(4).any(|p| p[3] == 255), "no opaque pixels");
        // Corner is outside the rounded square.
        assert_eq!(px[3], 0, "top-left corner should be transparent");
        // Centre is inside it.
        let mid = ((16 * 32 + 16) * 4) as usize;
        assert_eq!(px[mid + 3], 255, "centre should be opaque");
    }

    #[cfg(windows)]
    #[test]
    fn single_instance_excludes_a_second_acquire() {
        // Unique per process: using the production name would fail whenever a real
        // agent happens to be running on this machine.
        let name = format!("Local\\AirClipTest-{}", std::process::id());
        let first = SingleInstance::acquire_named(&name).unwrap();
        assert!(first.is_some(), "first acquire should succeed");
        let second = SingleInstance::acquire_named(&name).unwrap();
        assert!(second.is_none(), "second acquire must be refused");

        // Releasing the first holder frees the name again.
        drop(first);
        drop(second);
        assert!(SingleInstance::acquire_named(&name).unwrap().is_some());
    }
}
