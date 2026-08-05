//! T-11 — Windows clipboard integration (ARCHITECTURE §5).
//!
//! Watch: message-only HWND + `AddClipboardFormatListener`; on `WM_CLIPBOARDUPDATE` read
//! `CF_UNICODETEXT` and stage it. Write: open/empty/set with a retry loop, because the
//! clipboard is a contended global resource and `OpenClipboard` genuinely fails when
//! another app holds it.
//!
//! Own-write suppression uses `GetClipboardSequenceNumber`: after we set the clipboard we
//! record the sequence number, and the update it provokes is ignored. Without this, a clip
//! from the phone is immediately re-staged and offered straight back to the phone.

use std::sync::{Arc, Mutex};

use airclip_core::ContentType;

/// Retry budget for a contended clipboard (ARCHITECTURE §5: 5 × 50 ms).
pub const OPEN_RETRIES: u32 = 5;
pub const OPEN_RETRY_DELAY_MS: u64 = 50;

/// Sequence number of our own last write, so the watcher can ignore it.
#[derive(Clone, Default)]
pub struct OwnWriteGuard(Arc<Mutex<u32>>);

impl OwnWriteGuard {
    pub fn record(&self, seq: u32) {
        *self.0.lock().unwrap() = seq;
    }
    pub fn is_own(&self, seq: u32) -> bool {
        *self.0.lock().unwrap() == seq
    }
}

/// Tag text as URL or plain text for the wire (PROTOCOL §8.1).
pub fn classify(text: &str) -> ContentType {
    let t = text.trim();
    if !t.contains(char::is_whitespace) && (t.starts_with("http://") || t.starts_with("https://")) {
        ContentType::Url
    } else {
        ContentType::Text
    }
}

#[cfg(windows)]
#[allow(unused_imports)] // get_text is used by the watcher thread and by tests
pub use win::{get_text, set_text, spawn_watcher, ClipboardEvent};

#[cfg(windows)]
mod win {
    use super::*;
    use std::sync::mpsc;

    use anyhow::{bail, Result};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::DataExchange::{
        AddClipboardFormatListener, CloseClipboard, EmptyClipboard, GetClipboardData,
        GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, CW_USEDEFAULT, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE,
        WM_CLIPBOARDUPDATE, WNDCLASSW,
    };

    const CF_UNICODETEXT: u32 = 13;

    /// A locally-copied clip observed by the watcher.
    #[derive(Debug, Clone)]
    pub struct ClipboardEvent {
        pub content_type: ContentType,
        pub body: Vec<u8>,
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// RAII clipboard lock: every early return must close it, or the whole desktop
    /// blocks waiting for the clipboard.
    struct ClipboardLock;

    impl ClipboardLock {
        fn acquire() -> Result<Self> {
            for attempt in 0..OPEN_RETRIES {
                // SAFETY: a null owner is valid and scopes the clipboard to this thread.
                if unsafe { OpenClipboard(None) }.is_ok() {
                    return Ok(Self);
                }
                tracing::trace!(attempt, "clipboard busy, retrying");
                std::thread::sleep(std::time::Duration::from_millis(OPEN_RETRY_DELAY_MS));
            }
            bail!("clipboard busy after {OPEN_RETRIES} attempts")
        }
    }

    impl Drop for ClipboardLock {
        fn drop(&mut self) {
            // SAFETY: we hold the clipboard open.
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    /// Write UTF-8 text as `CF_UNICODETEXT`, returning the new sequence number.
    pub fn set_text(text: &str, guard: &OwnWriteGuard) -> Result<u32> {
        let wide = to_wide(text);
        let bytes = std::mem::size_of_val(&wide[..]);

        {
            let _lock = ClipboardLock::acquire()?;
            // SAFETY: the clipboard is open; on success ownership of `hglobal` transfers
            // to the system, so we must not free it ourselves.
            unsafe {
                EmptyClipboard()?;
                let hglobal = GlobalAlloc(GMEM_MOVEABLE, bytes)?;
                let ptr = GlobalLock(hglobal) as *mut u16;
                if ptr.is_null() {
                    bail!("GlobalLock failed");
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                let _ = GlobalUnlock(hglobal);
                SetClipboardData(CF_UNICODETEXT, Some(HANDLE(hglobal.0)))?;
            }
        }

        // SAFETY: no preconditions.
        let seq = unsafe { GetClipboardSequenceNumber() };
        guard.record(seq);
        Ok(seq)
    }

    /// Read `CF_UNICODETEXT` as UTF-8, if present.
    pub fn get_text() -> Result<Option<String>> {
        // SAFETY: no preconditions.
        if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) }.is_err() {
            return Ok(None);
        }
        let _lock = ClipboardLock::acquire()?;
        // SAFETY: clipboard is open and the format is available. The handle belongs to
        // the clipboard, so we only read through it and never free it.
        unsafe {
            let handle = GetClipboardData(CF_UNICODETEXT)?;
            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal) as *const u16;
            if ptr.is_null() {
                return Ok(None);
            }
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(hglobal);
            Ok(Some(text))
        }
    }

    static SENDER: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_CLIPBOARDUPDATE {
            if let Ok(guard) = SENDER.lock() {
                if let Some(tx) = guard.as_ref() {
                    let _ = tx.send(());
                }
            }
            return LRESULT(0);
        }
        // SAFETY: forwarding unhandled messages is the documented contract.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    /// Spawn the clipboard watcher. A message-only window is required because
    /// `AddClipboardFormatListener` needs an HWND and a tray app has no visible window.
    pub fn spawn_watcher(guard: OwnWriteGuard) -> Result<mpsc::Receiver<ClipboardEvent>> {
        let (out_tx, out_rx) = mpsc::channel::<ClipboardEvent>();
        let (tick_tx, tick_rx) = mpsc::channel::<()>();
        *SENDER.lock().unwrap() = Some(tick_tx);

        std::thread::Builder::new()
            .name("clipboard-watcher".into())
            .spawn(move || {
                // SAFETY: standard message-only window setup; the class name outlives
                // every call that borrows it.
                unsafe {
                    let class_name = to_wide("AirClipClipboardWatcher");
                    let title = to_wide("AirClip");
                    let wc = WNDCLASSW {
                        lpfnWndProc: Some(wnd_proc),
                        lpszClassName: PCWSTR(class_name.as_ptr()),
                        ..Default::default()
                    };
                    RegisterClassW(&wc);

                    let hwnd = CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(class_name.as_ptr()),
                        PCWSTR(title.as_ptr()),
                        WINDOW_STYLE(0),
                        CW_USEDEFAULT,
                        CW_USEDEFAULT,
                        0,
                        0,
                        Some(HWND_MESSAGE),
                        None,
                        None,
                        None,
                    );
                    let Ok(hwnd) = hwnd else {
                        tracing::error!("failed to create message-only window");
                        return;
                    };
                    if AddClipboardFormatListener(hwnd).is_err() {
                        tracing::error!("AddClipboardFormatListener failed");
                        return;
                    }

                    let mut msg = MSG::default();
                    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            })?;

        // Separate reader thread: the message pump must never block on clipboard I/O.
        std::thread::Builder::new()
            .name("clipboard-reader".into())
            .spawn(move || {
                while tick_rx.recv().is_ok() {
                    // Coalesce bursts — many apps fire several updates per copy.
                    while tick_rx
                        .recv_timeout(std::time::Duration::from_millis(100))
                        .is_ok()
                    {}

                    // SAFETY: no preconditions.
                    let seq = unsafe { GetClipboardSequenceNumber() };
                    if guard.is_own(seq) {
                        tracing::trace!("ignoring our own clipboard write");
                        continue;
                    }
                    match get_text() {
                        Ok(Some(text)) if !text.is_empty() => {
                            let content_type = classify(&text);
                            let ev = ClipboardEvent {
                                content_type,
                                body: text.into_bytes(),
                            };
                            if out_tx.send(ev).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::debug!(error = %e, "clipboard read failed"),
                    }
                }
            })?;

        Ok(out_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_urls_and_text() {
        assert_eq!(classify("https://example.com"), ContentType::Url);
        assert_eq!(classify("http://a.b/c?d=e"), ContentType::Url);
        assert_eq!(classify("  https://example.com  "), ContentType::Url);
        assert_eq!(classify("hello world"), ContentType::Text);
        // A URL inside a sentence is prose, not a link.
        assert_eq!(classify("see https://example.com now"), ContentType::Text);
        assert_eq!(classify("ftp://example.com"), ContentType::Text);
        assert_eq!(classify(""), ContentType::Text);
    }

    #[test]
    fn own_write_guard_matches_only_the_recorded_sequence() {
        let g = OwnWriteGuard::default();
        g.record(42);
        assert!(g.is_own(42));
        assert!(!g.is_own(43));
        g.record(43);
        assert!(!g.is_own(42), "only the latest write is suppressed");
    }

    /// Round-trip against the real Windows clipboard (T-11 acceptance).
    #[cfg(windows)]
    #[test]
    fn set_then_get_round_trips() {
        let guard = OwnWriteGuard::default();
        let text = "AirClip test 🚀 日本語";
        if set_text(text, &guard).is_err() {
            eprintln!("skipping: clipboard unavailable (headless session?)");
            return;
        }
        assert_eq!(get_text().unwrap().as_deref(), Some(text));
    }

    /// The watcher must not re-stage what we just wrote (T-11 acceptance loop test).
    #[cfg(windows)]
    #[test]
    fn own_write_is_suppressed() {
        let guard = OwnWriteGuard::default();
        let Ok(seq) = set_text("suppress me", &guard) else {
            eprintln!("skipping: clipboard unavailable");
            return;
        };
        assert!(guard.is_own(seq), "our own write must be recognised");
    }
}
