//! T-12 — arrival toasts via WinRT `ToastNotificationManager` (ARCHITECTURE §5).
//!
//! Toasts must not steal focus (SPEC R8) — the default ToastNotification behaviour is
//! already non-activating, so nothing extra is needed beyond not calling any focus API.
//!
//! Never put clip content in a log line; the toast body itself is a UI surface, not a
//! log, so a 40-char preview there is intentional (SPEC R5 wording).

/// Preview length shown in the toast (SPEC R5 / T-12).
pub const TOAST_PREVIEW_CHARS: usize = 40;

/// Truncate on a char boundary and flatten newlines for a single-line toast.
pub fn toast_preview(text: &str) -> String {
    let mut out = String::with_capacity(TOAST_PREVIEW_CHARS + 1);
    for (count, ch) in text.chars().enumerate() {
        if count == TOAST_PREVIEW_CHARS {
            out.push('…');
            break;
        }
        out.push(if ch == '\n' || ch == '\r' { ' ' } else { ch });
    }
    out
}

/// XML-escape text before it goes into the toast template.
///
/// A clip containing `<` or `&` would otherwise produce malformed XML and the toast
/// would silently never appear — a realistic case, since people copy HTML.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the ToastGeneric XML payload.
pub fn toast_xml(title: &str, body: &str) -> String {
    format!(
        r#"<toast activationType="foreground"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
        xml_escape(title),
        xml_escape(body)
    )
}

#[cfg(windows)]
pub use win::show_clip_arrived;

#[cfg(windows)]
mod win {
    use super::*;
    use anyhow::Result;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    /// AUMID registered by the installer (T-13). Toasts silently do nothing without a
    /// registered AUMID, which is the usual reason "toasts don't work" in dev runs.
    pub const AUMID: &str = "com.narrion.AirClip";

    pub fn show_clip_arrived(preview: &str, source: &str) -> Result<()> {
        let title = format!("📋 from {source}");
        let xml = toast_xml(&title, preview);

        let doc = XmlDocument::new()?;
        doc.LoadXml(&windows::core::HSTRING::from(xml))?;
        let toast = ToastNotification::CreateToastNotification(&doc)?;
        ToastNotificationManager::CreateToastNotifierWithId(&windows::core::HSTRING::from(AUMID))?
            .Show(&toast)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_truncates_with_ellipsis() {
        let long = "a".repeat(100);
        let p = toast_preview(&long);
        assert_eq!(p.chars().count(), TOAST_PREVIEW_CHARS + 1);
        assert!(p.ends_with('…'));
    }

    #[test]
    fn preview_leaves_short_text_alone() {
        assert_eq!(toast_preview("hello"), "hello");
        assert!(!toast_preview("hello").ends_with('…'));
    }

    #[test]
    fn preview_never_splits_a_codepoint() {
        let p = toast_preview(&"🚀".repeat(100));
        assert_eq!(
            p.chars().filter(|c| *c == '🚀').count(),
            TOAST_PREVIEW_CHARS
        );
        assert!(std::str::from_utf8(p.as_bytes()).is_ok());
    }

    #[test]
    fn preview_flattens_newlines() {
        assert_eq!(toast_preview("one\ntwo"), "one two");
    }

    #[test]
    fn xml_escaping_prevents_malformed_toasts() {
        // Copying HTML is common; unescaped it would break the XML and show nothing.
        let xml = toast_xml("t", r#"<a href="x">A & B</a>"#);
        assert!(!xml.contains("<a href"));
        assert!(xml.contains("&lt;a href=&quot;x&quot;&gt;A &amp; B"));
    }

    #[test]
    fn xml_has_both_text_nodes() {
        let xml = toast_xml("title", "body");
        assert!(xml.contains("<text>title</text>"));
        assert!(xml.contains("<text>body</text>"));
        assert!(xml.starts_with("<toast"));
    }
}
