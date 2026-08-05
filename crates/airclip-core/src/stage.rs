//! Staged-clip ring for the PC role (PROTOCOL.md §8.2).
//!
//! Holds the last `STAGE_DEPTH` local copies so the phone can pull them. In-memory only:
//! nothing here is ever written to disk (SPEC R5), and `clear()` runs on Pause/Quit.

use std::collections::VecDeque;

use crate::error::{Error, Result};
use crate::{ContentType, MAX_TEXT_CLIP, STAGE_DEPTH};

/// Preview length in characters, PROTOCOL §8.2.
pub const PREVIEW_CHARS: usize = 120;

/// A staged clip body plus its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedClip {
    pub stage_id: [u8; 8],
    pub content_type: ContentType,
    pub body: Vec<u8>,
    pub copied_at_ms: u64,
}

/// What STAGE_LIST returns — enough to render a chip row without fetching bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageMeta {
    pub stage_id: [u8; 8],
    pub content_type: ContentType,
    pub preview: String,
    pub size: u32,
    pub copied_at_ms: u64,
}

/// Fixed-depth ring of staged clips, newest last internally, newest first on the wire.
#[derive(Debug)]
pub struct StageRing {
    items: VecDeque<StagedClip>,
    depth: usize,
}

impl Default for StageRing {
    fn default() -> Self {
        Self::new(STAGE_DEPTH)
    }
}

impl StageRing {
    pub fn new(depth: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(depth),
            depth: depth.max(1),
        }
    }

    /// Stage a locally-copied clip. Returns the assigned stage id.
    ///
    /// Oversize clips are rejected rather than truncated — silently shipping half a
    /// clipboard would be worse than a visible failure (SPEC R5 caps at 256 KiB).
    pub fn push(
        &mut self,
        content_type: ContentType,
        body: Vec<u8>,
        now_ms: u64,
    ) -> Result<[u8; 8]> {
        if body.len() > MAX_TEXT_CLIP {
            return Err(Error::FrameTooLarge(body.len() as u32));
        }
        let mut stage_id = [0u8; 8];
        getrandom::fill(&mut stage_id).map_err(|_| Error::Crypto)?;
        self.push_with_id(stage_id, content_type, body, now_ms)?;
        Ok(stage_id)
    }

    /// Deterministic variant for tests and `--simulate-peer`.
    pub fn push_with_id(
        &mut self,
        stage_id: [u8; 8],
        content_type: ContentType,
        body: Vec<u8>,
        now_ms: u64,
    ) -> Result<()> {
        if body.len() > MAX_TEXT_CLIP {
            return Err(Error::FrameTooLarge(body.len() as u32));
        }
        if self.items.len() == self.depth {
            self.items.pop_front();
        }
        self.items.push_back(StagedClip {
            stage_id,
            content_type,
            body,
            copied_at_ms: now_ms,
        });
        Ok(())
    }

    /// Metadata for every staged clip, newest first (PROTOCOL §8.2).
    pub fn list(&self) -> Vec<StageMeta> {
        self.items
            .iter()
            .rev()
            .map(|c| StageMeta {
                stage_id: c.stage_id,
                content_type: c.content_type,
                preview: preview_of(&c.body),
                size: c.body.len() as u32,
                copied_at_ms: c.copied_at_ms,
            })
            .collect()
    }

    pub fn get(&self, stage_id: &[u8; 8]) -> Option<&StagedClip> {
        self.items.iter().find(|c| &c.stage_id == stage_id)
    }

    /// Most recently staged clip, if any.
    pub fn newest(&self) -> Option<&StagedClip> {
        self.items.back()
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// First `PREVIEW_CHARS` characters, truncated on a char boundary.
///
/// Truncation is by `char`, not byte: slicing mid-codepoint would panic, and slicing a
/// multi-byte character in half would render as a replacement glyph on the phone.
pub fn preview_of(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(PREVIEW_CHARS);
    for (i, ch) in text.chars().enumerate() {
        if i == PREVIEW_CHARS {
            break;
        }
        // Newlines would break the single-line chip layout in the keyboard extension.
        out.push(if ch == '\n' || ch == '\r' { ' ' } else { ch });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000;

    fn ring_with(n: usize) -> StageRing {
        let mut r = StageRing::default();
        for i in 0..n {
            r.push_with_id(
                [i as u8; 8],
                ContentType::Text,
                format!("clip {i}").into_bytes(),
                T0 + i as u64,
            )
            .unwrap();
        }
        r
    }

    #[test]
    fn default_depth_matches_protocol() {
        assert_eq!(StageRing::default().depth(), STAGE_DEPTH);
        assert_eq!(STAGE_DEPTH, 5);
    }

    #[test]
    fn evicts_oldest_beyond_depth() {
        // T-04 acceptance: stage 6 items into a depth-5 ring, oldest is gone.
        let r = ring_with(6);
        assert_eq!(r.len(), 5);
        assert!(r.get(&[0u8; 8]).is_none(), "oldest must be evicted");
        assert!(r.get(&[5u8; 8]).is_some(), "newest must be retained");
    }

    #[test]
    fn list_is_newest_first() {
        let r = ring_with(3);
        let list = r.list();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].stage_id, [2u8; 8]);
        assert_eq!(list[1].stage_id, [1u8; 8]);
        assert_eq!(list[2].stage_id, [0u8; 8]);
        assert_eq!(list[0].preview, "clip 2");
        assert_eq!(list[0].size, "clip 2".len() as u32);
    }

    #[test]
    fn get_returns_the_body() {
        let r = ring_with(2);
        assert_eq!(r.get(&[1u8; 8]).unwrap().body, b"clip 1");
        assert!(r.get(&[9u8; 8]).is_none());
    }

    #[test]
    fn rejects_oversize_clip() {
        let mut r = StageRing::default();
        let too_big = vec![b'x'; MAX_TEXT_CLIP + 1];
        assert!(matches!(
            r.push(ContentType::Text, too_big, T0),
            Err(Error::FrameTooLarge(_))
        ));
        assert!(r.is_empty(), "rejected clip must not be staged");
    }

    #[test]
    fn accepts_clip_at_exactly_the_cap() {
        let mut r = StageRing::default();
        assert!(r
            .push(ContentType::Text, vec![b'x'; MAX_TEXT_CLIP], T0)
            .is_ok());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn clear_empties_the_ring() {
        let mut r = ring_with(4);
        r.clear();
        assert!(r.is_empty());
        assert!(r.list().is_empty());
    }

    #[test]
    fn push_returns_distinct_random_ids() {
        let mut r = StageRing::default();
        let a = r.push(ContentType::Text, b"a".to_vec(), T0).unwrap();
        let b = r.push(ContentType::Text, b"b".to_vec(), T0).unwrap();
        assert_ne!(a, b);
    }

    // --- preview truncation ---

    #[test]
    fn preview_truncates_to_120_chars() {
        let long = "a".repeat(500);
        let p = preview_of(long.as_bytes());
        assert_eq!(p.chars().count(), PREVIEW_CHARS);
    }

    #[test]
    fn preview_never_splits_a_codepoint() {
        // 200 four-byte emoji: byte-slicing at 120 would land mid-codepoint and panic.
        let s = "🚀".repeat(200);
        let p = preview_of(s.as_bytes());
        assert_eq!(p.chars().count(), PREVIEW_CHARS);
        assert!(p.chars().all(|c| c == '🚀'));
        assert_eq!(p.len(), PREVIEW_CHARS * 4, "each emoji is 4 bytes");
    }

    #[test]
    fn preview_handles_cjk_and_rtl() {
        for s in ["日本語のテキスト".repeat(40), "مرحبا بالعالم ".repeat(40)] {
            let p = preview_of(s.as_bytes());
            assert!(p.chars().count() <= PREVIEW_CHARS);
            assert!(std::str::from_utf8(p.as_bytes()).is_ok());
        }
    }

    #[test]
    fn preview_flattens_newlines() {
        let p = preview_of(b"line one\nline two\r\nthree");
        assert_eq!(p, "line one line two  three");
        assert!(!p.contains('\n'));
    }

    #[test]
    fn preview_survives_invalid_utf8() {
        // Clipboard bytes are not guaranteed valid UTF-8; lossy is correct here.
        let p = preview_of(&[0xff, 0xfe, b'h', b'i']);
        assert!(p.ends_with("hi"));
    }

    #[test]
    fn preview_of_short_body_is_unchanged() {
        assert_eq!(preview_of(b"https://example.com"), "https://example.com");
    }
}
