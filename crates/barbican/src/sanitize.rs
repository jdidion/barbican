//! Text sanitization for `PostToolUse` hook content.
//!
//! Three independent passes, kept as free functions so callers can
//! compose them:
//!
//! - [`strip_ansi`] — strip CSI escape sequences before writing command
//!   strings to the audit log. Audit finding **L1**.
//! - [`strip_invisible`] — remove zero-width characters and bidi
//!   overrides from text being scanned for prompt-injection patterns.
//!   Audit finding **M3**.
//! - [`nfkc`] — Unicode NFKC compatibility normalization, used before
//!   injection-pattern matching so Cyrillic `і` / fullwidth `ｉ` collapse
//!   to ASCII `i`. Audit finding **M3**.
//!
//! None of these functions are safe to run on arbitrary binary data —
//! they operate on `&str` and the caller is responsible for decoding.

use std::borrow::Cow;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

/// Strip ANSI CSI escape sequences (`ESC [ ... letter`) from `s`.
///
/// Used for audit logging only: command strings are attacker-controllable
/// and we don't want them to rewrite the terminal when a human `less`es
/// the log.
///
/// This is CSI-only; it deliberately does NOT strip OSC (`ESC ]`) or
/// other single-char escapes, because those are rare in shell contexts
/// and we'd rather see them in the log as visible bytes than silently
/// eat them. If that turns out to matter, widen the regex.
#[must_use]
pub fn strip_ansi(s: &str) -> Cow<'_, str> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").expect("valid ANSI regex"));
    re.replace_all(s, "")
}

/// Remove zero-width and bidi-override characters.
///
/// The set:
/// - `U+200B` ZERO WIDTH SPACE
/// - `U+200C` ZERO WIDTH NON-JOINER
/// - `U+200D` ZERO WIDTH JOINER
/// - `U+FEFF` ZERO WIDTH NO-BREAK SPACE (BOM)
/// - `U+202A`..`U+202E` explicit bidi embeddings and overrides
/// - `U+2066`..`U+2069` isolates (LRI, RLI, FSI, PDI) — the missing
///   characters in the Narthex regex that audit finding M3 calls out.
///
/// Applied before injection-pattern matching. The result is a new
/// `String` because the removal is dense enough that borrow-tracking
/// isn't worth it.
#[must_use]
pub fn strip_invisible(s: &str) -> String {
    s.chars().filter(|&c| !is_invisible(c)).collect()
}

const fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
    )
}

/// NFKC-normalize `s`.
///
/// Converts compatibility variants to their canonical forms so
/// confusables (Cyrillic `і` U+0456, fullwidth Latin `ｉ` U+FF49,
/// mathematical alphanumerics, etc.) collapse to a single representation
/// before regex matching.
///
/// Note: NFKC does NOT map Cyrillic `і` (U+0456) to Latin `i` (U+0069) —
/// they are visually confusable but canonically distinct. Catching that
/// class requires a dedicated confusables step which we do not (yet)
/// ship. NFKC does catch fullwidth Latin, mathematical styled letters,
/// ligatures, and the like. See SECURITY.md §Known parser limits.
#[must_use]
pub fn nfkc(s: &str) -> String {
    s.nfkc().collect()
}

/// Convenience: apply all three passes for prompt-injection scanning.
/// Order matters: invisible chars removed first (so NFKC doesn't try to
/// fold them), then NFKC. ANSI strip is separate since we may want the
/// raw string for logging.
#[must_use]
pub fn normalize_for_scan(s: &str) -> String {
    nfkc(&strip_invisible(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_color() {
        let s = "\x1b[31mred\x1b[0m";
        assert_eq!(strip_ansi(s), "red");
    }

    #[test]
    fn strip_ansi_removes_cursor_move() {
        let s = "a\x1b[2Kb";
        assert_eq!(strip_ansi(s), "ab");
    }

    #[test]
    fn strip_ansi_preserves_plain() {
        assert_eq!(strip_ansi("hello"), "hello");
    }

    #[test]
    fn strip_invisible_removes_zwsp() {
        let s = "ab\u{200B}cd";
        assert_eq!(strip_invisible(s), "abcd");
    }

    #[test]
    fn strip_invisible_removes_lri_pdi() {
        // LRI (U+2066) + PDI (U+2069) — audit finding M3 specifically
        // lists these as the missing code points in Narthex's regex.
        let s = "\u{2066}malicious\u{2069}";
        assert_eq!(strip_invisible(s), "malicious");
    }

    #[test]
    fn strip_invisible_removes_bidi_override() {
        let s = "\u{202E}reversed";
        assert_eq!(strip_invisible(s), "reversed");
    }

    #[test]
    fn strip_invisible_removes_bom() {
        let s = "\u{FEFF}start";
        assert_eq!(strip_invisible(s), "start");
    }

    #[test]
    fn nfkc_folds_fullwidth() {
        // Fullwidth Latin `ｉｇｎｏｒｅ` → ASCII `ignore`.
        assert_eq!(nfkc("ｉｇｎｏｒｅ"), "ignore");
    }

    #[test]
    fn nfkc_folds_math_alnum() {
        // Mathematical bold `𝐢𝐠𝐧𝐨𝐫𝐞` → ASCII `ignore`.
        assert_eq!(nfkc("𝐢𝐠𝐧𝐨𝐫𝐞"), "ignore");
    }

    #[test]
    fn nfkc_does_not_map_cyrillic_i() {
        // U+0456 (Cyrillic `і`) is visually confusable with Latin `i`
        // but NFKC keeps them distinct. This test documents the limit;
        // catching this is future work, noted in SECURITY.md.
        assert_ne!(nfkc("іgnore"), "ignore");
    }

    #[test]
    fn normalize_for_scan_composes() {
        // Invisible + fullwidth.
        let s = "\u{2066}ｉｇｎｏｒｅ\u{2069}";
        assert_eq!(normalize_for_scan(s), "ignore");
    }
}
