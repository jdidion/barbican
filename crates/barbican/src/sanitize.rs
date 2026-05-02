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

/// Strip executable / loader HTML tags (`<script>`, `<style>`,
/// `<iframe>`, `<object>`, `<embed>`, `<noscript>`, `<template>`,
/// `<svg>` with `onload=`, `<meta http-equiv="refresh">`) + HTML
/// comments from `s`.
///
/// `safe_fetch` returns HTML bodies wrapped in `<untrusted-content>`
/// sentinels; before wrapping we drop the tag bodies that are most
/// likely to carry injection payloads, obfuscated code, or loader
/// pivots (iframes/objects fetch more content; `<meta refresh>`
/// redirects; `<svg onload=>` executes on parse in many renderers;
/// `<template>`/`<noscript>` are common places to stash HTML that
/// the model might try to "render"). This is not a real HTML parser
/// — it uses non-greedy regexes with the `(?s)` dot-matches-newline
/// flag. That is enough for the threat model: the model still sees
/// plain text inside `<untrusted-content>` (as data, not
/// instructions), but the visual surface is cleaner.
///
/// The regexes are intentionally loose around the tag — `<name` with
/// any attributes up to the closing `>`, then the shortest match to
/// `</name>`. Self-closing / void forms (`<meta …>`, `<embed …/>`)
/// match a single tag without a closing pair. HTML comments match
/// `<!--` to the next `-->`.
///
/// 1.2.1 L-6 adversarial review: pre-1.2.1 only `<script>`, `<style>`,
/// and HTML comments were stripped; the rest leaked through.
#[must_use]
pub fn strip_html_tags(s: &str) -> String {
    strip_html_tags_attributed(s).0
}

/// Like [`strip_html_tags`] but also returns a bitset describing which
/// of the sub-regexes actually removed bytes. Used by `inspect` to
/// attribute findings precisely — we only claim "removed <script>"
/// if the script regex itself removed bytes. This is the tight guard
/// that closes the false-positive attribution case from the Phase-10
/// adversarial review.
///
/// 1.2.1 L-6 adversarial review: widened the removal set to iframe,
/// object, embed, noscript, template, svg (whole tree — includes
/// `<svg onload=>`), and `<meta http-equiv="refresh">`. These all
/// collapse into the single `removed_executable` bit since the
/// `inspect` surface doesn't need to distinguish which kind fired.
#[must_use]
pub fn strip_html_tags_attributed(s: &str) -> (String, HtmlStripHits) {
    let res = html_tag_regexes();
    let mut hits = HtmlStripHits::default();

    let after_script = res.script.replace_all(s, "");
    hits.removed_script = after_script.len() != s.len();
    let after_style = res.style.replace_all(&after_script, "");
    hits.removed_style = after_style.len() != after_script.len();

    // Widened set: fires on any of the loader / pivot / executable
    // tags listed above. Attributed as a single bit because the inspect
    // surface only cares that "an executable-class tag was removed",
    // not which one.
    let mut after_executable = after_style;
    let mut executable_fired = false;
    for re in &res.executable {
        let next = re.replace_all(&after_executable, "");
        if next.len() != after_executable.len() {
            executable_fired = true;
        }
        after_executable = std::borrow::Cow::Owned(next.into_owned());
    }
    hits.removed_executable = executable_fired;

    let after_comment = res.comment.replace_all(&after_executable, "");
    hits.removed_comment = after_comment.len() != after_executable.len();

    (after_comment.into_owned(), hits)
}

/// Which HTML sub-strippers actually removed bytes in a given call.
///
/// Each field is an independent attribution signal for `inspect` —
/// they're not mutually exclusive (a document can have both a script
/// block and an iframe) and they're not orderable. A four-variant
/// enum + a `set()` helper would be strictly worse ergonomically,
/// so we lint-allow the "too many bools" suggestion.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent attribution signal for the inspect tool"
)]
pub struct HtmlStripHits {
    pub removed_script: bool,
    pub removed_style: bool,
    pub removed_comment: bool,
    /// True if any of the 1.2.1-widened loader/pivot/executable tags
    /// (`<iframe>`, `<object>`, `<embed>`, `<noscript>`, `<template>`,
    /// `<svg …>`, `<meta http-equiv="refresh" …>`) was removed.
    pub removed_executable: bool,
}

impl HtmlStripHits {
    #[must_use]
    pub fn any(&self) -> bool {
        self.removed_script || self.removed_style || self.removed_comment || self.removed_executable
    }
}

/// Compiled regexes for [`strip_html_tags_attributed`]. Each regex is
/// loose around attributes — `<name` with anything up to the closing
/// `>`, then shortest-match to the closing tag.
struct HtmlTagRegexes {
    script: &'static Regex,
    style: &'static Regex,
    comment: &'static Regex,
    /// Loader / pivot / executable-class tags. Attributed as a single
    /// bit; ordered by rough likelihood-of-appearance so the early
    /// patterns short-circuit on most inputs.
    executable: Vec<&'static Regex>,
}

fn html_tag_regexes() -> HtmlTagRegexes {
    static SCRIPT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static STYLE_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static COMMENT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    // 1.2.1 L-6: loader/pivot/executable-class tags.
    static IFRAME_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static OBJECT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static EMBED_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static NOSCRIPT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static TEMPLATE_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static SVG_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static META_REFRESH_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

    let executable = vec![
        IFRAME_RE
            .get_or_init(|| Regex::new(r"(?si)<iframe\b[^>]*>.*?</iframe>").expect("iframe regex")),
        OBJECT_RE
            .get_or_init(|| Regex::new(r"(?si)<object\b[^>]*>.*?</object>").expect("object regex")),
        // <embed …> and <embed …/> are void elements with no close tag.
        EMBED_RE.get_or_init(|| Regex::new(r"(?si)<embed\b[^>]*/?\s*>").expect("embed regex")),
        NOSCRIPT_RE.get_or_init(|| {
            Regex::new(r"(?si)<noscript\b[^>]*>.*?</noscript>").expect("noscript regex")
        }),
        TEMPLATE_RE.get_or_init(|| {
            Regex::new(r"(?si)<template\b[^>]*>.*?</template>").expect("template regex")
        }),
        // <svg …>…</svg> covers `<svg onload=…>` and friends by
        // removing the whole SVG subtree. Narrower-than-parsing but
        // safer than trying to pick individual event-handler
        // attributes out of live markup.
        SVG_RE.get_or_init(|| Regex::new(r"(?si)<svg\b[^>]*>.*?</svg>").expect("svg regex")),
        // <meta http-equiv="refresh" …> is void. Match any `<meta …>`
        // that carries an http-equiv attribute with "refresh" (case
        // insensitive). Other meta tags (charset, description,
        // og:…) pass through unchanged.
        META_REFRESH_RE.get_or_init(|| {
            Regex::new(
                r#"(?si)<meta\b[^>]*\bhttp-equiv\s*=\s*(?:"refresh"|'refresh'|refresh)[^>]*>"#,
            )
            .expect("meta refresh regex")
        }),
    ];

    HtmlTagRegexes {
        script: SCRIPT_RE
            .get_or_init(|| Regex::new(r"(?si)<script\b[^>]*>.*?</script>").expect("script regex")),
        style: STYLE_RE
            .get_or_init(|| Regex::new(r"(?si)<style\b[^>]*>.*?</style>").expect("style regex")),
        comment: COMMENT_RE
            .get_or_init(|| Regex::new(r"(?s)<!--.*?-->").expect("html comment regex")),
        executable,
    }
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

/// Convenience: apply all four passes for prompt-injection scanning.
/// Order: strip invisible → confusables-fold → NFKC. ANSI strip stays
/// separate (callers may want the raw string for logging).
///
/// Phase-7 review (GPT): NFKC alone does NOT fold Cyrillic `і` (U+0456)
/// or Greek `Ο` (U+039F) to their Latin counterparts — they are
/// canonically distinct even though they're visually identical. The
/// audit's M3 test specifically includes the Cyrillic homoglyph, so
/// we run a dedicated confusables pass here. Narrow and hand-maintained
/// rather than pulling an old UTS-39-skeleton crate.
#[must_use]
pub fn normalize_for_scan(s: &str) -> String {
    nfkc(&confusables_fold(&strip_invisible(s)))
}

/// Fold the most common Cyrillic / Greek / other homoglyphs to their
/// ASCII Latin equivalents. Intentionally small and focused — we only
/// cover the codepoints that realistically appear in adversarial
/// prompt-injection payloads.
///
/// The covered set below folds into ASCII letters when scanning, so a
/// `іgnore` (U+0456 + "gnore") normalizes to `ignore` and the
/// jailbreak regex fires. Non-covered codepoints pass through
/// unchanged.
#[must_use]
pub fn confusables_fold(s: &str) -> String {
    s.chars().map(fold_confusable).collect()
}

/// Map one codepoint through the confusables table. Split out of
/// `confusables_fold` so we can document the mapping without making
/// clippy complain about multi-alternation match arms that all fold
/// to the same letter.
fn fold_confusable(c: char) -> char {
    match c {
        // Cyrillic / Greek / other → Latin lowercase
        '\u{0430}' => 'a', // Cyrillic а
        '\u{0435}' => 'e', // Cyrillic е
        '\u{0456}' | '\u{0457}' | '\u{04CF}' | '\u{0131}' => 'i',
        '\u{0458}' => 'j',              // Cyrillic ј
        '\u{043E}' | '\u{03BF}' => 'o', // Cyrillic о / Greek ο
        '\u{0440}' | '\u{03C1}' => 'p', // Cyrillic р / Greek ρ
        '\u{0441}' => 'c',              // Cyrillic с
        '\u{0443}' | '\u{03C5}' | '\u{1D59F}' => 'y',
        '\u{0445}' => 'x', // Cyrillic х
        '\u{04BB}' => 'h', // Cyrillic һ
        // Cyrillic / Greek → Latin uppercase
        '\u{0410}' | '\u{0391}' => 'A',
        '\u{0412}' | '\u{0392}' => 'B',
        '\u{0415}' | '\u{0395}' => 'E',
        '\u{041A}' | '\u{039A}' => 'K',
        '\u{041C}' | '\u{039C}' => 'M',
        '\u{041D}' | '\u{0397}' => 'H',
        '\u{041E}' | '\u{039F}' => 'O',
        '\u{0420}' | '\u{03A1}' => 'P',
        '\u{0421}' => 'C',
        '\u{0422}' | '\u{03A4}' => 'T',
        '\u{0423}' | '\u{03A5}' => 'Y',
        '\u{0425}' | '\u{03A7}' => 'X',
        '\u{039D}' => 'N',
        '\u{0396}' => 'Z',
        '\u{0399}' => 'I',
        other => other,
    }
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

    #[test]
    fn strip_html_removes_script_block() {
        let s = "<p>ok</p><script>alert(1)</script>";
        assert_eq!(strip_html_tags(s), "<p>ok</p>");
    }

    #[test]
    fn strip_html_removes_script_with_attrs_and_newlines() {
        let s = "<p>ok</p>\n<script type=\"text/javascript\">\nfoo();\nbar();\n</script>after";
        assert_eq!(strip_html_tags(s), "<p>ok</p>\nafter");
    }

    #[test]
    fn strip_html_removes_style_block() {
        let s = "<p>ok</p><style>body{color:red}</style>after";
        assert_eq!(strip_html_tags(s), "<p>ok</p>after");
    }

    #[test]
    fn strip_html_removes_comment() {
        let s = "before<!-- secret payload -->after";
        assert_eq!(strip_html_tags(s), "beforeafter");
    }

    #[test]
    fn strip_html_case_insensitive_script() {
        let s = "<SCRIPT>x</ScRiPt>ok";
        assert_eq!(strip_html_tags(s), "ok");
    }

    #[test]
    fn strip_html_multiple_scripts() {
        let s = "<script>a</script>B<script>c</script>D";
        assert_eq!(strip_html_tags(s), "BD");
    }

    // --- 1.2.1 L-6: widened loader/pivot-tag stripping -------------------

    #[test]
    fn strip_html_removes_iframe() {
        // The explicit finding shape from the 5th-pass Claude review.
        let s = "<p>ok</p><iframe src=evil></iframe>after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<iframe"), "iframe not stripped: {out}");
        assert!(out.contains("<p>ok</p>"));
        assert!(out.contains("after"));
    }

    #[test]
    fn strip_html_removes_iframe_with_attrs_and_body() {
        let s = "<iframe src=\"https://evil/x\" sandbox=\"allow-scripts\">fallback</iframe>after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<iframe"));
        assert!(!out.contains("fallback"));
        assert_eq!(out, "after");
    }

    #[test]
    fn strip_html_removes_object_tag() {
        let s = "<object data=\"evil.swf\">alt</object>after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<object"));
        assert_eq!(out, "after");
    }

    #[test]
    fn strip_html_removes_embed_void_tag() {
        let s = "<p>ok</p><embed src=\"evil.swf\" type=\"application/x-shockwave-flash\">after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<embed"));
        assert!(out.contains("ok"));
        assert!(out.contains("after"));
    }

    #[test]
    fn strip_html_removes_noscript() {
        let s = "<noscript><iframe src=evil></iframe></noscript>after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<noscript"));
        assert_eq!(out, "after");
    }

    #[test]
    fn strip_html_removes_template() {
        let s = "<template id=\"t\"><script>evil()</script></template>after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<template"));
        assert!(!out.contains("<script"));
        assert_eq!(out, "after");
    }

    #[test]
    fn strip_html_removes_svg_with_onload() {
        let s = "<p>ok</p><svg onload=\"alert(1)\"><circle/></svg>after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<svg"));
        assert!(!out.contains("onload"));
        assert!(out.contains("ok"));
        assert!(out.contains("after"));
    }

    #[test]
    fn strip_html_removes_meta_refresh() {
        let s = "<meta http-equiv=\"refresh\" content=\"0;url=https://evil/\">after";
        let out = strip_html_tags(s);
        assert!(!out.contains("<meta"));
        assert_eq!(out, "after");
    }

    #[test]
    fn strip_html_preserves_benign_meta_tags() {
        // `<meta charset>`, `<meta name=description>`, etc. must NOT
        // be flagged — only `<meta http-equiv="refresh">` is the pivot.
        let s = "<meta charset=\"utf-8\"><meta name=\"description\" content=\"x\">ok";
        let out = strip_html_tags(s);
        assert!(
            out.contains("<meta charset") && out.contains("<meta name"),
            "benign meta tags must be preserved: {out}"
        );
    }

    #[test]
    fn strip_html_attribution_sets_executable_bit() {
        let s = "<iframe src=evil></iframe>";
        let (_, hits) = strip_html_tags_attributed(s);
        assert!(
            hits.removed_executable,
            "removed_executable must fire for iframe: {hits:?}"
        );
        assert!(!hits.removed_script);
        assert!(!hits.removed_style);
    }

    #[test]
    fn strip_html_attribution_is_per_pass_not_collective() {
        // Removing an iframe must NOT set removed_script — the
        // per-pass attribution was the whole point of the Phase-10
        // refactor; widening the set shouldn't break that invariant.
        let s = "<iframe src=evil></iframe>";
        let (_, hits) = strip_html_tags_attributed(s);
        assert!(!hits.removed_script);
        assert!(hits.removed_executable);
    }
}
