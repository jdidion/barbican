//! Surrounding-quote stripping helpers shared between the parser
//! (which treats `"..."`, `'...'`, `` `...` `` as one quoting layer
//! around `string` / `raw_string` / `ansi_c_string` argv words) and
//! the pre-bash classifier (which strips the same layer off
//! here-string bodies / argv values before re-parsing them).
//!
//! Previous to 1.6.0 there were two near-identical copies: one
//! borrowed-returning in `parser.rs` and one owned-returning in
//! `hooks/pre_bash.rs`. Keeping them in sync by eyeballing the
//! diff was error-prone — the classifier's version (accidentally?)
//! excluded backticks, a real semantic divergence the port review
//! caught in #59. Consolidating into one module pins the set of
//! quote characters to one source-of-truth constant and lets the
//! two use cases share the primitive with different behaviors
//! expressed explicitly.

/// ASCII bytes that [`strip_surrounding_quotes`] treats as matched
/// outer quotes. `"..."`, `'...'`, `` `...` `` all qualify.
const QUOTE_BYTES_WITH_BACKTICK: &[u8] = b"\"'`";

/// ASCII bytes that [`strip_surrounding_quotes_no_backtick`] treats
/// as matched outer quotes. Backticks are excluded — when the caller
/// is about to re-parse the inner bytes as bash (here-string bodies,
/// `-c` inline code, `--init-command=` values), a backtick is
/// command-substitution syntax, not a quoting layer, and stripping
/// it would remove context the parser needs to see.
const QUOTE_BYTES_NO_BACKTICK: &[u8] = b"\"'";

/// If `s` is wrapped in matching `"..."`, `'...'`, or `` `...` ``,
/// return the inner slice. Otherwise return `s`.
///
/// Kept narrow on purpose — `parser::strip_command_name_quoting`
/// handles the richer set (including `$'...'` / `$"..."`) used by
/// `argv[0]`.
#[must_use]
pub fn strip_surrounding_quotes(s: &str) -> &str {
    strip_with(s, QUOTE_BYTES_WITH_BACKTICK)
}

/// Like [`strip_surrounding_quotes`] but does NOT strip matched
/// backticks — the backtick is command-substitution syntax in bash,
/// so when the caller is about to re-parse the inner bytes as bash
/// (here-string bodies, wrapper `-c` values, alias targets) removing
/// it would lose a classifier-relevant construct.
///
/// Returns a borrow; call `.to_string()` on the result if you need
/// ownership. The separate owned wrapper that used to live in
/// `pre_bash.rs` is now one `to_string()` away.
#[must_use]
pub fn strip_surrounding_quotes_no_backtick(s: &str) -> &str {
    strip_with(s, QUOTE_BYTES_NO_BACKTICK)
}

#[inline]
fn strip_with<'a>(s: &'a str, quote_bytes: &[u8]) -> &'a str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && quote_bytes.contains(&first) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{strip_surrounding_quotes, strip_surrounding_quotes_no_backtick};

    #[test]
    fn strip_backtick_form() {
        assert_eq!(strip_surrounding_quotes("`hi`"), "hi");
    }

    #[test]
    fn strip_double_quotes() {
        assert_eq!(strip_surrounding_quotes("\"hi\""), "hi");
        assert_eq!(strip_surrounding_quotes_no_backtick("\"hi\""), "hi");
    }

    #[test]
    fn strip_single_quotes() {
        assert_eq!(strip_surrounding_quotes("'hi'"), "hi");
        assert_eq!(strip_surrounding_quotes_no_backtick("'hi'"), "hi");
    }

    #[test]
    fn bare_word_passthrough() {
        assert_eq!(strip_surrounding_quotes("hi"), "hi");
        assert_eq!(strip_surrounding_quotes_no_backtick("hi"), "hi");
    }

    #[test]
    fn single_quote_char_passthrough() {
        assert_eq!(strip_surrounding_quotes("\""), "\"");
        assert_eq!(strip_surrounding_quotes_no_backtick("\""), "\"");
    }

    #[test]
    fn empty_passthrough() {
        assert_eq!(strip_surrounding_quotes(""), "");
        assert_eq!(strip_surrounding_quotes_no_backtick(""), "");
    }

    #[test]
    fn mismatched_quotes_passthrough() {
        assert_eq!(strip_surrounding_quotes("\"mismatch'"), "\"mismatch'");
        assert_eq!(
            strip_surrounding_quotes_no_backtick("\"mismatch'"),
            "\"mismatch'"
        );
    }

    #[test]
    fn no_backtick_variant_leaves_backtick_content_alone() {
        // Backtick content is command substitution syntax. The
        // variant used for re-parsing must preserve it.
        assert_eq!(strip_surrounding_quotes_no_backtick("`cmd`"), "`cmd`");
    }
}
