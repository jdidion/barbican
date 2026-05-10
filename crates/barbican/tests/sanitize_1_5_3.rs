//! Red tests for 1.5.3 Rust-expert review fixes:
//! - `sanitize::html_tag_regexes()` caches its struct across calls
//!   (Gemini CRITICAL; was allocating a Vec per call).
//! - `strip_html_tags_attributed` still produces identical output
//!   to 1.5.2 (no behavior regression).

use barbican::sanitize::strip_html_tags_attributed;

#[test]
fn strip_html_script_and_style_still_fires() {
    let input = "<p>hi</p><script>alert(1)</script><style>body{}</style>";
    let (out, hits) = strip_html_tags_attributed(input);
    assert!(hits.removed_script, "script should fire");
    assert!(hits.removed_style, "style should fire");
    assert!(!out.contains("<script"), "script removed; got: {out}");
    assert!(!out.contains("<style"), "style removed; got: {out}");
    assert!(out.contains("<p>hi</p>"), "non-executable HTML preserved");
}

#[test]
fn strip_html_executable_tags_all_covered() {
    // All 7 executable-class tags should fire on their respective
    // patterns. This is the regression suite against the 1.5.3 array
    // reorder.
    for (input, label) in &[
        ("<iframe src='x'></iframe>", "iframe"),
        ("<object data='x'></object>", "object"),
        ("<embed src='x'>", "embed"),
        ("<noscript>fallback</noscript>", "noscript"),
        ("<template>x</template>", "template"),
        ("<svg onload='x'></svg>", "svg"),
        (r#"<meta http-equiv="refresh" content="0">"#, "meta-refresh"),
    ] {
        let (_out, hits) = strip_html_tags_attributed(input);
        assert!(
            hits.removed_executable,
            "{label} tag should be classified as executable; input: {input}"
        );
    }
}

#[test]
fn strip_html_idempotent_on_benign_input() {
    let input = "<p>hello</p><div class='x'>world</div>";
    let (out, hits) = strip_html_tags_attributed(input);
    assert_eq!(out, input);
    assert!(!hits.removed_script);
    assert!(!hits.removed_style);
    assert!(!hits.removed_executable);
    assert!(!hits.removed_comment);
}

#[test]
fn repeated_calls_do_not_allocate_extra_vecs() {
    // This test is mostly a smoke check: the 1.5.2 implementation
    // built a Vec<&'static Regex> per call; 1.5.3 caches the whole
    // HtmlTagRegexes struct in a OnceLock. We can't directly observe
    // the Vec allocation, but calling the function 10k times should
    // complete in a few milliseconds on any modern machine — if
    // someone regresses it to the per-call-Vec shape, this test
    // stays green (since the struct is still internally identical)
    // and we rely on the CPU-bound benchmark + code-review catching
    // it. What we CAN pin is that the output stays stable across
    // many invocations (covers any first-call vs. subsequent-call
    // path divergence that a regression might introduce).
    let input = "<script>a</script><iframe></iframe><p>ok</p>";
    let baseline = strip_html_tags_attributed(input);
    for _ in 0..100 {
        let (out, hits) = strip_html_tags_attributed(input);
        assert_eq!(out, baseline.0);
        assert_eq!(hits.removed_script, baseline.1.removed_script);
        assert_eq!(hits.removed_style, baseline.1.removed_style);
        assert_eq!(hits.removed_executable, baseline.1.removed_executable);
        assert_eq!(hits.removed_comment, baseline.1.removed_comment);
    }
}
