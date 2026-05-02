//! Targeted Linux bisect harness for the tree-sitter-bash SIGSEGV
//! finding. Loads a captured crasher from `tests/data/` and runs
//! `parser::parse` on truncated prefixes; the smallest prefix that
//! still crashes is the minimal reproducer.
//!
//! Like `linux_repro.rs`, this file is `#![cfg(target_os = "linux")]`
//! and gated behind `BARBICAN_LINUX_REPRO=1` so normal CI / local
//! runs are no-ops.
//!
//! Test ordering: tests run alphabetically under
//! `--test-threads=1`, so the prefix-bisect test is named
//! `aaa_prefix_bisect` to run first, followed by the full-input
//! test (`zzz_full_input`) which is expected to crash. If the full
//! input crashes, the bisect log still contains the full prefix
//! sweep because we got to it first.
//!
//! Output is written to `$BARBICAN_BISECT_LOG` (default
//! `/tmp/barbican-bisect.txt`): one line per prefix length tried,
//! `len=N about-to-parse` then (if the parse returned) `len=N parse=...`.
//! A line with no matching `parse=…` response is the crasher.

#![cfg(target_os = "linux")]

use barbican::parser::{parse, ParseError};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;

fn log_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        std::env::var_os("BARBICAN_BISECT_LOG")
            .map_or_else(|| PathBuf::from("/tmp/barbican-bisect.txt"), PathBuf::from)
    })
}

fn log(line: &str) {
    let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    else {
        return;
    };
    let _ = writeln!(f, "{line}");
    let _ = f.flush();
    let _ = f.sync_all();
}

fn enabled() -> bool {
    std::env::var_os("BARBICAN_LINUX_REPRO")
        .is_some_and(|v| matches!(v.to_str(), Some("1" | "true" | "yes" | "on")))
}

fn parse_and_log(bytes: &[u8]) {
    let Ok(s) = std::str::from_utf8(bytes) else {
        log(&format!("len={} skip-non-utf8", bytes.len()));
        return;
    };
    log(&format!("len={} about-to-parse", bytes.len()));
    let status = match parse(s) {
        Ok(_) => "ok",
        Err(ParseError::Malformed) => "err-malformed",
        Err(ParseError::ParserInit) => "err-init",
    };
    log(&format!("len={} parse={status}", bytes.len()));
}

/// Return the largest prefix of `bytes` whose length is ≤ `n` and
/// ends on a UTF-8 character boundary.
fn prefix_at_char_boundary(bytes: &[u8], n: usize) -> &[u8] {
    let cap = n.min(bytes.len());
    let mut end = cap;
    while end > 0 && !is_char_boundary(bytes, end) {
        end -= 1;
    }
    &bytes[..end]
}

fn is_char_boundary(bytes: &[u8], i: usize) -> bool {
    if i == 0 || i == bytes.len() {
        return true;
    }
    // A UTF-8 continuation byte is 10xxxxxx.
    bytes[i] & 0b1100_0000 != 0b1000_0000
}

/// Runs FIRST (alphabetical). Prefix-bisect the captured 2863-byte
/// input to find the smallest crashing prefix. Each step's input is
/// logged with `about-to-parse` BEFORE the parse call; a matching
/// `parse=…` line AFTER means that length didn't crash. The last
/// `about-to-parse` line with no following `parse=…` is the crasher.
#[test]
fn aaa_prefix_bisect_captured_crasher() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_01.bin");
    // Dense prefix sweep biased toward small sizes — we want to
    // discover the minimal crasher quickly. If none of these crash
    // but the full input does, that itself narrows to the tail.
    let targets = [
        1,
        10,
        50,
        100,
        200,
        400,
        800,
        1200,
        1600,
        2000,
        2200,
        2400,
        2500,
        2600,
        2700,
        2750,
        2800,
        2850,
        bytes.len(),
    ];
    for &n in &targets {
        let prefix = prefix_at_char_boundary(bytes, n);
        parse_and_log(prefix);
    }
}

/// Runs LAST. Confirms the full captured input crashes on Linux.
/// If the prefix bisect above already narrowed a smaller crasher,
/// this test is redundant but harmless.
#[test]
fn zzz_full_input_captured_crasher() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_01.bin");
    parse_and_log(bytes);
}
