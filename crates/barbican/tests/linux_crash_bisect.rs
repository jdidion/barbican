//! Targeted Linux bisect harness for the tree-sitter-bash SIGSEGV
//! finding. Loads a captured crasher from `tests/data/` and runs
//! `parser::parse` on truncated prefixes; the smallest prefix that
//! still crashes is the minimal reproducer.
//!
//! Like `linux_repro.rs`, this file is `#![cfg(target_os = "linux")]`
//! and gated behind `BARBICAN_LINUX_REPRO=1` so normal CI / local
//! runs are no-ops.
//!
//! Output is written to `$BARBICAN_REPRO_LOG` (default
//! `/tmp/barbican-bisect.txt`): one line per prefix length tried,
//! `len=N parse=ok|err|<about-to-try>`. The last line is the prefix
//! that either tripped the segfault or the largest prefix tried
//! (if no crash happened). `tail -n 1` + `xxd -r -p` on the latest
//! artifact gives the bisect-minimized input in bytes.

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

#[test]
fn linux_crash_01_full_input_triggers_segfault() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_01.bin");
    let Ok(s) = std::str::from_utf8(bytes) else {
        log("non-utf8 bytes; skipping");
        return;
    };
    log(&format!("len={} about-to-parse", bytes.len()));
    match parse(s) {
        Ok(_) => log(&format!("len={} parse=ok", bytes.len())),
        Err(ParseError::Malformed) => log(&format!("len={} parse=err-malformed", bytes.len())),
        Err(ParseError::ParserInit) => log(&format!("len={} parse=err-init", bytes.len())),
    }
}

#[test]
fn linux_crash_01_prefix_bisect() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_01.bin");

    // Try char-boundary prefix lengths: 100, 200, 400, 800, 1600, 2400,
    // 2700, 2800, 2863 (full). If any of these crashes, the artifact
    // log's last `about-to-parse` line tells us which one.
    let targets = [100, 200, 400, 800, 1600, 2400, 2700, 2800, bytes.len()];
    for &n in &targets {
        let Some(prefix) = prefix_at_char_boundary(bytes, n) else {
            log(&format!("len={n} skip-no-char-boundary"));
            continue;
        };
        let Ok(s) = std::str::from_utf8(prefix) else {
            log(&format!("len={n} skip-non-utf8"));
            continue;
        };
        log(&format!("len={} about-to-parse", prefix.len()));
        let r = parse(s);
        log(&format!(
            "len={} parse={}",
            prefix.len(),
            match r {
                Ok(_) => "ok",
                Err(ParseError::Malformed) => "err-malformed",
                Err(ParseError::ParserInit) => "err-init",
            }
        ));
    }
}

/// Return the largest prefix of `bytes` whose length is ≤ `n` and
/// ends on a UTF-8 character boundary.
fn prefix_at_char_boundary(bytes: &[u8], n: usize) -> Option<&[u8]> {
    let cap = n.min(bytes.len());
    let mut end = cap;
    while end > 0 && !is_char_boundary(bytes, end) {
        end -= 1;
    }
    Some(&bytes[..end])
}

fn is_char_boundary(bytes: &[u8], i: usize) -> bool {
    if i == 0 || i == bytes.len() {
        return true;
    }
    // A UTF-8 continuation byte is 10xxxxxx.
    bytes[i] & 0b1100_0000 != 0b1000_0000
}
