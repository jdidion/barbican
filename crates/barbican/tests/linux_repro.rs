//! Dedicated reproducer harness for the Linux-only `tree-sitter-bash`
//! SIGSEGV finding surfaced by the 1.3.0 proptest layer.
//!
//! The proptest properties in `fuzz_properties.rs` that reach
//! `parser::parse` are gated off Linux because the first CI run took
//! `SIGSEGV` with no per-input diagnostics. This file inverts the
//! gate: the parser-touching property runs ONLY on Linux, and ONLY
//! when `BARBICAN_LINUX_REPRO=1` is set — normal `cargo test`
//! invocations are no-ops.
//!
//! Before each parse call we append the input (length-prefixed,
//! LF-terminated) to a log file so the crash-triggering input
//! survives the segfault. Run in a dedicated `continue-on-error`
//! CI job that uploads the log as a workflow artifact — the last
//! line in the log is the minimized reproducer.
//!
//! Local usage (Linux host required to reproduce; no-op elsewhere):
//!
//! ```sh
//! BARBICAN_LINUX_REPRO=1 \
//!   BARBICAN_REPRO_LOG=/tmp/barbican-repro.txt \
//!   cargo test -p barbican --test linux_repro -- --nocapture
//! ```
//!
//! When the segfault fires, `tail -1 /tmp/barbican-repro.txt` shows
//! the input that caused it. That becomes the red-test-first PoC
//! for the fix.

#![cfg(target_os = "linux")]

use barbican::parser::{parse, ParseError};
use proptest::prelude::*;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Cached resolution of `BARBICAN_REPRO_LOG` — falls back to
/// `/tmp/barbican-repro.txt` so the harness has a knowable path even
/// when the env var is unset.
fn repro_log_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        std::env::var_os("BARBICAN_REPRO_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/barbican-repro.txt"))
    })
}

/// Write `input` to the repro log and flush + fsync so the bytes
/// reach disk before the potentially-crashing parse call. Returns
/// `true` on success; errors are logged but not propagated — we don't
/// want the logger itself to mask a real finding.
fn log_input(input: &str) -> bool {
    let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(repro_log_path())
    else {
        return false;
    };
    let _ = writeln!(f, "len={} utf8={:?}", input.len(), input);
    let _ = f.flush();
    let _ = f.sync_all();
    true
}

/// Gate: skip every property if the env var isn't set. Makes the
/// whole file a no-op on Linux developer machines and in normal CI
/// runs — only the dedicated `linux-fuzz-repro` job flips this on.
fn enabled() -> bool {
    std::env::var_os("BARBICAN_LINUX_REPRO")
        .is_some_and(|v| matches!(v.to_str(), Some("1" | "true" | "yes" | "on")))
}

proptest! {
    /// Parser-level property — runs only on Linux + only when the
    /// env gate is lit. Before calling `parse`, append the input to
    /// the repro log with an fsync, so a segfault leaves the
    /// triggering input on disk for the CI artifact uploader to
    /// capture.
    #[test]
    fn parser_linux_repro(input in "\\PC{0,2000}") {
        if !enabled() {
            return Ok(());
        }
        log_input(&input);
        match parse(&input) {
            Ok(_) | Err(ParseError::Malformed | ParseError::ParserInit) => {}
        }
    }
}
