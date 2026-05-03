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

/// Prefix-bisect the captured 2863-byte input. Each step's input is
/// logged with `about-to-parse` BEFORE the parse call; a matching
/// `parse=…` line AFTER means that length didn't crash. The last
/// `about-to-parse` line with no following `parse=…` is the crasher.
///
/// Ignored by default: the prefix bisect is known to crash the
/// process at byte 2490, which under `--test-threads=1` also kills
/// every subsequent test before it can log. Run explicitly with
/// `cargo test --test linux_crash_bisect -- --ignored
/// ccc_prefix_bisect_captured_crasher` when you want fresh prefix
/// data.
#[test]
#[ignore = "crashes the test process; run explicitly via --ignored"]
fn ccc_prefix_bisect_captured_crasher() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_01.bin");
    // Prior bisect (CI run 25261881247) narrowed the crasher window:
    // every prefix ≤ 2398 bytes returned `Err(Malformed)` cleanly, but
    // the 2500-byte prefix never returned a `parse=…` line — i.e. the
    // crash fires somewhere in the [2398, 2500) byte window.
    //
    // This pass does a dense 10-byte-grained sweep across that window
    // plus a couple of fast anchors at small sizes so we still catch
    // any regression that would bring the crash earlier. The smallest
    // size in the 2398-2500 window that crashes is the minimal
    // reproducer modulo UTF-8 char-boundary rounding.
    let targets = [
        // Fast anchors to confirm nothing below the window changed:
        1, 2000, 2479,
        // Byte-grained sweep across the narrowed [2479, 2490) window.
        // Prior bisect (CI run 25262176110) landed the crash strictly
        // between 2479 (err-malformed) and 2490 (no parse= line), so
        // this pass finds the exact trigger byte modulo UTF-8
        // char-boundary rounding.
        2480, 2481, 2482, 2483, 2484, 2485, 2486, 2487, 2488, 2489, 2490,
    ];
    for &n in &targets {
        let prefix = prefix_at_char_boundary(bytes, n);
        parse_and_log(prefix);
    }
}

/// Runs SECOND (alphabetical, between aaa_ and zzz_). Suffix probes
/// growing leftward from the identified crash point (byte 2490 in
/// the full input). The 4-byte suffix ending at byte 2490 is the
/// single codepoint `U+31860` (𱡀, CJK Unified Ideograph Ext G) —
/// the candidate trigger. Each larger probe adds more preceding
/// context. If one of the shorter probes crashes, the crash is
/// context-independent; if only the larger ones crash, the tree-
/// sitter error state built up over the preceding 2000+ bytes is
/// load-bearing.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "probe table is naturally long; every entry is a distinct attack-class probe, and compressing into data-driven loops hides which crasher each came from"
)]
fn aaa_classifier_probes() {
    if !enabled() {
        return;
    }
    // Prior run (CI 25264060820) pinned the minimal crasher to
    // 5 bytes: `{` + U+31860 (CJK Ext G, 4-byte UTF-8). `𱡀` alone
    // parses cleanly (`parse=ok` on 4 bytes). So a `{` followed by
    // an astral-plane codepoint seems to trip the crash.
    //
    // Each probe is run in a FORKED subprocess (the `barbican
    // pre-bash` binary) so a crash in one probe doesn't kill the
    // rest of the sweep. The subprocess exit code classifies the
    // outcome:
    //   - 0: parser accepted the input (classifier decided allow)
    //   - 2: parser denied (err-malformed → deny-by-default path)
    //   - 1 or signal: crashed (SIGSEGV = 139 in shell, here shows
    //     as exit_status.code() = None + signal number)
    let probes: &[(&str, &[u8])] = &[
        // Positive controls (expected to crash, from prior CI):
        (
            "openbrace_plus_31860",
            include_bytes!("data/probe-openbrace_31860.bin"),
        ),
        // Codepoint variation, brace constant:
        (
            "openbrace_plus_10000",
            include_bytes!("data/probe-openbrace_10000.bin"),
        ),
        (
            "openbrace_plus_1F600",
            include_bytes!("data/probe-openbrace_1F600.bin"),
        ),
        (
            "openbrace_plus_FFFD_BMP",
            include_bytes!("data/probe-openbrace_FFFD.bin"),
        ),
        (
            "openbrace_plus_cjk_BMP",
            include_bytes!("data/probe-openbrace_cjk_BMP.bin"),
        ),
        // Prefix variation, codepoint constant (U+31860):
        (
            "paren_plus_31860",
            include_bytes!("data/probe-parenopen_31860.bin"),
        ),
        (
            "bracket_plus_31860",
            include_bytes!("data/probe-bracket_31860.bin"),
        ),
        (
            "dquote_plus_31860",
            include_bytes!("data/probe-dquote_31860.bin"),
        ),
        (
            "space_plus_31860",
            include_bytes!("data/probe-space_31860.bin"),
        ),
        (
            "letter_plus_31860",
            include_bytes!("data/probe-letter_31860.bin"),
        ),
        // Negative control (prior CI confirmed ok):
        (
            "solo_31860_no_prefix",
            include_bytes!("data/probe-solo_31860.bin"),
        ),
        // --- 1.3.3 lane: second crasher captured from CI run 25282442816.
        // The 1.3.1 preflight correctly denies the `{ + U+31840..U+3187F`
        // class, but a proptest input that passes the preflight still
        // SIGSEGVs tree-sitter-bash on Ubuntu. The 3103-byte capture in
        // `data/linux_crash_02.bin` contains 13 distinct `{ + astral`
        // pairs (extracted by `tests/data/README.md` notes); each
        // candidate becomes its own probe below so CI can tell us which
        // pair owns the crash.
        //
        // If any of these return `signal-...` or fail to emit an
        // `outcome=` line after `about-to-spawn`, that pair is the
        // root cause and the preflight scan should widen to cover it.
        // Primary suspect: U+31BC3 (CJK Extension H) — same structural
        // shape as the known Ext G crasher, just a different block.
        (
            "openbrace_plus_31BC3_cjk_ext_h",
            include_bytes!("data/probe-openbrace_31BC3_cjk_ext_h.bin"),
        ),
        (
            "openbrace_plus_1AFFD_tangut",
            include_bytes!("data/probe-openbrace_1AFFD_tangut.bin"),
        ),
        (
            "openbrace_plus_10F52",
            include_bytes!("data/probe-openbrace_10F52.bin"),
        ),
        (
            "openbrace_plus_16AE9_bassa",
            include_bytes!("data/probe-openbrace_16AE9_bassa.bin"),
        ),
        (
            "openbrace_plus_1F8C1_supp_arrows_c",
            include_bytes!("data/probe-openbrace_1F8C1_supp_arrows_c.bin"),
        ),
        (
            "openbrace_plus_10FC5",
            include_bytes!("data/probe-openbrace_10FC5.bin"),
        ),
        (
            "openbrace_plus_1EE5D_arabmath",
            include_bytes!("data/probe-openbrace_1EE5D_arabmath.bin"),
        ),
        (
            "openbrace_plus_1EE61_arabmath",
            include_bytes!("data/probe-openbrace_1EE61_arabmath.bin"),
        ),
        (
            "openbrace_plus_FFD2_bmp",
            include_bytes!("data/probe-openbrace_FFD2_bmp.bin"),
        ),
        (
            "openbrace_plus_23A_latin",
            include_bytes!("data/probe-openbrace_23A_latin.bin"),
        ),
        (
            "openbrace_plus_1F5D_greek",
            include_bytes!("data/probe-openbrace_1F5D_greek.bin"),
        ),
        (
            "openbrace_plus_468_cyrillic",
            include_bytes!("data/probe-openbrace_468_cyrillic.bin"),
        ),
        (
            "openbrace_plus_DA7_sinhala",
            include_bytes!("data/probe-openbrace_DA7_sinhala.bin"),
        ),
        // --- 1.3.3 lane, third crasher captured after the Ext H
        // preflight widening. Input was `tests/data/linux_crash_03.bin`
        // (642 bytes), containing only 3 `{ + non-ASCII` pairs.
        (
            "openbrace_plus_1E5E2_ol_onal",
            include_bytes!("data/probe-openbrace_1E5E2_ol_onal.bin"),
        ),
        (
            "openbrace_plus_1CE7_vedic_visarga",
            include_bytes!("data/probe-openbrace_1CE7_vedic_visarga.bin"),
        ),
        (
            "openbrace_plus_C8_latin_egrave",
            include_bytes!("data/probe-openbrace_C8_latin_egrave.bin"),
        ),
        // --- 1.3.4 lane: prefix-bisect the 3rd crasher directly.
        // The per-codepoint probes above all returned `exit-2-deny`
        // in CI run 25284880008, so the crash is context-dependent:
        // some longer subsequence of `linux_crash_03.bin` triggers
        // it, not a simple `{` + astral pair. Forked subprocesses
        // let us sweep a power-of-2 prefix ladder without a single
        // crash killing the test binary. The smallest prefix that
        // returns `signal-...` is the localized crash window.
        (
            "crash03_prefix_0005",
            include_bytes!("data/probe-crash03_prefix_0005.bin"),
        ),
        (
            "crash03_prefix_0010",
            include_bytes!("data/probe-crash03_prefix_0010.bin"),
        ),
        (
            "crash03_prefix_0020",
            include_bytes!("data/probe-crash03_prefix_0020.bin"),
        ),
        (
            "crash03_prefix_0040",
            include_bytes!("data/probe-crash03_prefix_0040.bin"),
        ),
        (
            "crash03_prefix_0080",
            include_bytes!("data/probe-crash03_prefix_0080.bin"),
        ),
        (
            "crash03_prefix_0160",
            include_bytes!("data/probe-crash03_prefix_0160.bin"),
        ),
        (
            "crash03_prefix_0320",
            include_bytes!("data/probe-crash03_prefix_0320.bin"),
        ),
        (
            "crash03_prefix_0400",
            include_bytes!("data/probe-crash03_prefix_0400.bin"),
        ),
        (
            "crash03_prefix_0500",
            include_bytes!("data/probe-crash03_prefix_0500.bin"),
        ),
        (
            "crash03_prefix_0550",
            include_bytes!("data/probe-crash03_prefix_0550.bin"),
        ),
        (
            "crash03_prefix_0600",
            include_bytes!("data/probe-crash03_prefix_0600.bin"),
        ),
        (
            "crash03_prefix_0620",
            include_bytes!("data/probe-crash03_prefix_0620.bin"),
        ),
        (
            "crash03_prefix_0630",
            include_bytes!("data/probe-crash03_prefix_0630.bin"),
        ),
        (
            "crash03_prefix_0640",
            include_bytes!("data/probe-crash03_prefix_0640.bin"),
        ),
    ];
    let bin = env!("CARGO_BIN_EXE_barbican");
    for (name, bytes) in probes {
        let Ok(s) = std::str::from_utf8(bytes) else {
            log(&format!("probe={name} non-utf8 len={}", bytes.len()));
            continue;
        };
        // Build a well-formed hook-JSON envelope wrapping this probe
        // as a Bash command. serde_json handles the escape dance.
        let envelope = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": s },
        })
        .to_string();
        log(&format!("probe={name} about-to-spawn len={}", bytes.len()));
        let mut child = std::process::Command::new(bin)
            .arg("pre-bash")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn pre-bash");
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(envelope.as_bytes());
        }
        let status = child.wait().expect("wait pre-bash");
        let outcome = match status.code() {
            Some(0) => "exit-0-allow".to_string(),
            Some(2) => "exit-2-deny".to_string(),
            Some(n) => format!("exit-{n}"),
            None => format!("signal-{status:?}"),
        };
        log(&format!(
            "probe={name} outcome={outcome} len={}",
            bytes.len()
        ));
    }
}

/// Confirms the full captured input crashes on Linux.
///
/// Ignored by default for the same reason as `ccc_prefix_bisect_…`:
/// if it runs in the same binary as other tests, its SIGSEGV kills
/// them too. Run explicitly with `--ignored` when you want to
/// reconfirm.
#[test]
#[ignore = "crashes the test process; run explicitly via --ignored"]
fn zzz_full_input_captured_crasher() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_01.bin");
    parse_and_log(bytes);
}

/// 1.3.3 lane: same shape as `zzz_full_input_captured_crasher` but
/// on the NEW 3103-byte capture from CI run 25282442816 (the one
/// that resurfaced when the Linux proptest gates were removed
/// during 1.3.2). Pinned here so regression is deliberate, not
/// accidental.
#[test]
#[ignore = "crashes the test process; run explicitly via --ignored"]
fn zzz_full_input_captured_crasher_02() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_02.bin");
    parse_and_log(bytes);
}

/// 1.3.3 lane, third capture: after the Ext H preflight widening
/// landed, CI run 25284655051 surfaced ANOTHER 642-byte crasher
/// whose `{ + astral` pairs are all outside the Ext G/H rows.
/// Pinned here so the bisect harness knows about all three captures.
#[test]
#[ignore = "crashes the test process; run explicitly via --ignored"]
fn zzz_full_input_captured_crasher_03() {
    if !enabled() {
        return;
    }
    let bytes = include_bytes!("data/linux_crash_03.bin");
    parse_and_log(bytes);
}
