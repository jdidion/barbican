//! Proptest property tests — 1.3.0 fuzzing infrastructure, Layer 1.
//!
//! These properties run under plain `cargo test` on stable Rust
//! (pinned to 1.91.1). They do not try to discover new bypasses — the
//! shipped `pre_bash_*.rs` tests already cover every known attack
//! shape with red-test-first PoCs. This file's job is to assert the
//! *structural* invariants of the safety floor: no classifier path
//! panics, no parser path hangs, no hook path exits with a code
//! outside the Claude Code contract (0 = allow, 2 = deny).
//!
//! The proptest default config (256 cases per property) is used; the
//! whole file runs in a couple of seconds, keeping CI cost negligible.
//!
//! Layer 2 (nightly-only, exhaustive) lives in the out-of-workspace
//! `cargo-fuzz` crate under `crates/barbican/fuzz/`. See
//! `docs/fuzzing.md` for the full story.

use std::io::Write;
use std::process::{Command, Stdio};

use barbican::__fuzz::path_in_attacker_writable_dir;
use barbican::__fuzz::{classify_command, Decision};
use barbican::net::validate_url;
use barbican::parser::{parse, ParseError};
use proptest::prelude::*;

// ---------------------------------------------------------------------
// Invariant 1 — parser::parse
// ---------------------------------------------------------------------

// These parser-touching properties were briefly gated off Linux
// (1.3.0–1.3.2) pending root-cause of two tree-sitter-bash FFI
// SIGSEGVs that fired on arbitrary UTF-8 input on Ubuntu:
//
//   1. `{` + U+31840..U+3187F row (CJK Ext G) — pinned 1.3.1.
//   2. `{` + U+31BC0..U+31BFF row (CJK Ext H) — pinned 1.3.3.
//
// Both rows are caught by `parser::preflight_known_crashers` before
// the FFI is touched, so the proptest properties now run on every
// platform. If a third row surfaces, the per-probe classifier sweep
// in `tests/linux_crash_bisect.rs` identifies it and the table in
// `parser.rs::CRASHER_PREFIXES` grows by one entry.
proptest! {
    /// For any UTF-8 string under 2000 chars, `parser::parse` returns
    /// `Ok(Script)` or one of the two documented `ParseError` variants.
    /// It must never panic and must return in bounded time.
    ///
    /// Input cap matches `tree-sitter-bash`'s realistic ceiling for a
    /// single bash command line; larger inputs route through the
    /// existing `multi_megabyte_argument_word_parses_in_bounded_time`
    /// test in `tests/parser.rs`.
    #[test]
    fn parser_never_panics_on_bounded_utf8(
        input in "\\PC{0,2000}"
    ) {
        match parse(&input) {
            Ok(_) | Err(ParseError::Malformed | ParseError::ParserInit) => {}
        }
    }
}

// ---------------------------------------------------------------------
// Invariant 2 — classify_command
// ---------------------------------------------------------------------

proptest! {
    /// For any bash command string under 2000 chars, `classify_command`
    /// returns `Decision::Allow` or `Decision::Deny {...}`. Never
    /// panics — even on inputs that fail to parse (those deny with
    /// the "command could not be parsed safely" reason per CLAUDE.md
    /// rule #1).
    #[test]
    fn classify_command_never_panics_on_bounded_utf8(
        input in "\\PC{0,2000}"
    ) {
        match classify_command(&input) {
            Decision::Allow => {}
            Decision::Deny { reason } => {
                // The reason string must be non-empty so the user sees
                // why the command was blocked. A `Deny` with an empty
                // reason would be a regression against the hook's
                // "write {reason} to stderr" contract.
                prop_assert!(!reason.is_empty(), "Deny reason must not be empty");
            }
        }
    }

    /// A deny reason is always safe to surface on stderr: no embedded
    /// NUL bytes (would truncate the write), bounded length so a
    /// pathological input can't fill the audit log.
    #[test]
    fn classify_command_deny_reason_is_hygienic(
        input in "\\PC{0,2000}"
    ) {
        if let Decision::Deny { reason } = classify_command(&input) {
            prop_assert!(
                !reason.contains('\0'),
                "Deny reason must not embed NUL; got {reason:?}"
            );
            prop_assert!(
                reason.len() < 4096,
                "Deny reason must stay bounded; got {} bytes",
                reason.len()
            );
        }
    }
}

// ---------------------------------------------------------------------
// Invariant 3 — barbican pre-bash binary exit-code contract
// ---------------------------------------------------------------------

/// Run `barbican pre-bash` with `stdin_bytes` on stdin; return the
/// exit code and how long the call took. A `None` exit code indicates
/// the process was terminated by signal (we assert that never happens).
fn run_pre_bash(stdin_bytes: &[u8]) -> (Option<i32>, std::time::Duration) {
    let bin = env!("CARGO_BIN_EXE_barbican");
    let start = std::time::Instant::now();
    let mut child = Command::new(bin)
        .arg("pre-bash")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn barbican pre-bash");
    if let Some(mut stdin) = child.stdin.take() {
        // Writes may fail if the child exits early on large / malformed
        // input; that's fine — we still care about the exit code.
        let _ = stdin.write_all(stdin_bytes);
    }
    let status = child.wait().expect("pre-bash did not exit");
    (status.code(), start.elapsed())
}

proptest! {
    // Shell-out strategies keep the per-test budget narrow so the
    // aggregate `cargo test` runtime stays reasonable. 32 cases per
    // property here × ~20 ms per invocation ≈ well under a second.
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    /// For any JSON-shaped string up to 8 KiB, `barbican pre-bash`
    /// exits with code 0 (allow) or 2 (deny). Never 1 (unexpected
    /// anyhow bubble), never signal-killed, never hangs.
    ///
    /// Input cap is 8 KiB rather than the 8 MiB the task description
    /// mentions because (a) the spawn overhead dominates over buffer
    /// size — a wider cap doesn't change what's exercised — and (b)
    /// 8 MiB on 32 proptest cases would balloon CI runtime for no
    /// additional coverage on the exit-code contract.
    ///
    /// Red-test-first: on the 1.3.0 branch this property shrunk to
    /// ~4 KiB of arbitrary bytes on stdin, which fed into
    /// `stdin.read_to_string(&mut buf)` bubbled a UTF-8 error out of
    /// `main` as exit code 1 — violating CLAUDE.md rule #1
    /// (non-UTF-8 stdin should map to `EXIT_DENY=2` with a reason on
    /// stderr, like the malformed-JSON path from 1.2.0 H-3). Fixed
    /// by reading raw bytes and decoding through `str::from_utf8`
    /// with an explicit deny branch mirroring the JSON path.
    #[test]
    fn pre_bash_hook_exit_contract_holds(
        input in prop::collection::vec(any::<u8>(), 0..8192)
    ) {
        let (code, elapsed) = run_pre_bash(&input);
        prop_assert!(
            code == Some(0) || code == Some(2),
            "pre-bash exited with {code:?} on {} byte input",
            input.len()
        );
        prop_assert!(
            elapsed < std::time::Duration::from_secs(10),
            "pre-bash took {elapsed:?} on {} byte input",
            input.len()
        );
    }

    /// Repeat the contract check with a well-formed JSON envelope so
    /// the classifier path (not just the JSON deny-by-default) is
    /// exercised. `serde_json::to_string` on an arbitrary UTF-8 string
    /// is guaranteed valid JSON, so this reaches `classify_command`
    /// for every case.
    #[test]
    fn pre_bash_hook_exit_contract_holds_for_valid_json(
        command in "\\PC{0,2000}"
    ) {
        let escaped = serde_json::to_string(&command).unwrap();
        let envelope = format!(
            "{{\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":{escaped}}}}}"
        );
        let (code, elapsed) = run_pre_bash(envelope.as_bytes());
        prop_assert!(
            code == Some(0) || code == Some(2),
            "pre-bash exited with {code:?} on command {command:?}"
        );
        prop_assert!(
            elapsed < std::time::Duration::from_secs(10),
            "pre-bash took {elapsed:?} on command {command:?}"
        );
    }
}

// ---------------------------------------------------------------------
// Invariant 4 — net::validate_url
// ---------------------------------------------------------------------

proptest! {
    /// For any URL-shaped string under 500 chars, `validate_url`
    /// returns `Ok(Url)` or `Err(RejectReason)`. Never panics. The
    /// `url` crate's parser is the core here; this property pins the
    /// contract so a future `url` upgrade that panics on a weird input
    /// surfaces as a test failure rather than a safe_fetch crash.
    #[test]
    fn validate_url_never_panics(
        input in "\\PC{0,500}"
    ) {
        let _ = validate_url(&input);
    }

    /// Targeted shape: things that look like URLs but with attacker-
    /// flavored prefixes / suffixes / embedded authority. Any behavior
    /// is fine as long as it's not a panic.
    #[test]
    fn validate_url_never_panics_on_urlish_shapes(
        scheme in "[a-zA-Z][a-zA-Z0-9+.-]{0,20}",
        authority in "\\PC{0,200}",
        path in "\\PC{0,200}"
    ) {
        let candidate = format!("{scheme}://{authority}/{path}");
        if candidate.len() <= 500 {
            let _ = validate_url(&candidate);
        }
    }
}

// ---------------------------------------------------------------------
// Invariant 5 — path_in_attacker_writable_dir
// ---------------------------------------------------------------------

proptest! {
    /// Arbitrary Unicode never panics the chmod attacker-path check.
    /// `lex_normalize_chmod_path` splits on `/` and walks components;
    /// any character density on either side is fair game.
    #[test]
    fn path_in_attacker_writable_dir_never_panics(
        input in "\\PC{0,2000}"
    ) {
        let _ = path_in_attacker_writable_dir(&input);
    }

    /// Path-shaped inputs (explicit components separated by `/`) must
    /// also return a clean bool. This hits the segment-walk branches
    /// (`.`, `..`, empty, trailing-slash) more densely than the plain
    /// unicode stream above.
    #[test]
    fn path_in_attacker_writable_dir_handles_path_shapes(
        segments in prop::collection::vec("[^/]{0,30}", 0..20)
    ) {
        let path = format!("/{}", segments.join("/"));
        let _ = path_in_attacker_writable_dir(&path);
    }
}
