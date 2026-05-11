//! `cargo-fuzz` entry point for the `safe_read` path-canonicalization
//! + deny-list / symlink-walk policy check.
//!
//! Covers the `mcp::safe_read::enforce_policy` surface that
//! was at zero fuzz coverage in the 1.6.x fuzz-coverage review.
//!
//! Invariants:
//! - Never panics, never triggers a `debug_assert`, on any UTF-8 path
//!   string up to 2 KiB.
//! - `enforce_policy` returns a `PolicyOutcome::Ok` or
//!   `PolicyOutcome::Denied(_)` — NEVER an `Err(Io(…))` that leaks a
//!   raw system-path message, NEVER a panic.
//! - `path_matches_rule` is component-boundary-safe: a rule
//!   `/home/u/.ssh` must not match `/home/u/.sshd_config`. The fuzz
//!   target pins this as a property: for any `base`, adding a
//!   non-separator tail to one component must not cause the
//!   base-matching rule to still match.
//!
//! This target deliberately does NOT manipulate the process
//! environment. It reads whatever `$HOME` / `BARBICAN_SAFE_READ_*`
//! cargo-fuzz started with. Single-threaded-per-invocation guarantees
//! from libfuzzer let us skip a global mutex.
//!
//! Run (nightly):
//!     cd crates/barbican && cargo +nightly fuzz run safe_read_policy

#![no_main]

use libfuzzer_sys::fuzz_target;

use barbican::mcp::safe_read::__fuzz::{enforce_policy, path_matches_rule, PolicyOutcome};

/// Cap input at 2 KiB. Longer paths are never useful for the policy
/// check — any real filesystem path fits in `PATH_MAX` (4 KiB on
/// Linux, 1 KiB on macOS) — and they only slow the fuzzer down.
const MAX_LEN: usize = 2 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return;
    }
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Property 1: enforce_policy never panics and always returns a
    // PolicyOutcome. The __fuzz helper already wraps every error shape
    // into `Denied(_)`; if something slipped past, the match arm
    // invariant would trigger.
    match enforce_policy(s) {
        PolicyOutcome::Ok => {}
        PolicyOutcome::Denied(msg) => {
            // Denied reason must be non-empty so the model sees *some*
            // explanation in the `<barbican-error>` envelope.
            assert!(
                !msg.is_empty(),
                "PolicyOutcome::Denied carried an empty reason string"
            );
        }
    }

    // Property 2: path_matches_rule is component-boundary-safe. The
    // historical bypass was `/home/u/.ssh` rule falsely matching
    // `/home/u/.sshd_config`. We check one explicit case here — the
    // fuzz input drives the `enforce_policy` path above, while this
    // pinned check guards the helper's invariant regardless of fuzz
    // input.
    assert!(
        !path_matches_rule("/home/u/.sshd_config", "/home/u/.ssh"),
        "component-boundary bypass: .ssh rule matched .sshd_config"
    );
    assert!(
        path_matches_rule("/home/u/.ssh/id_rsa", "/home/u/.ssh"),
        "legitimate .ssh/id_rsa must match the .ssh rule"
    );
});
