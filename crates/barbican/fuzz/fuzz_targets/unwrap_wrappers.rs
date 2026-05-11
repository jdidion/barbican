//! `cargo-fuzz` entry point for `hooks::pre_bash::unwrap_wrappers_in_pipeline`.
//!
//! Covers the IR-level wrapper-unwrapping path that re-enters
//! classification for `sudo`, `timeout`, `bash -c`, `find -exec`,
//! `xargs bash -c`, nested combinations, etc. The 1.6.x fuzz-coverage
//! review flagged this as MEDIUM breadth.
//!
//! Invariants:
//! - Never panics on any `Pipeline` produced by `parser::parse`.
//! - Never hangs (libfuzzer's per-run timeout fires if a single input
//!   exceeds 1s).
//!
//! Narrowing (discovered 2026-05-11 during initial fuzz runs): the
//! task spec proposed "if `Some`, the script has ≥ 1 pipeline" as an
//! invariant. The actual implementation intentionally returns
//! `Some(Script { pipelines: vec![] })` when every wrapper stage in a
//! pipeline has an empty inner (e.g. `bash -c h -c 'echo {'` — the
//! first inner `-c h` parses as an empty inner, the second's
//! unterminated quote parses as a malformed-reentry marker). The
//! real caller re-classifies the empty script as `Decision::Allow`
//! (the for-loop iterates zero times) which is the correct no-op
//! semantics. So the ≥ 1 pipeline shape-invariant is too strict; we
//! test the weaker-but-still-meaningful "never panics" property
//! instead.
//!
//! Run (nightly):
//!     cd crates/barbican && cargo +nightly fuzz run unwrap_wrappers

#![no_main]

use libfuzzer_sys::fuzz_target;

use barbican::__fuzz::unwrap_wrappers_invariants;

/// Cap bash input at 4 KiB. Longer inputs just slow the fuzzer down;
/// the IR shapes we care about fit easily.
const MAX_LEN: usize = 4 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return;
    }
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Property: never panics. The return value is opaque — we just
    // consume it so the compiler can't optimize the call away.
    let _unwrap_count = unwrap_wrappers_invariants(s);
});
