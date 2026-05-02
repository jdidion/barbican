//! `cargo-fuzz` entry point for the tree-sitter-bash walker.
//!
//! Invariant: `barbican::parser::parse` returns `Ok(Script)` or one of
//! the `ParseError` variants. It must never panic, never hang, never
//! recurse past `MAX_DEPTH = 100`. See `tests/fuzz_properties.rs` for
//! the stable-Rust property-test version of the same invariant.
//!
//! Run (nightly):
//!     cd crates/barbican && cargo +nightly fuzz run parse
//!
//! See `docs/fuzzing.md` for the full workflow.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `parse` takes `&str`; libfuzzer gives us raw bytes, so gate on
    // UTF-8 validity. Non-UTF-8 inputs are dropped rather than turned
    // into a crash — the parser's contract is over `&str`.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = barbican::parser::parse(s);
    }
});
