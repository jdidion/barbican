//! `cargo-fuzz` entry point for the full pre-bash classifier.
//!
//! Invariant: `classify_command` always returns `Decision::Allow` or
//! `Decision::Deny { reason }`. Never panics. The deny-reason string
//! is non-empty and NUL-free (mirrors the proptest property).
//!
//! Run (nightly):
//!     cd crates/barbican && cargo +nightly fuzz run classify
//!
//! The corpus directory (`corpus/classify/`) is pre-seeded with
//! representative deny shapes from CHANGELOG PoCs plus a handful of
//! allow shapes so libfuzzer has a warm start on coverage.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = barbican::__fuzz::classify_command(s);
    }
});
