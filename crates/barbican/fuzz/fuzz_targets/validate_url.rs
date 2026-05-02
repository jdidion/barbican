//! `cargo-fuzz` entry point for the `safe_fetch` URL validator.
//!
//! Invariant: `barbican::net::validate_url` returns `Ok(Url)` or
//! `Err(RejectReason)`. Never panics. The `url` crate's parser is the
//! workhorse here; this target exists so that a future `url` upgrade
//! that introduces a panic path surfaces immediately instead of
//! showing up as a safe_fetch crash in production.
//!
//! Run (nightly):
//!     cd crates/barbican && cargo +nightly fuzz run validate_url
//!
//! See `docs/fuzzing.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = barbican::net::validate_url(s);
    }
});
