//! `cargo-fuzz` entry point for the `safe_fetch` redirect-chain URL
//! composer — the pure-sync half of the async redirect loop.
//!
//! Covers `net::validate_url_with` plus `url::Url::join` chained up to
//! `MAX_REDIRECTS + 1` times, which was at zero fuzz coverage in the
//! 1.6.x fuzz-coverage review.
//!
//! Algorithm per fuzz invocation:
//!   1. Decode the input into up to 6 URL candidates, each ≤ 500 chars.
//!   2. Validate URL[0] (with `allow_ip_literals = false`). If this
//!      rejects, stop.
//!   3. For i in 1..N: `url.join(URL[i])`, then re-validate the joined
//!      URL. Any `Err` is a correct rejection — stop, don't panic.
//!
//! Invariants:
//! - No panic at any step.
//! - Trailing-dot hosts (`example.com.`) survive `set_host`-via-join
//!   without panicking.
//! - Bracketed v6 (`[::1]`) survives `set_host`-via-join.
//! - Relative `Location` (`../x`, `//evil.com/y`) against a base URL
//!   either parses cleanly or rejects via `RejectReason` — never
//!   panics.
//!
//! Out of scope: the async redirect loop + host-keyed client cache in
//! `mcp::safe_fetch::fetch_with`. That can land as a future target
//! driven by `MockResolver`.
//!
//! Run (nightly):
//!     cd crates/barbican && cargo +nightly fuzz run safe_fetch_redirect

#![no_main]

use libfuzzer_sys::fuzz_target;

use barbican::net::__fuzz::validate_url_with;

/// Per-URL length cap. 500 chars is plenty for any realistic URL; a
/// longer input is a fuzzer artefact, not an interesting shape.
const MAX_URL_LEN: usize = 500;
/// Maximum number of hops to simulate — one more than
/// `MAX_REDIRECTS = 5` so the fuzzer can also exercise the boundary.
const MAX_HOPS: usize = 6;

fn decode_hops(data: &[u8]) -> Vec<&str> {
    // Simple framing: split by ASCII line feed (`\n`). Each non-empty,
    // UTF-8, ≤ MAX_URL_LEN slice becomes a hop. We cap at MAX_HOPS so
    // pathological inputs can't blow up runtime.
    let Ok(s) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    s.split('\n')
        .filter(|line| !line.is_empty() && line.len() <= MAX_URL_LEN)
        .take(MAX_HOPS)
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let hops = decode_hops(data);
    if hops.is_empty() {
        return;
    }

    // Step 1: validate the initial URL. If rejected, we're done —
    // `safe_fetch` wouldn't have followed any redirect.
    let mut current = match validate_url_with(hops[0], false) {
        Ok(u) => u,
        Err(_) => return,
    };

    // Step 2: walk the remaining hops. Each hop is treated as a
    // `Location:` header value — resolved against the current URL via
    // `Url::join` and then re-validated.
    for hop in &hops[1..] {
        // `Url::join` is where the trailing-dot / bracketed-v6 /
        // relative-path quirks surface. `url` crate should handle
        // every shape without panicking; this target pins that.
        let Ok(next) = current.join(hop) else {
            // Parse / join failure is an acceptable rejection.
            break;
        };
        match validate_url_with(next.as_str(), false) {
            Ok(validated) => {
                current = validated;
            }
            Err(_) => {
                // Correct rejection — stop. A once-rejected URL is
                // never "re-accepted" because we stop composing at
                // first Err.
                break;
            }
        }
    }
});
