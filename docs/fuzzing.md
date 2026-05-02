# Fuzzing Barbican

Barbican 1.3.0 ships a two-layer fuzzing story so that the question "is the classifier complete?" can be answered by machines instead of by yet another round of adversarial-review iteration. The guiding principle: the shipped red-test-first PoCs in `crates/barbican/tests/pre_bash_*.rs` remain the ground truth for *known* bypasses; fuzzing's job is to prove the safety floor has no *structural* failure modes — no classifier panic, no parser hang, no hook exit outside the Claude Code contract.

## Layer 1 — property tests (stable Rust, runs in CI)

Location: `crates/barbican/tests/fuzz_properties.rs`.

The proptest properties run under plain `cargo test` on the pinned stable toolchain (1.91.1 per `rust-toolchain.toml`). 256 cases per property by default; the shell-out properties that spawn `barbican pre-bash` narrow to 32 cases each to keep the wall-clock cost tolerable.

Invariants covered:

1. `parser::parse` returns `Ok(Script)` or `Err(ParseError::{Malformed, ParserInit})` for any UTF-8 string up to 2000 chars — never panics, never hangs.
2. `classify_command` returns `Decision::Allow` or `Decision::Deny { reason }` for any UTF-8 string up to 2000 chars. When it denies, the reason is non-empty, NUL-free, and bounded to under 4 KiB (the audit-log hygiene property).
3. `barbican pre-bash` exits with code 0 (allow) or 2 (deny) for any JSON envelope — never 1 (unhandled error), never signal-killed, never hangs past a 10-second timeout.
4. `net::validate_url` returns `Ok(Url)` or `Err(RejectReason)` for any URL-shaped string up to 500 chars.
5. `path_in_attacker_writable_dir` returns a clean `bool` on arbitrary Unicode input (covers the chmod-target attacker-dir check).

Run:

```sh
cargo test -p barbican --test fuzz_properties
```

### Findings from layer 1

The first run of the properties on the 1.3.0 branch caught one real bug; it is pinned in the test file as an `#[ignore]`d case rather than fixed in this PR (fix-scope rule: the fuzzing-infrastructure PR adds the test; a follow-up PR fixes the underlying behavior).

| Test | Shrunk input | Bug | Target release |
| ---- | ------------ | --- | -------------- |
| `pre_bash_hook_exit_contract_holds` | arbitrary non-UTF-8 bytes on stdin | `pre_bash::run` calls `stdin.read_to_string`, which returns `Err` on non-UTF-8 bytes. anyhow bubbles to `main`, exits 1. CLAUDE.md rule #1 (deny-by-default) demands the non-UTF-8 stdin path map to `EXIT_DENY=2` + reason-on-stderr, just like the malformed-JSON path added in 1.2.0 H-3. | 1.3.1 |

## Layer 2 — cargo-fuzz (nightly only, optional)

Location: `crates/barbican/fuzz/`.

`libfuzzer-sys` requires the Rust nightly toolchain. Barbican itself stays on stable; the fuzz crate is **excluded from the workspace** so `cargo build` / `cargo test` at the repo root continue to work on stable without any nightly dependency bleeding in.

Targets:

| Target | Entry point | Corpus |
| ------ | ----------- | ------ |
| `parse` | `parser::parse` | `corpus/parse/` — simple command, pipeline, command substitution, heredoc, here-string, process substitution, redirect, assignment, and/or, ANSI-C quoted command name. |
| `classify` | `__fuzz::classify_command` (via the shipped pipeline of every classifier) | `corpus/classify/` — 20 representative deny shapes drawn from CHANGELOG PoCs (H1 curl-pipe-bash variants, H2 base64-decode-exec, M1 wrapper families, M2 secret-exfil / DNS / reverse shell, persistence, chmod, git config injection, scripting-lang shellout) plus 10 benign allow shapes (ls, git status, cargo build, find/grep, benign command substitution). |
| `validate_url` | `net::validate_url` | `corpus/validate_url/` — public URLs, loopback v4/v6, IMDS, RFC1918, scheme rejections, v4-mapped v6, Teredo. |

Run:

```sh
cd crates/barbican
rustup toolchain install nightly        # once
cargo install cargo-fuzz                # once

cargo +nightly fuzz run parse -- -max_total_time=60
cargo +nightly fuzz run classify -- -max_total_time=60
cargo +nightly fuzz run validate_url -- -max_total_time=60
```

For longer runs, drop `-max_total_time` and let libfuzzer keep mutating until you `Ctrl-C`. Crashes land in `crates/barbican/fuzz/artifacts/<target>/`.

When a fuzz run finds a crash, the reduction workflow is:

1. Reproduce: `cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>`.
2. `cargo +nightly fuzz tmin <target> artifacts/<target>/crash-<hash>` to minimize.
3. Turn the minimized input into a red-test-first `#[test]` in the relevant `tests/` file (e.g. `tests/pre_bash_m2.rs`) — this pins the regression even without nightly.
4. Fix the classifier / parser.
5. Add the minimized input to the corpus so future runs stay warm.

### Why the fuzz crate is workspace-excluded

If `crates/barbican/fuzz/` were a workspace member, every stable user running `cargo build` from the repo root would have to resolve `libfuzzer-sys`'s nightly-only dependencies. Excluding it in the root `Cargo.toml`'s `[workspace] exclude = [...]` list keeps the stable build tree minimal. Nightly users opt in by `cd crates/barbican` and running `cargo +nightly fuzz ...` — the fuzz crate builds out-of-tree with its own lockfile.

## Internal API surface used by fuzzing

Both layers drive the classifier via `barbican::__fuzz` — a `#[doc(hidden)]` module that re-exports `classify_command` and `path_in_attacker_writable_dir` so the fuzzers don't need to shell out to the binary for every input.

The `__fuzz` module is deliberately not part of Barbican's stable public API. Downstream code must not depend on it; semver guarantees apply only to the items documented in `lib.rs` and in `SECURITY.md`.
