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

Two real bugs surfaced on the first runs of the 1.3.0 properties. One is now fixed; one remains pinned pending a reproducer.

| Test | Shrunk input | Bug | Status |
| ---- | ------------ | --- | ------ |
| `pre_bash_hook_exit_contract_holds` | arbitrary non-UTF-8 bytes on stdin | `pre_bash::run` called `stdin.read_to_string`, which returns `Err` on non-UTF-8 bytes. anyhow bubbled the error to `main` → exit 1. CLAUDE.md rule #1 demands the non-UTF-8 stdin path map to `EXIT_DENY=2` + reason-on-stderr, like the malformed-JSON path from 1.2.0 H-3. | **Fixed in 1.3.0**: read raw bytes, decode via `str::from_utf8`, mirror the JSON deny branch. Pinned by `non_utf8_stdin_denies_by_default` + `non_utf8_stdin_escape_hatch_allows_when_env_set` in `tests/pre_bash_h1.rs`; proptest property is now active. |
| `parser_never_panics_on_bounded_utf8` (and its classifier-layer siblings, which reach `parse` through `classify_command`) | 2863-byte UTF-8 string, mixed emoji + bidi + bash metacharacters, balanced {} depth 19, balanced () depth 6 (see `linux-fuzz-repro-log` CI artifact for exact bytes) | Linux-only: `SIGSEGV` inside the `tree-sitter-bash` FFI within 200 ms of starting. macOS parses the same input cleanly as `Err(Malformed)`. Likely a stack overflow in tree-sitter's C-level error recovery on inputs with deep brace nesting + many unbalanced quotes/backticks. | **Reproducer captured; fix pending**: the `linux-fuzz-repro` CI job (best-effort, `continue-on-error: true`) logs each proptest input as hex before calling `parse`, so crashes leave the triggering bytes on disk. The last `len=… hex=…` line of the uploaded `linux-fuzz-repro-log` artifact is the current crasher; `xxd -r -p` decodes it. Properties that reach `parse` remain `#[cfg(not(target_os = "linux"))]`-gated until the fix lands. |

#### Working with a captured Linux crasher

Every run of the `linux-fuzz-repro` CI job uploads a `linux-fuzz-repro-log` artifact (retained 14 days). On a run that crashed, the last line is the exact input that tripped the segfault. Workflow:

```sh
gh run download <run-id> -R jdidion/barbican --name linux-fuzz-repro-log --dir /tmp/repro
tail -n 1 /tmp/repro/barbican-repro.txt \
  | sed 's/^len=[0-9]* hex=//' \
  | xxd -r -p > /tmp/crash-input.bin
```

`/tmp/crash-input.bin` is the exact byte sequence that crashed the tree-sitter-bash FFI in that run. From there, the path to a fix is:

1. **Bisect the input**: binary-search on input prefix length + selective byte deletion to find the minimal crasher. Run on Linux — macOS parsing is not a reliable signal.
2. **Pin a red-test-first PoC**: `tests/pre_bash_parser.rs` (new file or extension) containing `#[test] fn linux_crash_<shape>_denies_cleanly()`, loading the minimized bytes via `include_bytes!`.
3. **Close the bug**: either an input-length / depth cap at `parser::parse`'s entrance, a patched tree-sitter-bash upstream, or a wrapper that catches the signal and returns `Err(Malformed)`.
4. **Drop the gates**: once the test passes on Linux, remove the `#[cfg(not(target_os = "linux"))]` attributes in `tests/fuzz_properties.rs`.

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
