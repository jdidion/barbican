# Barbican — Claude Code safety layer in Rust

You are working on **Barbican**, a Rust safety layer for [Claude Code](https://claude.com/claude-code): a single static binary that installs at `~/.claude/barbican/` and runs as a `PreToolUse` / `PostToolUse` hook plus an MCP server. A bug in Barbican is a bug in the safety floor of the user's entire Claude Code session — treat every change that way.

Barbican began as a clean-room Rust port of [Narthex](https://github.com/fitz2882/narthex) (MIT) pinned at commit `071fec0`, with fixes for every finding in an external security audit (H1, H2, M1-M4, L1-L3). The port + audit-patch roadmap closed at 1.0.0; follow-up polish shipped in 1.1.0. For what's currently shipped, read `CHANGELOG.md`. For threat model and configuration, read `SECURITY.md`. Ongoing work is tracked in GitHub issues.

## Critical rules for working on this codebase

1. **Deny by default.** If the parser can't classify a command, deny it. Surface the parse error in the audit log. Never ship a weaker-regex fallback when the real parser fails — pick one parser and fix its gaps.
2. **Basename-normalize every command lookup.** The single biggest bypass in the Python predecessor was `argv[0] = "/bin/bash"` sliding past `set.contains("bash")`. Use the `cmd_basename` helper everywhere; add a unit test for any new classifier.
3. **Compile-time-encode the dangerous sets.** `NETWORK_TOOLS`, `SHELL_INTERPRETERS`, `SECRET_PATHS`, etc. live in `const` tables or `phf` sets — never mutable `Vec`s that a future refactor might clear.
4. **No shell, no eval, ever.** `std::process::Command` with explicit argv only. No `sh -c`. Input JSON is `serde_json::from_*`, never executed.
5. **`safe_fetch` SSRF hardening.** Full RFC1918 / loopback / link-local / CGNAT (100.64/10) / IMDS (169.254.169.254) filtering. Resolve hostname, connect by IP, send original Host header (defeats DNS rebinding). Reject raw IP literals unless `BARBICAN_ALLOW_IP_LITERALS=1`.
6. **All file writes use explicit mode `0o600`.** Never rely on umask. Audit log, state files, backup files — everything.
7. **Strip ANSI escapes before writing to any log file.** Command strings are attacker-controllable.
8. **Red-test-first for any new finding or behavior change.** Commit the failing test, then the fix, in a pair. New classifiers land with negative-regression tests too (input the classifier must NOT flag).
9. **Audit your own dependencies.** `cargo audit` runs in CI; any new advisory must either upgrade the dep or be documented with a narrow `--ignore` + rationale in `SECURITY.md`.
10. **Self-review pass before claiming done.** Re-read your own code as an adversary. What would you try? `$(cmd)` substitution, here-strings (`<<<`), process substitution (`<(cmd)`), `eval "$var"`, variable indirection, unicode homoglyphs, env-var smuggling. Either block it or document as known-out-of-scope in `SECURITY.md`.

## Upstream attribution

Preserve the Narthex MIT attribution in `README.md`. The pinned snapshot at `refs/narthex-071fec0/` is reference-only — never vendor its code into the Rust tree.

## Directory layout

- `crates/barbican/` — main binary + all modules (parser, scanner, hooks, MCP server, installer).
- `CHANGELOG.md` — release history; every version has an entry.
- `SECURITY.md` — threat model, parser limits, configuration knobs, advisory allowlist.
- `README.md` — install + build + attribution.
- `PLAN.md` — archived port plan tombstone; roadmap lives in GitHub issues now.
- `refs/narthex-071fec0/` — pinned snapshot of upstream Narthex (reference only).
- `refs/audit-report.md` — the external security audit that motivated the original port.

## Workflow

- Don't work on `main`. Branch per feature (`feat/<name>`, `fix/<name>`, `chore/<name>`).
- Small commits; one concern per commit where possible. For a security fix, include the finding ID in the message.
- Open PRs against `main` as Draft until human review. The human reviewer wants a clean commit history, not a single dump.
- Before merging: `cargo test --all-targets --all-features`, `cargo clippy --all-targets --all-features -- -D warnings` (CI-matching invocation — library-only clippy misses test-file lints), `cargo fmt --check`, `cargo audit --deny warnings` (with documented ignores).
- For any non-trivial PR, run the full `/crew:review` pass (Claude `crew:code-reviewer` + GPT via cursor-agent + Gemini via cursor-agent) and fix every impact ≥ medium finding in-place before marking the PR ready for review.
- If you are blocked on a parser edge case that `tree-sitter-bash` can't handle, surface it — don't silently downgrade coverage. That's a finding to document in `SECURITY.md` and either fix or gate the existing behavior with a pinning test.
