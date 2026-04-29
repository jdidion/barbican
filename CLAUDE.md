# Barbican — Claude Code safety layer in Rust

You are working on **Barbican**, a Rust port of [Narthex](https://github.com/fitz2882/narthex) (a Python-based safety layer for Claude Code). Scope, audit findings, and the full plan are in `PLAN.md` — read that first.

## One-paragraph framing

Barbican installs at `~/.claude/barbican/` as a single static binary that Claude Code invokes on every `PreToolUse` and `PostToolUse` hook event. It blocks dangerous bash compositions (credential-read + network-egress, `curl | bash`, reverse shells, sensitive-path writes, base64-obfuscated payloads) and ships an MCP server with `safe_fetch` / `safe_read` / `inspect` tools that sanitize untrusted content before the model sees it. A bug in Barbican is a bug in the safety floor of the user's entire Claude Code usage — treat it that way.

## Critical rules for working on this codebase

1. **Deny by default.** If the parser can't classify a command, deny it. Surface the parse error in the audit log. Never ship a weaker-regex fallback when the real parser fails — pick one parser and fix its gaps.
2. **Basename-normalize every command lookup.** The single biggest bypass in the Python predecessor was `argv[0] = "/bin/bash"` sliding past `set.contains("bash")`. Write a `cmd_basename` helper and use it everywhere. Add a unit test.
3. **Compile-time-encode the dangerous sets.** `NETWORK_TOOLS`, `SHELL_INTERPRETERS`, `SECRET_PATHS`, etc. go in `const` tables or `phf` sets — never mutable `Vec`s that a future refactor might clear.
4. **No shell, no eval, ever.** `std::process::Command` with explicit argv only. No `sh -c`. Input JSON is `serde_json::from_*`, never executed.
5. **`safe_fetch` SSRF hardening** — full RFC1918 / loopback / link-local / CGNAT (100.64/10) / IMDS (169.254.169.254) filtering. Resolve hostname, connect by IP, send original Host header (defeats DNS rebinding). Reject raw IP literals unless `BARBICAN_ALLOW_IP_LITERALS=1`.
6. **All file writes use explicit mode `0o600`.** Never rely on umask. Audit log, state files, everything.
7. **Strip ANSI escapes before writing to any log file.** Command strings are attacker-controllable.
8. **Port the existing Python tests first.** They describe the behavior contract. Then write new tests for each finding H1-L3 *before* writing the fix (commit with the test failing, then make it pass).
9. **Audit your own dependencies.** `cargo tree` at the end; for each transitive dep, one-line justification. Reject anything with unmaintained status or `RUSTSEC` advisories. Run `cargo audit` in CI.
10. **Self-review pass before claiming done.** Re-read your own `pre_bash.rs` as an adversary. What would you try? `$(cmd)` substitution, here-strings (`<<<`), process substitution (`<(cmd)`), `eval "$var"`, variable indirection, unicode homoglyphs in tool names, env-var smuggling. Try each against your code and either block it or document it as known-out-of-scope in `SECURITY.md`.

## Upstream attribution

Port is based on Narthex commit `071fec0` (MIT license). Preserve attribution in `README.md`. This is a clean-room port — do not vendor Narthex source into the Rust tree. Re-implement each module, reading the Python as specification.

A pinned snapshot is at `refs/narthex-071fec0/` in this repo for reference. Do not copy code from it; read it to understand behavior.

## Acceptance criteria

- `cargo test` passes with ported + new tests (see `PLAN.md` → Acceptance tests).
- `cargo audit` clean.
- `cargo build --release --target aarch64-apple-darwin` produces a single static binary.
- `SECURITY.md` documents the threat model and known out-of-scope attack classes explicitly.
- All HIGH findings (H1, H2) and all MEDIUM findings (M1-M4) fixed, with a test proving each fix.
- `./barbican install` (replacing the Python `install.py`) and `./barbican uninstall` work with `--dry-run`.

## Directory layout in this repo

- `PLAN.md` — full port plan, audit findings, architecture decisions, acceptance tests.
- `CLAUDE.md` — this file, loaded every session.
- `refs/narthex-071fec0/` — pinned snapshot of upstream Narthex (reference only, don't edit, don't copy code).
- `refs/audit-report.md` — the external security audit of upstream Narthex that motivated this port.
- (will create) `Cargo.toml` — workspace root.
- (will create) `crates/barbican/` — main binary + subcommands.
- (will create) `SECURITY.md` — threat model.

## Workflow

- Don't work on `main`. Branch per feature (`feat/pre-bash`, `feat/safe-fetch-ssrf`, etc.).
- Small commits; one finding fixed per commit where possible, with the finding ID in the message (e.g., `H1: basename-normalize argv[0] in pipeline check`).
- Open PRs against `main`; the human reviewer wants a clean commit history, not a single dump.
- Before merging: confirm `cargo test`, `cargo clippy -- -D warnings`, `cargo audit`, and acceptance tests from `PLAN.md`.

If you are blocked on a parser edge case that `tree-sitter-bash` can't handle, surface it — don't silently downgrade coverage. That's a finding to document.
