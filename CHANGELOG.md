# Changelog

All notable changes to Barbican are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version numbers follow [SemVer](https://semver.org/).

## [0.1.0] — 2026-05-01

Initial release. Rust port of [Narthex](https://github.com/fitz2882/narthex) (pinned at commit `071fec0`) with every finding from the upstream security audit fixed and pinned by a regression test.

### Added

- **`barbican pre-bash`** hook (PreToolUse): denies dangerous bash compositions before Claude Code executes them.
  - H1: `curl|wget` piped into any shell interpreter, including basename-normalized variants (`/usr/bin/bash`, `/bin/sh`, …).
  - H2: staged decode-to-exec pipelines — `base64 -d | bash`, `xxd -r | sh`, `openssl enc -d | bash`, cross-command staging (`base64 -d > /tmp/x.sh; bash /tmp/x.sh`).
  - M1: re-entry wrappers that hide inner commands — `find -exec`, `xargs`, `sudo`, `timeout`, `nohup`, `env`, `watch`, `nice`, `parallel`, `su -c`, `doas`, `runuser`, `setsid`, `stdbuf`, `unbuffer`.
  - M2: DNS-channel exfil — `dig`, `host`, `nslookup`, `drill`, `resolvectl` composed with secret-read pipelines. Split `git` from the hard-deny into the configurable ask-list (`BARBICAN_GIT_HARD_DENY=1` to promote).
  - `tree-sitter-bash` parser foundation with `ParseError::Malformed` → hard-deny on unclean parse, per Barbican's deny-by-default rule.
- **`barbican post-edit` / `barbican post-mcp`** hooks (PostToolUse): scan tool output for prompt-injection patterns.
  - M3: NFKC normalization (fullwidth Latin, mathematical alphanumerics, compatibility ligatures), zero-width + bidi-override + isolate stripping, HTML-tag stripping with per-pass attribution, configurable scan cap (`BARBICAN_SCAN_MAX_BYTES`, default 5 MB) with explicit `scan-truncated` warning.
- **`barbican audit`** hook (all PostToolUse events): append-only audit log at `~/.claude/barbican/audit.log`, mode `0o600`, ANSI escape sequences stripped before write.
- **`barbican mcp-serve`** — stdio MCP server exposing three tools (rmcp 1.5):
  - `safe_fetch` — RFC1918 / loopback / link-local / CGNAT / IMDS SSRF filter; DNS-pinned connection (resolve once, connect by IP, send original Host header); raw-IP literals rejected unless `BARBICAN_ALLOW_IP_LITERALS=1`; redirects manually re-validated per hop (M4).
  - `safe_read` — sensitive-path deny list (default: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, `~/.kube/config`, `~/.git-credentials`, `~/.config/git/credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials(.toml)?`, `/etc/ssh`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`, `.env`, `.envrc`); canonicalization through symlinks; `BARBICAN_SAFE_READ_*` knobs for extra-deny / allow-carveout / max-bytes (L3).
  - `inspect` — runs the sanitizer on in-context text and returns a plain-text attribution report (NFKC bytes delta, control-character counts, HTML tag attribution, sentinel neutralization hits).
- **`barbican install` / `barbican uninstall`** — Rust replacement for Narthex's Python `install.py`.
  - Atomic writes via `create_new(true)` + `O_NOFOLLOW` (custom-flags) + fsync + rename; PID-scoped tmp path; mode `0o600` on all config writes.
  - Backs up `~/.claude/settings.json` and `~/.claude.json` to `*.pre-barbican` exactly once; torn or invalid backups detected and repaired.
  - Malformed user config surfaces a structured error (never panics); non-UTF-8 binary paths rejected explicitly.
  - Uninstall strips only Barbican-owned entries (Path-component matching, not substring) and prunes the empty `permissions` / `hooks` scaffolding it created.
  - `--dry-run` and `--keep-files` both supported.
- **Build & packaging**: single static binary on `aarch64-apple-darwin` with `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`. CI matrix (ubuntu-latest + macos-latest) runs `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets --all-features`, `cargo audit --deny warnings`, and a release-target build.

### Security

- **All H-finding and M-finding audit recommendations implemented.** See `SECURITY.md` for the threat model, in-scope / out-of-scope attack classes, documented parser limits, and configuration knobs.
- **Unsafe code forbidden** at the workspace level (`unsafe_code = "forbid"`).
- **Dependency audit**: `cargo audit` clean at release. One advisory (`RUSTSEC-2026-0118`, NSEC3 validation DoS in `hickory-proto`) is ignored with documented rationale in `SECURITY.md` — Barbican does not enable any DNSSEC feature on `hickory-resolver`, so the vulnerable code path is not compiled in.

### Attribution

Clean-room port of [Narthex](https://github.com/fitz2882/narthex) by @fitz2882 (MIT). No upstream Rust code vendored. The pinned snapshot at `refs/narthex-071fec0/` is retained as specification only.
