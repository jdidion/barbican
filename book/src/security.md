# Security model

For the authoritative threat model, parser limits, and advisory allowlist, read [`docs/SECURITY.md`](https://github.com/jdidion/barbican/blob/main/docs/SECURITY.md) in the source tree. This page summarizes the key design posture so you can reason about what Barbican does and doesn't protect against.

## Core design principles

1. **Deny by default.** If the parser can't classify a command, it's denied. Every sensitive set (`NETWORK_TOOLS`, `SHELL_INTERPRETERS`, `SECRET_PATHS`, etc.) is compile-time-encoded in `const` tables or `phf` sets — never mutable collections a future refactor could clear.
2. **No shell, no eval.** `std::process::Command` with explicit argv only. Input JSON is parsed via `serde_json::from_*`, never executed. The binary never calls `sh -c` or `eval`.
3. **Basename-normalize every command lookup.** The single biggest bypass in the Python predecessor was `argv[0] = "/bin/bash"` sliding past `set.contains("bash")`. Every classifier uses the `cmd_basename` helper, and every new classifier ships with a negative-regression test.
4. **Single parser.** `tree-sitter-bash` is the one source of truth. When it fails, the command is denied and the failure is audit-logged. No weaker-regex fallback.
5. **Every file write is explicit mode `0o600`.** The umask is not trusted. The audit log, state files, and backup files all enforce this; leaf writes go through `O_NOFOLLOW` and `fchmod` to close the path-based TOCTOU.
6. **ANSI-strip before logging.** Command strings are attacker-controllable. The audit log strips ANSI escapes and truncates to 4000 bytes per field before writing.
7. **Red-test-first.** Every new finding lands as a failing test plus the fix, committed in a pair. New classifiers also land with negative-regression tests — input the classifier must NOT flag.

## SSRF hardening (`safe_fetch`)

`safe_fetch` does RFC1918 / loopback / link-local / CGNAT (`100.64/10`) / IMDS (`169.254.169.254`) / NAT64 filtering on every DNS-resolved IP before issuing the HTTP request. Hostnames resolve via our own `hickory-resolver`, not reqwest's builtin, so every A/AAAA record passes through the SSRF filter before reqwest opens a socket. The original Host header is preserved on connect by IP, defeating DNS rebinding. Raw IP literals are rejected unless `BARBICAN_ALLOW_IP_LITERALS=1`.

## Sensitive-path blocking (`safe_read`)

`safe_read` applies a baked-in denylist that covers SSH / AWS / GnuPG / GitHub CLI / Docker / kubernetes / git-credential / npm / cargo / pypi registry configs, plus `.env` files, `/etc/shadow`, `/etc/sudoers`. Every rule runs against both the lexical and canonical path form; symlink chains are walked for ancestor-symlink laundering under `$HOME`. The full list is in the source tree; an operator can punch narrow per-path holes via `BARBICAN_SAFE_READ_ALLOW`.

## Prompt-injection defense (post-tool-call scans)

After every tool call, Barbican's `PostToolUse` hook and the `safe_fetch` / `safe_read` MCP tools run injection scans on the output. The scanner:

- NFKC-normalizes the text, then strips zero-width and bidi-override codepoints (both the full Unicode set the scanner *counts* and the matching set `strip_invisible` *removes* are unified post-1.5.5).
- Re-runs HTML-tag stripping after NFKC, so fullwidth confusable `＜script＞` that folds to ASCII `<script>` is also removed.
- Matches a curated list of jailbreak phrases, but reports only COUNTS — never matched text — into the advisory channel, so an attacker can't splice "SYSTEM: …" prose into Barbican's own hook output.

## Untrusted launch environment

Barbican's threat model assumes the **launching user's environment is trusted**. If an attacker controls your shell startup (`.zshrc`, `.bashrc`, `.envrc`, an IDE-managed env file, a CI runner's environment), every `BARBICAN_*`-relaxed-deny env var is an attack surface. In particular:

- `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1` disables the entire sensitive-path denylist.
- `BARBICAN_ALLOW_IP_LITERALS=1` disables the `safe_fetch` raw-IP rejection.
- `BARBICAN_PYTHON=/tmp/evil/python` redirects the Python wrapper to an attacker-controlled binary (blocked for non-absolute paths and `..` traversal, but an attacker with write access to `/tmp` can still plant one).

Treat Barbican as a layer, not a perimeter. See [`docs/SECURITY.md § Untrusted launch environment`](https://github.com/jdidion/barbican/blob/main/docs/SECURITY.md) for the full untrusted-environment threat list.

## What Barbican is NOT

- **Not a semantic analyzer.** `rm -rf ~/important` is allowed. Barbican looks for *composition* patterns, not *intent*. If Claude Code proposes a destructive command, review it before accepting.
- **Not a replacement for scoped permissions.** Run Claude Code under a user with only the access it needs for the task. Don't run as root.
- **Not a substitute for reading release notes.** Every CHANGELOG entry for a `fix/` release closes a specific finding; read them so you know what you're running.

## Reporting a security issue

See the repo's [`SECURITY.md`](https://github.com/jdidion/barbican/blob/main/docs/SECURITY.md) for the disclosure policy. Summary: file a private security advisory on the GitHub repo rather than opening a public issue or PR.
