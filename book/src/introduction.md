# Barbican

Barbican is a safety layer for [Claude Code](https://claude.com/claude-code): a single static Rust binary that runs as a `PreToolUse` / `PostToolUse` hook and as an MCP server, blocking a concrete list of known-dangerous bash compositions and prompt-injection patterns before they reach the model.

A bug in Barbican is a bug in the safety floor of your entire Claude Code session. It's designed to be small, auditable, and paranoid: deny-by-default, no shell evaluation, compile-time-encoded sensitive sets, mode `0o600` on every file write, and a red-test-first discipline for every finding.

This book is a practical guide to installing and operating Barbican. For the threat model and the authoritative list of what the classifier does and doesn't cover, see [`docs/SECURITY.md`](https://github.com/jdidion/barbican/blob/main/docs/SECURITY.md) in the source tree.

## What Barbican catches

- **Dangerous bash compositions before they run** — `curl | bash`, base64-decode-to-exec, re-entry wrappers (`sudo`, `timeout`, `find -exec`, `docker run`, `nsenter`, `chroot`, `pkexec`, `flatpak run`, etc.), DNS-channel exfil, staged download-and-execute payloads written to exec targets, shell-startup env-var smuggling (`PROMPT_COMMAND=`, `BASH_ENV=`, `ENV=`), reverse-shell patterns, git config injection, and scripting-language shellouts across python / perl / ruby / node / deno / bun / php / lua / tclsh / rscript / swift / racket / guile / julia / sbcl / awk / pwsh.
- **Prompt-injection markers in tool output** — NFKC-normalized scans for "ignore previous instructions"-style patterns, with zero-width and bidi-override stripping.
- **SSRF in `safe_fetch`** — RFC1918 / loopback / link-local / CGNAT / IMDS filtering, DNS pinning to defeat rebinding, mandatory `no_proxy()` to prevent proxy-side lookups.
- **Sensitive-path reads in `safe_read`** — `.ssh/`, `.aws/`, `.env`, SSH/GPG key files, `/etc/shadow`, `/etc/sudoers`, etc.
- **Parse failures** — any input `tree-sitter-bash` can't parse cleanly is denied.

## What Barbican does NOT catch

- **Commands that are syntactically fine but semantically harmful.** `rm -rf ~/important`, `git push --force origin main`, `aws s3 rb s3://prod-data` — all parseable, all allowed. Barbican detects *composition* patterns, not *intent*. Read what Claude Code emits.
- **Attacks outside the classifier families shipped today.** New shapes land as findings, then as red-test-first fixes. "No open vulnerabilities" is not "no vulnerabilities."
- **A compromised launch environment.** If an attacker controls `HOME`, `PATH`, `LD_PRELOAD`, a shell `.envrc`, or the Barbican binary itself, Barbican runs against you.
- **A modified Claude Code binary.** Barbican sits behind Claude Code's hook contract.

## Honest-assessment risks

1. **New attack surface you didn't have before.** The binary, the MCP server, and the installer all run as your user. A compromised release or a bug in the hook is code execution in every session. Sigstore build-provenance attestations close the release-supply-chain gap; there is no reproducible-build story yet.
2. **Silent opt-outs.** Env vars like `BARBICAN_ALLOW_MALFORMED_HOOK_JSON=1` or `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1` turn off individual checks. An attacker who can write to your shell startup can set them.
3. **False confidence.** If you install Barbican and stop reviewing Claude Code's commands because "the hook will catch anything dangerous," you are worse off than before.

Barbican is a safety floor, not a ceiling. Use it as one layer in a defense-in-depth posture, alongside reviewing the commands Claude Code proposes, running Claude Code under a scoped user, and keeping your shell startup uncompromised.
