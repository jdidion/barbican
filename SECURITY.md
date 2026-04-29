# Barbican threat model

Barbican sits on the `PreToolUse` / `PostToolUse` hook boundary of Claude Code and exposes an MCP server at `~/.claude/barbican/barbican mcp-serve`. A bug in Barbican is a bug in the safety floor of the user's entire Claude Code session — treat every finding that way.

This document enumerates what Barbican tries to defend against, what it explicitly does not defend against, the known parser limits, and the configuration knobs.

## In scope — Barbican's job

- **Bash composition attacks** detected pre-execution:
  - `curl | <shell>` / `wget | <shell>` including absolute-path variants (audit H1).
  - Base64 / xxd / openssl pipelines writing to an execution target (audit H2).
  - Re-entry wrappers that hide inner commands (`find -exec`, `xargs`, `sudo`, `timeout`, `nohup`, `env`, `watch`, `nice`, `parallel`, `su -c`, `doas`, `runuser`, `setsid`, `stdbuf`, `unbuffer`) (audit M1).
  - DNS-channel exfil (`dig`, `host`, `nslookup`, `drill`, `resolvectl`) (audit M2).
- **Prompt-injection patterns** in PostToolUse tool output, with Unicode awareness:
  - NFKC normalization before matching (fullwidth Latin, mathematical alphanumerics, compatibility ligatures) (audit M3).
  - Zero-width + bidi-override + isolate stripping (`U+200B`/`200C`/`200D`/`FEFF`, `U+202A..202E`, `U+2066..2069`) (audit M3).
  - Payload scan default cap 5 MB (configurable) with explicit truncation warning in the audit log (audit M3).
- **SSRF hardening** in `safe_fetch`:
  - Reject hostnames resolving to RFC1918, loopback, link-local, CGNAT (100.64/10), IMDS (169.254.169.254, fd00:ec2::254).
  - Reject raw IP literals unless `BARBICAN_ALLOW_IP_LITERALS=1`.
  - DNS-pin: resolve once, connect by IP, send original Host header (defeats DNS rebinding) (audit M4).
- **`safe_read` sensitive-path denial** by default (opt-out `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`) (audit L3).
- **Audit log hygiene**: ANSI escapes stripped (L1), files created with mode `0o600` (L2).

## Out of scope — explicit non-goals

Barbican does not defend against these classes; the user's operating environment or Claude Code itself must.

- **The underlying model being asked to produce malicious code that Barbican's parser can't classify.** If `tree-sitter-bash` cannot parse a construct, Barbican denies it (deny-by-default rule). We do not attempt to outsmart adversarial bash grammars.
- **Kernel / hypervisor exploits, TOCTOU against the filesystem.** Barbican runs as the same user as Claude Code with no privilege boundary.
- **Claude Code itself being compromised.** A modified Claude Code binary can bypass its own hooks.
- **The user granting Claude Code broad permissions outside of Barbican's scope** (e.g. enabling arbitrary MCP servers with no safety layer).
- **Prompt injection via attachments Claude Code hasn't yet rendered through a hook** (e.g. a PDF read directly by the model without triggering a PostToolUse hook we observe).
- **Confusables outside NFKC.** Specifically: Cyrillic `і` (U+0456) is NFKC-distinct from Latin `i` (U+0069). Catching Cyrillic-vs-Latin homoglyph attacks requires a dedicated confusables normalization pass, which is future work. A test in `sanitize.rs` documents this limit.
- **Process-level side channels** (timing, thermal, power) and network-level traffic analysis.

## Known parser limits

Enumerate each case where `tree-sitter-bash` or our wrapper can't classify an expression with confidence, and the Barbican response. Deny-by-default applies to all of these unless the user sets `BARBICAN_ALLOW_UNPARSEABLE=1` (explicit opt-out that surfaces the input in the audit log).

- _(Placeholder)_ Populated as `feat/pre-bash-*` branches land.

## Configuration

All knobs are environment variables read at process start; none are persistent on disk.

| Variable | Default | Meaning |
|---|---|---|
| `BARBICAN_LOG` | `warn` | `tracing` env-filter for stderr logs. |
| `BARBICAN_SCAN_MAX_BYTES` | `5242880` (5 MB) | Max bytes scanned for injection patterns; larger inputs emit a `scan-truncated` warning. (M3) |
| `BARBICAN_GIT_HARD_DENY` | `0` | If `1`, promote `git` from ask-list to hard network-tools deny. |
| `BARBICAN_ALLOW_IP_LITERALS` | `0` | If `1`, `safe_fetch` accepts raw IP literals (still subject to SSRF filter). (M4) |
| `BARBICAN_SAFE_READ_ALLOW_SENSITIVE` | `0` | If `1`, `safe_read` permits reads under `~/.ssh/`, `~/.aws/`, etc. (L3) |
| `BARBICAN_SAFE_READ_EXTRA_DENY` | _(empty)_ | Colon-separated path prefixes to add to the sensitive list. |
| `BARBICAN_SAFE_READ_ALLOW` | _(empty)_ | Colon-separated path prefixes to carve out of the sensitive list. |
| `BARBICAN_ALLOW_UNPARSEABLE` | `0` | If `1`, allow inputs the bash parser can't classify (with audit-log surfacing). |

The rule for new knobs: **strict default, named opt-out, documented here**. Never silently weaken a check; if a real false positive surfaces, add a knob.

## Reporting security issues

- Private report: open a [security advisory on GitHub](https://github.com/jdidion/barbican/security/advisories/new).
- If that is not available, email the maintainer (address in `Cargo.toml` / GitHub profile).
- Please include a minimal reproduction (the exact JSON fed to `barbican pre-bash` / `post-mcp` / etc.) and the Barbican version (`barbican --version`).
