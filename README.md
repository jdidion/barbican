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

A safety layer for [Claude Code](https://claude.com/claude-code) delivered as a single static Rust binary. Barbican runs as a `PreToolUse` / `PostToolUse` hook and as an MCP server that exposes sanitized fetch / read / inspect tools, blocking a concrete list of known-dangerous bash compositions and prompt-injection patterns before they reach the model.

This is a port of [Narthex](https://github.com/fitz2882/narthex) (MIT-licensed Python prototype) with fixes for every finding in an external security audit. See [`SECURITY.md`](SECURITY.md) for the threat model and [`CHANGELOG.md`](CHANGELOG.md) for release history.

Status: **1.3.7**. Eight adversarial review rounds closed 54 SEVERE+HIGH findings for 1.2.0; the 1.3.0 fuzzing infrastructure plus the 1.3.1–1.3.6 Linux tree-sitter-bash preflight lane have already caught and fixed real-world bugs, and 1.3.7 closes two more SSRF gaps from a final cross-provider audit. See [`CHANGELOG.md`](CHANGELOG.md) for the feature list.

## Is Barbican right for you?

Barbican is **a safety floor, not a ceiling.** Read this before installing.

### What Barbican catches

- **Dangerous bash compositions before they run**: `curl | bash`, base64-decode-to-exec, re-entry wrappers (`sudo`, `timeout`, `nohup`, `find -exec`, `docker run <shell> -c`, container/sandbox/debugger fronts), DNS-channel exfil, secret-to-network pipelines, git config injection, scripting-lang shellouts, and ~30 more concrete shapes. Every one ships with a red-test-first regression test under `tests/pre_bash_*.rs`.
- **Prompt-injection markers in tool output**: NFKC-normalized scans for "ignore previous instructions"-style patterns, with zero-width and bidi-override stripping. Not a complete defense, but closes the obvious cases.
- **SSRF in `safe_fetch`**: RFC1918 / loopback / link-local / CGNAT / IMDS filtering, DNS pinning to defeat rebinding, mandatory `no_proxy()` to prevent proxy-side lookups.
- **Sensitive-path reads in `safe_read`**: `.ssh/`, `.aws/`, `.env`, SSH/GPG key files, `/etc/shadow`, `/etc/sudoers`, etc. Escape hatch via `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`.
- **Parse failures**: any input `tree-sitter-bash` can't parse cleanly is denied, not allowed. Deny-by-default is the top rule in [`CLAUDE.md`](CLAUDE.md).

### What Barbican does NOT catch

- **Commands that are syntactically fine but semantically harmful.** `rm -rf ~/important`, `git push --force origin main`, `aws s3 rb s3://prod-data` — all parseable, all allow. Barbican detects *composition* patterns, not *intent*. You still need to read what Claude Code emits.
- **Attacks that fall outside the classifier families shipped today.** New attack shapes land as findings, then as red-test-first fixes. The fuzzing infrastructure narrows this surface daily, but "no open vulnerabilities" is not the same as "no vulnerabilities." See [`SECURITY.md § Explicit non-goals`](SECURITY.md) for the documented limits.
- **A compromised launch environment.** If an attacker controls `HOME`, `PATH`, `LD_PRELOAD`, a shell `.envrc`, or the Barbican binary itself, Barbican runs against you. Documented in `SECURITY.md § Untrusted-launch environment`.
- **A modified Claude Code binary.** Barbican sits behind Claude Code's hook contract. If Claude Code is compromised, so is everything it runs — including Barbican's hooks.

### Risks of adoption (honest assessment)

See [`SECURITY.md § Risks of adoption`](SECURITY.md#risks-of-adoption) for the full list. Headline risks:

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

Download the binary for your platform from the [latest release](https://github.com/jdidion/barbican/releases/latest), verify both the checksum and the build-provenance attestation, then run `./barbican install`:

```sh
# Example: macOS arm64. Substitute the tarball name for your target.
TAG=v1.3.7
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

**Limits.** The classifier decides on the body *statically*. Runtime-dynamic constructs — variable indirection, `eval`, `exec`-to-another-shell — still execute in the child. The wrappers block every pattern the `pre_bash` hook blocks, and no more.

## Build from source

```sh
cargo build --release --target aarch64-apple-darwin
```

Requires Rust stable 1.91+ (pinned in `rust-toolchain.toml`). See [`SECURITY.md`](SECURITY.md) for the environment variables Barbican reads.

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
