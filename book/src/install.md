# Install

Barbican ships as a single static Rust binary. Three install paths, picked by your platform.

## Prerequisites

- **[Claude Code](https://claude.com/claude-code) installed.** Barbican is a hook + MCP server for Claude Code; install it first. If `~/.claude/` doesn't exist yet, `barbican install` creates it, but Barbican on its own isn't useful without Claude Code.
- **Supported platforms:** macOS arm64/x86_64, Linux glibc arm64/x86_64. No Windows, no musl static builds yet. See the [release page](https://github.com/jdidion/barbican/releases/latest) for tarball targets.
- **Shell tools:** `curl`, `tar`, and `sha256sum` (Linux) or `shasum` (macOS). All three ship with stock macOS and Ubuntu; minimal containers may need `apt install curl ca-certificates tar`.

## Pick your install path

| Platform | Recommended |
|---|---|
| **macOS** | Homebrew (below) |
| **Linux desktop with `brew`** | Homebrew |
| **Bare Linux / fresh container** | [Direct tarball](#direct-tarball-download-any-unix) |
| **Have a Rust toolchain already** | [Cargo](#cargo-if-you-have-a-rust-toolchain) |

## Homebrew (macOS + Linuxbrew)

```sh
brew install jdidion/barbican/barbican
barbican install        # wires hooks + MCP server into ~/.claude
```

Restart Claude Code afterwards so the MCP registration takes effect.

The tap lives at [`jdidion/homebrew-barbican`](https://github.com/jdidion/homebrew-barbican). Its formula pins a SHA256 for each release and inherits the Sigstore build-provenance attestation from the upstream tarball — `brew install` transparently gets the supply-chain check.

### Uninstalling via Homebrew

To remove the hook wiring without uninstalling the binary:

```sh
barbican uninstall
```

To remove the binary too:

```sh
brew uninstall jdidion/barbican/barbican
```

## Cargo (if you have a Rust toolchain)

```sh
cargo install barbican
barbican install
```

Restart Claude Code.

Requires Rust 1.91 or newer — install via [rustup](https://rustup.rs/), not your distro's package manager (Ubuntu 24.04's `apt install rustc` is too old). `cargo install` builds Barbican from source, which typically takes 3-5 minutes on a fresh toolchain. Cargo publishes from the same tag the GitHub release does; the sources on crates.io are byte-identical to the sources on the release tarball.

## Direct tarball download (any Unix)

For release `v1.6.0` on your platform, e.g. macOS arm64:

```sh
VERSION=1.6.0
TARGET=aarch64-apple-darwin
URL="https://github.com/jdidion/barbican/releases/download/v${VERSION}/barbican-${VERSION}-${TARGET}.tar.gz"

curl -sSfL -o barbican.tar.gz "${URL}"
curl -sSfL -o barbican.tar.gz.sha256 "${URL}.sha256"

# Checksum verification: use `sha256sum -c` on Linux, `shasum -a 256 -c` on macOS.
sha256sum -c barbican.tar.gz.sha256   # Linux
# shasum -a 256 -c barbican.tar.gz.sha256   # macOS

tar -xzf barbican.tar.gz

# Drop the `sudo` if you're already root (e.g. in a fresh Docker container).
# The `barbican-*` glob picks up the five wrapper binaries shipped in the
# tarball: barbican-shell, barbican-python, barbican-node, barbican-ruby,
# barbican-perl. See the Configuration page for what each wrapper does.
sudo install -m 755 barbican-${VERSION}-${TARGET}/barbican /usr/local/bin/
sudo install -m 755 barbican-${VERSION}-${TARGET}/barbican-* /usr/local/bin/

barbican install
```

Restart Claude Code afterwards so the MCP registration takes effect.

Supported `TARGET` values: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`.

### Verifying a release (optional, recommended)

Every release tarball carries a [Sigstore build-provenance attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) signed by GitHub Actions' OIDC identity. To verify you got the same bytes that the `barbican` repo's release workflow produced on a commit in the repo's history:

```sh
gh attestation verify barbican.tar.gz --repo jdidion/barbican
```

Requires the [GitHub CLI (`gh`)](https://cli.github.com/). Anonymous verification works for public repos. This does not require any pinned key on your end — verification goes through Sigstore's transparency log using GitHub's OIDC identity for the repo.

## What `barbican install` does

`barbican install` creates `~/.claude/` at mode `0o700` if it doesn't already exist, then writes:

1. **`~/.claude/settings.json`** — adds `PreToolUse` + `PostToolUse` hook entries pointing at the binary. An existing `settings.json` is merged with explicit mode `0o600`; the prior file is backed up as `settings.json.bak`. If the file doesn't exist yet, it's created.
2. **`~/.claude/barbican/`** — the binary is copied here (not symlinked) so a `brew upgrade` that touches the Homebrew install doesn't swap out a running hook mid-session.
3. **`~/.claude/.mcp.json`** — an entry registering the Barbican MCP server (`safe_fetch`, `safe_read`, `inspect` tools). Claude Code picks this up on its next start.
4. **`~/.claude/barbican/audit.log`** — an initially-empty JSONL file at mode `0o600`. Every deny decision and every wrapper invocation writes one line here.

All four paths survive `barbican uninstall` except for changes `install` made to `settings.json` / `.mcp.json`, which are rolled back.

## Verify it worked

After `barbican install` from any install path, run these five commands — they don't require Claude Code to be running:

```sh
barbican --version                      # prove the binary runs
barbican --help                          # see available subcommands
ls -la ~/.claude/barbican/              # prove the 4 files exist at 0o600 / 0o700
barbican explain 'curl https://x | bash'  # show a deny decision without needing Claude Code live
tail -n 0 -f ~/.claude/barbican/audit.log  # watch the audit log for subsequent decisions (Ctrl-C to exit)
```

Once Claude Code is running with Barbican wired in, every denied bash invocation will append one JSONL line to `~/.claude/barbican/audit.log`. If that file grows when Claude Code tries something network-y, the hook is working.

## Uninstalling

`barbican uninstall` is the same regardless of install path. It rolls back every change `barbican install` made to `settings.json` and `.mcp.json`, but leaves the binary + audit log in place:

```sh
barbican uninstall
```

To remove the binary too, use your install path's standard uninstall (`brew uninstall`, `cargo uninstall`, or `rm /usr/local/bin/barbican*` for the tarball path).
