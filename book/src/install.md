# Install

Barbican ships as a single static Rust binary. Three install paths, in order of convenience:

## Homebrew (recommended on macOS / Linux with `brew`)

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

Requires Rust 1.91 or newer. Cargo publishes from the same tag the GitHub release does; the sources on crates.io are byte-identical to the sources on the release tarball.

## Direct tarball download (any Unix)

For release `v1.6.0` on your platform, e.g. macOS arm64:

```sh
VERSION=1.6.0
TARGET=aarch64-apple-darwin
URL="https://github.com/jdidion/barbican/releases/download/v${VERSION}/barbican-${VERSION}-${TARGET}.tar.gz"
curl -sSfL -o barbican.tar.gz "${URL}"
curl -sSfL -o barbican.tar.gz.sha256 "${URL}.sha256"
shasum -a 256 -c barbican.tar.gz.sha256
tar -xzf barbican.tar.gz
sudo install -m 755 barbican-${VERSION}-${TARGET}/barbican /usr/local/bin/
sudo install -m 755 barbican-${VERSION}-${TARGET}/barbican-* /usr/local/bin/
barbican install
```

Supported `TARGET` values: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`.

### Verifying a release (optional, recommended)

Every release tarball carries a [Sigstore build-provenance attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) signed by GitHub Actions' OIDC identity. To verify you got the same bytes that the `barbican` repo's release workflow produced on a commit in the repo's history:

```sh
gh attestation verify barbican.tar.gz --repo jdidion/barbican
```

This does not require any pinned key on your end — verification goes through Sigstore's transparency log using GitHub's OIDC identity for the repo.

## What `barbican install` does

`barbican install` writes four things under `~/.claude/`:

1. **`~/.claude/settings.json`** — adds `PreToolUse` + `PostToolUse` hook entries pointing at the binary. An existing `settings.json` is merged with explicit mode `0o600`; the prior file is backed up as `settings.json.bak`.
2. **`~/.claude/barbican/`** — the binary gets copied here (not symlinked) so a `brew upgrade` that touches the Homebrew install doesn't swap out a running hook mid-session.
3. **`.mcp.json`** — an entry registering the Barbican MCP server (`safe_fetch`, `safe_read`, `inspect` tools). Claude Code picks this up on its next start.
4. **`~/.claude/barbican/audit.log`** — an initially-empty JSONL file at mode `0o600`. Every deny decision and every wrapper invocation writes one line here.

All four paths survive `barbican uninstall` except for changes `install` made to `settings.json` / `.mcp.json`, which are rolled back.
