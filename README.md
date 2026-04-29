# Barbican

A safety layer for [Claude Code](https://claude.com/claude-code) delivered as a single static Rust binary. Barbican runs as a `PreToolUse` / `PostToolUse` hook and as an MCP server that exposes sanitized fetch / read / inspect tools, blocking a concrete list of known-dangerous bash compositions and prompt-injection patterns before they reach the model.

This is a port of [Narthex](https://github.com/fitz2882/narthex) (MIT-licensed Python prototype) with fixes for every finding in an external security audit. See [`PLAN.md`](PLAN.md) for the port plan and [`SECURITY.md`](SECURITY.md) for the threat model.

Status: **pre-release**. The scaffold is in place; feature branches (`feat/pre-bash-h1`, `feat/pre-bash-h2`, …) are landing one audit finding at a time.

## Install

Once a release is cut:

```sh
./barbican install           # backs up ~/.claude/settings.json and wires hooks
./barbican install --dry-run # preview, no filesystem changes
```

To remove:

```sh
./barbican uninstall              # restore the pre-Barbican backups
./barbican uninstall --keep-files # unwire hooks, leave the binary on disk
./barbican uninstall --dry-run
```

## Build from source

```sh
cargo build --release --target aarch64-apple-darwin
```

Requires Rust stable 1.91+ (pinned in `rust-toolchain.toml`). See [`SECURITY.md`](SECURITY.md) for the environment variables Barbican reads.

## License & attribution

Barbican is MIT-licensed (see [`LICENSE`](LICENSE)).

Barbican is a clean-room Rust port of [Narthex](https://github.com/fitz2882/narthex) by @fitz2882, pinned at commit `071fec0`. Narthex is MIT-licensed; the full text is reproduced in `refs/narthex-071fec0/LICENSE`. No Narthex source is vendored into the Rust tree; the snapshot at `refs/narthex-071fec0/` is read as specification only.

### Third-party dependency licenses

- [`rmcp`](https://crates.io/crates/rmcp) — Apache-2.0, the official Rust SDK for the Model Context Protocol. Compatible with Barbican's MIT license.
- All other runtime dependencies are MIT or MIT / Apache-2.0 dual-licensed. Run `cargo tree -e normal --prefix depth` for the current transitive list; `cargo audit` runs in CI.
