# Developing Barbican

This is the internal handbook for contributors working on the Barbican source. For the threat model and security posture, see [`SECURITY.md`](SECURITY.md). For the project rules any agent (human or AI) should follow, see the [`CLAUDE.md`](../CLAUDE.md) / [`AGENTS.md`](../AGENTS.md) symlink pair at the repo root.

## Build, test, lint

Barbican pins a specific stable Rust toolchain via [`rust-toolchain.toml`](../rust-toolchain.toml) so CI and local builds always run the same compiler.

```sh
# Build
cargo build                           # debug (fast iteration)
cargo build --release --bins          # release binaries (main + 5 wrappers)

# Test
cargo test --all-targets --all-features        # all tests, every surface
cargo test --test pre_bash_1_5_1               # one integration test file
cargo test --lib classify                      # one pattern
```

### Linters (CI-matching)

CI runs clippy across all targets, not just the library — library-only clippy misses test-file lints and is the most common reason a "passes locally" PR fails CI.

```sh
cargo clippy --all-targets --all-features -- -D warnings     # CI-matching
cargo fmt --check
cargo audit --deny warnings                                   # deps + advisory allowlist
```

### Test layout

- `crates/barbican/tests/pre_bash_*.rs` — classifier red tests. Every deny shape has a red-test-first entry. New classifiers must land with pinning tests (the shape that triggers the deny) AND negative-regression tests (a superficially-similar shape that must NOT fire).
- `crates/barbican/tests/fuzz_properties.rs` — proptest properties (invariants across arbitrary input).
- `crates/barbican/tests/safe_*.rs` — MCP tool integration tests (`safe_fetch`, `safe_read`, `inspect`).
- `crates/barbican/tests/wrappers*.rs` — wrapper-binary integration tests.
- `crates/barbican/fuzz/fuzz_targets/` — `cargo-fuzz` entry points. Requires nightly.

### Fuzzing

Barbican ships a proptest layer (runs on stable) plus a `cargo-fuzz` harness (requires nightly). The fuzz crate is deliberately excluded from the workspace so stable `cargo build` works at the repo root.

```sh
# Proptest (stable, part of `cargo test`)
cargo test --test fuzz_properties

# cargo-fuzz (nightly)
cd crates/barbican && cargo +nightly fuzz run classify
cd crates/barbican && cargo +nightly fuzz run parse
```

See [`fuzzing.md`](fuzzing.md) for the full workflow including corpus curation.

## Architecture

Layout in `crates/barbican/src/`:

- `main.rs` + `bin/barbican-*.rs` — CLI entry points.
- `parser.rs` — tree-sitter-bash wrapper + the `Script` / `Pipeline` / `Command` IR. The SIGSEGV preflight lives in `parser::preflight_known_crashers` (see upstream [tree-sitter-bash #337](https://github.com/tree-sitter/tree-sitter-bash/issues/337)).
- `hooks/pre_bash.rs` — classifier dispatch. Every policy is an `if let Some(r) = classifier(pipeline) { return r.into(); }`. ~20 classifiers dispatched here.
- `hooks/post_edit.rs`, `post_mcp.rs`, `post_advisory.rs`, `audit.rs` — the other four hook entry points.
- `mcp/server.rs`, `mcp/safe_fetch.rs`, `mcp/safe_read.rs`, `mcp/inspect.rs` — the MCP tool surface.
- `wrappers/mod.rs` — the five wrapper binaries' shared runtime (`barbican-shell`, `-python`, `-node`, `-ruby`, `-perl`).
- `installer.rs` — install / uninstall / backup logic.
- `scan.rs`, `sanitize.rs`, `redact.rs` — content-side primitives: injection detection, NFKC + invisible stripping, secret-token redaction.
- `tables.rs` — compile-time-encoded dangerous sets (`NETWORK_TOOLS`, `SHELL_INTERPRETERS`, `REENTRY_WRAPPERS`, etc.) as `phf_set!`. Never mutable Vecs.
- `cmd.rs` — `cmd_basename` helper. Every classifier lookup MUST route through this (see CLAUDE.md rule 2).

## Release process

1. **Branch.** `fix/<name>` for bug fixes, `feat/<name>` for features, `chore/<name>` for everything else. Never commit to `main`.
2. **Bump `version` in `Cargo.toml`** and **refresh `Cargo.lock`** in the same commit. Forgetting the lock bump will fail the release workflow's `--locked` build — this has happened more than once; the release workflow's first action should be to verify the lock matches.
3. **CHANGELOG entry.** Every version has a dated entry with `Added` / `Fixed` / `Changed` / `Known limits` sub-sections as needed. Link to any reviewer findings that drove the change (GPT-5.2 CRITICAL, Gemini WARNING, etc.).
4. **PR + crew review.** Every non-trivial PR runs a three-provider adversarial review (Claude `code-reviewer` agent + GPT-5.2 via cursor-agent + Gemini 3.1 Pro via cursor-agent). Every ≥ medium finding gets fixed in-place before marking ready. Don't run two cursor-agent invocations concurrently — they race on `~/.cursor/cli-config.json` and fail.
5. **Merge the PR** (squash), then on `main`:

   ```sh
   git pull origin main
   git tag -a vX.Y.Z -m "vX.Y.Z — short description" <commit-sha>
   git push origin vX.Y.Z
   ```

6. **Create the GitHub release** from the tag — the release workflow EXPECTS an already-created release to attach assets to:

   ```sh
   gh release create vX.Y.Z --title "vX.Y.Z — …" --notes-file /tmp/release-notes.md
   ```

   The release workflow fires on tag push and uploads all 8 assets (4 targets × tarball + `.sha256`).

7. **Homebrew tap** auto-bumps via `.github/workflows/update-homebrew-tap.yml` on `release: published`. If the tap-bump fails on an asset-timing race (it fires before the release workflow finishes attaching assets), retry manually:

   ```sh
   gh workflow run update-homebrew-tap.yml -f tag=vX.Y.Z --repo jdidion/barbican
   ```

   Review + merge the resulting tap PR at https://github.com/jdidion/homebrew-barbican/pulls.

### Release-workflow-created-as-Draft gotcha

GitHub's Actions sandbox can sometimes create the release as a Draft even when `--draft=false` is not set. If you see a v1.X.Y release tagged as Draft with 0 downloadable assets but the release workflow shows all jobs green, the fix is:

```sh
gh release edit vX.Y.Z --draft=false --repo jdidion/barbican
```

Check with `gh api repos/jdidion/barbican/releases --jq '.[] | select(.draft)'` — any `.draft: true` published tag is a leak.

## Secrets and `direnv` + `secretspec`

The project uses [secretspec](https://secretspec.dev) to manage developer-scoped secrets (e.g. `CARGO_REGISTRY_TOKEN` for future crates.io publishes, potentially an Apple Developer ID for codesigning). `.envrc` at the repo root auto-loads them when direnv is active:

```sh
# In the barbican checkout:
direnv allow    # first time only, authorizes the .envrc
```

After `direnv allow`, the next `cd` into the repo runs the `.envrc`, which invokes `secretspec run --export` and exports every secret in `secretspec.toml` (if present) as environment variables for the session.

### Managing `CARGO_REGISTRY_TOKEN`

The crates.io publish token is a high-value secret — a leak lets anyone publish under your crates.io account. secretspec + direnv keeps it off disk in plaintext.

1. **Register the secret in secretspec.toml** (one-time, at the repo root):

   ```toml
   # secretspec.toml
   [secrets.CARGO_REGISTRY_TOKEN]
   description = "crates.io publish token for the barbican crate"
   ```

2. **Set the secret value:**

   ```sh
   secretspec set CARGO_REGISTRY_TOKEN
   # Pastes from your clipboard or prompts interactively; value is
   # stored in the OS keychain (macOS Keychain / Linux secret-service).
   ```

   Secretspec supports multiple backends; the default on macOS is the Keychain, so the token never touches disk in plaintext. On Linux it delegates to the system secret-service (gnome-keyring / kwallet); on CI it can be sourced from an environment variable.

3. **`.envrc` exports it on `cd`.** When you `cd` into the barbican checkout after `direnv allow`:

   ```
   direnv: loading ~/projects/barbican/.envrc
   direnv: export +CARGO_REGISTRY_TOKEN
   ```

4. **Publish.** With `CARGO_REGISTRY_TOKEN` in the environment, `cargo publish` works without `--token` on the command line (where it would otherwise be captured in shell history).

5. **Verify the token is actually loaded:**

   ```sh
   # Confirm direnv exported it (should print `export CARGO_REGISTRY_TOKEN=…`):
   direnv status

   # Confirm the value length is nonzero without printing the value:
   [ -n "$CARGO_REGISTRY_TOKEN" ] && echo loaded || echo missing
   ```

### Why not just `~/.cargo/credentials.toml`?

cargo's credentials file stores the token in plaintext on disk at `~/.cargo/credentials.toml`. If your laptop is lost, stolen, or backed up unencrypted, the token leaks. Keychain-backed secrets via secretspec keep the token encrypted at rest and only export it into processes that pass through `.envrc`. For a token that can push malicious code to every downstream consumer, that's the right trade.

### Rotating the token

1. Revoke the current token at https://crates.io/me (Account → API Tokens).
2. Mint a new one there (scoped to the specific crate if possible).
3. `secretspec set CARGO_REGISTRY_TOKEN` — replaces the stored value.
4. Next `cd` into the checkout re-exports the new token.

## Development workflow tips

### Dogfood Barbican on Claude Code

If you run Claude Code yourself, install the binary you just built into `~/.claude/barbican/` and let Barbican gate your own development session:

```sh
cargo build --release --bins
./target/release/barbican install
```

Barbican's own PreToolUse hook will then scan the bash commands Claude Code generates while you work on Barbican. It is a useful forcing function — every time the hook flags your own development command, you either harden the workflow or add a documented exception.

### Iterate on a classifier

Fast loop for writing or tuning a classifier:

```sh
# Run just this classifier's tests in a watch loop (requires cargo-watch):
cargo watch -x 'test --test pre_bash_m2'

# Try a specific bash body through the classifier without spawning anything:
cargo run --bin barbican -- explain 'echo hi | base64 -d > /tmp/foo.sh'
```

The `barbican explain` subcommand is the fastest feedback path — it runs the full classifier pipeline and prints the verdict + detail prose without ever touching the real shell.

### Working with tree-sitter-bash crashes

`tree-sitter-bash` has a known Linux SIGSEGV class ([upstream #337](https://github.com/tree-sitter/tree-sitter-bash/issues/337)) that Barbican defends against with a byte-class preflight. If you hit a new crash shape, the recovery loop is:

1. Capture the crashing input (proptest logs it).
2. Bisect to the minimum reproducer (`linux_crash_bisect.rs` is the tool).
3. Add the crashing UTF-8 lead bytes to the preflight table in `parser.rs`.
4. Pin a red test in `linux_repro.rs` so the crash class doesn't regress.

## CI

- `.github/workflows/ci.yml` — tests + clippy + fmt + audit on every PR.
- `.github/workflows/release.yml` — builds release binaries + attaches them to the tagged release. Fires on `v*` tag push.
- `.github/workflows/fuzz.yml` — scheduled fuzz run on nightly.
- `.github/workflows/update-homebrew-tap.yml` — auto-bumps the Homebrew tap formula on `release: published`.

All `uses:` action references are SHA-pinned with the semantic version in a comment. If you bump an action, update both the SHA and the comment.

## Further reading

- [`SECURITY.md`](SECURITY.md) — threat model, parser limits, configuration knobs, advisory allowlist.
- [`fuzzing.md`](fuzzing.md) — the fuzz corpus + cargo-fuzz workflow.
- [`PLAN.md`](PLAN.md) — archived port plan (reference only; current roadmap is GitHub issues).
- [`permission-reduction-post-v1.md`](permission-reduction-post-v1.md) — v2 speculation on a narrower permission surface.
