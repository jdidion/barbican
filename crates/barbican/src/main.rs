//! Barbican binary entry point: parse subcommand, dispatch to the
//! matching hook or MCP-server runner, exit with an appropriate code.
//!
//! Hook contract (from Claude Code): read JSON on stdin, return 0 to
//! allow the tool call, non-zero to block. Stderr is surfaced to the
//! user in the hook output. We deliberately keep this file small — all
//! policy lives in `lib.rs` modules — so the dispatch layer is easy to
//! audit.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "barbican",
    version,
    about = "Safety layer for Claude Code hooks and MCP tools.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// PreToolUse(Bash): block dangerous compositions.
    PreBash,
    /// PostToolUse(Edit|Write|MultiEdit): scan for injection patterns.
    PostEdit,
    /// PostToolUse(mcp__*): scan MCP tool output for injection patterns.
    PostMcp,
    /// PostToolUse(any): append to the audit log.
    Audit,
    /// Start the MCP server over stdio (safe_fetch / safe_read / inspect).
    McpServe,
    /// Install Barbican hooks + MCP server into ~/.claude.
    Install {
        /// Print the planned changes without touching the filesystem.
        #[arg(long)]
        dry_run: bool,
        /// Override the Claude Code config directory (default: ~/.claude).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
    },
    /// Remove Barbican hooks + MCP server registration.
    Uninstall {
        /// Print the planned changes without touching the filesystem.
        #[arg(long)]
        dry_run: bool,
        /// Unwire hooks but leave the binary on disk.
        #[arg(long)]
        keep_files: bool,
        /// Override the Claude Code config directory (default: ~/.claude).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
    },
    /// Test-harness: read stdin as UTF-8 bash, run `classify_command`,
    /// exit 0 on Allow, 2 on Deny, non-zero on any panic / signal. Used
    /// by the 1.3.6 proptest invariants so each case runs in a fresh
    /// subprocess and doesn't accumulate tree-sitter-bash FFI state on
    /// Linux. Hidden from `--help`; not part of the stable CLI.
    #[command(hide = true)]
    ClassifyProbe,
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::PreBash => barbican::hooks::pre_bash::run(),
        Command::PostEdit => barbican::hooks::post_edit::run(),
        Command::PostMcp => barbican::hooks::post_mcp::run(),
        Command::Audit => barbican::hooks::audit::run(),
        Command::McpServe => barbican::mcp::server::run(),
        Command::Install { dry_run, home } => {
            let claude_home = resolve_claude_home(home)?;
            let binary_source = std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
            barbican::installer::install(&barbican::installer::InstallOptions {
                claude_home,
                binary_source,
                dry_run,
            })
        }
        Command::Uninstall {
            dry_run,
            keep_files,
            home,
        } => {
            let claude_home = resolve_claude_home(home)?;
            barbican::installer::uninstall(&barbican::installer::UninstallOptions {
                claude_home,
                dry_run,
                keep_files,
            })
        }
        Command::ClassifyProbe => classify_probe(),
    }
}

/// Test-harness: read stdin as UTF-8 bash, run `classify_command`,
/// exit 0 on Allow, 2 on Deny. Non-UTF-8 stdin → 2. Any panic or
/// signal is a test failure surfaced by the parent proptest runner.
/// Never reads env, never writes to the filesystem, never touches
/// stderr — keeps the interface clean for the proptest wrapper.
fn classify_probe() -> Result<()> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("stdin read failed: {e}"))?;
    let s = match std::str::from_utf8(&buf) {
        Ok(s) => s,
        // Non-UTF-8 input is a deny per CLAUDE.md rule #1.
        Err(_) => std::process::exit(2),
    };
    match barbican::__fuzz::classify_command(s) {
        barbican::__fuzz::Decision::Allow => std::process::exit(0),
        barbican::__fuzz::Decision::Deny { .. } => std::process::exit(2),
    }
}

/// Resolve `--home`, falling back to `$HOME/.claude`. We read `HOME`
/// directly instead of pulling a `dirs` crate: the binary already
/// assumes Unix-y paths, and the hook / installer tests need to be
/// able to point at a tempdir by setting `HOME` anyway.
fn resolve_claude_home(explicit: Option<std::path::PathBuf>) -> Result<std::path::PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let home = std::env::var("HOME")
        .map_err(|_| anyhow::anyhow!("HOME not set — pass --home explicitly"))?;
    Ok(std::path::PathBuf::from(home).join(".claude"))
}

/// Initialize `tracing-subscriber` once. Logs go to stderr so they
/// survive the hook's stdout contract, and are off by default — set
/// `BARBICAN_LOG=debug` to see them.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_env("BARBICAN_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));

    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();
}
