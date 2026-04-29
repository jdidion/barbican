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
    },
    /// Remove Barbican hooks + MCP server registration.
    Uninstall {
        /// Print the planned changes without touching the filesystem.
        #[arg(long)]
        dry_run: bool,
        /// Unwire hooks but leave the binary on disk.
        #[arg(long)]
        keep_files: bool,
    },
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
        Command::Install { dry_run } => {
            tracing::info!(dry_run, "install: not yet implemented (feat/install)");
            anyhow::bail!("`barbican install` lands on `feat/install`");
        }
        Command::Uninstall {
            dry_run,
            keep_files,
        } => {
            tracing::info!(dry_run, keep_files, "uninstall: not yet implemented");
            anyhow::bail!("`barbican uninstall` lands on `feat/install`");
        }
    }
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
