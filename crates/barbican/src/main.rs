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
