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
    /// Explain how Barbican would classify a command without running it.
    ///
    /// Reads a command (from argv or stdin), runs the same classifier
    /// the PreToolUse hook and the wrapper binaries use, and prints the
    /// verdict (`allow` / `deny`) plus the short reason and optional
    /// detail paragraph. Exits 0 on allow, 2 on deny — matching the
    /// hook's exit-code contract so scripts can just check `$?`.
    Explain {
        /// Command to classify. Mutually exclusive with `--stdin`.
        command: Option<String>,
        /// Read the command from stdin instead of an argv token. Useful
        /// for long commands, heredocs, or piping from a file.
        #[arg(long)]
        stdin: bool,
        /// Which wrapper's input to synthesize before classifying.
        /// `shell` (the default) classifies the command as-is.
        /// Other dialects wrap the command as `<interp> <-c|-e> 'BODY'`
        /// so you can see what `barbican-python -c …` etc. would decide.
        #[arg(long, default_value = "shell")]
        dialect: ExplainDialect,
        /// Emit machine-readable JSON instead of a human paragraph.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ExplainDialect {
    Shell,
    Python,
    Node,
    Ruby,
    Perl,
}

impl From<ExplainDialect> for barbican::wrappers::Dialect {
    fn from(d: ExplainDialect) -> Self {
        match d {
            ExplainDialect::Shell => Self::Shell,
            ExplainDialect::Python => Self::Python,
            ExplainDialect::Node => Self::Node,
            ExplainDialect::Ruby => Self::Ruby,
            ExplainDialect::Perl => Self::Perl,
        }
    }
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
        Command::Explain {
            command,
            stdin,
            dialect,
            json,
        } => explain(command, stdin, dialect.into(), json),
    }
}

/// Diagnostic: classify a command the same way the hook / wrappers do
/// and print the verdict + reason + detail. Exit 0 on allow, 2 on deny;
/// exit 1 on CLI misuse (both `command` and `--stdin`, neither given,
/// non-UTF-8 stdin) so scripts can distinguish "barbican denied" from
/// "explain was invoked wrong."
fn explain(
    command: Option<String>,
    from_stdin: bool,
    dialect: barbican::wrappers::Dialect,
    json: bool,
) -> Result<()> {
    use std::io::{Read, Write};

    // Exactly one of argv / stdin must be set.
    let body = match (command, from_stdin) {
        (Some(_), true) => {
            let _ = writeln!(
                std::io::stderr(),
                "barbican explain: pass either COMMAND or --stdin, not both"
            );
            std::process::exit(1);
        }
        (None, false) => {
            let _ = writeln!(
                std::io::stderr(),
                "barbican explain: provide a COMMAND argument or --stdin"
            );
            std::process::exit(1);
        }
        (Some(c), false) => c,
        (None, true) => {
            let mut raw = Vec::new();
            std::io::stdin()
                .read_to_end(&mut raw)
                .map_err(|e| anyhow::anyhow!("stdin read failed: {e}"))?;
            String::from_utf8(raw).map_err(|e| {
                anyhow::anyhow!(
                    "stdin contained non-UTF-8 bytes at offset {}",
                    e.utf8_error().valid_up_to()
                )
            })?
        }
    };

    // Reuse the wrappers' synthesis step so `--dialect python` etc.
    // classifies the same string `barbican-python -c BODY` would.
    let input = barbican::wrappers::synthesize_classifier_input(dialect, &body);
    let decision = barbican::__fuzz::classify_command(&input);

    match decision {
        barbican::__fuzz::Decision::Allow => {
            if json {
                println!(r#"{{"verdict":"allow"}}"#);
            } else {
                println!("Verdict: allow");
            }
            std::process::exit(0);
        }
        barbican::__fuzz::Decision::Deny { reason, detail } => {
            if json {
                let mut obj = serde_json::Map::new();
                obj.insert("verdict".into(), serde_json::Value::String("deny".into()));
                obj.insert("reason".into(), serde_json::Value::String(reason));
                if let Some(d) = detail {
                    obj.insert("detail".into(), serde_json::Value::String(d));
                }
                let line =
                    serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_else(|_| {
                        r#"{"verdict":"deny","error":"serialize failed"}"#.to_string()
                    });
                println!("{line}");
            } else {
                println!("Verdict: deny");
                println!("Reason:  {reason}");
                if let Some(d) = detail {
                    println!("Detail:  {d}");
                }
            }
            std::process::exit(2);
        }
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
    // Non-UTF-8 input is a deny per CLAUDE.md rule #1.
    let Ok(s) = std::str::from_utf8(&buf) else {
        std::process::exit(2);
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
