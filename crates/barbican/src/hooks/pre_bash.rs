//! `barbican pre-bash` — the PreToolUse(Bash) hook.
//!
//! Deny-by-default classifier for bash composition attacks. The real
//! implementation lands on `feat/pre-bash-h1` and subsequent branches;
//! this stub only reads the hook JSON and exits cleanly so CI can
//! exercise the dispatch path.

use std::io::Read;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Shape of the JSON Claude Code sends on stdin for a PreToolUse(Bash)
/// hook. We only bind the fields we actually inspect — extras are
/// ignored.
#[derive(Debug, Deserialize)]
struct PreBashInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: ToolInput,
}

#[derive(Debug, Default, Deserialize)]
struct ToolInput {
    #[serde(default)]
    command: String,
}

/// Run the `pre-bash` subcommand.
///
/// On `feat/scaffold` this is deliberately permissive: it proves the
/// JSON-in / exit-code-out contract without implementing any policy.
/// The first finding-fix branch (`feat/pre-bash-h1`) replaces the body
/// with the real classifier.
pub fn run() -> Result<()> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading pre-bash hook JSON from stdin")?;

    // Parse but do not yet enforce. A malformed input on a later branch
    // will be a hard deny (rule #1 in CLAUDE.md: deny by default).
    let parsed: PreBashInput = if buf.trim().is_empty() {
        PreBashInput {
            tool_name: String::new(),
            tool_input: ToolInput::default(),
        }
    } else {
        serde_json::from_str(&buf).context("parsing pre-bash hook JSON")?
    };

    tracing::debug!(
        tool_name = %parsed.tool_name,
        command_len = parsed.tool_input.command.len(),
        "pre-bash scaffold: allow (classifier not yet implemented)"
    );

    Ok(())
}
