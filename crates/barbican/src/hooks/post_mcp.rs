//! `barbican post-mcp` — `PostToolUse` hook for MCP tool responses.
//! Stub on `feat/scaffold`; real scanner lands on `feat/post-mcp-m3`.

use std::io::Read;

use anyhow::{Context, Result};

pub fn run() -> Result<()> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading post-mcp hook JSON from stdin")?;
    tracing::debug!(bytes = buf.len(), "post-mcp scaffold: allow");
    Ok(())
}
