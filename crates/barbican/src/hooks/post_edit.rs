//! `barbican post-edit` — `PostToolUse` hook for Edit / Write / `MultiEdit`.
//! Stub on `feat/scaffold`; real scanner lands on `feat/post-edit-m3`.

use std::io::Read;

use anyhow::{Context, Result};

pub fn run() -> Result<()> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading post-edit hook JSON from stdin")?;
    tracing::debug!(bytes = buf.len(), "post-edit scaffold: allow");
    Ok(())
}
