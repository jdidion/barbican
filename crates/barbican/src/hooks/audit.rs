//! `barbican audit` — PostToolUse audit-logger hook.
//! Stub on `feat/scaffold`; real writer lands on `feat/audit-l1-l2`
//! (ANSI strip + 0o600 mode).

use std::io::Read;

use anyhow::{Context, Result};

pub fn run() -> Result<()> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading audit hook JSON from stdin")?;
    tracing::debug!(bytes = buf.len(), "audit scaffold: no-op");
    Ok(())
}
