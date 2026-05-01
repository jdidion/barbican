//! MCP server — `safe_fetch`, `safe_read`, `inspect`.
//!
//! Wrapped around the official `rmcp` SDK. Shared envelope helpers
//! live in `wrap`. `inspect` is the only tool that does NOT wrap
//! output in `<untrusted-content>` — it emits a plain-text diagnostic
//! report for the model.

pub mod inspect;
pub mod safe_fetch;
pub mod safe_read;
pub mod server;
pub mod wrap;
