//! MCP server — `safe_fetch`, `safe_read`, `inspect`.
//!
//! Wrapped around the official `rmcp` SDK. `safe_fetch` landed on
//! `feat/safe-fetch-m4`; `safe_read` lands on `feat/safe-read-l3`;
//! `inspect` ships in an upcoming branch. Shared envelope helpers
//! live in `wrap`.

pub mod safe_fetch;
pub mod safe_read;
pub mod server;
pub mod wrap;
