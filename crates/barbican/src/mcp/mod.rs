//! MCP server — `safe_fetch`, `safe_read`, `inspect`.
//!
//! Wrapped around the official `rmcp` SDK. `safe_fetch` lands on
//! `feat/safe-fetch-m4`; `safe_read` and `inspect` ship in upcoming
//! branches.

pub mod safe_fetch;
pub mod server;
