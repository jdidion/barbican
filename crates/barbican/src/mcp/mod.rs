//! MCP server — `safe_fetch`, `safe_read`, `inspect`.
//!
//! Wrapped around the official `rmcp` SDK. On `feat/scaffold` we expose
//! an empty tool list so `initialize` + `tools/list` succeed; the real
//! tools land on `feat/safe-fetch-m4`, `feat/safe-read-l3`, and
//! `feat/inspect`.

pub mod server;
