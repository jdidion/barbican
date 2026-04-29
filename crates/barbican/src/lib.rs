//! Barbican library surface.
//!
//! Public so integration tests and the `barbican` binary can share
//! implementations. Module layout mirrors the plan in `PLAN.md`
//! §Module layout; every item is a stub until its feature branch
//! lands.

pub mod cmd;
pub mod hooks;
pub mod mcp;
pub mod sanitize;
pub mod tables;
