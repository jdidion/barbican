//! Barbican library surface.
//!
//! Public so integration tests and the `barbican` binary can share
//! implementations. Module layout mirrors the plan in `PLAN.md`
//! §Module layout; every item is a stub until its feature branch
//! lands.

pub mod cmd;
pub mod hooks;
pub mod installer;
pub mod mcp;
pub mod net;
pub mod parser;
pub mod sanitize;
pub mod scan;
pub mod tables;
