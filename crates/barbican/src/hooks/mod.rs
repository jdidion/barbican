//! Hook entry points invoked from `main.rs` once a subcommand has been
//! dispatched. Each module here holds one subcommand's behavior and its
//! parser/test surface.
//!
//! Everything is a stub on `feat/scaffold`; real implementations land on
//! their own feature branches (`feat/pre-bash-h1`, `feat/post-mcp-m3`,
//! …) so each audit finding gets its own commit with its own test.

pub mod audit;
pub mod post_advisory;
pub mod post_edit;
pub mod post_mcp;
pub mod pre_bash;
