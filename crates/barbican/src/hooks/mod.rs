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

/// Max bytes any hook will read from stdin. Guards against OOM DoS on
/// an unbounded payload (e.g. an attacker influencing Claude Code's
/// hook JSON via prompt-injected tool args that blow up the outer
/// `tool_input.command`). 8 MiB comfortably covers any realistic
/// tool-call payload; anything larger is truncated silently for the
/// advisory (`post_edit` / `post_mcp`) paths or denied outright by
/// the pre-bash path (the truncated JSON will fail to parse and the
/// existing deny-by-default branch fires).
///
/// 1.3.7 adversarial review (Claude WARNING #7, #8): pre-bash /
/// post-edit / post-mcp previously read stdin unbounded.
pub const MAX_STDIN_BYTES: u64 = 8 * 1024 * 1024;
