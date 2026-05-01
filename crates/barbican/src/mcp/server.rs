//! Stdio MCP server entry point.
//!
//! On `feat/scaffold` we expose a `ServerHandler` with zero tools. That
//! is still useful: it exercises the `rmcp` dependency end-to-end, it
//! proves the stdio framing works, and it gives `install.rs` something
//! concrete to register.
//!
//! Tool implementations land per feature branch.

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};

use crate::mcp::safe_fetch::{self, SafeFetchArgs};
use crate::mcp::safe_read::{self, SafeReadArgs};

/// Barbican's MCP server state. Currently empty; later branches will
/// hold per-tool state such as the DNS resolver for `safe_fetch`.
#[derive(Clone, Debug, Default)]
pub struct Barbican {
    // Consumed by the `#[tool_handler]` macro; not read directly.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Barbican {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// MCP tool: fetch a URL with SSRF and prompt-injection hardening.
    ///
    /// Blocks RFC1918 / loopback / link-local / CGNAT / IMDS addresses
    /// even when the hostname resolves to one of them (DNS rebinding
    /// defense). Strips zero-width/bidi Unicode, removes HTML
    /// `<script>` / `<style>` / comment blocks, NFKC-normalizes, and
    /// wraps the result in `<untrusted-content>` sentinels so the
    /// model treats the body as data. Use instead of `WebFetch` for
    /// attacker-influenced sources (forum threads, PR descriptions,
    /// scraped pages).
    #[tool(
        name = "safe_fetch",
        description = "Fetch a URL with SSRF and prompt-injection hardening. \
                       Blocks RFC1918/loopback/link-local/CGNAT/IMDS. Strips \
                       zero-width/bidi unicode and <script>/<style>. Wraps body \
                       in <untrusted-content>. Use instead of WebFetch for \
                       attacker-influenced sources."
    )]
    pub async fn safe_fetch(
        &self,
        Parameters(args): Parameters<SafeFetchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let body = safe_fetch::run(args).await;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }

    /// MCP tool: read a local file, sanitize it, wrap it in an
    /// `<untrusted-content>` sentinel.
    ///
    /// Denies well-known sensitive paths by default
    /// (`~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.config/gh/`, `~/.netrc`,
    /// `~/.docker/config.json`, `/etc/shadow`, `/etc/sudoers`,
    /// `/etc/sudoers.d/`, any `.env` file except `.env.example` /
    /// `.env.sample` / `.env.template`). Symlinks are resolved before
    /// the policy check so they can't be used to bypass the deny list.
    /// Opt out with `BARBICAN_SAFE_READ_ALLOW_SENSITIVE=1`.
    #[tool(
        name = "safe_read",
        description = "Read a local file, sanitize it, wrap it in <untrusted-content>. \
                       Denies ~/.ssh/, ~/.aws/, ~/.gnupg/, /etc/shadow, .env, and \
                       similar sensitive paths by default. Resolves symlinks before \
                       the policy check. Use for files that came from outside your \
                       trust boundary (downloads, pasted transcripts, scraped pages)."
    )]
    pub async fn safe_read(
        &self,
        Parameters(args): Parameters<SafeReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let body = safe_read::run(args).await;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }
}

#[tool_handler]
impl ServerHandler for Barbican {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
            .with_instructions(
                "Barbican MCP server. Tools: safe_fetch (SSRF-hardened HTTP \
                 fetch with prompt-injection sanitization); safe_read \
                 (local file read with sensitive-path deny list). inspect \
                 lands in an upcoming branch.",
            )
            .with_protocol_version(rmcp::model::ProtocolVersion::default())
            .with_server_info(rmcp::model::Implementation::from_build_env())
            .with_capabilities(ServerCapabilities::builder().enable_tools().build())
    }
}

/// Extension-style helper so the builder chain stays on `ServerInfo`
/// itself. `with_capabilities` isn't part of the upstream builder set
/// yet; hand-roll it locally.
trait WithCapabilities {
    fn with_capabilities(self, capabilities: ServerCapabilities) -> Self;
}

impl WithCapabilities for ServerInfo {
    fn with_capabilities(mut self, capabilities: ServerCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
}

/// Entry point for the `barbican mcp-serve` subcommand.
///
/// Current-thread tokio runtime on purpose — the hook is a single-shot
/// stdio session and we do not need a multi-threaded scheduler.
pub fn run() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let service = Barbican::new().serve(stdio()).await?;
        service.waiting().await?;
        anyhow::Ok(())
    })
}
