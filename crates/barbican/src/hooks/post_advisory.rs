//! Shared advisory emitter for `post-edit` and `post-mcp` hooks.
//!
//! On a non-empty findings set:
//! - print the Claude-Code hook-output JSON to stdout (carries
//!   `additionalContext` so the model and user see the warning);
//! - write a human-readable block to stderr (advisors that don't
//!   render `additionalContext` still see it);
//! - append one JSONL entry to `~/.claude/barbican/audit.log`.

use std::io::Write;

use serde_json::json;

use crate::sanitize::escape_for_prose;

/// Shape of a single advisory emission.
pub struct Finding<'a> {
    /// Short event tag for the audit log (`post_edit_scan`, `post_mcp_scan`).
    pub event: &'a str,
    /// The tool name from the hook JSON (`Write`, `Edit`, `mcp__…`).
    pub tool: &'a str,
    /// Optional file path — only meaningful for post-edit.
    pub path: Option<&'a str>,
    /// Optional session id from the hook payload.
    pub session_id: Option<&'a str>,
    /// The list of findings (one per line). Non-empty — caller's
    /// responsibility.
    pub findings: &'a [String],
    /// Pre-rendered advisory block, surfaced both as
    /// `additionalContext` and to stderr.
    pub advisory_intro: String,
}

pub fn emit_advisory(f: &Finding<'_>) {
    // 1.5.1 crew-review (GPT-5.2 CRITICAL-1): every attacker-influenced
    // string that lands in the advisory prose goes through
    // `escape_for_prose`, which neutralizes control characters (so an
    // attacker can't splice `\n\nSYSTEM: …` into the trusted channel),
    // strips zero-width / bidi overrides, strips ANSI, and caps length.
    // Finding strings are the classifier's own output; they're safe.
    let tool = escape_for_prose(f.tool);
    let path = f.path.map(escape_for_prose);
    let findings: Vec<String> = f.findings.iter().map(|s| escape_for_prose(s)).collect();
    // `advisory_intro` is built by the caller from sanitized parts, so
    // the ANSI-strip here is belt-and-suspenders.
    let intro = escape_for_prose_long(&f.advisory_intro);

    // Stdout JSON → Claude Code renders this in the transcript.
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": &intro,
        }
    });
    let _ = writeln!(std::io::stdout(), "{out}");

    // Stderr duplicate so harnesses without additionalContext rendering
    // still surface the warning.
    let _ = writeln!(std::io::stderr(), "{intro}");

    // Audit log append (best effort). We pass the sanitized copies
    // through the struct so append_audit_jsonl doesn't need to know
    // anything about ANSI.
    let sanitized = Finding {
        event: f.event,
        tool: &tool,
        path: path.as_deref(),
        session_id: f.session_id,
        findings: &findings,
        advisory_intro: intro,
    };
    let _ = append_audit_jsonl(&sanitized);
}

/// Like `escape_for_prose` but without the 256-byte cap — the
/// `advisory_intro` is Barbican-authored static-ish prose that contains
/// legitimate newlines. All we need to do here is strip ANSI and
/// invisibles; the intro's own newlines are supposed to survive.
fn escape_for_prose_long(s: &str) -> String {
    use crate::sanitize::{strip_ansi, strip_invisible};
    let ansi_free = strip_ansi(s).into_owned();
    strip_invisible(&ansi_free)
}

fn append_audit_jsonl(f: &Finding<'_>) -> std::io::Result<()> {
    // 1.5.1 crew-review (GPT-5.2 CRITICAL-2, Claude N-1): delegate to
    // the hardened writer in `audit_io` instead of duplicating the
    // directory-creation / ancestor-symlink / mode / O_NOFOLLOW dance
    // locally. The bespoke version in 1.5.0 and earlier checked only
    // the immediate parent for a symlink, so a planted
    // `~/.claude → /tmp/attacker` ancestor laundered advisory writes
    // into an attacker-controlled directory. `audit_io` walks every
    // ancestor under $HOME.
    let Some(path) = crate::audit_io::audit_log_path() else {
        return Ok(());
    };

    let entry = json!({
        "ts": crate::audit_io::iso8601_utc_now(),
        "event": f.event,
        "tool": f.tool,
        "path": f.path,
        "session": f.session_id,
        "findings": f.findings,
    });
    let line = format!("{entry}\n");
    crate::audit_io::append_jsonl_line(&path, &line)
}
