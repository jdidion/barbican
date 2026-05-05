//! `barbican audit` — `PostToolUse` audit-logger hook.
//!
//! Appends every Bash / WebFetch / MCP tool call to
//! `~/.claude/barbican/audit.log` as JSONL. Never blocks — logging
//! must not break the session, so any write failure exits 0.
//!
//! Audit findings:
//! - **L1**: strip ANSI CSI escape sequences from every string field
//!   before writing. Command strings are attacker-controllable and
//!   we don't want them to rewrite the terminal when a human
//!   `less`es the log.
//! - **L2**: file mode is `0o600`. Never rely on umask — the log
//!   contains command strings and URLs (may include tokens).
//!
//! Payload truncation: any string field longer than 4000 chars is
//! trimmed with a `...[truncated N chars]` marker (Narthex parity).

use std::io::Read;

use anyhow::Result;
use serde_json::Value;

use crate::audit_io::MAX_STRING_CHARS;
use crate::audit_io::{append_jsonl_line, audit_log_path, iso8601_utc_now, sanitize_field};

/// Run the audit hook. Never returns Err — writer failures are
/// swallowed so the parent tool call proceeds.
pub fn run() -> Result<()> {
    let mut buf = String::new();
    if std::io::stdin()
        .take(crate::hooks::MAX_STDIN_BYTES)
        .read_to_string(&mut buf)
        .is_err()
    {
        return Ok(());
    }
    let Ok(payload) = serde_json::from_str::<Value>(&buf) else {
        return Ok(());
    };

    let entry = build_entry(&payload);
    let Ok(line) = serde_json::to_string(&entry) else {
        return Ok(());
    };

    let Some(log_path) = audit_log_path() else {
        return Ok(());
    };
    let _ = append_jsonl_line(&log_path, &format!("{line}\n"));
    Ok(())
}

/// Shape the stored JSONL entry: UTC timestamp, event name, tool,
/// session, cwd, input (truncated + ANSI-stripped).
fn build_entry(payload: &Value) -> Value {
    let ts = iso8601_utc_now();
    let event = scalar_string(payload.get("hook_event_name"));
    let tool = scalar_string(payload.get("tool_name"));
    let session = scalar_string(payload.get("session_id"));
    let cwd = scalar_string(payload.get("cwd"));
    let input = payload
        .get("tool_input")
        .cloned()
        .map_or(Value::Null, sanitize_value);
    serde_json::json!({
        "ts": ts,
        "event": event,
        "tool": tool,
        "session": session,
        "cwd": cwd,
        "input": input,
    })
}

/// Recursively walk a JSON value, ANSI-stripping every string
/// (including object KEYS) and truncating anything over
/// [`MAX_STRING_CHARS`]. Object keys are sanitized too so a log
/// consumer decoding the JSONL and displaying a key doesn't render
/// an attacker-planted ESC.
fn sanitize_value(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(sanitize_string(&s)),
        Value::Array(xs) => Value::Array(xs.into_iter().map(sanitize_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(sanitize_string(&k), sanitize_value(v));
            }
            Value::Object(out)
        }
        other => other,
    }
}

fn sanitize_string(s: &str) -> String {
    // Delegate to the shared audit_io helper — keeps the ANSI-strip +
    // truncate discipline consistent between this hook and the 1.4.0
    // wrapper binaries.
    sanitize_field(s, MAX_STRING_CHARS)
}

/// Render a top-level JSON field for the log entry. Strings go
/// through `sanitize_string`; anything else (object/array/num/bool)
/// gets recursively sanitized via `sanitize_value` so nested ESC
/// bytes in e.g. `session_id: {nested: "<ESC>…"}` can't slip through.
/// Null -> Null.
fn scalar_string(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(s)) => Value::String(sanitize_string(s)),
        Some(other) => sanitize_value(other.clone()),
        None => Value::Null,
    }
}

// `append_line` (now `audit_io::append_jsonl_line`),
// `ancestor_chain_has_symlink`, `o_nofollow`, `iso8601_utc_now`, and
// `civil_from_unix` all live in `crate::audit_io` now. They're reused
// by both this hook and the 1.4.0 wrapper binaries; duplicating them
// in two places is how regressions happen, so the hardening lives in
// one module with one set of tests.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_string_strips_ansi_and_truncates() {
        let s = format!("\x1b[31m{}\x1b[0m", "A".repeat(5000));
        let out = sanitize_string(&s);
        assert!(!out.contains('\x1b'));
        assert!(out.contains("truncated 1000 chars"));
    }
}
