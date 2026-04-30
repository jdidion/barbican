//! Shared advisory emitter for `post-edit` and `post-mcp` hooks.
//!
//! On a non-empty findings set:
//! - print the Claude-Code hook-output JSON to stdout (carries
//!   `additionalContext` so the model and user see the warning);
//! - write a human-readable block to stderr (advisors that don't
//!   render `additionalContext` still see it);
//! - append one JSONL entry to `~/.claude/barbican/audit.log`.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use serde_json::json;

use crate::sanitize::strip_ansi;

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
    // Strip ANSI from every attacker-influenced string that reaches
    // the terminal or the audit log. Matches the L1 hardening in
    // hooks/audit.rs — a malicious MCP tool name or file path cannot
    // rewrite the user's terminal via `less ~/.claude/barbican/audit.log`
    // or the Claude Code transcript.
    let tool = strip_ansi(f.tool).into_owned();
    let path = f.path.map(|p| strip_ansi(p).into_owned());
    let findings: Vec<String> = f
        .findings
        .iter()
        .map(|s| strip_ansi(s).into_owned())
        .collect();
    let intro = strip_ansi(&f.advisory_intro).into_owned();

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

fn append_audit_jsonl(f: &Finding<'_>) -> std::io::Result<()> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(());
    };
    let home = std::path::PathBuf::from(home);
    if !home.is_absolute() {
        return Ok(());
    }
    let log = home.join(".claude").join("barbican").join("audit.log");
    let parent = log.parent().unwrap();
    // DirBuilder with mode(0o700) sets the mode atomically at creation
    // time — no race between create_dir_all and a subsequent chmod.
    // Also handles the already-exists case gracefully (returns Ok).
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    // If the dir pre-existed with wider perms, tighten it now.
    let current_mode = std::fs::metadata(parent)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    if current_mode != 0o700 {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let entry = json!({
        "ts": iso8601_now(),
        "event": f.event,
        "tool": f.tool,
        "path": f.path,
        "session": f.session_id,
        "findings": f.findings,
    });
    let line = entry.to_string();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(o_nofollow())
        .open(&log)?;
    let mut perms = file.metadata()?.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
    }
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

const fn o_nofollow() -> i32 {
    #[cfg(target_os = "macos")]
    {
        0x0100
    }
    #[cfg(target_os = "linux")]
    {
        0x20000
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

fn iso8601_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn civil_from_unix(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days_since_epoch = i64::try_from(secs / 86_400).unwrap_or(0);
    let secs_in_day = (secs % 86_400) as u32;
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day / 60) % 60;
    let second = secs_in_day % 60;
    let shifted = days_since_epoch + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097) as u32;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let year_i64 = i64::from(year_of_era) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_shifted + 2) / 5 + 1;
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    };
    let year_i64 = if month <= 2 { year_i64 + 1 } else { year_i64 };
    let year = u32::try_from(year_i64).unwrap_or(0);
    (year, month, day, hour, minute, second)
}
