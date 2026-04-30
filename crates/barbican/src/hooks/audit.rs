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

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Result;
use serde_json::Value;

use crate::sanitize::strip_ansi;

/// Max chars any string field is allowed to reach before truncation.
const MAX_STRING_CHARS: usize = 4000;

/// Run the audit hook. Never returns Err — writer failures are
/// swallowed so the parent tool call proceeds.
pub fn run() -> Result<()> {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        return Ok(());
    }
    let Ok(payload) = serde_json::from_str::<Value>(&buf) else {
        return Ok(());
    };

    let entry = build_entry(&payload);
    let Ok(line) = serde_json::to_string(&entry) else {
        return Ok(());
    };

    let Some(log_path) = log_path_from_env() else {
        return Ok(());
    };
    let _ = append_line(&log_path, &line);
    Ok(())
}

/// Derive the audit-log path from `$HOME`. Returns `None` if the env
/// var is unset or empty — no sensible fallback on Unix.
fn log_path_from_env() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let home = PathBuf::from(home);
    if home.as_os_str().is_empty() {
        return None;
    }
    Some(home.join(".claude").join("barbican").join("audit.log"))
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

/// Recursively walk a JSON value, ANSI-stripping every string and
/// truncating anything over [`MAX_STRING_CHARS`].
fn sanitize_value(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(sanitize_string(&s)),
        Value::Array(xs) => Value::Array(xs.into_iter().map(sanitize_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k, sanitize_value(v));
            }
            Value::Object(out)
        }
        other => other,
    }
}

fn sanitize_string(s: &str) -> String {
    // Strip ANSI CSI escapes first (L1), then truncate. Stripping
    // first avoids the edge case where truncation cuts an escape in
    // half and leaves a stray ESC byte.
    let stripped = strip_ansi(s).into_owned();
    truncate_with_marker(&stripped, MAX_STRING_CHARS)
}

fn truncate_with_marker(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    // Truncate on a char boundary.
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = s.len() - end;
    format!("{prefix}...[truncated {dropped} chars]", prefix = &s[..end])
}

/// Pull a JSON value and render it as a string if it's one, or the
/// JSON text for objects/arrays/numbers/bools. Null → "".
fn scalar_string(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(s)) => Value::String(sanitize_string(s)),
        Some(other) => other.clone(),
        None => Value::Null,
    }
}

/// Open the log file (create + append), set mode `0o600`, write one
/// JSONL line + newline. Best-effort — ignore any failure. Creates
/// parent directories as needed.
fn append_line(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file: File = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    // `.mode(0o600)` only affects creation. If the file already
    // existed with looser perms, fix them now — L2 says we never
    // rely on umask and the perms must always be 0o600.
    let mut perms = file.metadata()?.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Render `SystemTime::now()` as an ISO-8601 UTC timestamp:
/// `2026-04-29T23:51:00.123Z`. Hand-rolled to avoid pulling `chrono`
/// as a direct dep.
fn iso8601_utc_now() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Split a Unix timestamp into `(year, month, day, hour, minute,
/// second)` in UTC. Based on Howard Hinnant's civil-date algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>).
///
/// Accepts seconds up to ~year 10000, which comfortably covers every
/// realistic `SystemTime::now()` for the lifetime of this binary.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_below_cap_is_unchanged() {
        assert_eq!(truncate_with_marker("hello", 10), "hello");
    }

    #[test]
    fn truncate_above_cap_marks_dropped_chars() {
        let s = "A".repeat(20);
        let out = truncate_with_marker(&s, 8);
        assert!(out.starts_with(&"A".repeat(8)));
        assert!(out.contains("truncated 12 chars"));
    }

    #[test]
    fn truncate_respects_utf8_boundary() {
        // A 4-byte emoji right at the boundary — truncation must not
        // cut into a codepoint.
        let s = format!("{}{}", "A".repeat(7), "🦀");
        let out = truncate_with_marker(&s, 8);
        // At cap 8, the boundary lands mid-codepoint; back off to 7.
        assert!(out.starts_with("AAAAAAA"));
        assert!(!out.contains('\u{FFFD}'));
    }

    #[test]
    fn sanitize_strips_ansi_then_truncates() {
        let s = format!("\x1b[31m{}\x1b[0m", "A".repeat(5000));
        let out = sanitize_string(&s);
        // 5000 - 4000 = 1000 dropped chars.
        assert!(!out.contains('\x1b'));
        assert!(out.contains("truncated 1000 chars"));
    }

    #[test]
    fn iso8601_now_matches_expected_shape() {
        let s = iso8601_utc_now();
        // YYYY-MM-DDTHH:MM:SS.mmmZ — 24 chars
        assert_eq!(s.len(), 24, "got {s}");
        assert!(s.ends_with('Z'));
        assert!(s.chars().nth(10) == Some('T'));
    }

    #[test]
    fn civil_from_unix_known_epochs() {
        // Unix epoch.
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2024-02-29 (leap year).
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29, 0, 0, 0));
        // 2026-04-29 00:00:00 UTC.
        assert_eq!(civil_from_unix(1_777_420_800), (2026, 4, 29, 0, 0, 0));
        // 2026-04-29 14:23:45 UTC — checks h/m/s too.
        assert_eq!(civil_from_unix(1_777_472_625), (2026, 4, 29, 14, 23, 45));
    }
}
