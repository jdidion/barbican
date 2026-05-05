//! Shared audit-log I/O primitives for both `hooks::audit` and
//! `wrappers`.
//!
//! Barbican's audit log lives at `~/.claude/barbican/audit.log`, is
//! JSONL, mode `0o600`, and is written from two places: the
//! `PostToolUse` audit hook (`crate::hooks::audit`) and each wrapper
//! binary (`crate::wrappers`). The hardening to protect the log
//! against symlink-based tampering and attacker-controllable
//! terminal-injection strings is non-trivial — three separate findings
//! drove it (H1.2.0 #1 symlinked destination, 1.3.7 gemini CRITICAL
//! ancestor-symlink TOCTOU, L1 ANSI stripping). Duplicating that
//! discipline across two writers is how regressions happen; this
//! module is the single authoritative implementation.
//!
//! Public API:
//! - [`append_jsonl_line`] — symlink-hardened, fchmod-safe append of
//!   one JSON line (caller appends the `\n`). The caller constructs
//!   the line; this module does not care what fields go in it.
//! - [`sanitize_field`] — ANSI-strip + truncate a single string
//!   destined for the log. Either the hook's recursive
//!   `sanitize_value` or the wrapper's per-field writer calls this
//!   before appending.
//! - [`iso8601_utc_now`] — shared wall-clock formatter.
//!
//! 1.4.0 adversarial review: all three Cursor reviewers flagged the
//! wrapper's prior open-coded `append_audit_line` as a regression of
//! the 1.3.7 ancestor-symlink fix. This module closes that gap.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::SystemTime;

use crate::sanitize::strip_ansi;

/// Max chars any single string field is allowed to reach before
/// truncation. Matches the hook's historical cap (Narthex parity).
pub const MAX_STRING_CHARS: usize = 4000;

/// Resolve `~/.claude/barbican/audit.log` from the current `HOME` env
/// var. Returns `None` if HOME is unset, empty, or non-absolute —
/// matching the hook's policy of refusing to write a relative-path log.
#[must_use]
pub fn audit_log_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let home = std::path::PathBuf::from(home);
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return None;
    }
    Some(home.join(".claude").join("barbican").join("audit.log"))
}

/// Open the log file and write `line` verbatim (caller includes the
/// trailing `\n`).
///
/// # Hardening
///
/// 1. **Ancestor-symlink rejection** — walk every existing component
///    of `path.parent()` under `$HOME` and refuse to write if any is
///    a symlink. Closes the 1.3.7 gemini-3.1-pro CRITICAL #1
///    (pre-planted `~/.claude` symlink laundering).
/// 2. **Parent-symlink rejection** — even after `create_dir_all`, the
///    immediate parent directory is checked with `symlink_metadata`
///    and rejected if it's a symlink. Closes H 1.2.0 #1.
/// 3. **Parent mode 0o700** — directory listings + metadata shouldn't
///    leak either; tighten any pre-existing parent to `0o700` (L2
///    defense-in-depth).
/// 4. **`O_NOFOLLOW` on the leaf** — a symlinked log path returns
///    ELOOP instead of redirecting the write.
/// 5. **fd-based `fchmod`** via `file.set_permissions` — avoids the
///    path-based TOCTOU on tightening a pre-existing wide-perms log.
/// 6. **Write skipped if chmod fails** — the `0o600` guarantee is
///    load-bearing (logs contain URL tokens, classifier reasons).
///    Refuse rather than leak into a wide log.
///
/// All failures propagate as `Err`; the caller decides whether to
/// swallow (hooks must never break the session) or surface.
pub fn append_jsonl_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if ancestor_chain_has_symlink(parent) {
            return Err(std::io::Error::other(format!(
                "barbican audit: refusing to write — symlinked ancestor on `{}`",
                parent.display()
            )));
        }
        std::fs::create_dir_all(parent)?;
        match std::fs::symlink_metadata(parent) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::other(format!(
                    "barbican audit: refusing to write under symlinked parent `{}`",
                    parent.display()
                )));
            }
            Ok(meta) if meta.file_type().is_dir() => {
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
            _ => {}
        }
    }
    let mut file: File = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(o_nofollow())
        .open(path)?;
    let mut perms = file.metadata()?.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
    }
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Walk the existing portion of `parent`'s ancestor chain under
/// `$HOME`, return true if any is a symlink. Matches the 1.2.0 H-8
/// anti-laundering pattern in `mcp::safe_read::path_contains_symlink`:
/// system-level ancestors above `$HOME` (macOS `/var` → `/private/var`)
/// are platform fixtures outside the attacker model and would produce
/// false positives. Intermediate non-existent components are fine —
/// `create_dir_all` materializes them as real dirs.
fn ancestor_chain_has_symlink(parent: &Path) -> bool {
    let home = match std::env::var_os("HOME") {
        Some(h) => std::path::PathBuf::from(h),
        None => return false,
    };
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return false;
    }
    if !parent.starts_with(&home) {
        return false;
    }
    let mut cur: Option<&Path> = Some(parent);
    while let Some(p) = cur {
        if !p.starts_with(&home) {
            break;
        }
        if let Ok(md) = std::fs::symlink_metadata(p) {
            if md.file_type().is_symlink() {
                return true;
            }
        }
        cur = p.parent();
        if let Some(next) = cur {
            if next == p {
                break;
            }
        }
    }
    false
}

/// The POSIX `O_NOFOLLOW` flag. Differs by OS; fallback to 0 on
/// exotic platforms (they lose symlink hardening but still build).
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

/// ANSI-strip `s` and truncate to `cap` chars with a
/// `...[truncated N chars]` marker. Use for every caller-provided
/// string field that lands in the audit log — classifier deny
/// reasons, command strings, URLs, session ids. Stripping first
/// ensures truncation never cuts an escape in half.
#[must_use]
pub fn sanitize_field(s: &str, cap: usize) -> String {
    let stripped = strip_ansi(s).into_owned();
    truncate_with_marker(&stripped, cap)
}

fn truncate_with_marker(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = s.len() - end;
    format!("{prefix}...[truncated {dropped} chars]", prefix = &s[..end])
}

/// ISO-8601 UTC timestamp to millisecond precision:
/// `2026-04-29T23:51:00.123Z`. Hand-rolled (vs. `chrono`) to avoid a
/// dep just for one formatter.
#[must_use]
pub fn iso8601_utc_now() -> String {
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
    fn civil_from_unix_known_epochs() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn iso8601_has_z_suffix_and_t_separator() {
        let s = iso8601_utc_now();
        // `YYYY-MM-DDTHH:MM:SS.mmmZ` is 24 chars.
        assert_eq!(s.len(), 24, "want `YYYY-MM-DDTHH:MM:SS.mmmZ`, got {s}");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[23..24], "Z");
    }

    #[test]
    fn sanitize_field_strips_ansi_and_caps_length() {
        let esc = "\x1b[31mred\x1b[0m";
        assert_eq!(sanitize_field(esc, 4000), "red");
        let long = "a".repeat(5000);
        let out = sanitize_field(&long, 4000);
        assert!(out.starts_with(&"a".repeat(4000)));
        assert!(out.contains("...[truncated 1000 chars]"));
    }

    /// 1.3.7 adversarial review (gemini-3.1-pro CRITICAL #1):
    /// `create_dir_all` transparently follows symlinks in any existing
    /// ancestor. Pin the anti-laundering walk so a symlinked ancestor
    /// surfaces before the audit write happens.
    ///
    /// SAFETY: mutates process-global `HOME`. Single-threaded body;
    /// prior value is restored on exit.
    #[test]
    fn ancestor_chain_has_symlink_catches_planted_ancestor() {
        let base = std::env::temp_dir().join(format!(
            "barbican-audit-io-symlink-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let fake_home = base.join("home");
        std::fs::create_dir_all(&fake_home).unwrap();
        let prior_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &fake_home);

        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = fake_home.join("planted");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let under_symlink = link.join("nested");
        assert!(
            ancestor_chain_has_symlink(&under_symlink),
            "symlinked ancestor must be caught"
        );

        let plain = fake_home.join("plain").join("nested");
        assert!(!ancestor_chain_has_symlink(&plain));

        let outside = std::path::PathBuf::from("/var/log/whatever");
        assert!(!ancestor_chain_has_symlink(&outside));

        match prior_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn truncate_respects_char_boundary() {
        // 4-byte UTF-8 codepoint (U+1F600, 😀). 4000 chars is fine;
        // truncate just-past the codepoint must not cut mid-sequence.
        let s = format!("{}😀tail", "a".repeat(3998));
        // len is 3998 + 4 + "tail".len() = 4006; cap at 4000 forces
        // truncation to backtrack from byte 4000 (mid-😀) to the
        // boundary at 3998 or 4002.
        let out = sanitize_field(&s, 4000);
        // No stray mid-utf8 bytes (serde_json would have rejected
        // otherwise when we tried to round-trip).
        assert!(String::from_utf8(out.into_bytes()).is_ok());
    }
}
