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

/// Max UTF-8 bytes any single string field is allowed to reach
/// before truncation. Matches the hook's historical cap (Narthex
/// parity).
///
/// 1.5.5 GPT-5.2 review: pre-1.5.5 this was named `MAX_STRING_CHARS`
/// and documentation said "chars". The implementation has always
/// measured in bytes (`s.len()`), with a trailing char-boundary
/// backtrack to preserve UTF-8 validity. Renamed for accuracy and
/// so a future reviewer doesn't "fix" the code to match the stale
/// name. The on-disk cap is unchanged (4000 bytes).
pub const MAX_STRING_BYTES: usize = 4000;

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
                // Best-effort tighten to 0o700 (defense-in-depth L2). If
                // this silently failed — e.g. parent is on a filesystem
                // that doesn't honor POSIX perms, or the running user
                // doesn't own it — the advertised `0o700` guarantee would
                // be weakened without operators knowing. Surface the
                // failure via `tracing::warn!` so it shows up in the
                // session log. The write still proceeds because the
                // other security properties (leaf mode 0o600,
                // O_NOFOLLOW, ancestor-symlink rejection) still hold.
                if let Err(e) =
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                {
                    tracing::warn!(
                        parent = %parent.display(),
                        error = %e,
                        "barbican audit: failed to tighten parent directory permissions to 0o700 \
                         — log write proceeds (leaf mode 0o600 + O_NOFOLLOW still enforced), \
                         but directory listings may be readable by other users on this host",
                    );
                }
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

/// The POSIX `O_NOFOLLOW` flag. Delegates to `libc` so the per-OS
/// value stays correct across platforms; the previous hand-rolled
/// constant duplicated libc's values and risked drifting on any
/// target we hadn't thought about. Non-unix targets get `0` (they
/// lose symlink hardening but still build).
const fn o_nofollow() -> i32 {
    #[cfg(unix)]
    {
        libc::O_NOFOLLOW
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// ANSI-strip `s` and truncate to `cap` UTF-8 bytes with a
/// `...[truncated N bytes]` marker. Use for every caller-provided
/// string field that lands in the audit log — classifier deny
/// reasons, command strings, URLs, session ids. Stripping first
/// ensures truncation never cuts an escape in half. Truncation
/// backtracks from `cap` to the preceding UTF-8 char boundary so
/// the output is always valid UTF-8.
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
    format!("{prefix}...[truncated {dropped} bytes]", prefix = &s[..end])
}

/// Anomaly marker emitted when the wall clock reports a pre-1970 time.
/// RFC3339-shaped year `0000` + `-CLOCK_ANOMALY` suffix so forensic
/// readers can grep `^0000` and downstream parsers expecting a normal
/// 24-char timestamp will fail-loud rather than silently accepting a
/// frozen 1970-01-01 record. Length is intentionally different from
/// the normal-path 24 chars.
pub const CLOCK_ANOMALY_MARKER: &str = "0000-00-00T00:00:00.000Z-CLOCK_ANOMALY";

/// ISO-8601 UTC timestamp to millisecond precision:
/// `2026-04-29T23:51:00.123Z`. Hand-rolled (vs. `chrono`) to avoid a
/// dep just for one formatter.
///
/// Returns [`CLOCK_ANOMALY_MARKER`] (a distinct 40-char string) when the
/// system clock reports a pre-1970 time. Callers / log parsers must
/// therefore accept both the normal 24-char shape *and* the anomaly
/// marker; a fixed-width length check would be wrong.
#[must_use]
pub fn iso8601_utc_now() -> String {
    iso8601_utc_from(SystemTime::now())
}

/// Testable core of [`iso8601_utc_now`]. Takes an explicit `SystemTime`
/// so the anomaly-marker path (clock before `UNIX_EPOCH`) can be
/// exercised without rolling the system clock back.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "year/month/day/hour/minute/second are the canonical single-letter names for the civil-from-unix tuple"
)]
pub(crate) fn iso8601_utc_from(t: SystemTime) -> String {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(now) => {
            let secs = now.as_secs();
            let millis = now.subsec_millis();
            let (y, mo, d, h, mi, s) = civil_from_unix(secs);
            format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
        }
        Err(_) => CLOCK_ANOMALY_MARKER.to_string(),
    }
}

/// Split a Unix timestamp into `(year, month, day, hour, minute,
/// second)` in UTC. Based on Howard Hinnant's civil-date algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>).
///
/// Casts here are all provably safe because the algorithm floors each
/// intermediate value into a sub-u32 range before the cast fires. A
/// blanket `#[allow]` was attached on the function previously; each
/// cast now carries its own justification so a future reader sees
/// exactly why the truncation is fine.
fn civil_from_unix(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days_since_epoch = i64::try_from(secs / 86_400).unwrap_or(0);
    // `secs % 86_400` is in `0..86_400`, which fits in u32 (max 86_399).
    #[allow(
        clippy::cast_possible_truncation,
        reason = "secs % 86_400 is bounded to 0..86_400, fits in u32"
    )]
    let secs_in_day = (secs % 86_400) as u32;
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day / 60) % 60;
    let second = secs_in_day % 60;

    let shifted = days_since_epoch + 719_468;
    let era = shifted.div_euclid(146_097);
    // `rem_euclid(146_097)` is always in `0..146_097`, which fits in u32.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "rem_euclid(146_097) is bounded to 0..146_097, fits in u32 and is non-negative"
    )]
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
        // Normal-path shape: `YYYY-MM-DDTHH:MM:SS.mmmZ` = 24 chars. The
        // function may also return `CLOCK_ANOMALY_MARKER` (40 chars) if
        // the wall clock is pre-1970; tolerate either so a host with a
        // skewed clock doesn't flake this test (the anomaly path has
        // its own dedicated test below).
        if s == CLOCK_ANOMALY_MARKER {
            return;
        }
        assert_eq!(s.len(), 24, "want `YYYY-MM-DDTHH:MM:SS.mmmZ`, got {s}");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[23..24], "Z");
    }

    #[test]
    fn iso8601_from_pre_epoch_emits_clock_anomaly_marker() {
        // Exercise the Err(_) arm by feeding a SystemTime known to be
        // before UNIX_EPOCH. This is the 1.5.4 Rust-expert finding:
        // before 1.5.4 the function used `.unwrap_or_default()` and
        // silently produced `1970-01-01T00:00:00.000Z` on clock
        // rollback. Now it emits the anomaly marker.
        let pre_epoch = SystemTime::UNIX_EPOCH - std::time::Duration::from_hours(1);
        assert_eq!(iso8601_utc_from(pre_epoch), CLOCK_ANOMALY_MARKER);
        // Anomaly marker is intentionally a different length from the
        // normal 24-char timestamp, so any downstream parser doing a
        // fixed-width length check fails loud on the anomaly path
        // rather than silently treating it as a normal record.
        assert_ne!(CLOCK_ANOMALY_MARKER.len(), 24);
        // Forensic grep affordance: starts with "0000" so `^0000` hits.
        assert!(CLOCK_ANOMALY_MARKER.starts_with("0000"));
        assert!(CLOCK_ANOMALY_MARKER.ends_with("-CLOCK_ANOMALY"));
    }

    #[test]
    fn iso8601_from_known_epoch_matches_expected_format() {
        // 2024-02-29T00:00:00.000Z — a leap day, catches civil_from_unix
        // regressions through the public function.
        // 2024-02-29 00:00 UTC is 474_768 hours after UNIX_EPOCH; the
        // `from_hours` form reads cleaner than the equivalent second
        // count. clippy's `duration_suboptimal_units` surfaced this.
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_hours(474_768);
        assert_eq!(iso8601_utc_from(t), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn sanitize_field_strips_ansi_and_caps_length() {
        let esc = "\x1b[31mred\x1b[0m";
        assert_eq!(sanitize_field(esc, 4000), "red");
        let long = "a".repeat(5000);
        let out = sanitize_field(&long, 4000);
        assert!(out.starts_with(&"a".repeat(4000)));
        assert!(out.contains("...[truncated 1000 bytes]"));
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
