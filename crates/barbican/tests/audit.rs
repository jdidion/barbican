//! Integration tests for `barbican audit` — the PostToolUse hook that
//! records every tool call to ~/.claude/barbican/audit.log as JSONL.
//!
//! Audit findings:
//! - **L1**: strip ANSI CSI escape sequences from all string fields
//!   before writing to the log. Command strings are attacker-
//!   controllable and we don't want them to rewrite the terminal
//!   when a human `less`es the log.
//! - **L2**: create the log file with explicit mode `0o600`. Never
//!   rely on umask — the log may contain tokens in URL queries.
//!
//! Also: never block the session. Any failure in the logger exits 0
//! (the parent tool call proceeds regardless).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Run `barbican audit` with a temp `$HOME` so we don't touch the
/// user's real `~/.claude/barbican/audit.log`.
fn run_audit(stdin_json: &str, home: &std::path::Path) -> i32 {
    let bin = env!("CARGO_BIN_EXE_barbican");
    let mut child = Command::new(bin)
        .arg("audit")
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn barbican audit");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_json.as_bytes())
        .unwrap();
    child
        .wait()
        .expect("barbican audit did not exit")
        .code()
        .unwrap_or(-1)
}

fn log_path(home: &std::path::Path) -> PathBuf {
    home.join(".claude").join("barbican").join("audit.log")
}

fn tempdir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "barbican-audit-{}-{}",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

#[test]
fn audit_hook_exits_zero_even_when_home_is_read_only() {
    // The audit hook MUST NOT fail a tool call even if it can't write
    // the log. Point HOME at `/dev/null`-ish so any write will fail.
    assert_eq!(
        run_audit(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            std::path::Path::new("/nonexistent/barbican/audit")
        ),
        0,
    );
}

#[test]
fn audit_hook_exits_zero_on_empty_stdin() {
    let home = tempdir("empty");
    assert_eq!(run_audit("", &home), 0);
}

#[test]
fn audit_hook_exits_zero_on_garbage_stdin() {
    let home = tempdir("garbage");
    assert_eq!(run_audit("not json {{{", &home), 0);
}

#[test]
fn audit_log_created_with_mode_0600() {
    let home = tempdir("mode");
    assert_eq!(
        run_audit(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            &home
        ),
        0,
    );
    let log = log_path(&home);
    assert!(log.exists(), "log file should be created at {log:?}");
    let meta = std::fs::metadata(&log).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "audit log must be mode 0600, got {:o}",
        mode
    );
}

#[test]
fn audit_log_appends_jsonl() {
    let home = tempdir("append");
    for cmd in ["ls", "pwd", "git status"] {
        let json = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":"{cmd}"}}}}"#
        );
        assert_eq!(run_audit(&json, &home), 0);
    }
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    assert_eq!(
        contents.lines().count(),
        3,
        "expected 3 JSONL entries, got {:?}",
        contents
    );
    for line in contents.lines() {
        let _: serde_json::Value =
            serde_json::from_str(line).expect("each line parses as JSON");
    }
}

#[test]
fn audit_entry_contains_required_fields() {
    let home = tempdir("fields");
    let input = r#"{"hook_event_name":"PreToolUse","session_id":"abc123","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    assert_eq!(run_audit(input, &home), 0);
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    let entry: serde_json::Value =
        serde_json::from_str(contents.trim()).unwrap();
    assert!(entry.get("ts").is_some(), "ts missing: {entry}");
    assert_eq!(entry["event"], "PreToolUse");
    assert_eq!(entry["tool"], "Bash");
    assert_eq!(entry["session"], "abc123");
    assert_eq!(entry["cwd"], "/tmp");
    assert_eq!(entry["input"]["command"], "ls");
}

// ---------------------------------------------------------------------
// L1 — ANSI escape stripping.
// ---------------------------------------------------------------------

#[test]
fn audit_log_strips_ansi_escapes_from_command() {
    let home = tempdir("ansi");
    // `echo \x1b[31mred\x1b[0m` — ESC is encoded as JSON .
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo [31mred[0m"}}"#;
    assert_eq!(run_audit(input, &home), 0);
    let bytes = std::fs::read(log_path(&home)).unwrap();
    assert!(
        !bytes.contains(&0x1b),
        "ANSI ESC (0x1b) must not appear in the written log; got bytes {:?}",
        bytes
    );
}

#[test]
fn audit_log_strips_ansi_from_nested_string_fields() {
    let home = tempdir("nested");
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"x","description":"[2K clobber"}}"#;
    assert_eq!(run_audit(input, &home), 0);
    let bytes = std::fs::read(log_path(&home)).unwrap();
    assert!(
        !bytes.contains(&0x1b),
        "nested string fields must also be ANSI-stripped"
    );
}

#[test]
fn audit_log_strips_ansi_from_session_id() {
    // Attacker-controllable-ish — ensure top-level strings sanitize too.
    let home = tempdir("topstr");
    let input = r#"{"session_id":"[31mid","tool_name":"Bash","tool_input":{"command":"x"}}"#;
    assert_eq!(run_audit(input, &home), 0);
    let bytes = std::fs::read(log_path(&home)).unwrap();
    assert!(!bytes.contains(&0x1b));
}

// ---------------------------------------------------------------------
// Payload truncation (Narthex parity — 4000 char cap per string field).
// ---------------------------------------------------------------------

#[test]
fn audit_log_truncates_very_long_strings() {
    let home = tempdir("trunc");
    let huge = "A".repeat(6000);
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": huge.clone() }
    });
    assert_eq!(run_audit(&input.to_string(), &home), 0);
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
    let logged_cmd = entry["input"]["command"].as_str().unwrap();
    assert!(
        logged_cmd.len() < huge.len(),
        "command should have been truncated; got {} chars",
        logged_cmd.len()
    );
    assert!(
        logged_cmd.contains("truncated"),
        "truncation marker should appear, got: {logged_cmd}"
    );
}

// ---------------------------------------------------------------------
// Log directory auto-creation.
// ---------------------------------------------------------------------

#[test]
fn audit_hook_creates_log_directory_if_missing() {
    let home = tempdir("mkdir");
    // Do not pre-create the .claude/barbican dir — the hook must mkdir.
    assert_eq!(
        run_audit(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            &home
        ),
        0,
    );
    assert!(log_path(&home).exists());
}
