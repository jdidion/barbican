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
    let base = std::env::temp_dir().join(format!("barbican-audit-{}-{}", name, std::process::id()));
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
    assert_eq!(mode, 0o600, "audit log must be mode 0600, got {mode:o}");
}

#[test]
fn audit_log_appends_jsonl() {
    let home = tempdir("append");
    for cmd in ["ls", "pwd", "git status"] {
        let json = format!(r#"{{"tool_name":"Bash","tool_input":{{"command":"{cmd}"}}}}"#);
        assert_eq!(run_audit(&json, &home), 0);
    }
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    assert_eq!(
        contents.lines().count(),
        3,
        "expected 3 JSONL entries, got {contents:?}"
    );
    for line in contents.lines() {
        let _: serde_json::Value = serde_json::from_str(line).expect("each line parses as JSON");
    }
}

#[test]
fn audit_entry_contains_required_fields() {
    let home = tempdir("fields");
    let input = r#"{"hook_event_name":"PreToolUse","session_id":"abc123","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    assert_eq!(run_audit(input, &home), 0);
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
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
    // `echo \x1b[31mred\x1b[0m` — ESC is encoded as JSON .
    let input =
        "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"echo \\u001b[31mred\\u001b[0m\"}}";
    assert_eq!(run_audit(input, &home), 0);
    let bytes = std::fs::read(log_path(&home)).unwrap();
    assert!(
        !bytes.contains(&0x1b),
        "ANSI ESC (0x1b) must not appear in the written log; got bytes {bytes:?}"
    );
}

#[test]
fn audit_log_strips_ansi_from_nested_string_fields() {
    let home = tempdir("nested");
    let input = "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"x\",\"description\":\"\\u001b[2K clobber\"}}";
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
    let input = "{\"session_id\":\"\\u001b[31mid\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"x\"}}";
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

// ---------------------------------------------------------------------
// Phase-6 /crew:review regression tests.
// ---------------------------------------------------------------------

// ---- CRITICAL C1: symlink-follow on audit.log path ----
// Claude + GPT + Gemini all flagged.

#[test]
fn audit_rejects_pre_existing_symlink_at_log_path() {
    let home = tempdir("symlink_attack");
    let log_dir = home.join(".claude").join("barbican");
    std::fs::create_dir_all(&log_dir).unwrap();
    // Plant a target file that the symlink will point at.
    let target =
        std::env::temp_dir().join(format!("barbican-symlink-target-{}", std::process::id()));
    std::fs::write(&target, b"pre-existing content\n").unwrap();
    let before = std::fs::read(&target).unwrap();
    // Symlink audit.log -> target.
    std::os::unix::fs::symlink(&target, log_dir.join("audit.log")).unwrap();

    // Run the hook.
    assert_eq!(
        run_audit(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            &home
        ),
        0,
    );

    // The symlink target must be UNCHANGED — the hook must refuse to
    // follow symlinks when opening the log file.
    let after = std::fs::read(&target).unwrap();
    assert_eq!(
        after, before,
        "symlink target was modified; O_NOFOLLOW not enforced"
    );
    // Cleanup.
    let _ = std::fs::remove_file(&target);
}

// ---- CRITICAL C2: JSON object keys not sanitized ----
// Defense in depth — the JSON serializer escapes ESC today, but if a
// consumer decodes the JSONL and displays the key, ESC renders.

#[test]
fn audit_log_sanitizes_object_keys() {
    let home = tempdir("keys");
    let input = "{\"tool_name\":\"Bash\",\"tool_input\":\
                 {\"\\u001b[31mevilkey\":\"v\",\"command\":\"ls\"}}";
    assert_eq!(run_audit(input, &home), 0);
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
    // The original key contained ESC; after sanitization the key must
    // have no ESC char when the JSON is *decoded*.
    let input_map = entry["input"].as_object().unwrap();
    for key in input_map.keys() {
        assert!(
            !key.contains('\x1b'),
            "object key still contains ESC after sanitize: {key:?}"
        );
    }
}

// ---- CRITICAL C3: non-string top-level fields preserved verbatim ----

#[test]
fn audit_log_sanitizes_nonstring_top_level_fields() {
    let home = tempdir("topnonstr");
    // session_id as an object with ESC in a string value.
    let input = "{\"session_id\":{\"nested\":\"\\u001b[31mboom\"},\
                 \"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}";
    assert_eq!(run_audit(input, &home), 0);
    let contents = std::fs::read_to_string(log_path(&home)).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
    // The decoded session field must not contain ESC anywhere in its
    // rendered form.
    let session_text = entry["session"].to_string();
    assert!(
        !session_text.contains('\x1b'),
        "top-level non-string session was not sanitized: {session_text}"
    );
}

// ---- WARNING W1: unbounded stdin is a DoS surface ----

#[test]
fn audit_hook_rejects_huge_stdin_without_oom() {
    let home = tempdir("bigstdin");
    // 50 MB should be well above our 8 MB cap. Must return quickly
    // without allocating the whole stream. The hook will read up to
    // the cap and close stdin, which can surface as EPIPE on the
    // writing side — tolerate that; what we care about is exit code.
    let bin = env!("CARGO_BIN_EXE_barbican");
    let mut child = std::process::Command::new(bin)
        .arg("audit")
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn barbican audit");
    let huge = "A".repeat(50 * 1024 * 1024);
    let input = format!("{{\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"{huge}\"}}}}");
    let start = std::time::Instant::now();
    // Ignore EPIPE — the hook legitimately closes stdin after the cap.
    let _ = child.stdin.as_mut().unwrap().write_all(input.as_bytes());
    let code = child.wait().expect("wait").code().unwrap_or(-1);
    let elapsed = start.elapsed();
    assert_eq!(code, 0);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "50MB stdin took {elapsed:?} (expected <5s)"
    );
}

// ---- WARNING W2: parent dir created with umask, not 0o700 ----

#[test]
fn audit_log_parent_dir_is_0700() {
    let home = tempdir("dirperm");
    assert_eq!(
        run_audit(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            &home
        ),
        0,
    );
    let parent = log_path(&home).parent().unwrap().to_path_buf();
    let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "~/.claude/barbican dir must be 0o700, got {mode:o}"
    );
}

// ---- WARNING W3: relative HOME silently writes into cwd ----

#[test]
fn audit_hook_refuses_relative_home() {
    // If HOME is "." or a relative path, the hook must skip logging
    // rather than writing under the current working dir.
    let bin = env!("CARGO_BIN_EXE_barbican");
    let cwd_before: Vec<_> = std::fs::read_dir(std::env::current_dir().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let mut child = std::process::Command::new(bin)
        .arg("audit")
        .env("HOME", "./relative-home-should-be-rejected")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#)
        .unwrap();
    let code = child.wait().unwrap().code().unwrap_or(-1);
    assert_eq!(code, 0);
    // Nothing new in the cwd.
    let cwd_after: Vec<_> = std::fs::read_dir(std::env::current_dir().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(cwd_before, cwd_after, "relative HOME leaked log into cwd");
}

// ---- WARNING W5: chmod failure must prevent write ----

#[test]
fn audit_log_tightens_pre_existing_wide_perms() {
    let home = tempdir("wideperm");
    let log = log_path(&home);
    let parent = log.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&parent).unwrap();
    // Pre-create log at 0644 so the hook must tighten it.
    std::fs::write(&log, b"pre-existing\n").unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        run_audit(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
            &home
        ),
        0,
    );
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "pre-existing wide-perm log must be tightened to 0o600; got {mode:o}"
    );
}

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
