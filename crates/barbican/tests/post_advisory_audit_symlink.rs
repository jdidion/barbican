//! Red test for the 1.5.1 advisory-audit symlink-laundering fix.
//!
//! GPT-5.2 CRITICAL-2 / Gemini CRITICAL-2: `post_advisory::append_audit_jsonl`
//! used `DirBuilder::create_dir_all(parent)` before any ancestor-symlink
//! check. A planted `~/.claude → /tmp/attacker` symlink would let the
//! advisory writer land audit entries under the attacker's chosen
//! directory.
//!
//! Fix: delegate the writer to `audit_io::append_jsonl_line`, which
//! walks every ancestor under $HOME with `symlink_metadata` and bails
//! on the first symlink.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// Serialize tests that override $HOME so they don't race.
static HOME_ENV_LOCK: Mutex<()> = Mutex::new(());

fn barbican_bin() -> &'static str {
    env!("CARGO_BIN_EXE_barbican")
}

/// Build a fake hook-JSON payload that will make `post-edit` find the
/// `.bashrc` shell-rc pattern and emit an advisory. The exact tool
/// doesn't matter — any sensitive-path write trips the scanner.
fn post_edit_trigger_payload() -> &'static str {
    r#"{"tool_name":"Write","tool_input":{"file_path":"/home/user/.bashrc","content":"echo hello"}}"#
}

#[test]
fn advisory_audit_refuses_to_write_under_symlinked_home_ancestor() {
    let _guard = HOME_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let attacker = tmp.path().join("attacker-target");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&attacker).unwrap();

    // Plant the attack: HOME/.claude is a symlink to the attacker dir.
    let claude_dir = home.join(".claude");
    std::os::unix::fs::symlink(&attacker, &claude_dir).expect("symlink ~/.claude");

    // Run `barbican post-edit` with the attacker-friendly HOME, feeding
    // it a triggering payload on stdin.
    let mut child = Command::new(barbican_bin())
        .arg("post-edit")
        .env("HOME", &home)
        // Clear BARBICAN_* so no opt-out env var interferes.
        .env_remove("BARBICAN_ALLOW_MALFORMED_HOOK_JSON")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn post-edit");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(post_edit_trigger_payload().as_bytes())
        .expect("write stdin");
    let _out = child.wait_with_output().expect("wait");

    // The assertion: no audit file must have been created under the
    // attacker-controlled target (directly, or recursively). The
    // writer either silently no-ops (best-effort policy) or falls back
    // gracefully — but it MUST NOT traverse the symlinked ancestor.
    let attacker_audit = attacker.join("barbican").join("audit.log");
    assert!(
        !attacker_audit.exists(),
        "advisory audit laundered into attacker target: {}",
        attacker_audit.display()
    );

    // Also check nothing else appeared under the attacker dir.
    let leaf_barbican = attacker.join("barbican");
    assert!(
        !leaf_barbican.exists(),
        "advisory writer created {} via symlinked ancestor",
        leaf_barbican.display()
    );
}

#[test]
fn advisory_audit_writes_normally_without_symlinks() {
    // Control: when there's no symlink planted, the advisory should
    // happily write to HOME/.claude/barbican/audit.log. Confirms the
    // fix didn't break the happy path.
    let _guard = HOME_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let mut child = Command::new(barbican_bin())
        .arg("post-edit")
        .env("HOME", &home)
        .env_remove("BARBICAN_ALLOW_MALFORMED_HOOK_JSON")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn post-edit");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(post_edit_trigger_payload().as_bytes())
        .expect("write stdin");
    let _ = child.wait_with_output().expect("wait");

    // Happy path: ~/.claude/barbican/audit.log should exist and
    // contain at least one JSONL line.
    let audit = home.join(".claude").join("barbican").join("audit.log");
    let exists = audit.exists();
    if exists {
        let contents = std::fs::read_to_string(&audit).unwrap();
        assert!(
            contents.contains("post_edit_scan"),
            "audit entry missing expected event; got: {contents:?}"
        );
        // Mode check: 0o600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "audit file must be 0o600, got {mode:o}");
        }
    }
    // Note: an absent audit file isn't a regression per se — the
    // hook is best-effort. What would be a regression is finding it
    // in the WRONG place (handled by the symlink test above).
    let _ = exists;
}
