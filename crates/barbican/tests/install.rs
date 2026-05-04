//! Integration tests for `barbican install` / `barbican uninstall`.
//!
//! These are the port of Narthex's `install.py` / `uninstall.py` with
//! the following hardenings:
//! - All writes go through `0o600` create-and-rename, never a naive
//!   open-truncate (CLAUDE.md rule 6).
//! - Install is idempotent: re-running adds nothing new.
//! - Backups are made exactly once per config file, matching the
//!   `*.pre-barbican` suffix.
//! - Uninstall strips only Barbican-owned entries — users' custom
//!   allow/ask/hook rules survive round-trips.
//! - `--dry-run` never touches the filesystem.

use std::fs;
use std::path::{Path, PathBuf};

use barbican::installer::{self, InstallOptions, UninstallOptions};
use serde_json::json;

/// Build a fresh `$HOME` under a tempdir that looks like a Claude Code
/// install: `~/.claude/` exists and is empty. Returns (tempdir,
/// claude_home_path). Drop the tempdir to clean up.
fn fake_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let claude_home = dir.path().join(".claude");
    fs::create_dir_all(&claude_home).expect("mkdir .claude");
    (dir, claude_home)
}

fn read_json(path: &Path) -> serde_json::Value {
    let s = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

/// Default install options pointing at the given claude_home; the
/// binary source defaults to a dummy path so tests don't copy Cargo's
/// real build output. Use `.with_binary_source(...)` to override for
/// copy-path tests.
fn opts(claude_home: &Path) -> InstallOptions {
    // A synthetic "binary" — in reality just a file whose contents we
    // can inspect after install copies it.
    let src = claude_home.parent().unwrap().join("fake-barbican-bin");
    fs::write(&src, b"#!/bin/sh\necho barbican-dummy\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&src).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&src, perms).unwrap();
    }

    InstallOptions {
        claude_home: claude_home.to_path_buf(),
        binary_source: src,
        dry_run: false,
    }
}

// ---------------------------------------------------------------------
// Happy path — first-time install.
// ---------------------------------------------------------------------

#[test]
fn install_creates_barbican_dir_and_copies_binary() {
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");

    let binary = home.join("barbican").join("barbican");
    assert!(binary.is_file(), "binary should be copied to {binary:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&binary).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "binary must be executable (0o755), got {mode:o}"
        );
    }
}

#[test]
fn install_writes_settings_with_allow_ask_hooks() {
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");
    let settings = read_json(&home.join("settings.json"));

    let allow = settings["permissions"]["allow"].as_array().unwrap();
    assert!(
        allow.iter().any(|v| v == "mcp__barbican"),
        "mcp__barbican must be in allow list: {allow:?}"
    );
    assert!(
        allow.len() >= 15,
        "want ≥15 allow entries, got {}",
        allow.len()
    );

    let ask = settings["permissions"]["ask"].as_array().unwrap();
    assert!(
        ask.iter().any(|v| v == "Bash(curl:*)"),
        "Bash(curl:*) must be in ask list: {ask:?}"
    );
    assert!(ask.len() >= 11, "want ≥11 ask entries, got {}", ask.len());

    // Four hook entries, each pointing at ~/.claude/barbican/barbican.
    let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
    let post = settings["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 1, "want 1 PreToolUse entry");
    assert_eq!(
        post.len(),
        3,
        "want 3 PostToolUse entries (audit, mcp scanner, edit scanner)"
    );

    let bin = home.join("barbican").join("barbican");
    let bin_str = bin.to_string_lossy();
    for entry in pre.iter().chain(post.iter()) {
        let cmd = entry["hooks"][0]["command"].as_str().unwrap();
        assert!(
            cmd.starts_with(bin_str.as_ref()),
            "hook command must invoke installed binary; got: {cmd}"
        );
    }
}

#[test]
fn install_registers_mcp_server_in_claude_json() {
    let (dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");

    let claude_json = dir.path().join(".claude.json");
    assert!(
        claude_json.exists(),
        "~/.claude.json should exist after install"
    );

    let cfg = read_json(&claude_json);
    let server = &cfg["mcpServers"]["barbican"];
    assert_eq!(
        server["command"].as_str().unwrap(),
        home.join("barbican").join("barbican").to_string_lossy()
    );
    assert_eq!(server["args"][0], "mcp-serve");
}

// ---------------------------------------------------------------------
// Idempotency.
// ---------------------------------------------------------------------

#[test]
fn install_twice_is_idempotent() {
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install #1");
    let settings_v1 = read_json(&home.join("settings.json"));

    installer::install(&opts(&home)).expect("install #2");
    let settings_v2 = read_json(&home.join("settings.json"));

    assert_eq!(
        settings_v1, settings_v2,
        "second install must not add duplicates"
    );
}

// ---------------------------------------------------------------------
// Backups: created once, never overwritten.
// ---------------------------------------------------------------------

#[test]
fn backup_created_on_first_install_and_preserved_on_second() {
    let (dir, home) = fake_home();
    // Seed a settings.json with a user's own custom rule.
    let original = json!({
        "permissions": { "allow": ["MyCustomRule"], "ask": [] },
        "hooks": {}
    });
    write_json(&home.join("settings.json"), &original);

    installer::install(&opts(&home)).expect("install #1");

    let backup = home.join("settings.json.pre-barbican");
    assert!(
        backup.exists(),
        "first install should back up settings.json"
    );
    let backup_v1 = read_json(&backup);
    assert_eq!(backup_v1, original, "backup must contain pre-install data");

    // Simulate the user editing settings.json between installs.
    // The backup must NOT get overwritten by the second install — it
    // must continue to reflect the PRE-FIRST-INSTALL state.
    let after = read_json(&home.join("settings.json"));
    // Mutate file contents AFTER install #1.
    write_json(&home.join("settings.json"), &after); // no-op but touches mtime
    installer::install(&opts(&home)).expect("install #2");

    let backup_v2 = read_json(&backup);
    assert_eq!(
        backup_v2, original,
        "second install must NOT overwrite the original backup"
    );
    // Also ~/.claude.json should have one, if it existed.
    drop(dir);
}

#[test]
fn install_preserves_user_custom_allow_rules() {
    let (_dir, home) = fake_home();
    let original = json!({
        "permissions": {
            "allow": ["MyCustomRule", "WebFetch(domain:example.com)"],
            "ask": ["MyAskRule"]
        },
        "hooks": {}
    });
    write_json(&home.join("settings.json"), &original);

    installer::install(&opts(&home)).expect("install");

    let settings = read_json(&home.join("settings.json"));
    let allow = settings["permissions"]["allow"].as_array().unwrap();
    assert!(
        allow.iter().any(|v| v == "MyCustomRule"),
        "user's custom allow rule must survive: {allow:?}"
    );
    assert!(
        allow.iter().any(|v| v == "WebFetch(domain:example.com)"),
        "user's custom WebFetch rule must survive: {allow:?}"
    );
    let ask = settings["permissions"]["ask"].as_array().unwrap();
    assert!(
        ask.iter().any(|v| v == "MyAskRule"),
        "user's custom ask rule must survive: {ask:?}"
    );
}

// ---------------------------------------------------------------------
// File permissions: all config writes mode 0o600.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn config_files_written_with_mode_0o600() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");

    for path in [home.join("settings.json"), dir.path().join(".claude.json")] {
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "config file {path:?} must be mode 0o600 (got {mode:o})"
        );
    }
}

// ---------------------------------------------------------------------
// --dry-run: no filesystem changes.
// ---------------------------------------------------------------------

#[test]
fn dry_run_install_writes_nothing() {
    let (dir, home) = fake_home();
    let mut o = opts(&home);
    o.dry_run = true;

    installer::install(&o).expect("dry-run install");

    assert!(
        !home.join("barbican").exists(),
        "dry run must not create barbican/"
    );
    assert!(
        !home.join("settings.json").exists(),
        "dry run must not write settings.json"
    );
    assert!(
        !dir.path().join(".claude.json").exists(),
        "dry run must not write ~/.claude.json"
    );
}

// ---------------------------------------------------------------------
// Missing ~/.claude is a clear error.
// ---------------------------------------------------------------------

#[test]
fn missing_claude_home_errors_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope/.claude");
    let src = dir.path().join("fake-bin");
    fs::write(&src, b"dummy").unwrap();

    let err = installer::install(&InstallOptions {
        claude_home: missing,
        binary_source: src,
        dry_run: false,
    })
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Claude Code") || msg.contains("not found"),
        "want clear missing-home error; got: {msg}"
    );
}

// ---------------------------------------------------------------------
// Uninstall.
// ---------------------------------------------------------------------

#[test]
fn uninstall_strips_barbican_entries_and_preserves_user_rules() {
    let (_dir, home) = fake_home();
    let original = json!({
        "permissions": {
            "allow": ["MyCustomRule"],
            "ask": ["MyAskRule"]
        },
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "/opt/my-own-tool check"}]
            }]
        }
    });
    write_json(&home.join("settings.json"), &original);

    installer::install(&opts(&home)).expect("install");
    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: false,
        keep_files: false,
    })
    .expect("uninstall");

    let settings = read_json(&home.join("settings.json"));
    let allow = settings["permissions"]["allow"].as_array().unwrap();
    let ask = settings["permissions"]["ask"].as_array().unwrap();
    assert!(
        allow.iter().any(|v| v == "MyCustomRule"),
        "user's custom allow must survive uninstall: {allow:?}"
    );
    assert!(
        !allow.iter().any(|v| v == "mcp__barbican"),
        "mcp__barbican must be gone: {allow:?}"
    );
    assert!(
        ask.iter().any(|v| v == "MyAskRule"),
        "user's custom ask must survive: {ask:?}"
    );

    let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
    assert!(
        pre.iter().any(|entry| entry["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("my-own-tool")),
        "user's own PreToolUse hook must survive: {pre:?}"
    );
    assert!(
        !pre.iter().any(|entry| entry["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("barbican/barbican")),
        "barbican hook must be stripped: {pre:?}"
    );
}

#[test]
fn uninstall_removes_mcp_server_entry() {
    let (dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");
    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: false,
        keep_files: false,
    })
    .expect("uninstall");

    let cfg = read_json(&dir.path().join(".claude.json"));
    let servers = &cfg["mcpServers"];
    assert!(
        servers.get("barbican").is_none(),
        "barbican entry must be removed: {servers:?}"
    );
}

#[test]
fn uninstall_removes_barbican_dir_by_default() {
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");
    assert!(home.join("barbican").is_dir());

    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: false,
        keep_files: false,
    })
    .expect("uninstall");

    assert!(
        !home.join("barbican").exists(),
        "~/.claude/barbican/ must be removed on uninstall"
    );
}

#[test]
fn uninstall_keep_files_preserves_binary_dir() {
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");

    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: false,
        keep_files: true,
    })
    .expect("uninstall --keep-files");

    assert!(
        home.join("barbican").join("barbican").is_file(),
        "--keep-files must leave the binary on disk"
    );
    // Hooks must be unwired. After pruning, the `hooks` key is gone
    // entirely (no user-owned hooks remained); the key absence IS
    // the unwiring.
    let settings = read_json(&home.join("settings.json"));
    let pre = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        pre.iter().all(|entry| {
            entry["hooks"][0]["command"]
                .as_str()
                .is_none_or(|c| !c.contains("barbican/barbican"))
        }),
        "--keep-files must still unwire barbican hooks: {pre:?}"
    );
}

#[test]
fn uninstall_dry_run_writes_nothing() {
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");

    let settings_before = read_json(&home.join("settings.json"));

    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: true,
        keep_files: false,
    })
    .expect("uninstall --dry-run");

    assert!(
        home.join("barbican").is_dir(),
        "dry-run must not delete dir"
    );
    let settings_after = read_json(&home.join("settings.json"));
    assert_eq!(
        settings_before, settings_after,
        "dry-run must not modify settings.json"
    );
}

#[test]
fn uninstall_missing_claude_home_errors_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope/.claude");
    let err = installer::uninstall(&UninstallOptions {
        claude_home: missing,
        dry_run: false,
        keep_files: false,
    })
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not found") || msg.contains("Claude Code"),
        "want clear error; got: {msg}"
    );
}

// ---------------------------------------------------------------------
// Atomic writes — no torn config even on interrupted run.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn install_never_leaves_partial_config_file() {
    // Smoke test: after a successful install, settings.json exists and
    // parses. The real atomic-rename guarantee lives in the installer
    // implementation; this test only pins the post-condition.
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");
    let settings = home.join("settings.json");
    assert!(settings.is_file());
    let _parsed = read_json(&settings);

    // No stray temp files sitting around.
    for entry in fs::read_dir(&home).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.contains(".tmp") && !name.contains(".swp"),
            "stray temp file left: {name}"
        );
    }
}

// ---------------------------------------------------------------------
// Phase-11 adversarial-review regression tests.
// ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn stale_pid_scoped_temp_symlink_is_refused() {
    // HIGH: write_json_mode_0600 used O_CREAT+O_TRUNC. Now it uses
    // `create_new(true) + O_NOFOLLOW` against a PID-scoped tmp path.
    // A leftover symlink at exactly that PID's path (planted by a
    // prior crashed run that happened to share the same PID, or by
    // an attacker with pid-guessing) must cause the install to
    // refuse rather than follow.
    let (_dir, home) = fake_home();
    fs::write(home.join("settings.json"), "{}").unwrap();

    let bait_dir = tempfile::tempdir().unwrap();
    let bait = bait_dir.path().join("victim");
    fs::write(&bait, "pre-existing bait data").unwrap();
    // Plant a symlink at the exact PID-scoped tmp the installer is
    // about to use this run. This is a same-process test harness, so
    // the PID matches.
    let tmp = home.join(format!("settings.json.barbican-tmp.{}", std::process::id()));
    std::os::unix::fs::symlink(&bait, &tmp).unwrap();

    let err = installer::install(&opts(&home)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("stale") || msg.contains("AlreadyExists") || msg.contains("already exists"),
        "installer must refuse to write through a stale temp symlink; got: {msg}"
    );
    // Bait file must remain unchanged — symlink was not followed.
    let bait_contents = fs::read_to_string(&bait).unwrap();
    assert_eq!(
        bait_contents, "pre-existing bait data",
        "bait file must not be overwritten"
    );
}

#[cfg(unix)]
#[test]
fn torn_backup_from_prior_crash_is_detected_not_reused() {
    // HIGH: fs::copy for the backup was not atomic; a truncated
    // `.pre-barbican` from a killed prior run was silently reused.
    // Seed a plausibly-torn backup and verify the installer either
    // repairs it (re-copies the current source) or errors clearly.
    let (_dir, home) = fake_home();
    let settings = home.join("settings.json");
    let backup = home.join("settings.json.pre-barbican");
    let pristine = r#"{"permissions":{"allow":["MyRule"],"ask":[]}}"#;
    fs::write(&settings, pristine).unwrap();
    // Truncated prefix that parses as invalid JSON.
    fs::write(&backup, "{\"permi").unwrap();

    // Install should NOT proceed and leave a corrupt backup in place.
    // Accept either: (a) install succeeds after rewriting the
    // backup atomically (so the backup matches current settings), OR
    // (b) install errors clearly naming the corrupt backup.
    let result = installer::install(&opts(&home));
    match result {
        Ok(()) => {
            let b = fs::read_to_string(&backup).unwrap();
            // If install proceeded, the backup must now be valid JSON
            // reflecting the pre-install settings. Previously, the
            // installer left the truncated "{\"permi" in place.
            assert!(
                serde_json::from_str::<serde_json::Value>(&b).is_ok(),
                "backup must be valid JSON after install, got: {b}"
            );
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("backup") || msg.contains("pre-barbican"),
                "install error must mention the backup; got: {msg}"
            );
        }
    }
}

#[test]
fn uninstall_does_not_strip_user_hook_with_barbican_substring_in_path() {
    // HIGH: is_barbican_hook_command matched substring
    // 'barbican/barbican' — a user's own hook at
    // /opt/barbican/barbican-helper would be falsely stripped.
    let (_dir, home) = fake_home();
    let user_hook_cmd = "/opt/barbican/barbican-helper --mode=check";
    let original = json!({
        "permissions": { "allow": [], "ask": [] },
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": user_hook_cmd}]
            }]
        }
    });
    write_json(&home.join("settings.json"), &original);

    installer::install(&opts(&home)).expect("install");
    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: false,
        keep_files: false,
    })
    .expect("uninstall");

    let settings = read_json(&home.join("settings.json"));
    let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
    let preserved = pre.iter().any(|entry| {
        entry["hooks"][0]["command"]
            .as_str()
            .is_some_and(|c| c == user_hook_cmd)
    });
    assert!(
        preserved,
        "user hook at /opt/barbican/barbican-helper must survive uninstall: {pre:?}"
    );
}

#[test]
fn install_errors_cleanly_on_non_object_permissions() {
    // LOW-2 (elevated): panic if user's settings.json contains
    // `"permissions": "disabled"` — a string where we expected an
    // object. Installer must surface a clear error, not crash.
    let (_dir, home) = fake_home();
    let malformed = json!({ "permissions": "disabled" });
    write_json(&home.join("settings.json"), &malformed);

    let err = installer::install(&opts(&home)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("permissions") || msg.contains("object"),
        "want helpful error about malformed config; got: {msg}"
    );
}

#[test]
fn install_errors_cleanly_on_non_array_allow() {
    // LOW-2: same class — permissions.allow is a string. Must not
    // panic through array_entry().
    let (_dir, home) = fake_home();
    let malformed = json!({ "permissions": { "allow": "nope" } });
    write_json(&home.join("settings.json"), &malformed);

    let err = installer::install(&opts(&home)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("allow") || msg.contains("array"),
        "want helpful error about allow-list type; got: {msg}"
    );
}

#[test]
fn install_preserves_user_key_order() {
    // MEDIUM: serde_json::Map without `preserve_order` reorders keys
    // on every round-trip, churning the user's dotfile diff.
    let (_dir, home) = fake_home();
    // Hand-crafted key order that serde_json's default hash-map
    // would scramble.
    let original_str = "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"allow\": [],\n    \"ask\": []\n  },\n  \"hooks\": {},\n  \"experimental\": {\n    \"foo\": 1\n  }\n}\n";
    fs::write(home.join("settings.json"), original_str).unwrap();

    installer::install(&opts(&home)).expect("install");

    let out = fs::read_to_string(home.join("settings.json")).unwrap();
    let model_idx = out.find("\"model\"").expect("model key present");
    let perms_idx = out
        .find("\"permissions\"")
        .expect("permissions key present");
    let hooks_idx = out.find("\"hooks\"").expect("hooks key present");
    let exp_idx = out
        .find("\"experimental\"")
        .expect("experimental key present");
    assert!(
        model_idx < perms_idx && perms_idx < hooks_idx && hooks_idx < exp_idx,
        "user key order must be preserved on round-trip; got:\n{out}"
    );
}

#[test]
fn uninstall_removes_empty_scaffolding() {
    // MEDIUM: after a fresh install+uninstall on a previously-empty
    // config, no orphan `hooks: {}`, `permissions.allow: []`, etc.
    // should be left behind.
    let (_dir, home) = fake_home();
    installer::install(&opts(&home)).expect("install");
    installer::uninstall(&UninstallOptions {
        claude_home: home.clone(),
        dry_run: false,
        keep_files: false,
    })
    .expect("uninstall");

    let settings = read_json(&home.join("settings.json"));
    // Empty arrays/objects inserted by install must be removed once
    // they're no longer populated.
    if let Some(perms) = settings.get("permissions") {
        if let Some(obj) = perms.as_object() {
            assert!(
                obj.get("allow")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(|a| !a.is_empty())
                    || obj.get("allow").is_none(),
                "empty permissions.allow must be removed: {settings}"
            );
        }
    }
    if let Some(hooks) = settings.get("hooks") {
        if let Some(obj) = hooks.as_object() {
            for (_k, v) in obj {
                if let Some(arr) = v.as_array() {
                    assert!(!arr.is_empty(), "empty hook event arrays must be removed");
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn install_refuses_to_follow_binary_dst_symlink() {
    // 1.2.0 adversarial review (GPT HIGH #16): `fs::copy(src, dst)` in
    // copy_binary followed symlinks at dst. An attacker who pre-plants
    // `~/.claude/barbican/barbican` as a symlink to (e.g.) `~/.bashrc`
    // would get that file silently overwritten by the Barbican binary
    // on the next install. The fix routes binary staging through the
    // same O_NOFOLLOW + O_EXCL + fsync + rename discipline the JSON
    // writers already use.
    let (_dir, home) = fake_home();
    // Plant `~/.claude/barbican/` with `barbican` as a symlink to a
    // sibling bait file.
    fs::create_dir_all(home.join("barbican")).unwrap();
    let bait_dir = tempfile::tempdir().unwrap();
    let bait = bait_dir.path().join("victim");
    fs::write(&bait, b"pre-existing bait data").unwrap();
    let dst = home.join("barbican").join("barbican");
    std::os::unix::fs::symlink(&bait, &dst).unwrap();

    // Install may succeed (atomic rename REPLACES the symlink rather
    // than following it) or fail (if the symlink existed pre-staging
    // and rename trips), but in EITHER case the bait file must be
    // untouched. The previous `fs::copy(src, dst)` implementation
    // followed the symlink and clobbered the bait file.
    let _ = installer::install(&opts(&home));
    let bait_contents = fs::read(&bait).unwrap();
    assert_eq!(
        bait_contents, b"pre-existing bait data",
        "symlink target must not be followed (the previous fs::copy \
         implementation would have clobbered the bait file)"
    );
    // If install succeeded, dst must now be a regular file, not a
    // symlink (the atomic rename replaces the symlink with the real
    // binary file).
    if let Ok(meta) = fs::symlink_metadata(&dst) {
        assert!(
            !meta.file_type().is_symlink(),
            "dst must no longer be a symlink after a successful install"
        );
    }
}

// ---------------------------------------------------------------------
// 1.4.0 wrapper binaries — `barbican install` copies each wrapper
// (barbican-shell/python/node/ruby/perl) that sits next to the main
// binary into ~/.claude/barbican/. Missing wrappers are skipped.
// ---------------------------------------------------------------------

const WRAPPER_NAMES: &[&str] = &[
    "barbican-shell",
    "barbican-python",
    "barbican-node",
    "barbican-ruby",
    "barbican-perl",
];

#[test]
fn install_copies_wrapper_binaries_when_present_next_to_source() {
    let (_dir, home) = fake_home();
    let o = opts(&home);
    // Drop a fake wrapper binary next to the main binary source — the
    // installer looks for `<bin-src-parent>/barbican-<lang>`.
    let src_parent = o.binary_source.parent().unwrap();
    for name in WRAPPER_NAMES {
        let p = src_parent.join(name);
        fs::write(&p, format!("#!/bin/sh\necho {name}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&p, perms).unwrap();
        }
    }

    installer::install(&o).expect("install");

    for name in WRAPPER_NAMES {
        let dst = home.join("barbican").join(name);
        assert!(dst.is_file(), "wrapper {name} should be copied to {dst:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "wrapper {name} should be 0o755, got {mode:o}");
        }
    }
}

#[test]
fn install_succeeds_when_wrapper_binaries_are_absent() {
    let (_dir, home) = fake_home();
    let o = opts(&home);
    // Do NOT create any wrapper files next to the source; the installer
    // must log + skip each missing wrapper instead of aborting.
    installer::install(&o).expect("install must still succeed without wrappers");

    let main_bin = home.join("barbican").join("barbican");
    assert!(main_bin.is_file(), "main binary should still land");
    for name in WRAPPER_NAMES {
        let dst = home.join("barbican").join(name);
        assert!(
            !dst.exists(),
            "wrapper {name} must not be fabricated when source is missing"
        );
    }
}
