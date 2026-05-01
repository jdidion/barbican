//! Barbican installer/uninstaller.
//!
//! Replaces Narthex's `install.py` / `uninstall.py`. Two things are
//! interesting about this module relative to the Python originals:
//!
//! 1. **All file writes are mode `0o600` via create-and-rename.** The
//!    Python installer relied on the umask. CLAUDE.md rule 6 forbids
//!    that — every file we touch (`settings.json`, `~/.claude.json`)
//!    must be readable only by the user. We write a sibling
//!    `<name>.tmp` with an explicit mode, then `rename(2)` into place.
//!    An interrupted run leaves the original intact.
//! 2. **Binary self-install copies `std::env::current_exe()`.** The
//!    Python installer copied a Python script; we copy a single static
//!    binary. Callers can override via `InstallOptions::binary_source`
//!    so integration tests don't need a real release build.
//!
//! Per-tool lookup tables (allow / ask / hook entries) live in
//! [`tables`] so install and uninstall agree about what "Barbican-
//! owned" means.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

/// What to install and where. The binary source defaults to
/// `std::env::current_exe()` in the CLI entry point; tests inject a
/// fake binary so they don't depend on Cargo's build output.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub claude_home: PathBuf,
    pub binary_source: PathBuf,
    pub dry_run: bool,
}

/// What to strip, mirroring install.
#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub claude_home: PathBuf,
    pub dry_run: bool,
    pub keep_files: bool,
}

mod tables {
    //! The single source of truth for "Barbican-owned" config
    //! entries. Install adds these; uninstall strips them; tests
    //! assert the counts. Keep both in lock-step.

    pub const ALLOW: &[&str] = &[
        "mcp__barbican",
        "WebFetch(domain:docs.anthropic.com)",
        "WebFetch(domain:github.com)",
        "WebFetch(domain:raw.githubusercontent.com)",
        "WebFetch(domain:gist.githubusercontent.com)",
        "WebFetch(domain:api.github.com)",
        "WebFetch(domain:registry.npmjs.org)",
        "WebFetch(domain:www.npmjs.com)",
        "WebFetch(domain:pypi.org)",
        "WebFetch(domain:files.pythonhosted.org)",
        "WebFetch(domain:crates.io)",
        "WebFetch(domain:go.dev)",
        "WebFetch(domain:pkg.go.dev)",
        "WebFetch(domain:developer.mozilla.org)",
        "WebFetch(domain:stackoverflow.com)",
    ];

    pub const ASK: &[&str] = &[
        "WebFetch",
        "Bash(curl:*)",
        "Bash(wget:*)",
        "Bash(nc:*)",
        "Bash(ncat:*)",
        "Bash(netcat:*)",
        "Bash(scp:*)",
        "Bash(sftp:*)",
        "Bash(ftp:*)",
        "Bash(httpie:*)",
        "Bash(http:*)",
        "Bash(xh:*)",
    ];

    /// Each hook entry is `(event, matcher, subcommand)`. The
    /// installed command is `<binary> <subcommand>`, assembled in
    /// `hook_command()`.
    pub const HOOKS: &[(&str, &str, &str)] = &[
        ("PreToolUse", "Bash", "pre-bash"),
        ("PostToolUse", "Bash|WebFetch", "audit"),
        ("PostToolUse", "mcp__.*", "post-mcp"),
        (
            "PostToolUse",
            "Edit|Write|MultiEdit|NotebookEdit",
            "post-edit",
        ),
    ];
}

/// Install Barbican into `opts.claude_home`. Steps:
/// 1. Confirm `~/.claude` exists.
/// 2. Copy the binary to `~/.claude/barbican/barbican`, mode `0o755`.
/// 3. Back up `settings.json` and `~/.claude.json` once.
/// 4. Patch `settings.json` with allow/ask/hooks entries (idempotent).
/// 5. Register the MCP server in `~/.claude.json`.
///
/// All steps are idempotent: re-running only adds what's missing.
pub fn install(opts: &InstallOptions) -> Result<()> {
    ensure_claude_home(&opts.claude_home)?;
    let barbican_dir = opts.claude_home.join("barbican");
    let installed_binary = barbican_dir.join("barbican");

    if opts.dry_run {
        log(&format!("DRY RUN — no filesystem changes"));
        log(&format!("would create {}", barbican_dir.display()));
        log(&format!(
            "would copy {} -> {}",
            opts.binary_source.display(),
            installed_binary.display()
        ));
    } else {
        fs::create_dir_all(&barbican_dir)
            .with_context(|| format!("create {}", barbican_dir.display()))?;
        copy_binary(&opts.binary_source, &installed_binary)?;
    }

    let settings_path = opts.claude_home.join("settings.json");
    // Claude Code's global MCP registry lives alongside the home dir,
    // not inside it: `~/.claude.json` is a sibling of `~/.claude/`.
    let mcp_path = claude_json_path(&opts.claude_home);

    backup_once(&settings_path, opts.dry_run)?;
    backup_once(&mcp_path, opts.dry_run)?;

    patch_settings(&settings_path, &installed_binary, opts.dry_run)?;
    patch_mcp_registry(&mcp_path, &installed_binary, opts.dry_run)?;

    log("install complete");
    if !opts.dry_run {
        log("restart Claude Code for the MCP registration to take effect");
    }
    Ok(())
}

/// Uninstall Barbican. Mirrors [`install`]: strips the same entries
/// back out, removes the `~/.claude/barbican/` directory, and leaves
/// the `*.pre-barbican` backups in place for manual recovery.
pub fn uninstall(opts: &UninstallOptions) -> Result<()> {
    ensure_claude_home(&opts.claude_home)?;

    let settings_path = opts.claude_home.join("settings.json");
    if settings_path.exists() {
        let mut cfg = read_json_or_empty(&settings_path)?;
        let allow_removed = strip_permission_list(&mut cfg, "allow", tables::ALLOW);
        let ask_removed = strip_permission_list(&mut cfg, "ask", tables::ASK);
        let hook_removed = strip_hooks(&mut cfg);
        log(&format!(
            "settings.json: removed {hook_removed} hook entries, {} permission rules",
            allow_removed + ask_removed
        ));
        if !opts.dry_run {
            write_json_mode_0600(&settings_path, &cfg)?;
        }
    }

    let mcp_path = claude_json_path(&opts.claude_home);
    if mcp_path.exists() {
        let mut cfg = read_json_or_empty(&mcp_path)?;
        if let Some(servers) = cfg.get_mut("mcpServers").and_then(Value::as_object_mut) {
            if servers.remove("barbican").is_some() {
                log(&format!("{}: removed barbican server", mcp_path.display()));
                if !opts.dry_run {
                    write_json_mode_0600(&mcp_path, &cfg)?;
                }
            }
        }
    }

    let barbican_dir = opts.claude_home.join("barbican");
    if barbican_dir.exists() {
        if opts.keep_files {
            log(&format!("keeping {} (--keep-files)", barbican_dir.display()));
        } else if opts.dry_run {
            log(&format!("would remove {}", barbican_dir.display()));
        } else {
            fs::remove_dir_all(&barbican_dir)
                .with_context(|| format!("remove {}", barbican_dir.display()))?;
            log(&format!("removed {}", barbican_dir.display()));
        }
    }

    log("uninstall complete");
    Ok(())
}

// --- internals ------------------------------------------------------

fn log(msg: &str) {
    // CLI tooling: go to stdout so the user sees a progress log. The
    // hook subcommands use tracing for stderr; this is a different
    // code path (interactive install) and stdout is the right sink.
    println!("[barbican] {msg}");
}

fn ensure_claude_home(home: &Path) -> Result<()> {
    if !home.is_dir() {
        bail!(
            "Claude Code config directory not found at {}. Install Claude Code first.",
            home.display()
        );
    }
    Ok(())
}

fn claude_json_path(claude_home: &Path) -> PathBuf {
    let parent = claude_home.parent().unwrap_or_else(|| Path::new("/"));
    let name = claude_home
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| std::ffi::OsString::from(".claude"));
    let mut out = name;
    out.push(".json");
    parent.join(out)
}

fn copy_binary(src: &Path, dst: &Path) -> Result<()> {
    fs::copy(src, dst).with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dst)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dst, perms)?;
    }
    log(&format!("installed binary to {}", dst.display()));
    Ok(())
}

fn backup_once(path: &Path, dry_run: bool) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let backup = backup_path(path);
    if backup.exists() {
        log(&format!(
            "backup already exists at {} — leaving as-is",
            backup.display()
        ));
        return Ok(());
    }
    if dry_run {
        log(&format!(
            "would back up {} -> {}",
            path.display(),
            backup.display()
        ));
        return Ok(());
    }
    fs::copy(path, &backup)
        .with_context(|| format!("backup {} -> {}", path.display(), backup.display()))?;
    // Backups inherit the source's mode — if we just wrote the
    // original with 0o600, this copy is 0o600 too. Explicitly tighten
    // to 0o600 for freshly backed-up files to cover the case where
    // the user's original predates Barbican.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&backup)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&backup, perms)?;
    }
    log(&format!("backed up {}", path.display()));
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    // Narthex uses `settings.json.pre-narthex`; we use `.pre-barbican`.
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".pre-barbican");
    path.with_file_name(name)
}

fn read_json_or_empty(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let bytes =
        fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(json!({}));
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON from {}", path.display()))
}

/// Write `value` to `path` atomically with mode `0o600`.
///
/// The sequence is: create `<path>.barbican-tmp` with mode `0o600`,
/// write + flush, then `rename` into place. `rename(2)` is atomic on
/// the same filesystem; if it fails partway there is no torn config
/// file because the original was never truncated.
fn write_json_mode_0600(path: &Path, value: &Value) -> Result<()> {
    let tmp_path = {
        let mut name = path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        name.push(".barbican-tmp");
        path.with_file_name(name)
    };

    let serialized = serde_json::to_vec_pretty(value)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("open {}", tmp_path.display()))?;
        f.write_all(&serialized)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| format!("open {}", tmp_path.display()))?;
        f.write_all(&serialized)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }

    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn patch_settings(settings_path: &Path, binary: &Path, dry_run: bool) -> Result<()> {
    let mut cfg = read_json_or_empty(settings_path)?;
    ensure_object(&mut cfg);

    let perms = object_entry(&mut cfg, "permissions");
    merge_string_list(perms, "allow", tables::ALLOW);
    merge_string_list(perms, "ask", tables::ASK);

    let hooks = object_entry(&mut cfg, "hooks");
    for (event, matcher, subcommand) in tables::HOOKS {
        let event_arr = array_entry(hooks, event);
        let cmd = hook_command(binary, subcommand);
        if !hook_array_contains(event_arr, &cmd) {
            event_arr.push(json!({
                "matcher": matcher,
                "hooks": [{"type": "command", "command": cmd}],
            }));
        }
    }

    if dry_run {
        log(&format!("would write {}", settings_path.display()));
        return Ok(());
    }
    write_json_mode_0600(settings_path, &cfg)?;
    log(&format!("wrote {}", settings_path.display()));
    Ok(())
}

fn patch_mcp_registry(mcp_path: &Path, binary: &Path, dry_run: bool) -> Result<()> {
    let mut cfg = read_json_or_empty(mcp_path)?;
    ensure_object(&mut cfg);
    let servers = object_entry(&mut cfg, "mcpServers");

    let entry = json!({
        "command": binary.to_string_lossy(),
        "args": ["mcp-serve"],
    });
    let servers_obj = servers
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers is not an object"))?;
    if servers_obj.get("barbican") == Some(&entry) {
        log("MCP server `barbican` already registered — skipping");
    } else {
        servers_obj.insert("barbican".to_string(), entry);
        log("registered MCP server `barbican`");
    }

    if dry_run {
        log(&format!("would write {}", mcp_path.display()));
        return Ok(());
    }
    write_json_mode_0600(mcp_path, &cfg)?;
    log(&format!("wrote {}", mcp_path.display()));
    Ok(())
}

fn hook_command(binary: &Path, subcommand: &str) -> String {
    format!("{} {}", binary.to_string_lossy(), subcommand)
}

fn hook_array_contains(arr: &[Value], cmd: &str) -> bool {
    arr.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hs| {
                hs.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.trim() == cmd)
                })
            })
    })
}

fn strip_permission_list(cfg: &mut Value, key: &str, owned: &[&str]) -> usize {
    let Some(arr) = cfg
        .get_mut("permissions")
        .and_then(|p| p.get_mut(key))
        .and_then(Value::as_array_mut)
    else {
        return 0;
    };
    let before = arr.len();
    arr.retain(|v| {
        v.as_str()
            .is_none_or(|s| !owned.iter().any(|owned_rule| s == *owned_rule))
    });
    before - arr.len()
}

fn strip_hooks(cfg: &mut Value) -> usize {
    let Some(hooks) = cfg.get_mut("hooks").and_then(Value::as_object_mut) else {
        return 0;
    };
    let mut removed = 0;
    for (_event, entries_val) in hooks.iter_mut() {
        let Some(entries) = entries_val.as_array_mut() else {
            continue;
        };
        entries.retain_mut(|entry| {
            let Some(inner) = entry
                .get_mut("hooks")
                .and_then(Value::as_array_mut)
            else {
                return true;
            };
            inner.retain(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_none_or(|cmd| !is_barbican_hook_command(cmd))
            });
            if inner.is_empty() {
                removed += 1;
                return false;
            }
            true
        });
    }
    removed
}

fn is_barbican_hook_command(cmd: &str) -> bool {
    // Match anything invoking the installed binary path tail
    // `barbican/barbican`. Works regardless of `~/.claude` location.
    cmd.contains("barbican/barbican") || cmd.contains("\\barbican\\barbican")
}

// --- tiny JSON ergonomic helpers ------------------------------------

fn ensure_object(v: &mut Value) {
    if !v.is_object() {
        *v = json!({});
    }
}

fn object_entry<'a>(parent: &'a mut Value, key: &str) -> &'a mut Value {
    let obj = parent
        .as_object_mut()
        .expect("ensure_object called first");
    obj.entry(key.to_string()).or_insert_with(|| json!({}))
}

fn array_entry<'a>(parent: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let obj = parent.as_object_mut().expect("object parent");
    obj.entry(key.to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("array entry")
}

fn merge_string_list(parent: &mut Value, key: &str, values: &[&str]) {
    let arr = array_entry(parent, key);
    for v in values {
        let val = Value::String((*v).to_string());
        if !arr.iter().any(|existing| existing == &val) {
            arr.push(val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_command_joins_with_space() {
        assert_eq!(
            hook_command(Path::new("/foo/bar"), "pre-bash"),
            "/foo/bar pre-bash"
        );
    }

    #[test]
    fn is_barbican_hook_command_matches_install_path() {
        assert!(is_barbican_hook_command(
            "/home/u/.claude/barbican/barbican pre-bash"
        ));
        assert!(!is_barbican_hook_command("/opt/my-own-tool check"));
    }

    #[test]
    fn backup_path_appends_pre_barbican_suffix() {
        assert_eq!(
            backup_path(Path::new("/x/y/settings.json")),
            Path::new("/x/y/settings.json.pre-barbican"),
        );
    }

    #[test]
    fn claude_json_path_sits_next_to_home() {
        assert_eq!(
            claude_json_path(Path::new("/home/u/.claude")),
            Path::new("/home/u/.claude.json"),
        );
    }
}
