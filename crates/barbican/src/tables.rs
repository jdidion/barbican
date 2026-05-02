//! Compile-time-encoded dangerous command sets.
//!
//! These are `phf::Set`s so membership is an O(1) perfect-hash lookup
//! and the data is baked into the binary. A future refactor cannot clear
//! a `const` set, which is the whole point: the Python predecessor held
//! these as mutable lists and we don't want to repeat that mistake.
//!
//! **All lookups must go through [`crate::cmd::cmd_basename`] first.**
//! Passing raw `argv[0]` strings to these sets re-introduces the H1
//! bypass.

use phf::{phf_set, Set};

/// Tools that can transmit data off-host.
///
/// Splits into two tiers:
/// - [`NETWORK_TOOLS_HARD`]: always flagged in exfil-adjacent compositions.
/// - [`NETWORK_TOOLS_ASK`]: flagged only in composition with secret-read
///   (e.g. `cat ~/.ssh/id_rsa | git ...`). `git push` to a normal remote
///   is legitimate.
///
/// The combined [`NETWORK_TOOLS`] set is the union, used where any egress
/// channel matters (e.g. DNS exfil via `dig`).
pub static NETWORK_TOOLS_HARD: Set<&'static str> = phf_set! {
    "curl", "wget", "nc", "ncat", "socat",
    "dig", "host", "nslookup", "drill", "resolvectl",
    "ssh",
};

/// Tools that are egress channels but have legitimate daily use and
/// should only be flagged in composition with secret-read or when
/// `BARBICAN_GIT_HARD_DENY=1`.
pub static NETWORK_TOOLS_ASK: Set<&'static str> = phf_set! {
    "git",
};

/// Union of [`NETWORK_TOOLS_HARD`] and [`NETWORK_TOOLS_ASK`].
pub static NETWORK_TOOLS: Set<&'static str> = phf_set! {
    "curl", "wget", "nc", "ncat", "socat",
    "dig", "host", "nslookup", "drill", "resolvectl",
    "ssh",
    "git",
};

/// Commands that execute arbitrary shell code from their argv. The H1
/// bypass lived in the per-element match of this set against un-basenamed
/// `argv[0]`.
pub static SHELL_INTERPRETERS: Set<&'static str> = phf_set! {
    "bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "tcsh", "csh",
};

/// Commands that take another command as argv and should therefore have
/// that inner command re-parsed. Narthex only re-entered for `bash -c`,
/// `sh -c`, and `eval` — audit finding **M1** is the full list below.
///
/// The paired value names the flag (or special form) after which the
/// wrapped command begins. A value of `None` means the wrapped command
/// follows the `--` separator or the first non-flag argument; callers
/// must use parser context.
pub static REENTRY_WRAPPERS: Set<&'static str> = phf_set! {
    "bash",     // bash -c '...'
    "sh",       // sh -c '...'
    "zsh",      // zsh -c '...'
    "dash",     // dash -c '...'
    "ksh",      // ksh -c '...'
    "eval",     // eval '...'
    "find",     // find ... -exec <cmd> {} \;
    "xargs",    // xargs <cmd>
    "sudo",     // sudo <cmd>
    "doas",     // doas <cmd>
    "timeout", // timeout <duration> <cmd>
    "nohup",   // nohup <cmd>
    "env",     // env [VARS=...] <cmd>
    "watch",   // watch <cmd>
    "nice",    // nice <cmd>
    "ionice",  // ionice <cmd>
    "parallel", // parallel <cmd>
    "su",      // su -c '...' [user]
    "runuser", // runuser -c '...' [user]
    "setsid",  // setsid <cmd>
    "stdbuf",  // stdbuf <cmd>
    "unbuffer", // unbuffer <cmd>
    // 1.2.0 adversarial-review additions — shell builtins that
    // transparently run the remainder of argv as an inner command.
    // Without these in the unwrap set, `time curl | bash` and
    // `command bash -c '...'` route around H1/M1 entirely.
    "time",    // time <cmd>  (also the `time` keyword form)
    "command", // command [-pVv] <cmd>  (bypasses function shadowing)
    "builtin", // builtin <cmd>
    "exec",    // exec [-cl] [-a NAME] <cmd>
    // 1.2.0 5th-pass review (GPT SEVERE #2): sandboxing / re-exec
    // fronts. All four take a prefix-runner shape (`unshare -r bash`,
    // `systemd-run --pipe bash`, `chpst -u nobody bash`). busybox /
    // toybox are also APPLET MULTIPLEXERS: `busybox sh`, `busybox
    // wget -qO- URL` invoke their bundled applet. Handled as both a
    // wrapper and in the applet-aware extractor.
    "unshare",     // unshare [-r] [-m] [--user] CMD
    "systemd-run", // systemd-run [--pipe] [--wait] [--scope] CMD
    "chpst",       // chpst [-u user] [-e ENVDIR] CMD
    "busybox",     // busybox APPLET [args] — applet ~= argv[0] for classify
    "toybox",      // toybox APPLET [args] — same shape as busybox
    // ssh [opts] HOST CMD... — remote shell sink. CMD classifies as
    // bash on the remote, but attack shapes (curl|bash, secret exfil)
    // deny on the local invocation regardless of remote execution.
    "ssh",
};

/// Tools that can decode/reconstruct binary payloads written to disk.
/// Any pipeline terminating in `<tool> > <exec-target>` is flagged.
/// Audit finding **H2**.
pub static OBFUSCATION_TOOLS: Set<&'static str> = phf_set! {
    "base64", "xxd", "openssl", "uudecode", "atob",
};

/// Path prefixes that should never appear on the read side of an exfil
/// pipeline, nor on the read side of `safe_read` unless the sensitive
/// allow-flag is set. Prefix match (rooted at each entry) — callers must
/// canonicalize and expand `~` first.
///
/// Individual leaf files are enumerated separately to avoid false
/// positives on siblings (e.g. we don't want to flag `.envrc` as `.env`).
pub static SECRET_PATH_PREFIXES: Set<&'static str> = phf_set! {
    // Home-relative
    ".ssh/",
    ".aws/",
    ".gnupg/",
    ".config/gh/",
    ".docker/config.json",
    ".netrc",
    ".pgpass",
    ".kube/",
    // System
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/ssh/",
    "/root/.ssh/",
};

/// Exact-match sensitive filenames where a prefix test would be wrong.
///
/// `.env` is sensitive; `.env.example`, `.env.sample`, `.env.template`
/// are safe conventions for committed sample configs and are handled as
/// explicit carve-outs in `safe_read.rs`.
pub static SECRET_EXACT_BASENAMES: Set<&'static str> = phf_set! {
    ".env",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "id_rsa.pub", "id_ed25519.pub",
    "authorized_keys",
    "known_hosts",
    "credentials",
    "credentials.json",
};

/// Commands that can be used to gate a later execution of a file (chmod
/// +x, bash <file>, etc.). Terminating a decode pipeline at one of these
/// targets is the H2 staging pattern.
pub static EXEC_TARGETS: Set<&'static str> = phf_set! {
    "bash", "sh", "zsh", "dash", "ksh",
    "source", ".", "chmod",
};

/// Commands that dump the user's environment (which typically contains
/// secrets: API keys, access tokens, passwords). Piping these into a
/// network tool is the env-exfil shape (Narthex parity).
pub static ENV_DUMPERS: Set<&'static str> = phf_set! {
    "env", "printenv", "export", "declare", "set",
};

/// Broader network/exfil-channel set for M2. Wider than
/// `NETWORK_TOOLS_HARD` (which is H1's tight curl|wget|nc|socat|ssh
/// set) — M2 also cares about upload-style tools that write a local
/// file directly to a remote host.
pub static EXFIL_NETWORK_TOOLS: Set<&'static str> = phf_set! {
    // Direct transfer
    "curl", "wget", "nc", "ncat", "netcat", "socat",
    // DNS exfil channels
    "dig", "host", "nslookup", "drill", "resolvectl",
    // Remote copy / sync
    "scp", "rsync", "sftp", "ftp", "tftp",
    // HTTP clients
    "http", "https", "httpie", "xh",
    // Mail clients (can be used for exfil)
    "mail", "sendmail", "mutt",
    // Shell / transport
    "ssh",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_tools_covers_dns_exfil() {
        for tool in ["dig", "host", "nslookup", "drill", "resolvectl"] {
            assert!(
                NETWORK_TOOLS.contains(tool),
                "{tool} missing from NETWORK_TOOLS"
            );
        }
    }

    #[test]
    fn git_is_ask_not_hard() {
        assert!(NETWORK_TOOLS_ASK.contains("git"));
        assert!(!NETWORK_TOOLS_HARD.contains("git"));
        assert!(NETWORK_TOOLS.contains("git"));
    }

    #[test]
    fn shell_interpreters_covers_common() {
        for shell in ["bash", "sh", "zsh", "dash", "ksh", "fish"] {
            assert!(SHELL_INTERPRETERS.contains(shell));
        }
    }

    #[test]
    fn reentry_wrappers_covers_m1() {
        for wrapper in [
            "find", "xargs", "sudo", "timeout", "nohup", "env", "watch", "nice", "parallel", "su",
        ] {
            assert!(
                REENTRY_WRAPPERS.contains(wrapper),
                "{wrapper} missing from REENTRY_WRAPPERS"
            );
        }
    }

    #[test]
    fn obfuscation_tools_covers_h2() {
        assert!(OBFUSCATION_TOOLS.contains("base64"));
        assert!(OBFUSCATION_TOOLS.contains("xxd"));
    }
}
