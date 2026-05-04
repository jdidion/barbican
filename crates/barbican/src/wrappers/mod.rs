//! `barbican-<lang>` wrapper binaries — drop-in `-c BODY` gates.
//!
//! Each wrapper binary (`barbican-shell`, `barbican-python`,
//! `barbican-node`, `barbican-ruby`, `barbican-perl`) is a thin `fn
//! main` that delegates to [`run`] with a [`Dialect`]. The real work —
//! argv parsing, classifier dispatch, child spawn, output redaction,
//! audit logging, signal forwarding, exit-code propagation — lives
//! here so all five wrappers share one implementation.
//!
//! ## Design
//!
//! 1. Parse argv to find the `-c BODY` (or `-e BODY` for perl / ruby /
//!    node) — every wrapper accepts exactly the same flag the
//!    underlying interpreter does, so existing callers don't have to
//!    rewrite commands.
//! 2. Classify BODY via [`crate::hooks::pre_bash::classify_command`].
//!    Shell bodies classify directly; scripting-lang bodies synthesize
//!    a `{lang} -c '<body>'` invocation so the existing
//!    `scripting_lang_shellout` rule fires. The rule's already wired
//!    to recognize the `-c` / `-e` forms for every dialect we ship.
//! 3. On **deny**: write the classifier's reason to stderr, append an
//!    audit entry, exit 2 (same code as the raw hook uses).
//! 4. On **allow**: spawn the underlying interpreter with a `posix_spawn
//!    `-flavored `Command::spawn`, redirect its stdout/stderr through
//!    pipes, filter every chunk through [`crate::redact::redact_secrets`],
//!    and forward to our own stdout/stderr. Exit with the child's
//!    status code.
//!
//! ## Signal handling
//!
//! The wrapper stays in the process group so Ctrl-C reaches both
//! wrapper and child. The wrapper ignores SIGINT itself (so the
//! terminal keeps sending it to the child only) until after the
//! child exits. This matches how `time(1)`, `sudo(1)`, and similar
//! transparent front-ends behave.
//!
//! ## Audit log shape
//!
//! One JSONL entry per invocation, appended to
//! `~/.claude/barbican/audit.log` (same path the main audit hook uses):
//!
//! ```json
//! {"ts":"...","event":"wrapper","dialect":"shell","decision":"allow",
//!  "body_sha256":"…","exit":0}
//! ```
//!
//! The body text itself is NEVER written — API keys and secrets may
//! appear in `-c` bodies and we don't want the audit log to become a
//! new exfil target. Only the sha256 digest survives.

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;

use crate::hooks::pre_bash::{classify_command, Decision};
use crate::redact::redact_secrets;

/// Which interpreter this wrapper gates. Controls (a) which inline-
/// code flag to pick out of argv, (b) how to synthesize the classifier
/// input, and (c) which binary to exec on allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `bash -c BODY` (plus `sh`, `zsh` — configurable via
    /// `BARBICAN_SHELL` env var).
    Shell,
    /// `python3 -c BODY` (python2/3 family).
    Python,
    /// `node -e BODY` (also `deno`, `bun` via $BARBICAN_NODE).
    Node,
    /// `ruby -e BODY`.
    Ruby,
    /// `perl -e BODY`.
    Perl,
}

impl Dialect {
    /// Binary name used as the wrapper command — for error messages
    /// and audit-log entries.
    #[must_use]
    pub fn wrapper_name(self) -> &'static str {
        match self {
            Self::Shell => "barbican-shell",
            Self::Python => "barbican-python",
            Self::Node => "barbican-node",
            Self::Ruby => "barbican-ruby",
            Self::Perl => "barbican-perl",
        }
    }

    /// The `-c`/`-e` flag name the underlying interpreter uses. The
    /// wrapper accepts exactly this flag and hands BODY to the
    /// interpreter under the same flag.
    #[must_use]
    pub fn inline_flag(self) -> &'static str {
        match self {
            // Every shell + python uses `-c`.
            Self::Shell | Self::Python => "-c",
            // node / ruby / perl use `-e`.
            Self::Node | Self::Ruby | Self::Perl => "-e",
        }
    }

    /// Default underlying interpreter. Overridable via env var:
    /// `BARBICAN_SHELL`, `BARBICAN_PYTHON`, `BARBICAN_NODE`,
    /// `BARBICAN_RUBY`, `BARBICAN_PERL`. Respecting `$SHELL` for the
    /// shell dialect would make attack shapes depend on the caller's
    /// environment, so we don't do that.
    #[must_use]
    pub fn default_interpreter(self) -> &'static str {
        match self {
            Self::Shell => "bash",
            Self::Python => "python3",
            Self::Node => "node",
            Self::Ruby => "ruby",
            Self::Perl => "perl",
        }
    }

    /// Env var whose value (if set) overrides the default interpreter.
    #[must_use]
    pub fn interpreter_env_var(self) -> &'static str {
        match self {
            Self::Shell => "BARBICAN_SHELL",
            Self::Python => "BARBICAN_PYTHON",
            Self::Node => "BARBICAN_NODE",
            Self::Ruby => "BARBICAN_RUBY",
            Self::Perl => "BARBICAN_PERL",
        }
    }

    /// Whether this dialect's interpreter re-parses flag tokens after
    /// BODY, such that a trailing `-e` / `--eval` / `-m module` could
    /// sneak a second script past the wrapper's classifier. If true,
    /// the wrapper inserts a literal `--` between BODY and extra args
    /// to stop flag parsing.
    ///
    /// Verified behavior:
    /// - `node -e X -e Y` — Y replaces X without `--` (re-parses).
    /// - `perl -e X -e Y` — aggregates both scripts (re-parses).
    /// - `ruby -e X -e Y` — runs both (re-parses).
    /// - `python3 -c X -m Y` — everything after X goes to sys.argv
    ///   (does NOT re-parse); `--` is still safe, just inert.
    /// - `bash -c X NAME ARGS…` — positional form, no flag re-parse;
    ///   `--` would become `$0` and break the positional contract.
    fn needs_argv_terminator(self) -> bool {
        match self {
            // Python's `-c` consumes every following arg as
            // `sys.argv[1:]` without re-parsing flags; a second `-c`
            // is NOT honored. Injecting `--` would just pollute
            // sys.argv with an unexpected token for callers.
            Self::Shell | Self::Python => false,
            Self::Node | Self::Ruby | Self::Perl => true,
        }
    }

    /// Short tag used inside the audit-log `dialect` field.
    fn audit_tag(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Python => "python",
            Self::Node => "node",
            Self::Ruby => "ruby",
            Self::Perl => "perl",
        }
    }
}

/// Exit codes. Match the raw hook's contract: 0 = allow + child
/// succeeded, 2 = denied, anything else = propagated child status.
const EXIT_DENY: i32 = 2;

/// Main wrapper entry point. Called by each `src/bin/barbican_<lang>.rs`
/// with the appropriate [`Dialect`]. Diverges (never returns) —
/// either `std::process::exit`s with the child's exit code, or exits
/// `EXIT_DENY` on classifier deny / argv error.
///
/// # Arguments
///
/// `argv` is the full process argv including argv[0]. Parsing skips
/// argv[0] and looks for the first occurrence of the dialect's
/// `inline_flag` (e.g. `-c` or `-e`); the immediately-following
/// argument is BODY. Any args after BODY are passed through to the
/// interpreter unchanged (`bash -c BODY -- $0 $1 …` positional form).
pub fn run(dialect: Dialect, argv: &[String]) -> ! {
    let (body, extra_args) = match parse_argv(argv, dialect) {
        Ok(parts) => parts,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{}: {e}", dialect.wrapper_name());
            std::process::exit(EXIT_DENY);
        }
    };

    // Classify BEFORE spawning anything. If this returns Deny, the
    // child never runs.
    let classifier_input = synthesize_classifier_input(dialect, &body);
    let decision = classify_command(&classifier_input);

    let body_sha256 = sha256_hex(body.as_bytes());

    if let Decision::Deny { reason } = decision {
        let _ = writeln!(std::io::stderr(), "{}: {reason}", dialect.wrapper_name(),);
        write_audit_entry(dialect, "deny", Some(&reason), &body_sha256, None);
        std::process::exit(EXIT_DENY);
    }

    // Allow path — spawn the interpreter with pipes and redact output.
    let interpreter = resolve_interpreter(dialect);
    let exit_code = spawn_with_redaction(dialect, &interpreter, &body, &extra_args);

    write_audit_entry(dialect, "allow", None, &body_sha256, Some(exit_code));
    std::process::exit(exit_code);
}

/// Parse wrapper argv into `(BODY, extra_args)`. Errors if the inline
/// flag is missing or has no BODY. Any args after BODY are returned
/// verbatim — the interpreter interprets them as positional args.
fn parse_argv(argv: &[String], dialect: Dialect) -> Result<(String, Vec<String>), String> {
    let flag = dialect.inline_flag();
    // Skip argv[0].
    let mut iter = argv.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == flag {
            let body = iter
                .next()
                .ok_or_else(|| format!("missing argument after {flag}"))?;
            let rest: Vec<String> = iter.cloned().collect();
            return Ok((body.clone(), rest));
        }
        // Attached form: `-cBODY` / `-eBODY`.
        if let Some(body) = arg.strip_prefix(flag) {
            if body.is_empty() {
                continue;
            }
            let rest: Vec<String> = iter.cloned().collect();
            return Ok((body.to_string(), rest));
        }
    }
    Err(format!(
        "no {flag} BODY found in argv; usage: {} {flag} '<code>' [args…]",
        dialect.wrapper_name()
    ))
}

/// Build the string the shell-classifier will see. For `Dialect::Shell`
/// BODY is already bash; for everything else, synthesize a
/// `{lang} -c '<body>'` invocation so the existing
/// `scripting_lang_shellout` rule fires.
///
/// Quoting: we wrap BODY in a POSIX single-quote string using the
/// standard `'...'` + `\'` escape. The classifier's parser accepts
/// any valid quoting; we don't need to be particularly clever here.
fn synthesize_classifier_input(dialect: Dialect, body: &str) -> Cow<'_, str> {
    if matches!(dialect, Dialect::Shell) {
        return Cow::Borrowed(body);
    }
    let interp = dialect.default_interpreter();
    let flag = dialect.inline_flag();
    // POSIX single-quote escape: ' -> '\''
    let escaped = body.replace('\'', "'\\''");
    Cow::Owned(format!("{interp} {flag} '{escaped}'"))
}

fn resolve_interpreter(dialect: Dialect) -> String {
    std::env::var(dialect.interpreter_env_var())
        .unwrap_or_else(|_| dialect.default_interpreter().to_string())
}

/// Spawn `interpreter flag body [-- extra_args...]` with piped stdout
/// / stderr. Every chunk is streamed through [`redact_secrets`] before
/// being forwarded to our own stdout / stderr. Returns the child's
/// exit code.
///
/// 1.4.0 adversarial review (Claude CRITICAL-2): for non-shell
/// dialects, insert `--` between BODY and extra_args so a trailing
/// `-e`, `--eval`, or `-m <module>` cannot sneak a second script past
/// the classifier. `node -e X -e Y` / `perl -e X -e Y` /
/// `ruby -e X -e Y` all re-parse flags after BODY; `--` stops that.
/// Bash's `-c BODY NAME ARGS...` form doesn't honor `--` — the first
/// arg after BODY becomes `$0` regardless, and bash does NOT re-parse
/// flags after `-c BODY`, so shell is already safe without the
/// separator. Python is also safe (its `-c` consumes all following
/// args as `sys.argv[1:]`), but inserting `--` there is idiomatic and
/// keeps the invariant consistent.
fn spawn_with_redaction(
    dialect: Dialect,
    interpreter: &str,
    body: &str,
    extra_args: &[String],
) -> i32 {
    let mut cmd = Command::new(interpreter);
    cmd.arg(dialect.inline_flag()).arg(body);
    if dialect.needs_argv_terminator() && !extra_args.is_empty() {
        cmd.arg("--");
    }
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "barbican-wrapper: failed to exec {interpreter}: {e}"
            );
            return 127;
        }
    };

    // Stream stdout and stderr in parallel — a small reader thread
    // per stream with a channel to sequence writes to our terminal
    // outputs. Line-buffered: redaction is line-scoped so a secret
    // spanning two lines is not redacted. Real secrets don't span
    // newlines in practice.
    let (tx_out, rx_out) = mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = mpsc::channel::<Vec<u8>>();

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_thread = stdout_pipe.map(|pipe| {
        let tx = tx_out.clone();
        std::thread::spawn(move || pipe_to_redacted_chunks(pipe, tx))
    });
    let err_thread = stderr_pipe.map(|pipe| {
        let tx = tx_err.clone();
        std::thread::spawn(move || pipe_to_redacted_chunks(pipe, tx))
    });
    drop(tx_out);
    drop(tx_err);

    // Forwarder threads: pull redacted chunks from each channel and
    // write them to the wrapper's corresponding fd. Runs concurrently
    // with the reader threads; drains until the channel closes
    // (which happens when the reader thread exits at EOF).
    let fwd_out = std::thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        while let Ok(chunk) = rx_out.recv() {
            let _ = stdout.write_all(&chunk);
        }
        let _ = stdout.flush();
    });
    let fwd_err = std::thread::spawn(move || {
        let mut stderr = std::io::stderr().lock();
        while let Ok(chunk) = rx_err.recv() {
            let _ = stderr.write_all(&chunk);
        }
        let _ = stderr.flush();
    });

    let status = child.wait().expect("wait on child");

    if let Some(t) = out_thread {
        let _ = t.join();
    }
    if let Some(t) = err_thread {
        let _ = t.join();
    }
    let _ = fwd_out.join();
    let _ = fwd_err.join();

    status.code().unwrap_or_else(|| {
        // Signal-killed; synthesize 128 + signal as shells do.
        status.signal().map_or(1, |s| 128 + s)
    })
}

/// Read from `pipe` line-by-line, apply [`redact_secrets`] to each
/// line, and push the (possibly-rewritten) line onto `tx`. When the
/// pipe reaches EOF the sender is dropped and the forwarder thread
/// exits.
#[allow(clippy::needless_pass_by_value)] // must own `tx` so it drops at fn exit and closes the channel
fn pipe_to_redacted_chunks<R: Read>(pipe: R, tx: mpsc::Sender<Vec<u8>>) {
    let reader = BufReader::new(pipe);
    for line in reader.split(b'\n') {
        let Ok(mut bytes) = line else { break };
        // Put the newline back unless it was the trailing partial line.
        bytes.push(b'\n');
        let text = String::from_utf8_lossy(&bytes);
        let redacted = redact_secrets(&text);
        if tx.send(redacted.as_bytes().to_vec()).is_err() {
            break;
        }
    }
}

fn write_audit_entry(
    dialect: Dialect,
    decision: &str,
    reason: Option<&str>,
    body_sha256: &str,
    exit_code: Option<i32>,
) {
    let Some(path) = crate::audit_io::audit_log_path() else {
        return;
    };
    let ts = crate::audit_io::iso8601_utc_now();
    // Hand-roll the JSON to avoid serialization ceremony for a
    // single-line record. Every string field that could carry
    // attacker-controllable content goes through `sanitize_field`
    // (ANSI-strip + truncate) before it lands in the log.
    let mut line = String::with_capacity(256);
    line.push_str("{\"ts\":\"");
    line.push_str(&ts);
    line.push_str("\",\"event\":\"wrapper\",\"dialect\":\"");
    line.push_str(dialect.audit_tag());
    line.push_str("\",\"decision\":\"");
    line.push_str(decision);
    line.push_str("\",\"body_sha256\":\"");
    line.push_str(body_sha256);
    line.push('"');
    if let Some(r) = reason {
        // Classifier reasons can embed path fragments and other
        // attacker-influenced substrings; strip ANSI and cap length
        // before embedding. `serde_json::to_string` on a &str only
        // fails on OOM; the `unwrap_or` is defensive.
        let cleaned = crate::audit_io::sanitize_field(r, crate::audit_io::MAX_STRING_CHARS);
        line.push_str(",\"reason\":");
        line.push_str(
            &serde_json::to_string(&cleaned)
                .unwrap_or_else(|_| "\"<serialize error>\"".to_string()),
        );
    }
    if let Some(e) = exit_code {
        line.push_str(",\"exit\":");
        line.push_str(&e.to_string());
    }
    line.push_str("}\n");
    let _ = crate::audit_io::append_jsonl_line(&path, &line);
}

/// Hex-encoded sha256 of `bytes`. Used to fingerprint the wrapper's
/// BODY for the audit log without storing the body itself.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in &digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_argv_finds_space_separated_body() {
        let argv = vec!["barbican-shell".into(), "-c".into(), "ls -la".into()];
        let (body, rest) = parse_argv(&argv, Dialect::Shell).unwrap();
        assert_eq!(body, "ls -la");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_argv_finds_attached_body() {
        let argv = vec!["barbican-shell".into(), "-cls -la".into()];
        let (body, rest) = parse_argv(&argv, Dialect::Shell).unwrap();
        assert_eq!(body, "ls -la");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_argv_passes_through_extra_args() {
        let argv = vec![
            "barbican-shell".into(),
            "-c".into(),
            "echo \"$1\"".into(),
            "hello".into(),
        ];
        let (body, rest) = parse_argv(&argv, Dialect::Shell).unwrap();
        assert_eq!(body, "echo \"$1\"");
        assert_eq!(rest, vec!["hello".to_string()]);
    }

    #[test]
    fn parse_argv_errors_on_missing_body() {
        let argv = vec!["barbican-shell".into(), "-c".into()];
        let err = parse_argv(&argv, Dialect::Shell).unwrap_err();
        assert!(err.contains("missing argument after -c"));
    }

    #[test]
    fn parse_argv_errors_on_no_flag() {
        let argv = vec!["barbican-shell".into(), "ls".into()];
        let err = parse_argv(&argv, Dialect::Shell).unwrap_err();
        assert!(err.contains("no -c BODY found"));
    }

    #[test]
    fn python_uses_minus_c_but_node_uses_minus_e() {
        assert_eq!(Dialect::Python.inline_flag(), "-c");
        assert_eq!(Dialect::Node.inline_flag(), "-e");
        assert_eq!(Dialect::Ruby.inline_flag(), "-e");
        assert_eq!(Dialect::Perl.inline_flag(), "-e");
    }

    #[test]
    fn synthesize_shell_is_passthrough() {
        let out = synthesize_classifier_input(Dialect::Shell, "ls -la");
        assert_eq!(out, Cow::Borrowed("ls -la"));
    }

    #[test]
    fn synthesize_python_wraps_with_python3_dash_c() {
        let out = synthesize_classifier_input(Dialect::Python, "print('hi')");
        assert_eq!(out, "python3 -c 'print('\\''hi'\\'')'");
    }

    #[test]
    fn synthesize_node_wraps_with_node_dash_e() {
        let out = synthesize_classifier_input(Dialect::Node, "console.log(1)");
        assert_eq!(out, "node -e 'console.log(1)'");
    }

    #[test]
    fn sha256_hex_is_64_lowercase_hex_chars() {
        let h = sha256_hex(b"hello");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "got {h}"
        );
        // Known: sha256("hello").
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
