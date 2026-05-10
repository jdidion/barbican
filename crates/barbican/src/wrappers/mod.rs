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
//! Before spawning the child, the wrapper installs `SIG_IGN` for
//! SIGINT, SIGTERM, and SIGHUP in its own process. It passes a
//! `pre_exec` hook that resets those three signals to `SIG_DFL` in
//! the child before `execve` so the child's usual handling is
//! preserved. This matches how `time(1)`, `sudo(1)`, and similar
//! transparent front-ends behave: SIGINT from the terminal reaches
//! both processes (they're in the same pgrp), but only the child
//! acts on it — the wrapper survives to `wait()`, capture the
//! child's exit code, and write the audit entry.
//!
//! After `wait()` returns, the wrapper restores `SIG_DFL` for the
//! same three signals (cosmetic, since it's about to exit anyway).
//! An explicit SIGKILL to the wrapper still terminates it; SIGKILL
//! cannot be ignored.
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
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;

use crate::hooks::pre_bash::{classify_command, Decision};
use crate::redact::redact_secrets_bytes;

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

    if let Decision::Deny { reason, detail } = decision {
        let _ = writeln!(std::io::stderr(), "{}: {reason}", dialect.wrapper_name(),);
        if let Some(d) = detail.as_deref() {
            let _ = writeln!(std::io::stderr(), "detail: {d}");
        }
        write_audit_entry(
            dialect,
            "deny",
            Some(&reason),
            detail.as_deref(),
            &body_sha256,
            None,
        );
        std::process::exit(EXIT_DENY);
    }

    // Allow path — spawn the interpreter with pipes and redact output.
    let interpreter = resolve_interpreter(dialect);
    let exit_code = spawn_with_redaction(dialect, &interpreter, &body, &extra_args);

    write_audit_entry(dialect, "allow", None, None, &body_sha256, Some(exit_code));
    std::process::exit(exit_code);
}

/// Parse wrapper argv into `(BODY, extra_args)`. Errors if the inline
/// flag is missing or has no BODY. Any args after BODY are returned
/// verbatim — the interpreter interprets them as positional args.
///
/// Handles three shapes:
/// - Space-separated: `barbican-shell -c "ls"` → BODY="ls"
/// - Attached: `barbican-shell -c"ls"` → BODY="ls"
/// - Bundled short options (shell only): `barbican-shell -ce "ls"` →
///   BODY="ls". Bash / sh / zsh parse `-ce` as `-c -e`; the wrapper
///   has to do the same or `-ce` misparses as `-cBODY=e`. Detected
///   by: token starts with `-`, is longer than `-<flag_letter>`,
///   contains the flag letter, and does NOT strip cleanly into a
///   `-c<body>` form that would be a valid non-empty BODY. Non-shell
///   dialects (python/node/ruby/perl) don't bundle `-e` in practice,
///   so we don't apply the bundled-option heuristic there.
///
/// 1.4.0 crew review (gpt-5.2 WARNING).
fn parse_argv(argv: &[String], dialect: Dialect) -> Result<(String, Vec<String>), String> {
    let flag = dialect.inline_flag();
    let flag_letter = flag.as_bytes()[1]; // `-c` → b'c', `-e` → b'e'
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
        // Bundled shell short-options: `-ce`, `-ec`, `-cex`, etc.
        // Shape: starts with `-`, not just `--`, contains flag_letter,
        // and every char after `-` is a single-letter short option
        // (ASCII alphabetic). Only applies to shell; other dialects
        // don't mix flag letters with BODY in a single token.
        if dialect == Dialect::Shell && arg.starts_with('-') && arg.len() >= 3 {
            let after_dash = &arg.as_bytes()[1..];
            let is_bundle = !arg.starts_with("--")
                && after_dash.iter().all(u8::is_ascii_alphabetic)
                && after_dash.contains(&flag_letter);
            if is_bundle {
                // BODY is the next arg.
                let body = iter
                    .next()
                    .ok_or_else(|| format!("missing argument after {arg}"))?;
                let rest: Vec<String> = iter.cloned().collect();
                return Ok((body.clone(), rest));
            }
        }
        // Attached form: `-cBODY` / `-eBODY`.
        if let Some(body) = arg.strip_prefix(flag) {
            if body.is_empty() {
                continue;
            }
            let rest: Vec<String> = iter.cloned().collect();
            return Ok((body.to_string(), rest));
        }
        // 1.4.0 second crew review (Gemini WARNING-3): an arg before
        // the inline flag is either dropped (old behavior — broke
        // transparency) or passed through to the interpreter
        // (dangerous — `bash --init-file /tmp/evil.sh -c BODY` would
        // source an attacker-chosen init file before classified BODY
        // runs). Deny-by-default: refuse unrecognized pre-flag tokens.
        // The classifier cannot reason about pre-flag interpreter
        // flags, so the safe default is to reject the invocation.
        return Err(format!(
            "unrecognized argument before {flag}: `{arg}`; the wrapper only \
             accepts `[{flag} BODY] [ARGS…]` — use the underlying interpreter \
             directly if you need its pre-BODY flags"
        ));
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
#[must_use]
pub fn synthesize_classifier_input(dialect: Dialect, body: &str) -> Cow<'_, str> {
    if matches!(dialect, Dialect::Shell) {
        return Cow::Borrowed(body);
    }
    let interp = dialect.default_interpreter();
    let flag = dialect.inline_flag();
    // POSIX single-quote escape: ' -> '\''
    let escaped = body.replace('\'', "'\\''");
    Cow::Owned(format!("{interp} {flag} '{escaped}'"))
}

/// Resolve which interpreter binary the wrapper will exec.
///
/// Policy:
/// - If the per-dialect env var (e.g. `BARBICAN_SHELL`) is set, it
///   MUST be an absolute path. A bare basename (`BARBICAN_SHELL=bash`)
///   would go through `$PATH` lookup, which the caller controls —
///   `PATH=/tmp/evil:/usr/bin` then `barbican-shell …` would exec
///   the attacker's planted `/tmp/evil/bash`. The env var is a power
///   tool for sysadmins pointing at a specific interpreter; users
///   who just want "whatever bash is on PATH" should leave it unset.
/// - If unset, fall back to the default basename (`bash`, `python3`,
///   etc.). `Command::new("bash")` does go through `$PATH`, but the
///   default path is a trust boundary set by the install environment
///   (Homebrew, distro packaging), not by a Claude Code session
///   mid-run. SECURITY.md documents this explicitly as "caller
///   controls `$PATH` is out of scope — run Barbican under a trusted
///   parent shell" (1.4.0 crew review, Claude WARNING-4).
///
/// On absolute-path-violation, we log to stderr and exit 2 (same
/// code as classifier deny) so the failure is visible to the caller
/// and no interpreter is spawned.
fn resolve_interpreter(dialect: Dialect) -> String {
    let env_var = dialect.interpreter_env_var();
    match std::env::var(env_var) {
        Ok(v) => {
            let path = std::path::Path::new(&v);
            if !path.is_absolute() {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}: ${env_var}=`{v}` must be an absolute path; \
                     refusing to resolve via $PATH (1.4.0 crew review)",
                    dialect.wrapper_name()
                );
                std::process::exit(EXIT_DENY);
            }
            // 1.4.0 second crew review (Claude SUG-2): `is_absolute`
            // accepts `/usr/bin/../../tmp/evil/bash`. Reject any `..`
            // component so a caller who manages to set an
            // attacker-chosen env value can't escape via traversal.
            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}: ${env_var}=`{v}` contains `..` path components; refusing",
                    dialect.wrapper_name()
                );
                std::process::exit(EXIT_DENY);
            }
            v
        }
        Err(_) => dialect.default_interpreter().to_string(),
    }
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

    // 1.4.0 adversarial review (all three reviewers): the module docs
    // claim "wrapper ignores SIGINT so the terminal keeps sending it
    // to the child only" — but without the call we're about to make,
    // that's a lie. Ctrl-C in the foreground process group reaches
    // both wrapper and child; the wrapper dies first (default SIGINT
    // handler), the child is orphaned, `wait()` never returns, and
    // the allow-path audit entry is never written.
    //
    // Fix: set SIGINT (and SIGTERM/SIGHUP for symmetry) to SIG_IGN
    // in the wrapper, and use `pre_exec` to reset them to SIG_DFL in
    // the child. POSIX preserves SIG_IGN across `execve`; without
    // the pre_exec reset, the child would also inherit the
    // ignore-handler and become uninterruptible.
    //
    // 1.5.2 crew-review CRITICAL (Claude + GPT-5.2): this block uses
    // `sigaction` (POSIX-standard, well-defined semantics) instead
    // of `signal` (legacy, historically ambiguous), checks every
    // return value so a failed install surfaces on stderr, and
    // installs a `SignalGuard` that restores the original
    // disposition on drop. That means EVERY early return below
    // (spawn failure, interpreter-resolution panic, any future
    // error path) automatically restores the parent's SIGINT /
    // SIGTERM / SIGHUP handlers — no more signal-set leak.
    //
    // SAFETY: `pre_exec` runs between `fork` and `execve` in the
    // child, a context where only async-signal-safe calls are
    // permitted. `sigaction` is listed as async-signal-safe in
    // POSIX.1-2008 § System Interfaces → sigaction(). We call
    // nothing else in pre_exec. In the wrapper itself, `sigaction`
    // is the POSIX signal-handler installer — safe to call from any
    // thread at any time. The saved `sigaction_t` inside
    // `SignalGuard` is POD and safe to carry across the Drop.
    let _signal_guard = install_signal_guard(&mut cmd);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "barbican-wrapper: failed to exec {interpreter}: {e}"
            );
            // `_signal_guard` drops here and restores parent handlers
            // — before 1.5.2 this was a signal-set leak (parent
            // continued with SIG_IGN on SIGINT/TERM/HUP).
            return 127;
        }
    };

    // Stream stdout and stderr in parallel — a small reader thread
    // per stream with a channel to sequence writes to our terminal
    // outputs. Line-buffered: redaction is line-scoped so a secret
    // spanning two lines is not redacted. Real secrets don't span
    // newlines in practice.
    // 1.4.0 crew review (gpt-5.2 WARNING): unbounded `mpsc::channel`
    // let a fast-writing child grow the wrapper's RSS unboundedly if
    // the terminal forwarder couldn't keep up. Use bounded
    // `sync_channel(64)` — 64 buffered chunks × ~8KB typical line
    // = ~512KB of in-flight per stream, which is plenty for realistic
    // human-scale output and a hard cap against a DoS child.
    let (tx_out, rx_out) = mpsc::sync_channel::<Vec<u8>>(64);
    let (tx_err, rx_err) = mpsc::sync_channel::<Vec<u8>>(64);

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

    // 1.5.2 crew-review CRITICAL (Claude + GPT-5.2): previous code
    // used `.expect("wait on child")`, which panics if
    // `Child::wait` returns an I/O error. A panic in the wrapper
    // kills the user's Claude Code session with an unclean stderr
    // dump — the exact DoS a safety-tool runtime must avoid. Handle
    // the error explicitly: log to stderr, still run the post-wait
    // cleanup (thread joins, signal reset, audit entry), and return
    // a conservative exit code (1) so the caller sees failure.
    let wait_result = child.wait();

    // Always run cleanup regardless of wait success/failure — the
    // threads and signal handlers need to unwind cleanly.
    if let Some(t) = out_thread {
        let _ = t.join();
    }
    if let Some(t) = err_thread {
        let _ = t.join();
    }
    let _ = fwd_out.join();
    let _ = fwd_err.join();

    // Signal handlers are restored when `_signal_guard` drops (end
    // of function). 1.5.2: previously this path had its own
    // `libc::signal(SIG_DFL)` block; the guard makes it redundant.

    match wait_result {
        Ok(status) => status.code().unwrap_or_else(|| {
            // Signal-killed; synthesize 128 + signal as shells do.
            status.signal().map_or(1, |s| 128 + s)
        }),
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "{}: wait on child failed: {e}",
                dialect.wrapper_name()
            );
            // Conservative exit: the child's true status is unknown.
            // `1` is shell-convention for "something went wrong."
            1
        }
    }
}

/// RAII guard that installs `SIG_IGN` for SIGINT/SIGTERM/SIGHUP in
/// the current process, and restores the previous disposition on
/// drop. Also registers a `pre_exec` hook on the command so the
/// child resets the three signals to `SIG_DFL` between `fork` and
/// `execve` (POSIX preserves `SIG_IGN` across `execve` otherwise, so
/// without the pre_exec the child would also inherit the ignore
/// handler and be uninterruptible).
///
/// 1.5.2 crew-review CRITICAL (Claude + GPT-5.2): before this guard
/// the wrapper used `libc::signal` directly, (a) ignored return
/// values (missing `SIG_ERR` handling), (b) never restored handlers
/// if the subsequent `spawn()` failed, (c) conflated single-thread
/// correctness with async-signal-safety in SAFETY comments. This
/// type replaces that pattern with `sigaction` (POSIX-standard,
/// well-defined across multi-threaded parents) + Drop-based
/// restoration. Every early return from `spawn_with_redaction` now
/// automatically restores the parent's signal dispositions.
struct SignalGuard {
    /// Saved `sigaction` for each of our three signals. `None` means
    /// the install failed — nothing to restore.
    saved: [Option<(libc::c_int, libc::sigaction)>; 3],
}

impl SignalGuard {
    /// The three signals we ignore in the wrapper parent.
    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // Restore each saved disposition. Any failure here is
        // logged to stderr and ignored (we're on the drop path
        // and cannot propagate).
        for slot in &self.saved {
            if let Some((signum, ref prev)) = *slot {
                // SAFETY: `sigaction(signum, &prev, NULL)` restores
                // the previously-saved handler. Both `signum` and
                // `prev` came from a successful install call below,
                // so the types match. `sigaction` is async-signal-
                // safe per POSIX.1-2008 § sigaction.
                #[allow(unsafe_code)]
                let rc = unsafe { libc::sigaction(signum, &raw const *prev, std::ptr::null_mut()) };
                if rc != 0 {
                    let _ = writeln!(
                        std::io::stderr(),
                        "barbican-wrapper: failed to restore handler for signal {signum}: {}",
                        std::io::Error::last_os_error(),
                    );
                }
            }
        }
    }
}

/// Install SIG_IGN on the three wrapper-ignored signals and register
/// a `pre_exec` that resets them to SIG_DFL in the child. Returns a
/// `SignalGuard` that restores the saved dispositions when it drops.
///
/// 1.5.3 Rust-expert review (Gemini CRITICAL): refactored to narrow
/// `unsafe` blocks to the individual FFI calls that need them, rather
/// than wrapping the whole function body. Each `unsafe` has its own
/// dedicated SAFETY comment explaining the specific contract, and
/// the `pre_exec` closure has an internal SAFETY comment for its
/// post-fork async-signal-safety guarantees (separate from the
/// parent-side install, which runs in a normal thread context).
fn install_signal_guard(cmd: &mut Command) -> SignalGuard {
    let mut saved: [Option<(libc::c_int, libc::sigaction)>; 3] = [None, None, None];

    for (i, &signum) in SignalGuard::SIGNALS.iter().enumerate() {
        // SAFETY: `libc::sigaction` is POD; zero-initialization via
        // `MaybeUninit::zeroed()` produces a valid-but-nulled struct.
        // The constant `SIG_IGN` is written into the handler slot
        // before the struct is handed to the OS.
        #[allow(unsafe_code)]
        let mut new_action: libc::sigaction =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // Portable way to assign SIG_IGN: the `sa_sigaction` /
        // `sa_handler` union's `sa_handler` slot holds a function
        // pointer whose integer value is SIG_IGN. `libc` exposes it
        // via the `sa_sigaction` field.
        new_action.sa_sigaction = libc::SIG_IGN;
        // SAFETY: sigemptyset initializes the sa_mask set-type
        // through a stable POSIX API. The pointer is derived from
        // our owned local; no aliasing issues.
        #[allow(unsafe_code)]
        unsafe {
            libc::sigemptyset(&raw mut new_action.sa_mask);
        }
        new_action.sa_flags = 0;

        // SAFETY: same POD-zeroed argument for `old_action`. The
        // OS will overwrite it on successful sigaction().
        #[allow(unsafe_code)]
        let mut old_action: libc::sigaction =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        // SAFETY: `sigaction(2)` is the POSIX-standard signal-handler
        // installer, explicitly safe to call from any thread at any
        // time (POSIX.1-2008 § XSH 2.4.3). We pass a read-only
        // pointer to our fully-populated `new_action` and a
        // writable pointer to our owned `old_action` for the old
        // disposition save. Both pointers are derived from locals
        // we own exclusively within this loop iteration.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::sigaction(signum, &raw const new_action, &raw mut old_action) };
        if rc == 0 {
            saved[i] = Some((signum, old_action));
        } else {
            let _ = writeln!(
                std::io::stderr(),
                "barbican-wrapper: failed to install SIG_IGN for signal {signum}: {}",
                std::io::Error::last_os_error(),
            );
            // Leave saved[i] = None so Drop skips restoration for
            // this signal — nothing changed, nothing to undo. The
            // wrapper continues in a slightly-less-ideal state but
            // does not panic.
        }
    }

    // Child reset: between `fork(2)` and `execve(2)`, restore
    // SIG_DFL on the three signals so the child remains
    // interruptible. `pre_exec` is executed in the forked child
    // before exec, so only async-signal-safe calls are permitted.
    //
    // SAFETY: `pre_exec` itself is unsafe because the closure runs
    // in a post-fork, pre-exec context where calling most libc
    // functions is undefined behavior. Our closure only calls
    // `sigaction` and `sigemptyset`, both of which are on the
    // POSIX.1-2008 async-signal-safe list (§ XSH 2.4.3). We do not
    // touch heap, shared memory, locks, stdio, or allocation. We
    // capture zero closure environment beyond the SIGNALS constant.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            for &signum in &SignalGuard::SIGNALS {
                // SAFETY: zeroed POD, same rationale as parent.
                let mut dfl_action: libc::sigaction = std::mem::MaybeUninit::zeroed().assume_init();
                dfl_action.sa_sigaction = libc::SIG_DFL;
                // SAFETY: sigemptyset is on the POSIX AS-safe list.
                libc::sigemptyset(&raw mut dfl_action.sa_mask);
                dfl_action.sa_flags = 0;
                // SAFETY: sigaction is on the POSIX AS-safe list.
                // If the call fails here, there is nothing safe we
                // can do — we're post-fork, pre-exec, with no
                // stderr to write to without violating async-signal-
                // safety. The child will inherit whatever
                // disposition we failed to change; in the worst
                // case it inherits SIG_IGN from the parent, which
                // is still recoverable (the user can SIGKILL).
                let _ = libc::sigaction(signum, &raw const dfl_action, std::ptr::null_mut());
            }
            Ok(())
        });
    }

    SignalGuard { saved }
}

/// Read from `pipe` line-by-line, apply [`redact_secrets`] to each
/// line, and push the (possibly-rewritten) line onto `tx`. When the
/// pipe reaches EOF the sender is dropped and the forwarder thread
/// exits.
///
/// 1.4.0 adversarial review (all three reviewers): uses
/// `BufRead::read_until(b'\n', …)` rather than `split(b'\n')` so the
/// trailing newline is preserved when present and NOT fabricated when
/// absent. `split` strips the delimiter unconditionally and leaves
/// the caller unable to tell whether the last chunk was newline-
/// terminated — a child that writes `printf 'x'` must see its output
/// reach our stdout as exactly `x`, not `x\n`.
/// Hard cap on bytes buffered before a forced flush. A child that
/// writes without newlines (e.g. a long `printf` or tight binary
/// loop) would otherwise grow `buf` unboundedly — the `sync_channel`
/// bound only controls inter-thread queue depth, not intra-buffer
/// growth. 1 MiB is generous for any realistic line and keeps a
/// pathological child from blowing wrapper RSS.
///
/// 1.4.0 second crew review (gpt-5.2 CRITICAL): discovered as a
/// regression of CRITICAL-C's `read_until` switch — the unbounded
/// grow-until-newline loop was a new DoS vector.
const MAX_LINE_BYTES: usize = 1024 * 1024;

#[allow(clippy::needless_pass_by_value)] // must own `tx` so it drops at fn exit and closes the channel
fn pipe_to_redacted_chunks<R: Read>(pipe: R, tx: mpsc::SyncSender<Vec<u8>>) {
    let mut reader = BufReader::new(pipe);
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    // 1.5.2 crew-review CRITICAL (GPT-5.2): previous implementation
    // read one byte at a time to enforce the MAX_LINE_BYTES cap; even
    // with `BufReader`'s 8KB internal buffer, the per-byte branch /
    // bounds-check / Vec::push overhead made this CPU-heavy on
    // fast-writing children. Use `read_until(b'\n', …)` over a
    // *bounded* reader that yields at most `MAX_LINE_BYTES + 1 -
    // buf.len()` bytes per attempt; when the take-limit is hit
    // without a newline we flush the partial line (mid-line
    // truncation preserves the memory cap) and continue.
    loop {
        let remaining = MAX_LINE_BYTES.saturating_sub(buf.len());
        // Guaranteed >= 1 because we clear `buf` after each flush.
        // Add 1 to the take budget so a read that lands exactly on
        // `\n` at position `MAX_LINE_BYTES` still terminates the
        // line cleanly.
        let budget = (remaining.saturating_add(1)) as u64;
        let starting_len = buf.len();
        match (&mut reader).take(budget).read_until(b'\n', &mut buf) {
            Ok(0) => {
                // EOF — flush any trailing partial line and exit.
                if !buf.is_empty() {
                    let redacted = redact_secrets_bytes(&buf);
                    let _ = tx.send(redacted.into_owned());
                }
                break;
            }
            Ok(_n) => {
                // Check terminating condition. We flush if:
                //   (a) the last byte read is `\n` (full line), OR
                //   (b) `buf` has reached / exceeded `MAX_LINE_BYTES`
                //       without a newline (mid-line cap flush).
                // Otherwise the take-limit was shorter than expected
                // (should not happen; read_until with take always
                // returns 0 or a nonzero including trailing `\n`).
                let last_is_newline = buf.last().copied() == Some(b'\n');
                let at_cap = buf.len() >= MAX_LINE_BYTES;
                if last_is_newline || at_cap {
                    let redacted = redact_secrets_bytes(&buf);
                    if tx.send(redacted.into_owned()).is_err() {
                        break;
                    }
                    buf.clear();
                } else {
                    // No newline, not at cap — this can only happen
                    // if the underlying reader returned a short
                    // read. The next loop iteration will resume.
                    // Defensive: if we made zero progress, bail to
                    // avoid a tight spin.
                    if buf.len() == starting_len {
                        break;
                    }
                }
            }
            // I/O error — pipe broken.
            Err(_) => break,
        }
    }
}

fn write_audit_entry(
    dialect: Dialect,
    decision: &str,
    reason: Option<&str>,
    detail: Option<&str>,
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
    if let Some(d) = detail {
        let cleaned = crate::audit_io::sanitize_field(d, crate::audit_io::MAX_STRING_CHARS);
        line.push_str(",\"detail\":");
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

    /// 1.4.0 crew review (gpt-5.2 WARNING): `bash -ce 'cmd'` is a
    /// common shell-compatibility shape. The naive attached-form
    /// parser misreads `-ce` as `-cBODY=e`; the real BODY in the
    /// next arg goes unclassified. Pin the bundle-aware handling.
    #[test]
    fn parse_argv_handles_bundled_ce_flag_for_shell() {
        let argv = vec!["barbican-shell".into(), "-ce".into(), "ls -la".into()];
        let (body, rest) = parse_argv(&argv, Dialect::Shell).unwrap();
        assert_eq!(body, "ls -la");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_argv_handles_bundled_ec_flag_for_shell() {
        let argv = vec!["barbican-shell".into(), "-ec".into(), "ls -la".into()];
        let (body, rest) = parse_argv(&argv, Dialect::Shell).unwrap();
        assert_eq!(body, "ls -la");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_argv_handles_bundled_multi_flag_for_shell() {
        // `-cex` = `-c -e -x`; BODY in next arg.
        let argv = vec!["barbican-shell".into(), "-cex".into(), "echo hi".into()];
        let (body, rest) = parse_argv(&argv, Dialect::Shell).unwrap();
        assert_eq!(body, "echo hi");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_argv_does_not_bundle_non_shell_dialects() {
        // For python/node/ruby/perl, `-el` is NOT a bundled-option
        // form; `-e` is always attached-to-BODY. The heuristic must
        // not fire and consume the next arg as BODY.
        let argv = vec![
            "barbican-node".into(),
            "-el".into(),
            "console.log(1)".into(),
        ];
        // `-el` tries attached form → BODY="l", extra=["console.log(1)"].
        // This is harmless — the classifier sees "l", node gets
        // `-e l console.log(1)` which is a node error. Pin that the
        // wrapper does NOT interpret `-el` as bundled + consume next.
        let (body, _rest) = parse_argv(&argv, Dialect::Node).unwrap();
        assert_eq!(body, "l", "non-shell must not apply bundle heuristic");
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
        // 1.4.0 second crew review (Gemini WARNING-3): pre-flag args
        // now trigger a dedicated "unrecognized argument before -c"
        // message; the bare no-args case is still the old error.
        assert!(
            err.contains("unrecognized argument before -c") || err.contains("no -c BODY"),
            "err: {err}"
        );
    }

    #[test]
    fn parse_argv_rejects_init_file_smuggling_before_c() {
        // Deny-by-default: pre-flag interpreter flags could source an
        // attacker-chosen file before BODY runs.
        let argv = vec![
            "barbican-shell".into(),
            "--init-file".into(),
            "/tmp/evil".into(),
            "-c".into(),
            "echo hi".into(),
        ];
        let err = parse_argv(&argv, Dialect::Shell).unwrap_err();
        assert!(
            err.contains("unrecognized argument before -c"),
            "err: {err}"
        );
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
