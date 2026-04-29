//! Bash parser + IR used by every composition classifier.
//!
//! Wrapper around `tree-sitter-bash`. A single parser choice, with
//! `tree.root_node().has_error()` as the hard-deny signal per
//! CLAUDE.md rule #1 (deny by default). There is no regex fallback.
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
//! - `case` / `if` / `while` / `for` bodies — they parse but don't
//!   surface as first-class IR yet. Classifiers that care must walk
//!   the raw tree-sitter tree until a later phase.
//!
//! Parser edge cases that we deliberately hard-deny (documented in
//! SECURITY.md §Known parser limits):
//! - Any input that `tree-sitter-bash` reports with `has_error()`,
//!   including unterminated quotes, unmatched parens, truncated heredocs.
//! - Any input that parses cleanly but contains node kinds we don't yet
//!   traverse is reported through the tree but may result in missing
//!   substitution/redirect entries; classifiers treat "missing"
//!   conservatively and the integration test suite catches regressions.

use tree_sitter::{Node, Parser, Tree};

use crate::cmd::cmd_basename;

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
    /// `argv[0]` after [`cmd_basename`] + surrounding-quote strip.
    /// This is the string classifiers match against [`crate::tables`] sets.
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
}

/// A redirect attached to a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    /// Raw text of the redirect target: a filename for file redirects,
    /// the here-string body for `<<<`, the delimiter for a heredoc,
    /// the wrapped command for a process substitution.
    pub target: String,
}

/// Classification of a redirect operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    /// `> file`, `2> file`, `&> file`, `>> file`.
    OutFile { append: bool },
    /// `< file`.
    InFile,
    /// `<<< string`.
    HereString,
    /// `<< EOF ... EOF`.
    Heredoc,
    /// `<(...)` or `>(...)` — the inner command also appears in the
    /// parent command's `substitutions` list.
    ProcessSubstitution,
}

/// Parser failure mode. Every variant is a hard deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Could not load the bash grammar. Treat as system error, but
    /// still deny — we cannot classify anything.
    ParserInit,
    /// The parser emitted at least one `ERROR` or `MISSING` node.
    /// Could be attacker-crafted unterminated quoting, or could be
    /// benign exotic syntax. Barbican denies either way.
    Malformed,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParserInit => write!(f, "bash parser failed to initialize"),
            Self::Malformed => write!(
                f,
                "bash input could not be parsed cleanly (ERROR or MISSING node) \
                 — denied by default"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse `input` as a bash script.
///
/// Errors:
/// - [`ParseError::ParserInit`] if the tree-sitter-bash language fails
///   to load (shouldn't happen in practice; the grammar is statically
///   linked).
/// - [`ParseError::Malformed`] if the parser produced an error tree
///   — hard-deny per CLAUDE.md rule #1.
pub fn parse(input: &str) -> Result<Script, ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| ParseError::ParserInit)?;

    let tree = parser.parse(input, None).ok_or(ParseError::ParserInit)?;
    if tree.root_node().has_error() {
        return Err(ParseError::Malformed);
    }

    let src = input.as_bytes();
    Ok(walk_program(&tree, src))
}

/// Walk the `program` root and collect every pipeline.
fn walk_program(tree: &Tree, src: &[u8]) -> Script {
    let mut script = Script::default();
    let root = tree.root_node();
    for child in named_children(root) {
        walk_statement(child, src, &mut script.pipelines);
    }
    script
}

/// Recurse into a single top-level statement, appending any pipelines
/// it contains to `out`.
///
/// tree-sitter-bash's node kinds we care about:
/// - `pipeline`: `a | b | c`
/// - `command`: a bare simple command
/// - `redirected_statement`: wraps a command or pipeline with trailing
///   redirects, e.g. `echo hi > file`
/// - `list`: `a ; b`, `a && b`, `a || b`
/// - `compound_statement`, `subshell`, `if_statement`, `while_statement`,
///   `for_statement`, `function_definition`, `case_statement`: recurse
///   into their bodies so we pick up nested commands. Not first-class
///   IR in Phase 1; they flatten into the surrounding pipeline list.
fn walk_statement(node: Node<'_>, src: &[u8], out: &mut Vec<Pipeline>) {
    match node.kind() {
        "pipeline" => out.push(walk_pipeline(node, src)),
        "command" => out.push(Pipeline {
            stages: vec![walk_command(node, src)],
        }),
        "redirected_statement" => {
            let body = node
                .child_by_field_name("body")
                .unwrap_or_else(|| named_children(node).next().unwrap_or(node));
            let redirects = collect_redirects(node, src);

            match body.kind() {
                "pipeline" => {
                    let mut p = walk_pipeline(body, src);
                    if let Some(last) = p.stages.last_mut() {
                        last.redirects.extend(redirects);
                    }
                    out.push(p);
                }
                "command" => {
                    let mut c = walk_command(body, src);
                    c.redirects.extend(redirects);
                    out.push(Pipeline { stages: vec![c] });
                }
                _ => {
                    // Unrecognized body — recurse; attached redirects
                    // are lost in this phase. Documented limit.
                    walk_statement(body, src, out);
                }
            }
        }
        "variable_assignment" | "declaration_command" | "unset_command" | "comment" => {
            // Not attack-interesting. Classifier may re-walk the tree
            // in later phases if variable tracking is needed.
        }
        // `list`, compound/subshell/function/if/while/until/for/case:
        // recurse into named children so nested commands surface as
        // top-level pipelines. Also the catch-all for grammar node
        // kinds we haven't enumerated — defensive recursion beats
        // silent drop.
        _ => {
            for child in named_children(node) {
                walk_statement(child, src, out);
            }
        }
    }
}

fn walk_pipeline(node: Node<'_>, src: &[u8]) -> Pipeline {
    let mut stages = Vec::with_capacity(2);
    for child in named_children(node) {
        match child.kind() {
            "command" => stages.push(walk_command(child, src)),
            "redirected_statement" => {
                let body = child
                    .child_by_field_name("body")
                    .unwrap_or_else(|| named_children(child).next().unwrap_or(child));
                let redirects = collect_redirects(child, src);
                if body.kind() == "command" {
                    let mut c = walk_command(body, src);
                    c.redirects.extend(redirects);
                    stages.push(c);
                }
            }
            _ => {}
        }
    }
    Pipeline { stages }
}

fn walk_command(node: Node<'_>, src: &[u8]) -> Command {
    let mut cmd = Command::default();

    // argv[0] comes from the `command_name` field.
    if let Some(name_node) = node.child_by_field_name("name") {
        let raw = extract_word_text(name_node, src);
        cmd.basename = cmd_basename(strip_surrounding_quotes(&raw)).to_string();
        cmd.argv0_raw = raw;
        // Substitutions nested inside the command name itself.
        collect_substitutions(name_node, src, &mut cmd.substitutions);
    }

    // Remaining argv: every `argument`-field child, plus inline
    // redirects collected into the redirects vec.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // `child_by_field_name` only yields one; iterate all children
        // so repeated fields like `argument` all show up.
        if !child.is_named() {
            continue;
        }
        if is_redirect_kind(child.kind()) {
            if let Some(r) = redirect_from_node(child, src) {
                cmd.redirects.push(r);
            }
            // A process substitution also contributes a sub-script.
            collect_substitutions(child, src, &mut cmd.substitutions);
            continue;
        }
        if node
            .child_by_field_name("name")
            .is_some_and(|n| n.id() == child.id())
        {
            // Already consumed as argv[0].
            continue;
        }
        // Treat every remaining non-redirect named child as an argument.
        cmd.args.push(extract_word_text(child, src));
        collect_substitutions(child, src, &mut cmd.substitutions);
    }

    cmd
}

/// Return `true` if the node kind is any of tree-sitter-bash's redirect
/// nodes.
const fn is_redirect_kind(kind: &str) -> bool {
    matches!(
        kind.as_bytes(),
        b"file_redirect" | b"herestring_redirect" | b"heredoc_redirect",
    )
}

/// Build a [`Redirect`] from a tree-sitter redirect node, or `None` if
/// the node is something we don't yet model.
fn redirect_from_node(node: Node<'_>, src: &[u8]) -> Option<Redirect> {
    match node.kind() {
        "file_redirect" => {
            let op_text = redirect_operator_text(node, src);
            let append = op_text.starts_with(">>") || op_text == "&>>";
            let is_out = op_text.contains('>');
            let kind = if is_out {
                RedirectKind::OutFile { append }
            } else {
                RedirectKind::InFile
            };
            let target = node
                .child_by_field_name("destination")
                .map(|n| extract_word_text(n, src))
                .unwrap_or_default();
            Some(Redirect { kind, target })
        }
        "herestring_redirect" => {
            let target = node
                .child_by_field_name("value")
                .or_else(|| named_children(node).last())
                .map(|n| extract_word_text(n, src))
                .unwrap_or_default();
            Some(Redirect {
                kind: RedirectKind::HereString,
                target,
            })
        }
        "heredoc_redirect" => Some(Redirect {
            kind: RedirectKind::Heredoc,
            target: node
                .child_by_field_name("delimiter")
                .map(|n| extract_word_text(n, src))
                .unwrap_or_default(),
        }),
        _ => None,
    }
}

/// Collect every trailing redirect on a `redirected_statement`.
fn collect_redirects(node: Node<'_>, src: &[u8]) -> Vec<Redirect> {
    let mut out = Vec::new();
    for child in named_children(node) {
        if is_redirect_kind(child.kind()) {
            if let Some(r) = redirect_from_node(child, src) {
                out.push(r);
            }
        }
    }
    out
}

/// Extract the unquoted, unexpanded text that best represents this
/// word's shell-level value. For Phase 1 this is best-effort:
/// - `word` → raw bytes.
/// - `string` / `raw_string` → stripped of surrounding quotes.
/// - `concatenation` → each child recursively and concatenated.
/// - everything else → raw bytes.
fn extract_word_text(node: Node<'_>, src: &[u8]) -> String {
    match node.kind() {
        "string" | "raw_string" | "ansi_c_string" => {
            let raw = raw_text(node, src);
            strip_surrounding_quotes(raw).to_string()
        }
        "concatenation" => {
            let mut s = String::new();
            for child in named_children(node) {
                s.push_str(&extract_word_text(child, src));
            }
            s
        }
        // `word`, `simple_expansion`, `expansion`, and every other node
        // kind we don't specialize: use the raw byte slice from source.
        _ => raw_text(node, src).to_string(),
    }
}

/// Find every `$(...)` / `` `...` `` / `<(...)` / `>(...)` inside the
/// subtree rooted at `node` and append each one, fully parsed, to `out`.
fn collect_substitutions(node: Node<'_>, src: &[u8], out: &mut Vec<Script>) {
    match node.kind() {
        "command_substitution" | "process_substitution" => {
            let mut inner = Script::default();
            for child in named_children(node) {
                walk_statement(child, src, &mut inner.pipelines);
            }
            out.push(inner);
            // Do not descend further — a nested $(...)  inside $(...)
            // will be picked up by the outer walk when the classifier
            // recurses into `inner`.
        }
        _ => {
            for child in named_children(node) {
                collect_substitutions(child, src, out);
            }
        }
    }
}

fn raw_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    let range = node.byte_range();
    std::str::from_utf8(&src[range]).unwrap_or("")
}

/// Return just the operator text (`>`, `>>`, `2>`, `&>`, `&>>`) of a
/// `file_redirect` by reading bytes from the node up to the destination
/// field.
fn redirect_operator_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    let start = node.start_byte();
    let end = node
        .child_by_field_name("destination")
        .map_or_else(|| node.end_byte(), |n| n.start_byte());
    std::str::from_utf8(&src[start..end])
        .unwrap_or("")
        .trim_end()
}

/// If `s` is wrapped in matching `"..."`, `'...'`, or `` `...` ``,
/// return the inner slice; otherwise return `s`.
fn strip_surrounding_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && (first == b'"' || first == b'\'' || first == b'`') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Iterator over the named children of `node`, hiding the cursor
/// boilerplate. Named children skip punctuation / whitespace tokens.
fn named_children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut cursor = node.walk();
    let ids: Vec<_> = node.named_children(&mut cursor).collect();
    ids.into_iter()
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
    fn is_redirect_kind_covers_all_three() {
        assert!(is_redirect_kind("file_redirect"));
        assert!(is_redirect_kind("herestring_redirect"));
        assert!(is_redirect_kind("heredoc_redirect"));
        assert!(!is_redirect_kind("command"));
    }
}
