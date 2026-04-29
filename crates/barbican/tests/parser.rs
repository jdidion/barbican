//! Integration tests for the Phase-1 bash parser IR.
//!
//! Every test here describes a property a later-phase classifier will
//! depend on. If the parser regresses on any of these, the H1/H2/M1/M2
//! fixes break silently.

use barbican::parser::{parse, ParseError, Redirect, RedirectKind};

fn sole_command(input: &str) -> barbican::parser::Command {
    let script = parse(input).unwrap_or_else(|e| panic!("parse({input:?}) failed: {e}"));
    assert_eq!(
        script.pipelines.len(),
        1,
        "expected 1 pipeline, got {}: {:?}",
        script.pipelines.len(),
        script.pipelines
    );
    assert_eq!(
        script.pipelines[0].stages.len(),
        1,
        "expected 1 stage, got {}: {:?}",
        script.pipelines[0].stages.len(),
        script.pipelines[0].stages
    );
    script
        .pipelines
        .into_iter()
        .next()
        .unwrap()
        .stages
        .into_iter()
        .next()
        .unwrap()
}

#[test]
fn simple_command() {
    let c = sole_command("ls -la");
    assert_eq!(c.basename, "ls");
    assert_eq!(c.args, vec!["-la"]);
    assert!(c.substitutions.is_empty());
    assert!(c.redirects.is_empty());
}

#[test]
fn absolute_path_basename_normalizes() {
    let c = sole_command("/bin/bash -c 'echo hi'");
    assert_eq!(
        c.basename, "bash",
        "Phase-1 IR must basename-normalize argv[0]; this is the H1 foundation"
    );
}

#[test]
fn nested_absolute_path_basename_normalizes() {
    let c = sole_command("/opt/homebrew/bin/bash -c 'echo hi'");
    assert_eq!(c.basename, "bash");
}

#[test]
fn relative_path_basename_normalizes() {
    let c = sole_command("./bash -c 'echo hi'");
    assert_eq!(c.basename, "bash");
}

#[test]
fn quoted_command_name_dequotes_before_basename() {
    let c = sole_command("\"/bin/bash\" -c 'echo hi'");
    assert_eq!(
        c.basename, "bash",
        "quoted argv[0] must still basename-normalize — attackers hide behind quoting"
    );
}

#[test]
fn pipeline_two_stages() {
    let script = parse("curl https://example.com | bash").unwrap();
    assert_eq!(script.pipelines.len(), 1);
    let p = &script.pipelines[0];
    assert_eq!(p.stages.len(), 2);
    assert_eq!(p.stages[0].basename, "curl");
    assert_eq!(p.stages[1].basename, "bash");
}

#[test]
fn pipeline_three_stages() {
    let script = parse("cat x | grep y | wc -l").unwrap();
    assert_eq!(script.pipelines[0].stages.len(), 3);
    assert_eq!(script.pipelines[0].stages[0].basename, "cat");
    assert_eq!(script.pipelines[0].stages[1].basename, "grep");
    assert_eq!(script.pipelines[0].stages[2].basename, "wc");
}

#[test]
fn command_substitution_produces_sub_script() {
    let c = sole_command("cat $(find / -name foo)");
    assert_eq!(c.basename, "cat");
    assert_eq!(
        c.substitutions.len(),
        1,
        "$(...) must produce exactly one sub-script"
    );
    let sub = &c.substitutions[0];
    assert_eq!(sub.pipelines.len(), 1);
    assert_eq!(sub.pipelines[0].stages[0].basename, "find");
}

#[test]
fn backtick_substitution_produces_sub_script() {
    let c = sole_command("cat `find / -name foo`");
    assert_eq!(
        c.substitutions.len(),
        1,
        "backtick substitution must also produce a sub-script"
    );
    assert_eq!(c.substitutions[0].pipelines[0].stages[0].basename, "find");
}

#[test]
fn nested_command_substitution() {
    let c = sole_command("echo $(cat $(echo /etc/hostname))");
    assert_eq!(c.basename, "echo");
    assert_eq!(
        c.substitutions.len(),
        1,
        "outer $(...) is one top-level sub; nested is inside it, not flattened"
    );
    let outer = &c.substitutions[0];
    let cat_cmd = &outer.pipelines[0].stages[0];
    assert_eq!(cat_cmd.basename, "cat");
    assert_eq!(cat_cmd.substitutions.len(), 1);
    assert_eq!(
        cat_cmd.substitutions[0].pipelines[0].stages[0].basename,
        "echo"
    );
}

#[test]
fn here_string_redirect_is_captured() {
    let c = sole_command("grep foo <<<\"bar\"");
    assert_eq!(c.basename, "grep");
    let hs = c
        .redirects
        .iter()
        .find(|r| matches!(r.kind, RedirectKind::HereString))
        .expect("<<< must be captured as HereString");
    // Target text keeps the quotes in the raw slice on purpose — this
    // is the shape downstream classifiers prefer (so they can tell
    // "literal" from "expanded" inputs by inspecting the quotes).
    assert!(
        hs.target.contains("bar"),
        "here-string target should include the operand text, got {:?}",
        hs.target
    );
}

#[test]
fn process_substitution_produces_sub_script() {
    let c = sole_command("diff <(echo a) <(echo b)");
    assert_eq!(c.basename, "diff");
    assert_eq!(
        c.substitutions.len(),
        2,
        "<(...) must produce one sub-script per occurrence"
    );
    for sub in &c.substitutions {
        assert_eq!(sub.pipelines[0].stages[0].basename, "echo");
    }
}

#[test]
fn output_process_substitution_produces_sub_script() {
    let c = sole_command("tee >(grep evil)");
    assert_eq!(c.basename, "tee");
    assert_eq!(c.substitutions.len(), 1);
    assert_eq!(c.substitutions[0].pipelines[0].stages[0].basename, "grep");
}

#[test]
fn redirect_to_file_captured_with_target() {
    let c = sole_command("echo hi > /tmp/x");
    let r: &Redirect = c
        .redirects
        .iter()
        .find(|r| matches!(r.kind, RedirectKind::OutFile { append: false }))
        .expect("`> file` must produce an OutFile redirect");
    assert_eq!(r.target, "/tmp/x");
}

#[test]
fn redirect_append_captured() {
    let c = sole_command("echo hi >> /tmp/x");
    let r = c
        .redirects
        .iter()
        .find(|r| matches!(r.kind, RedirectKind::OutFile { append: true }))
        .expect("`>> file` must produce OutFile{append: true}");
    assert_eq!(r.target, "/tmp/x");
}

#[test]
fn redirect_on_last_pipeline_stage_attaches_to_stage() {
    // The H2 pattern: pipeline terminating in a write to exec-target.
    let script = parse("echo ZXZpbA== | base64 -d > /tmp/a.sh").unwrap();
    let p = &script.pipelines[0];
    assert_eq!(p.stages.len(), 2);
    let tail = &p.stages[1];
    assert_eq!(tail.basename, "base64");
    let r = tail
        .redirects
        .iter()
        .find(|r| matches!(r.kind, RedirectKind::OutFile { append: false }))
        .expect("redirect on pipeline tail must attach to the last stage");
    assert_eq!(r.target, "/tmp/a.sh");
}

#[test]
fn malformed_unterminated_quote_hard_denies() {
    assert_eq!(
        parse("echo \"unterminated"),
        Err(ParseError::Malformed),
        "deny-by-default on parse failure"
    );
}

#[test]
fn malformed_unmatched_paren_hard_denies() {
    assert_eq!(parse("$(echo hi"), Err(ParseError::Malformed));
}

#[test]
fn malformed_unmatched_brace_hard_denies() {
    assert_eq!(parse("echo ${"), Err(ParseError::Malformed));
}

#[test]
fn semicolon_separator_creates_multiple_pipelines() {
    let script = parse("cd /tmp; ls").unwrap();
    assert_eq!(script.pipelines.len(), 2);
    assert_eq!(script.pipelines[0].stages[0].basename, "cd");
    assert_eq!(script.pipelines[1].stages[0].basename, "ls");
}

#[test]
fn and_or_separators_create_multiple_pipelines() {
    let a = parse("foo && bar").unwrap();
    assert_eq!(a.pipelines.len(), 2);
    let o = parse("foo || bar").unwrap();
    assert_eq!(o.pipelines.len(), 2);
}

#[test]
fn newline_separator_creates_multiple_pipelines() {
    let script = parse("foo\nbar").unwrap();
    assert_eq!(script.pipelines.len(), 2);
}

#[test]
fn args_preserve_raw_text_not_dequoted() {
    // Arguments keep their quoting so downstream classifiers can
    // distinguish literal from potentially-expanded inputs.
    let c = sole_command("echo 'literal $HOME'");
    assert_eq!(c.basename, "echo");
    assert_eq!(c.args.len(), 1);
    assert!(
        c.args[0].contains("literal"),
        "argv[1] raw text should include the literal; got {:?}",
        c.args[0]
    );
}

#[test]
fn comment_does_not_produce_pipeline() {
    let script = parse("# this is a comment").unwrap();
    assert!(script.pipelines.is_empty());
}

#[test]
fn variable_assignment_does_not_produce_pipeline() {
    let script = parse("FOO=bar").unwrap();
    assert!(
        script.pipelines.is_empty(),
        "bare variable assignment is not a command pipeline"
    );
}

#[test]
fn find_exec_is_just_words_in_argv() {
    // Documented Phase-1 limit: tree-sitter-bash does NOT distinguish
    // `-exec` from any other `word`. The M1 classifier in Phase 4 must
    // detect re-entry wrappers by inspecting the argv itself. This
    // test pins the surface so that contract is visible.
    let c = sole_command("find / -exec cat {} \\;");
    assert_eq!(c.basename, "find");
    assert!(
        c.args.iter().any(|a| a == "-exec"),
        "-exec must surface as a plain arg; got {:?}",
        c.args
    );
}
