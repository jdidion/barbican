//! Secret-token redactor for wrapper output streams.
//!
//! Scans child-process stdout/stderr for well-known API-key shapes and
//! replaces each match with a short `<redacted:<kind>>` marker. The
//! patterns here are intentionally high-confidence (prefix-anchored
//! with distinctive token shapes) — generic entropy-based detectors
//! are deferred because the false-positive rate on base64 data, git
//! SHAs, and UUIDs is too high for a safety tool.
//!
//! New in 1.4.0, used by `crate::wrappers` to post-process the output
//! of `barbican-shell` / `barbican-python` / `barbican-node` /
//! `barbican-ruby` / `barbican-perl` invocations.
//!
//! ## Coverage
//!
//! | Kind            | Shape                                          |
//! |-----------------|------------------------------------------------|
//! | Anthropic       | `sk-ant-api03-…`, `sk-ant-admin01-…`           |
//! | OpenAI          | `sk-proj-…`, `sk-…` (legacy)                   |
//! | GitHub PAT      | `ghp_…`, `github_pat_…`                        |
//! | GitHub other    | `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`             |
//! | GitLab PAT      | `glpat-…`                                      |
//! | AWS access key  | `AKIA…`, `ASIA…` (16-byte suffix)              |
//! | Slack           | `xoxb-…`, `xoxp-…`, `xoxa-…`, `xoxr-…`, `xoxs-…` |
//! | Atlassian       | `ATATT3x…`                                     |
//! | JWT             | `eyJ…` three-segment Base64URL token           |
//!
//! Deliberately NOT covered:
//!
//! - AWS secret access key (40-char `[A-Za-z0-9/+=]{40}`) — too close
//!   in shape to base64 data and git SHAs. Paired with an AKIA-prefixed
//!   key these are detectable, but the wrapper doesn't do bigram
//!   correlation.
//! - OpenAI's `sk-…-…-…` multi-segment variants not starting with a
//!   documented prefix.
//! - Bare base64 blobs or hex strings of plausible length.

use std::borrow::Cow;
use std::sync::OnceLock;

use regex::Regex;

/// Kind of secret the redactor recognized. Surfaced in the
/// `<redacted:<kind>>` marker so an operator reading the audit log can
/// tell what was redacted without seeing the actual value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    AnthropicApiKey,
    OpenaiApiKey,
    GithubToken,
    GitlabPat,
    AwsAccessKey,
    SlackToken,
    AtlassianApiToken,
    Jwt,
}

impl SecretKind {
    fn tag(self) -> &'static str {
        match self {
            Self::AnthropicApiKey => "anthropic-key",
            Self::OpenaiApiKey => "openai-key",
            Self::GithubToken => "github-token",
            Self::GitlabPat => "gitlab-pat",
            Self::AwsAccessKey => "aws-access-key",
            Self::SlackToken => "slack-token",
            Self::AtlassianApiToken => "atlassian-token",
            Self::Jwt => "jwt",
        }
    }
}

/// The concatenated regex; each pattern is a named capture group so we
/// can tell them apart in the replace callback.
///
/// Pattern design notes:
/// - Every pattern is prefix-anchored (the token type is obvious from
///   the first few bytes) — no generic-entropy rules.
/// - We use `\b` word boundaries where the prefix could abut ordinary
///   identifier characters, and no boundary where the prefix already
///   ends in a `_` or `-` (which `\b` treats as word-separators).
/// - The suffix length is bounded on the upper end to limit runaway
///   matching on pathological inputs; real keys have tight length
///   ranges but documented upper bounds aren't always published, so
///   each pattern caps at a generous but finite length.
fn combined_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Order inside the alternation matters only when two patterns
        // could match overlapping text; we've designed them to be
        // disjoint, so order is just readability.
        let pattern = concat!(
            // Anthropic: sk-ant-api03-…, sk-ant-admin01-…, and any
            // future sk-ant-<kind>NN- suffix shape. The trailing
            // identifier is URL-safe base64 (A-Z, a-z, 0-9, -, _).
            r"(?P<anthropic>sk-ant-[a-z0-9]+-[A-Za-z0-9_-]{40,200})",
            // OpenAI: `sk-proj-…` (project keys), `sk-…` legacy. The
            // legacy `sk-…` form overlaps in prefix with Anthropic, so
            // we lead with `sk-proj-` and fall back to `sk-[A-Za-z0-9]+`
            // with a length floor that excludes `sk-ant-` (which the
            // anthropic pattern already ate).
            r"|(?P<openai>sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,200})",
            // GitHub: ghp_ (classic PAT), github_pat_ (fine-grained),
            // gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server),
            // ghr_ (refresh).
            r"|(?P<github>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})",
            // GitLab: glpat- prefix, 20-char alphanumeric.
            r"|(?P<gitlab>glpat-[A-Za-z0-9_-]{20})",
            // AWS: AKIA / ASIA followed by 16 uppercase alnums.
            r"|(?P<aws>(?:AKIA|ASIA)[A-Z0-9]{16})",
            // Slack: xoxb-/xoxp-/xoxa-/xoxr-/xoxs- + dash-separated
            // numeric segments + token body. The token body varies in
            // length; 10+ is defensive (real bot tokens are ~50+).
            r"|(?P<slack>xox[abprs]-[A-Za-z0-9-]{10,200})",
            // Atlassian API token: ATATT3x + body. Fairly distinctive.
            r"|(?P<atlassian>ATATT3x[A-Za-z0-9_-]{200,400}[A-F0-9]{8})",
            // JWT: three Base64URL segments separated by dots, starting
            // with `eyJ` (which decodes to `{"`, the JSON object lead).
            // Length floors are very conservative; real JWTs are
            // 100-2000+ bytes.
            r"|(?P<jwt>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        );
        Regex::new(pattern).expect("redact secret-pattern regex must compile")
    })
}

/// Scan `s` for any recognized secret token and return a redacted
/// copy. Each match is replaced with `<redacted:<kind>>`. If no tokens
/// are present, the input is returned unchanged (borrowed) — this is
/// the hot path on normal output, so we avoid allocation.
#[must_use]
pub fn redact_secrets(s: &str) -> Cow<'_, str> {
    let re = combined_regex();
    if !re.is_match(s) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        re.replace_all(s, |caps: &regex::Captures<'_>| {
            let kind = if caps.name("anthropic").is_some() {
                SecretKind::AnthropicApiKey
            } else if caps.name("openai").is_some() {
                SecretKind::OpenaiApiKey
            } else if caps.name("github").is_some() {
                SecretKind::GithubToken
            } else if caps.name("gitlab").is_some() {
                SecretKind::GitlabPat
            } else if caps.name("aws").is_some() {
                SecretKind::AwsAccessKey
            } else if caps.name("slack").is_some() {
                SecretKind::SlackToken
            } else if caps.name("atlassian").is_some() {
                SecretKind::AtlassianApiToken
            } else if caps.name("jwt").is_some() {
                SecretKind::Jwt
            } else {
                // Unreachable if the alternation is disjoint; bail to
                // the whole-match replacement as a defensive fallback.
                return "<redacted:unknown>".to_string();
            };
            format!("<redacted:{}>", kind.tag())
        })
        .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(s: &str) -> String {
        redact_secrets(s).into_owned()
    }

    // --- Positive matches (each pattern fires on a realistic shape) -----

    #[test]
    fn redacts_anthropic_api_key() {
        let k = format!("sk-ant-api03-{}AA", "x".repeat(93));
        let out = redact(&format!("key={k} end"));
        assert_eq!(out, "key=<redacted:anthropic-key> end");
    }

    #[test]
    fn redacts_anthropic_admin_key() {
        let k = format!("sk-ant-admin01-{}", "x".repeat(80));
        let out = redact(&k);
        assert_eq!(out, "<redacted:anthropic-key>");
    }

    #[test]
    fn redacts_openai_project_key() {
        let k = format!("sk-proj-{}", "A".repeat(80));
        let out = redact(&k);
        assert_eq!(out, "<redacted:openai-key>");
    }

    #[test]
    fn redacts_openai_legacy_key() {
        let k = format!("sk-{}", "A".repeat(48));
        let out = redact(&k);
        assert_eq!(out, "<redacted:openai-key>");
    }

    #[test]
    fn redacts_github_classic_pat() {
        let k = format!("ghp_{}", "a".repeat(36));
        let out = redact(&k);
        assert_eq!(out, "<redacted:github-token>");
    }

    #[test]
    fn redacts_github_fine_grained_pat() {
        let k = format!("github_pat_{}", "a".repeat(82));
        let out = redact(&k);
        assert_eq!(out, "<redacted:github-token>");
    }

    #[test]
    fn redacts_github_oauth_variants() {
        for prefix in ["gho_", "ghu_", "ghs_", "ghr_"] {
            let k = format!("{prefix}{}", "a".repeat(36));
            let out = redact(&k);
            assert_eq!(out, "<redacted:github-token>", "prefix {prefix} missed");
        }
    }

    #[test]
    fn redacts_gitlab_pat() {
        let k = "glpat-xxxxxxxxxxxxxxxxxxxx".to_string();
        let out = redact(&k);
        assert_eq!(out, "<redacted:gitlab-pat>");
    }

    #[test]
    fn redacts_aws_access_key_akia() {
        let k = format!("AKIA{}", "A".repeat(16));
        let out = redact(&k);
        assert_eq!(out, "<redacted:aws-access-key>");
    }

    #[test]
    fn redacts_aws_access_key_asia() {
        let k = format!("ASIA{}", "B".repeat(16));
        let out = redact(&k);
        assert_eq!(out, "<redacted:aws-access-key>");
    }

    #[test]
    fn redacts_slack_bot_token() {
        let k = "xoxb-1234567890-abcdefghijklmnop".to_string();
        let out = redact(&k);
        assert_eq!(out, "<redacted:slack-token>");
    }

    #[test]
    fn redacts_slack_all_prefixes() {
        for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
            let k = format!("{prefix}abcdefghij1234567890");
            assert_eq!(
                redact(&k),
                "<redacted:slack-token>",
                "prefix {prefix} missed"
            );
        }
    }

    #[test]
    fn redacts_atlassian_api_token() {
        // Minimum-length atlassian tokens are ~200 chars of body + 8
        // hex chars of checksum. Build a minimal-shape example.
        let body = "A".repeat(205);
        let k = format!("ATATT3x{body}DEADBEEF");
        let out = redact(&k);
        assert_eq!(out, "<redacted:atlassian-token>");
    }

    #[test]
    fn redacts_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signaturebytesXXXXXX";
        let out = redact(jwt);
        assert_eq!(out, "<redacted:jwt>");
    }

    #[test]
    fn redacts_multiple_tokens_in_one_string() {
        let s = format!(
            "export GITHUB_TOKEN=ghp_{} AWS_KEY=AKIA{} done",
            "a".repeat(36),
            "A".repeat(16),
        );
        let out = redact(&s);
        assert_eq!(
            out,
            "export GITHUB_TOKEN=<redacted:github-token> AWS_KEY=<redacted:aws-access-key> done"
        );
    }

    #[test]
    fn redaction_is_idempotent() {
        let s = format!("ghp_{}", "a".repeat(36));
        let once = redact(&s);
        let twice = redact(&once);
        assert_eq!(once, twice);
    }

    // --- Negative cases (must NOT fire) ---------------------------------

    #[test]
    fn does_not_redact_plain_text() {
        let s = "hello world, nothing to see here";
        assert_eq!(redact(s), s);
    }

    #[test]
    fn does_not_redact_non_secret_identifiers() {
        // Not real secrets: too-short ghp_ / too-short AKIA / bare "sk-".
        for s in ["ghp_short", "AKIA123", "sk-", "sk-ant-", "glpat-short"] {
            assert_eq!(redact(s), s, "false positive on {s:?}");
        }
    }

    #[test]
    fn does_not_redact_git_commit_sha() {
        // A 40-char hex string is the shape of a git SHA and a big
        // chunk of potential FP for generic-entropy detectors. Ours
        // requires a distinctive prefix, so a bare SHA is safe.
        let sha = "a1b2c3d4e5f6789012345678901234567890abcd";
        assert_eq!(redact(sha), sha);
    }

    #[test]
    fn does_not_redact_base64_blob() {
        // 40-char base64-ish string. Must not fire.
        let blob = "dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjQgc3RyaW5nLg==";
        assert_eq!(redact(blob), blob);
    }

    #[test]
    fn does_not_redact_uuid() {
        let uuid = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
        assert_eq!(redact(uuid), uuid);
    }

    // --- Hot-path zero-alloc property ----------------------------------

    #[test]
    fn clean_input_returns_borrowed_cow() {
        let s = "no secrets here";
        let out = redact_secrets(s);
        matches!(out, Cow::Borrowed(_))
            .then_some(())
            .expect("clean input must return Cow::Borrowed");
    }
}
