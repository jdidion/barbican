//! `argv[0]` handling for bash composition analysis.
//!
//! Single source of truth for turning a command token into the basename
//! we match against `NETWORK_TOOLS`, `SHELL_INTERPRETERS`, and so on.
//!
//! The bug this exists to prevent (audit finding **H1**): Narthex compared
//! `argv[0]` to literal strings like `"bash"`, so `/bin/bash`,
//! `/usr/bin/bash`, `/opt/homebrew/bin/bash`, and `./bash` all slipped past
//! the `curl | <shell>` pipeline check. Every set-membership check in
//! Barbican must go through `cmd_basename` first.

/// Return the basename of a command token, stripping any directory prefix.
///
/// Handles:
/// - absolute paths: `/bin/bash` → `bash`
/// - nested absolute paths: `/opt/homebrew/bin/bash` → `bash`
/// - relative paths: `./bash` → `bash`, `../tools/curl` → `curl`
/// - bare names (no separator): `bash` → `bash`
/// - trailing slashes: `/bin/bash/` → `""` (caller must treat as unknown)
/// - empty input: `""` → `""`
///
/// Deliberately NOT a full `Path::file_name` because that strips
/// `..` components in surprising ways and allocates. We want a dumb,
/// auditable character scan.
#[must_use]
pub fn cmd_basename(argv0: &str) -> &str {
    match argv0.rfind('/') {
        Some(idx) => &argv0[idx + 1..],
        None => argv0,
    }
}

#[cfg(test)]
mod tests {
    use super::cmd_basename;

    #[test]
    fn bare_name() {
        assert_eq!(cmd_basename("bash"), "bash");
    }

    #[test]
    fn absolute_bin() {
        assert_eq!(cmd_basename("/bin/bash"), "bash");
    }

    #[test]
    fn absolute_usr_bin() {
        assert_eq!(cmd_basename("/usr/bin/bash"), "bash");
    }

    #[test]
    fn homebrew_path() {
        // The exact bypass from H1.
        assert_eq!(cmd_basename("/opt/homebrew/bin/bash"), "bash");
    }

    #[test]
    fn relative_dot_slash() {
        assert_eq!(cmd_basename("./bash"), "bash");
    }

    #[test]
    fn relative_parent() {
        assert_eq!(cmd_basename("../tools/curl"), "curl");
    }

    #[test]
    fn trailing_slash_is_empty() {
        // A trailing slash produces empty basename; composition checks
        // must treat the result as unknown / not-in-set, which is the
        // deny-by-default behavior we want.
        assert_eq!(cmd_basename("/bin/bash/"), "");
    }

    #[test]
    fn empty_input() {
        assert_eq!(cmd_basename(""), "");
    }

    #[test]
    fn just_slash() {
        assert_eq!(cmd_basename("/"), "");
    }

    #[test]
    fn no_directory_component() {
        assert_eq!(cmd_basename("curl"), "curl");
    }
}
