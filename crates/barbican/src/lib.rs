//! Barbican library surface.
//!
//! Public so integration tests and the `barbican` binary can share
//! implementations.

pub mod cmd;
pub mod hooks;
pub mod installer;
pub mod mcp;
pub mod net;
pub mod parser;
pub mod sanitize;
pub mod scan;
pub mod tables;

/// Uniform boolean-env-var parser: `1` / `true` / `yes` / `on`
/// (case-insensitive) are true; everything else (including unset) is
/// false. Use this for every `BARBICAN_*_FLAG`-style knob so users
/// don't hit the "I set it to `true` but it only accepts `1`" footgun
/// that 1.1.0's review flagged.
#[must_use]
pub fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        let v = v.trim();
        v == "1"
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    })
}

#[cfg(test)]
mod tests {
    use super::env_flag;

    #[test]
    fn env_flag_accepts_canonical_truthy_values() {
        // Dedicated var so this test can't race with any other env-var
        // setting code in the process.
        let name = "BARBICAN_TEST_ENV_FLAG_CANONICAL";
        for truthy in ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"] {
            std::env::set_var(name, truthy);
            assert!(env_flag(name), "{truthy:?} must parse as true");
        }
        std::env::remove_var(name);
    }

    #[test]
    fn env_flag_rejects_falsy_and_unset() {
        let name = "BARBICAN_TEST_ENV_FLAG_FALSY";
        std::env::remove_var(name);
        assert!(!env_flag(name), "unset must be false");
        for falsy in ["", "0", "false", "no", "off", "maybe", "2", "TRUE1"] {
            std::env::set_var(name, falsy);
            assert!(!env_flag(name), "{falsy:?} must parse as false");
        }
        std::env::remove_var(name);
    }
}
