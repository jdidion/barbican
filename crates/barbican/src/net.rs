//! SSRF filter and URL validation for `safe_fetch`.
//!
//! The audit's M4 finding is that Narthex's `safe_fetch` only filters
//! the URL scheme, so it happily fetches `http://127.0.0.1`,
//! `http://169.254.169.254/latest/meta-data/` (AWS IMDS),
//! `http://localhost:22/`, and RFC1918 hosts. On top of that, the
//! Narthex installer auto-allowlists `mcp__narthex`, effectively
//! bypassing any `WebFetch` domain gate the user is relying on.
//!
//! This module is the ground truth for "is this address allowed to
//! egress?". It is deliberately pure and network-free — every decision
//! is a function of the parsed URL and the resolved IPs. The actual
//! resolver + HTTP client live in `mcp::safe_fetch` and delegate here.
//!
//! The blocked ranges are:
//!
//! | Range                      | Rationale                        |
//! |----------------------------|----------------------------------|
//! | 127.0.0.0/8, ::1           | Loopback                         |
//! | 10.0.0.0/8                 | RFC1918 private                  |
//! | 172.16.0.0/12              | RFC1918 private                  |
//! | 192.168.0.0/16             | RFC1918 private                  |
//! | 169.254.0.0/16, fe80::/10  | Link-local (incl. IMDS v4)       |
//! | 100.64.0.0/10              | Carrier-grade NAT (RFC6598)      |
//! | 192.0.0.0/24               | IETF protocol assignments        |
//! |                            | (incl. Oracle IMDS 192.0.0.192)  |
//! | fd00::/8                   | IPv6 unique local                |
//! | fd00:ec2::/64              | EC2 IMDS v6                      |
//! | fec0::/10                  | Deprecated IPv6 site-local       |
//! | 100::/64                   | IPv6 discard-only                |
//! | 2001::/32                  | Teredo tunneling                 |
//! | 2002::/16                  | 6to4 tunnel (unwrap embedded v4) |
//! | 64:ff9b::/96, 64:ff9b:1::/48| NAT64 (unwrap embedded v4)      |
//! | ff00::/8, 224.0.0.0/4      | Multicast                        |
//! | 0.0.0.0/8, ::               | Unspecified                      |
//! | 255.255.255.255            | Broadcast                        |
//! | ::ffff:0.0.0.0/96          | IPv4-mapped IPv6 (unwrap+recheck)|

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

/// Reason a URL or IP was rejected. Embedded in error responses so the
/// model can see why a fetch failed without leaking internal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Scheme other than `http` or `https`.
    BadScheme,
    /// No host component in the URL.
    NoHost,
    /// URL host is a raw IP literal and `BARBICAN_ALLOW_IP_LITERALS` is not set.
    RawIpLiteral,
    /// IP is in a blocked private / loopback / link-local / metadata range.
    BlockedIp(&'static str),
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadScheme => write!(f, "refused non-http(s) scheme"),
            Self::NoHost => write!(f, "URL has no host component"),
            Self::RawIpLiteral => write!(
                f,
                "raw IP literals rejected (set BARBICAN_ALLOW_IP_LITERALS=1 to override)"
            ),
            Self::BlockedIp(range) => write!(f, "IP address in blocked range: {range}"),
        }
    }
}

/// Parse a URL string and return it only if the scheme is http(s), the
/// host is present, and — unless `BARBICAN_ALLOW_IP_LITERALS=1` — the
/// host is a DNS name rather than an IP literal.
///
/// If the host is an IP literal and the env override is set, we still
/// run it through [`is_blocked_ip`] so loopback / RFC1918 / IMDS are
/// always blocked even in opt-in mode.
pub fn validate_url(s: &str) -> Result<Url, RejectReason> {
    validate_url_with(s, allow_ip_literals())
}

/// Explicit-flag variant of [`validate_url`] for callers that want to
/// pin the `BARBICAN_ALLOW_IP_LITERALS` policy once and reuse it across
/// multiple calls (e.g. every redirect hop of a single `safe_fetch`).
/// Reading the env per-hop leaves a narrow TOCTOU where a concurrent
/// writer to the process's environment could flip policy mid-fetch;
/// this variant removes that surface.
pub(crate) fn validate_url_with(s: &str, allow: bool) -> Result<Url, RejectReason> {
    let url = Url::parse(s).map_err(|_| RejectReason::NoHost)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(RejectReason::BadScheme),
    }
    let host = url.host().ok_or(RejectReason::NoHost)?;
    match host {
        url::Host::Domain(_) => Ok(url),
        url::Host::Ipv4(v4) => {
            let ip = IpAddr::V4(v4);
            check_ip_literal(ip, allow)?;
            Ok(url)
        }
        url::Host::Ipv6(v6) => {
            let ip = IpAddr::V6(v6);
            check_ip_literal(ip, allow)?;
            Ok(url)
        }
    }
}

/// Whether the raw-IP-literal override is on.
#[must_use]
pub fn allow_ip_literals() -> bool {
    crate::env_flag("BARBICAN_ALLOW_IP_LITERALS")
}

fn check_ip_literal(ip: IpAddr, allow: bool) -> Result<(), RejectReason> {
    if !allow {
        return Err(RejectReason::RawIpLiteral);
    }
    if let Some(reason) = is_blocked_ip(ip) {
        return Err(RejectReason::BlockedIp(reason));
    }
    Ok(())
}

/// Return `Some(range_name)` if `ip` is in any blocked range, `None`
/// if the address is public and safe to fetch.
///
/// Every resolved A / AAAA record must pass this before reqwest opens
/// a socket. Keep the match exhaustive — a gap here is a live SSRF.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn is_blocked_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) — unwrap and re-check
            // against the IPv4 table, otherwise ::ffff:127.0.0.1 would
            // sneak through.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_v4(v4);
            }
            // IPv4-compatible IPv6 (RFC4291 § 2.5.5.1) — the deprecated
            // `::a.b.c.d` form where the first 96 bits are zero. Distinct
            // from the mapped form above. `to_ipv4_mapped()` explicitly
            // does NOT match this shape. We handle `::` and `::1` first
            // in `is_blocked_v6` so their labels stay v6-flavored; the
            // compatible form only fires for non-trivial embedded v4
            // addresses, so the segment guards here must accept the v6
            // unspecified/loopback cases falling through to `is_blocked_v6`.
            // 1.3.7 adversarial review (gpt-5.2 CRITICAL).
            let seg = v6.segments();
            let first_96_bits_zero = seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0;
            if first_96_bits_zero && !v6.is_unspecified() && !v6.is_loopback() {
                if let Some(v4) = v6.to_ipv4() {
                    return is_blocked_v4(v4);
                }
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> Option<&'static str> {
    let octets = v4.octets();
    // Unspecified / "this network" per RFC1122 — the whole 0.0.0.0/8
    // block. `Ipv4Addr::is_unspecified()` only matches the single
    // address 0.0.0.0; historically Linux treated every address in
    // the /8 as loopback, and some legacy stacks still do. Block
    // the whole range to match the doc table. 1.3.7 adversarial
    // review (gpt-5.2 CRITICAL).
    if octets[0] == 0 {
        return Some("unspecified / this-network (0.0.0.0/8)");
    }
    if v4.is_loopback() {
        return Some("loopback (127.0.0.0/8)");
    }
    if v4.is_broadcast() {
        return Some("broadcast (255.255.255.255)");
    }
    if v4.is_multicast() {
        return Some("multicast (224.0.0.0/4)");
    }
    if v4.is_link_local() {
        // Covers IMDS at 169.254.169.254 as well.
        return Some("link-local (169.254.0.0/16)");
    }
    // RFC1918 — std's `is_private` handles this but we want a specific
    // label for the three ranges for the audit log.
    match octets[0] {
        10 => return Some("RFC1918 private (10.0.0.0/8)"),
        172 if (16..=31).contains(&octets[1]) => {
            return Some("RFC1918 private (172.16.0.0/12)");
        }
        192 if octets[1] == 168 => return Some("RFC1918 private (192.168.0.0/16)"),
        _ => {}
    }
    // CGNAT (RFC6598).
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Some("carrier-grade NAT (100.64.0.0/10)");
    }
    // IETF protocol assignments (RFC6890) — includes Oracle OCI IMDS at
    // 192.0.0.192. Not a private address range, but nothing here should
    // ever be reachable from a user-controlled URL.
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Some("IETF protocol assignments (192.0.0.0/24, incl. Oracle IMDS 192.0.0.192)");
    }
    // Reserved / documentation / benchmark — not exploitable but not
    // useful either. Keep them blocked so a typo in a config doesn't
    // trigger an unexpected probe.
    if v4.is_documentation() {
        return Some("documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)");
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("benchmarking (198.18.0.0/15)");
    }
    if octets[0] == 240 {
        return Some("reserved (240.0.0.0/4)");
    }
    None
}

fn is_blocked_v6(v6: Ipv6Addr) -> Option<&'static str> {
    if v6.is_unspecified() {
        return Some("unspecified (::)");
    }
    if v6.is_loopback() {
        return Some("loopback (::1)");
    }
    if v6.is_multicast() {
        return Some("multicast (ff00::/8)");
    }
    let seg = v6.segments();
    // Link-local fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return Some("link-local (fe80::/10)");
    }
    // Deprecated site-local fec0::/10 (RFC3879). Still treated as
    // internal by routers that kept legacy configs.
    if (seg[0] & 0xffc0) == 0xfec0 {
        return Some("deprecated site-local (fec0::/10)");
    }
    // Unique local fc00::/7 (includes fd00::/8 used by AWS IMDS v6).
    if (seg[0] & 0xfe00) == 0xfc00 {
        // Specifically flag the EC2 IMDS v6 address for the audit log.
        if seg[0] == 0xfd00 && seg[1] == 0xec2 {
            return Some("IMDS v6 (fd00:ec2::/64)");
        }
        return Some("unique local (fc00::/7)");
    }
    // Discard-only prefix 100::/64 (RFC6666).
    if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
        return Some("discard-only (100::/64)");
    }
    // Teredo tunneling 2001::/32 — outer IPv6 wraps an IPv4 endpoint
    // in the lower 32 bits; a crafted Teredo address can embed
    // loopback / IMDS. Block the whole range.
    if seg[0] == 0x2001 && seg[1] == 0 {
        return Some("Teredo tunneling (2001::/32)");
    }
    // 6to4 2002::/16 — bits [16..48] of the v6 address encode an IPv4.
    // Unwrap that IPv4 and re-check against the v4 block table so a
    // 2002:7f00:0001:: can't sneak loopback past us.
    if seg[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        );
        if let Some(_reason) = is_blocked_v4(embedded) {
            return Some("6to4 tunnel with blocked embedded IPv4 (2002::/16)");
        }
        return Some("6to4 tunnel (2002::/16)");
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC6052) and local prefix
    // 64:ff9b:1::/48 (RFC8215). Both embed an IPv4 in the low 32 bits.
    // Block unconditionally — safer than per-address unwrap because
    // the model has no business reaching these tunnels.
    if seg[0] == 0x0064 && seg[1] == 0xff9b {
        return Some("NAT64 prefix (64:ff9b::/96 or 64:ff9b:1::/48)");
    }
    // IETF documentation prefix.
    if seg[0] == 0x2001 && seg[1] == 0xdb8 {
        return Some("documentation (2001:db8::/32)");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(ip: &str) -> Option<&'static str> {
        is_blocked_ip(ip.parse().unwrap())
    }

    // --- IPv4 blocked ranges -------------------------------------------------

    #[test]
    fn blocks_loopback_v4() {
        assert!(block("127.0.0.1").is_some());
        assert!(block("127.255.255.254").is_some());
    }

    #[test]
    fn blocks_rfc1918_10() {
        assert!(block("10.0.0.1").is_some());
        assert!(block("10.255.255.255").is_some());
    }

    #[test]
    fn blocks_rfc1918_172_16() {
        assert!(block("172.16.0.1").is_some());
        assert!(block("172.31.255.255").is_some());
        assert!(block("172.15.0.1").is_none(), "172.15 is public");
        assert!(block("172.32.0.1").is_none(), "172.32 is public");
    }

    #[test]
    fn blocks_rfc1918_192_168() {
        assert!(block("192.168.0.1").is_some());
        assert!(block("192.168.255.255").is_some());
        assert!(block("192.167.0.1").is_none());
    }

    #[test]
    fn blocks_link_local_v4() {
        assert!(block("169.254.0.1").is_some());
        assert!(block("169.254.169.254").is_some(), "AWS IMDS v4");
    }

    #[test]
    fn blocks_cgnat() {
        assert!(block("100.64.0.1").is_some());
        assert!(block("100.127.255.255").is_some());
        assert!(block("100.63.0.1").is_none(), "just below CGNAT");
        assert!(block("100.128.0.1").is_none(), "just above CGNAT");
    }

    #[test]
    fn blocks_multicast_v4() {
        assert!(block("224.0.0.1").is_some());
        assert!(block("239.255.255.255").is_some());
    }

    #[test]
    fn blocks_unspecified_v4() {
        assert!(block("0.0.0.0").is_some());
    }

    /// The doc-table entry for "Unspecified" is `0.0.0.0/8`, not just
    /// `0.0.0.0`. Historically, Linux kernels treated connects to the
    /// whole `0.0.0.0/8` block as loopback (the behavior was narrowed
    /// over time but not uniformly across distros / older kernels).
    /// `Ipv4Addr::is_unspecified()` only matches the single address
    /// `0.0.0.0`, so anything else in the `/8` silently slipped the
    /// filter. 1.3.7 adversarial review (`gpt-5.2` CRITICAL).
    #[test]
    fn blocks_entire_zero_slash_8() {
        assert!(
            block("0.0.0.1").is_some(),
            "0.0.0.1 in 0.0.0.0/8 must block"
        );
        assert!(
            block("0.255.255.255").is_some(),
            "top of 0.0.0.0/8 must block"
        );
        assert!(block("1.0.0.0").is_none(), "just above 0.0.0.0/8 is public");
    }

    #[test]
    fn blocks_broadcast_v4() {
        assert!(block("255.255.255.255").is_some());
    }

    // --- IPv4 allowed (public) -----------------------------------------------

    #[test]
    fn allows_public_v4() {
        assert!(block("8.8.8.8").is_none());
        assert!(block("1.1.1.1").is_none());
        assert!(block("93.184.216.34").is_none(), "example.com");
    }

    // --- IPv6 ------------------------------------------------------

    #[test]
    fn blocks_loopback_v6() {
        assert!(block("::1").is_some());
    }

    #[test]
    fn blocks_unspecified_v6() {
        assert!(block("::").is_some());
    }

    #[test]
    fn blocks_link_local_v6() {
        assert!(block("fe80::1").is_some());
        assert!(block("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff").is_some());
    }

    #[test]
    fn blocks_unique_local_v6() {
        assert!(block("fc00::1").is_some());
        assert!(block("fd00::1").is_some());
    }

    #[test]
    fn blocks_imds_v6() {
        let reason = block("fd00:ec2::254").expect("IMDS v6 must be blocked");
        assert!(
            reason.contains("IMDS"),
            "IMDS v6 reason should name IMDS; got: {reason}"
        );
    }

    #[test]
    fn blocks_multicast_v6() {
        assert!(block("ff00::1").is_some());
    }

    #[test]
    fn blocks_ipv4_mapped_v6() {
        // ::ffff:127.0.0.1 must unwrap and hit the IPv4 loopback rule.
        let reason = block("::ffff:127.0.0.1").expect("v4-mapped loopback must block");
        assert!(
            reason.contains("loopback"),
            "should report loopback not v6; got: {reason}"
        );
    }

    /// IPv4-compatible IPv6 (RFC4291 § 2.5.5.1) — the deprecated
    /// `::a.b.c.d` form where the first 96 bits are zero and the last
    /// 32 bits embed an IPv4. Distinct from the *-mapped* form
    /// (`::ffff:a.b.c.d`, first 80 zero + 16 all-ones + v4). Most
    /// stacks won't route compatible addresses today, but some
    /// libraries / older kernels accept them. The std helper
    /// `to_ipv4_mapped()` explicitly does NOT cover this form —
    /// `Ipv6Addr::to_ipv4()` does. 1.3.7 adversarial review
    /// (`gpt-5.2` CRITICAL).
    #[test]
    fn blocks_ipv4_compatible_v6_loopback() {
        // `::7f00:1` == `::127.0.0.1`
        let reason = block("::7f00:1").expect("v4-compatible loopback must block");
        assert!(
            reason.contains("loopback") || reason.contains("IPv4-compatible"),
            "should unwrap+report loopback; got: {reason}"
        );
    }

    #[test]
    fn blocks_ipv4_compatible_v6_imds() {
        // `::a9fe:a9fe` == `::169.254.169.254` (AWS IMDS).
        assert!(block("::a9fe:a9fe").is_some());
    }

    #[test]
    fn blocks_ipv4_compatible_v6_rfc1918() {
        // `::a00:1` == `::10.0.0.1`.
        assert!(block("::a00:1").is_some());
    }

    #[test]
    fn allows_public_v6() {
        assert!(block("2606:4700:4700::1111").is_none(), "Cloudflare DNS");
        assert!(block("2001:4860:4860::8888").is_none(), "Google DNS");
    }

    // --- Special-use ranges added after M4 adversarial review -------

    #[test]
    fn blocks_oracle_imds_v4() {
        // 192.0.0.192 is Oracle Cloud's IMDS endpoint; the 192.0.0.0/24
        // IETF protocol-assignments block catches it and several other
        // metadata-service-class addresses.
        let reason = block("192.0.0.192").expect("Oracle IMDS must block");
        assert!(reason.contains("192.0.0.0/24"));
        assert!(block("192.0.0.1").is_some(), "whole 192.0.0.0/24 blocked");
    }

    #[test]
    fn blocks_alibaba_imds_via_cgnat() {
        // 100.100.100.200 is Alibaba Cloud's IMDS; it falls inside
        // 100.64.0.0/10 and should already be blocked. Pin the
        // guarantee as a regression test so a future CGNAT refactor
        // can't silently re-expose it.
        assert!(block("100.100.100.200").is_some());
    }

    #[test]
    fn blocks_teredo_v6() {
        // Teredo 2001::/32 — the prefix itself must block regardless
        // of the embedded IPv4, because a rebinding attacker can craft
        // the inner bits.
        assert!(block("2001::1").is_some());
        let reason = block("2001::1").unwrap();
        assert!(reason.contains("Teredo"), "got: {reason}");
    }

    #[test]
    fn blocks_6to4_with_embedded_loopback() {
        // 2002:7f00:0001:: embeds 127.0.0.1 in the 6to4 prefix.
        let reason = block("2002:7f00:0001::").expect("6to4 loopback must block");
        assert!(
            reason.contains("6to4"),
            "should name 6to4 family; got: {reason}"
        );
    }

    #[test]
    fn blocks_6to4_with_embedded_imds() {
        // 2002:a9fe:a9fe:: embeds 169.254.169.254 (AWS IMDS).
        assert!(block("2002:a9fe:a9fe::").is_some());
    }

    #[test]
    fn blocks_6to4_with_public_embed_still() {
        // Plain 6to4 is deprecated in practice (RFC7526). Block the
        // whole /16 even if the embedded IPv4 looks public.
        let reason = block("2002:0808:0808::").expect("whole 2002::/16 must block");
        assert!(reason.contains("6to4"));
    }

    #[test]
    fn blocks_nat64_well_known() {
        // 64:ff9b::7f00:1 is the NAT64 well-known mapping of 127.0.0.1.
        // Block the whole /96 unconditionally.
        let reason = block("64:ff9b::7f00:1").expect("NAT64 must block");
        assert!(reason.contains("NAT64"));
    }

    #[test]
    fn blocks_nat64_local() {
        // RFC8215 local NAT64 prefix 64:ff9b:1::/48 — also blocked by
        // the same check.
        assert!(block("64:ff9b:1::1").is_some());
    }

    #[test]
    fn blocks_site_local_v6() {
        // Deprecated fec0::/10 (RFC3879). Some legacy networks still
        // route it internally.
        let reason = block("fec0::1").expect("site-local must block");
        assert!(reason.contains("site-local"));
    }

    #[test]
    fn blocks_discard_only_v6() {
        // RFC6666 discard-only 100::/64.
        let reason = block("100::1").expect("discard-only must block");
        assert!(reason.contains("discard"));
    }

    // --- URL validation ------------------------------------------------------

    #[test]
    fn validate_rejects_non_http_scheme() {
        for s in [
            "file:///etc/passwd",
            "gopher://x",
            "javascript:alert(1)",
            "data:text/plain,x",
        ] {
            let err = validate_url(s).unwrap_err();
            assert!(
                matches!(err, RejectReason::BadScheme),
                "{s} should fail with BadScheme, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_raw_ip_literal_by_default() {
        // SAFETY: env vars are process-global; this test must assume the
        // override is off. Other tests that set it also unset it.
        std::env::remove_var("BARBICAN_ALLOW_IP_LITERALS");
        for s in [
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://169.254.169.254/",
        ] {
            let err = validate_url(s).unwrap_err();
            assert!(
                matches!(err, RejectReason::RawIpLiteral),
                "{s} should be RawIpLiteral; got {err:?}"
            );
        }
    }

    #[test]
    fn validate_allows_domain_host() {
        let url = validate_url("https://example.com/x").unwrap();
        assert_eq!(url.host_str(), Some("example.com"));
    }

    #[test]
    fn validate_url_with_rejects_raw_ip_when_flag_is_false() {
        // Passing `false` explicitly must reject IP literals. The
        // function is pure (no env read) by design — that's the whole
        // TOCTOU-narrowing point — so the test must be pure too and
        // must NOT mutate BARBICAN_ALLOW_IP_LITERALS. Setting it here
        // would race the other env-sensitive tests under the default
        // parallel test runner.
        let err = validate_url_with("http://127.0.0.1/", false).unwrap_err();
        assert!(
            matches!(err, RejectReason::RawIpLiteral),
            "explicit allow=false must reject; got {err:?}"
        );
    }

    #[test]
    fn validate_url_with_allows_public_ip_when_flag_is_true() {
        // Public (routable) IP with the flag on: passes the RawIpLiteral
        // gate AND the is_blocked_ip check, so we get a valid Url back.
        let url = validate_url_with("http://1.1.1.1/", true).expect("public IP with flag=true");
        assert_eq!(url.host_str(), Some("1.1.1.1"));
    }

    #[test]
    fn validate_url_with_still_blocks_loopback_when_flag_is_true() {
        // The flag only unlocks "IP literals are spellable as hosts" —
        // it never weakens the is_blocked_ip SSRF filter. Loopback must
        // still be rejected.
        let err = validate_url_with("http://127.0.0.1/", true).unwrap_err();
        assert!(
            matches!(err, RejectReason::BlockedIp(_)),
            "loopback must stay blocked even with flag=true; got {err:?}"
        );
    }

    /// 1.3.7 adversarial review (gemini-3.1-pro WARNING #2): link-local
    /// IPv6 literals with zone IDs (`%eth0` / `%25eth0`). The `url`
    /// crate rejects zone IDs at the parse layer for `http`/`https`
    /// schemes — `[fe80::1]` parses cleanly and routes into
    /// `is_blocked_ip` as fe80::/10, but `[fe80::1%eth0]` and
    /// `[fe80::1%25eth0]` fail parse with `InvalidIpv6Address`,
    /// landing in the deny-by-default branch. Pin the guarantee.
    #[test]
    fn validate_url_rejects_ipv6_zone_id() {
        for s in ["http://[fe80::1%eth0]/", "http://[fe80::1%25eth0]/"] {
            let res = validate_url_with(s, true);
            assert!(
                res.is_err(),
                "IPv6 zone-id literal must not parse through: {s} => {res:?}"
            );
        }
        // Sanity: plain `[fe80::1]` (no zone id) parses and is blocked
        // as link-local — no change from prior behavior.
        let err = validate_url_with("http://[fe80::1]/", true).unwrap_err();
        assert!(
            matches!(err, RejectReason::BlockedIp(_)),
            "plain fe80::1 must be BlockedIp; got {err:?}"
        );
    }
}
