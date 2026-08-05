use std::{fmt::Display, net::SocketAddr};

use idna::AsciiDenyList;

#[allow(clippy::large_enum_variant)]
pub enum InboundStream {
    TcpStream(tokio::net::TcpStream),
    TlsStream(tokio_rustls::TlsStream<tokio::net::TcpStream>),
}

#[allow(dead_code)]
enum ProxyProtocol {
    Socks5,
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
    IP(SocketAddr),
}

impl TargetAddr {
    pub fn into_string_and_port(self) -> (String, u16) {
        match self {
            Self::Domain(domain, port) => (domain, port),
            Self::IP(ip) => (ip.ip().to_string(), ip.port()),
        }
    }
}

impl Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(domain, port) => f.write_fmt(format_args!("{}:{}", domain, port)),
            Self::IP(ip) => f.write_fmt(format_args!("{}", ip)),
        }
    }
}

impl From<fast_socks5::util::target_addr::TargetAddr> for TargetAddr {
    fn from(value: fast_socks5::util::target_addr::TargetAddr) -> Self {
        match value {
            fast_socks5::util::target_addr::TargetAddr::Ip(socket_addr) => Self::IP(socket_addr),
            fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => {
                Self::Domain(domain, port)
            }
        }
    }
}

#[derive(Debug)]
pub struct TargetContext {
    pub initial_target: TargetAddr,
}

#[derive(Debug, Clone)]
pub struct OwnedRequestContext {
    pub trace_id: uuid::Uuid,
    pub client_address: SocketAddr,
    pub acl_ctx: crate::acl::OwnedEvaluationContext,
}

#[derive(Debug, Clone)]
pub struct LocalRequestContext<'s> {
    #[allow(dead_code)]
    pub client_address: &'s SocketAddr,
    #[allow(dead_code)]
    pub trace_id: uuid::Uuid,
    pub acl_ctx: crate::acl::EvaluationContext<'s>,
}

impl OwnedRequestContext {
    pub fn new(client_address: SocketAddr) -> Self {
        Self {
            client_address,
            trace_id: uuid::Uuid::new_v4(),
            acl_ctx: crate::acl::OwnedEvaluationContext::empty(),
        }
    }

    pub fn as_local<'s>(&'s self) -> LocalRequestContext<'s> {
        LocalRequestContext {
            client_address: &self.client_address,
            acl_ctx: self.acl_ctx.fork(),
            trace_id: self.trace_id,
        }
    }
}

/// Normalize a hostname for ACL evaluation.
///
/// DNS resolution is case-insensitive (RFC 4343), trailing-dot-agnostic, and IDNA-aware (RFC
/// 5891).
///
/// ACL string comparison is byte-exact. Without normalization, bypasses are trivial.
///
/// This function uses UTS #46 (Unicode IDNA Compatibility Processing) which handles: ASCII
/// lowercasing, trailing dot stripping, Unicode normalization (NFC/NFD equivalence), punycode
/// conversion for non-ASCII labels, and IDN validity checks.
///
/// IPv6 addresses (wrapped in `[...]` per RFC 3986) are left unchanged.
pub fn normalize_host_for_acl(host: &str) -> Result<String, idna::Errors> {
    if host.starts_with('[') {
        // This is an IPv6 literal.
        return Ok(host.to_owned());
    }

    idna::domain_to_ascii_cow(host.trim_end_matches('.').as_bytes(), AsciiDenyList::URL)
        .map(|s| s.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_lowercase() {
        assert_eq!(normalize_host_for_acl("EvIl.CoM").unwrap(), "evil.com");
        assert_eq!(normalize_host_for_acl("EVIL.COM").unwrap(), "evil.com");
        assert_eq!(normalize_host_for_acl("evil.com").unwrap(), "evil.com");
    }

    #[test]
    fn ascii_trailing_dot() {
        assert_eq!(normalize_host_for_acl("evil.com.").unwrap(), "evil.com");
        assert_eq!(normalize_host_for_acl("EvIl.CoM.").unwrap(), "evil.com");
    }

    #[test]
    fn multiple_trailing_dots() {
        // All dots at the end are stripped.
        let result = normalize_host_for_acl("evil.com..").unwrap();
        assert_eq!(result, "evil.com");
    }

    #[test]
    fn ascii_single_label() {
        assert_eq!(normalize_host_for_acl("LOCALHOST").unwrap(), "localhost");
        assert_eq!(normalize_host_for_acl("localhost.").unwrap(), "localhost");
    }

    #[test]
    fn idn_utf8_to_punycode() {
        assert_eq!(
            normalize_host_for_acl("münchen.com").unwrap(),
            "xn--mnchen-3ya.com"
        );
        assert_eq!(
            normalize_host_for_acl("mÜNCHEN.com").unwrap(),
            "xn--mnchen-3ya.com"
        );
    }

    #[test]
    fn idn_punycode_idempotent() {
        assert_eq!(
            normalize_host_for_acl("xn--mnchen-3ya.com").unwrap(),
            "xn--mnchen-3ya.com"
        );
    }

    #[test]
    fn idn_utf8_and_punycode_are_equal() {
        let a = normalize_host_for_acl("münchen.com").unwrap();
        let b = normalize_host_for_acl("xn--mnchen-3ya.com").unwrap();
        assert_eq!(
            a, b,
            "UTF-8 and punycode forms must normalize to same string"
        );
    }

    #[test]
    fn unicode_nfc_nfd_equivalence() {
        // NFC: U+00E9 = LATIN SMALL LETTER E WITH ACUTE
        let nfc = "caf\u{00E9}.com";
        // NFD: U+0065 U+0301 = LATIN SMALL LETTER E + COMBINING ACUTE ACCENT
        let nfd = "cafe\u{0301}.com";

        let a = normalize_host_for_acl(nfc).unwrap();
        let b = normalize_host_for_acl(nfd).unwrap();
        assert_eq!(a, b, "NFC and NFD forms must normalize to same string");

        // Both should be punycode: the non-ASCII character gets encoded.
        assert!(a.starts_with("xn--"));
    }

    #[test]
    fn unicode_fullwidth() {
        // Fullwidth letters (U+FF21 = Ａ, U+FF44 = ｄ etc.)
        let fullwidth = "\u{FF41}\u{FF42}\u{FF43}.com"; // ａｂｃ.com
        let result = normalize_host_for_acl(fullwidth).unwrap();
        // IDNA maps fullwidth to ASCII equivalents: abc.com
        assert_eq!(result, "abc.com");
    }

    #[test]
    fn ipv6_bracketed_preserved() {
        assert_eq!(normalize_host_for_acl("[::1]").unwrap(), "[::1]");
        assert_eq!(normalize_host_for_acl("[::]").unwrap(), "[::]");
        assert_eq!(
            normalize_host_for_acl("[2001:db8::1]").unwrap(),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn ipv6_unbracketed_lowercased() {
        assert!(normalize_host_for_acl("::1").is_err());
        assert!(normalize_host_for_acl("::").is_err());
        assert!(normalize_host_for_acl("2001:DB8::1").is_err());
    }

    #[test]
    fn ipv6_bracketed_does_not_go_through_idna() {
        // Bracketed IPv6 must not be converted to punycode.
        assert_eq!(normalize_host_for_acl("[::1]").unwrap(), "[::1]");
    }

    #[test]
    fn empty_string() {
        // Empty host: idna rejects, fallback lowercases (no-op).
        assert_eq!(normalize_host_for_acl("").unwrap(), "");
    }

    #[test]
    fn dot_only() {
        // Single dot is the root label.
        let result = normalize_host_for_acl(".").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn very_long_label() {
        // 64-byte label is valid; 65+ is invalid per RFC 5891.
        let label_63 = format!("{}.com", "a".repeat(63));
        assert_eq!(
            normalize_host_for_acl(&label_63).unwrap(),
            label_63.to_ascii_lowercase()
        );
    }

    #[test]
    fn invalid_punycode_falls_back() {
        // "xn--" followed by invalid punycode.
        assert!(normalize_host_for_acl("xn--invalid-punycode.example").is_err());
    }

    #[test]
    fn bidirectional_attack() {
        // Mixed-direction text (right-to-left + left-to-right) in a label
        // is rejected by IDNA. Example: "a\u{05D0}b.com" (Hebrew alef).
        assert!(normalize_host_for_acl("a\u{05D0}b.com").is_err());
    }

    #[test]
    fn nul_byte() {
        // NUL byte is a forbidden code point, it is rejected.
        assert!(normalize_host_for_acl("evil\0.com").is_err());
    }

    #[test]
    fn idempotent() {
        // Normalizing twice must produce the same result.
        let cases = [
            "EvIl.CoM",
            "evil.com.",
            "münchen.com",
            "xn--mnchen-3ya.com",
            "café.com",
            "[::1]",
            "127.0.0.1",
        ];
        for case in &cases {
            let once = normalize_host_for_acl(case).unwrap();
            let twice = normalize_host_for_acl(&once).unwrap();
            assert_eq!(
                once, twice,
                "normalize_host_for_acl not idempotent for '{case}' → '{once}' → '{twice}'"
            );
        }
    }
}
