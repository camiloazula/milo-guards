//! How an `http` or `https` URL is spelled, read only to find a spelling that
//! two clients may read as two hosts.
//!
//! The host is always the one the parser read. What is looked for here is a
//! spelling where the parser's reading and another client's could differ,
//! which makes the URL unreadable: a backslash or a missing slash where the
//! authority starts, a percent sign in the host, an IPv4 address spelled any
//! way but four plain decimal numbers.

/// What is odd about how `text` (an `http` or `https` URL, `scheme` its
/// scheme) is spelled, or `None` when it is the plain `scheme://host…`.
/// `ipv4` is whether the parser read the host as an IPv4 address.
pub(crate) fn odd(text: &str, scheme: &str, ipv4: bool) -> Option<&'static str> {
    const ODD: &str = "is spelled in a way clients read differently";
    let Some(rest) = text.get(scheme.len() + 1..) else {
        return Some(ODD);
    };
    // The scheme is followed by exactly `//` and the host: the parser also
    // takes `http:/host`, `http:host` and `http:\\host`, which a client that
    // follows the RFC reads as a path.
    let Some(after) = rest.strip_prefix("//") else {
        return Some(ODD);
    };
    if after.starts_with(['/', '\\']) {
        return Some(ODD);
    }
    // The authority ends at the first `/`, `?` or `#`. The parser ends it at
    // a backslash too, which a client that follows the RFC does not: the
    // `example.com` of `http://example.com\@127.0.0.1/` is one client's host
    // and `127.0.0.1` another's.
    let end = after.find(['/', '?', '#', '\\']).unwrap_or(after.len());
    if after[end..].starts_with('\\') {
        return Some(ODD);
    }
    let authority = &after[..end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    // A percent-encoded host is read by the parser and left alone by a
    // client that treats the host as plain text.
    if host.contains('%') {
        return Some(ODD);
    }
    if ipv4 && !plain_ipv4(host.rsplit_once(':').map_or(host, |(name, _port)| name)) {
        return Some("spells an address in a form clients read differently");
    }
    None
}

/// The host of `text` as it is written, between the last `@` of the authority
/// and its port (an IP literal in brackets is returned whole): `None` when there is no `://` to start an authority at.
pub(crate) fn written_host(text: &str) -> Option<&str> {
    let (_, after) = text.split_once("://")?;
    let end = after.find(['/', '?', '#', '\\']).unwrap_or(after.len());
    let authority = &after[..end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.starts_with('[') {
        return Some(host);
    }
    Some(host.rsplit_once(':').map_or(host, |(name, _port)| name))
}

/// A host name read the IDNA2003 way, when it holds a character the two
/// standards read differently: `ß` is `ss`, `ς` is `σ`, and the zero-width
/// joiners are dropped. The parser keeps them (`ßlip.io` is `xn--lip-4ka.io`),
/// and a client on the older standard (Python's `idna` codec, older
/// libraries) reads `sslip.io`: two hosts. `None` when the name holds none.
pub(crate) fn idna2003(host: &str) -> Option<String> {
    if !host.contains(['\u{df}', '\u{3c2}', '\u{200c}', '\u{200d}']) {
        return None;
    }
    let mut mapped = String::with_capacity(host.len() + 2);
    for c in host.chars() {
        match c {
            '\u{df}' => mapped.push_str("ss"),
            '\u{3c2}' => mapped.push('\u{3c3}'),
            '\u{200c}' | '\u{200d}' => {}
            c => mapped.push(c),
        }
    }
    Some(mapped)
}

/// Four decimal numbers from 0 to 255 with no leading zero: the one spelling
/// of an IPv4 address every client reads the same way. `010.0.0.1` is
/// `8.0.0.1` to the parser and to `inet_aton`, and `10.0.0.1` to a client
/// that reads every number as decimal.
fn plain_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_plain_decimal_numbers_are_plain() {
        for text in ["127.0.0.1", "0.0.0.0", "93.184.216.34", "255.255.255.255"] {
            assert!(plain_ipv4(text), "{text}");
        }
    }

    #[test]
    fn every_other_spelling_of_an_address_is_not() {
        for text in [
            "2130706433",
            "0177.0.0.1",
            "010.0.0.1",
            "0x7f.1",
            "127.1",
            "127.0.0.1.",
            "127.0.0.01",
            "127.0.0.256",
            "1.2.3",
            "1.2.3.4.5",
            "１２７.0.0.1",
            "",
        ] {
            assert!(!plain_ipv4(text), "{text}");
        }
    }

    #[test]
    fn the_host_is_read_from_the_authority_as_written() {
        for (text, host) in [
            ("http://example.com/a", "example.com"),
            ("http://me:pw@example.com:80/", "example.com"),
            ("http://a@b@faß.de?x", "faß.de"),
            ("http://[::1]:80/", "[::1]:80"),
            ("ftp://host#x", "host"),
        ] {
            assert_eq!(written_host(text), Some(host), "{text}");
        }
        assert_eq!(written_host("file:///x"), Some(""));
        assert_eq!(written_host("javascript:alert(1)"), None);
    }

    #[test]
    fn a_deviation_character_is_read_the_older_way() {
        assert_eq!(idna2003("faß.de").as_deref(), Some("fass.de"));
        assert_eq!(idna2003("loca\u{3c2}").as_deref(), Some("loca\u{3c3}"));
        assert_eq!(idna2003("a\u{200c}b\u{200d}c").as_deref(), Some("abc"));
        assert_eq!(idna2003("example.com"), None);
        assert_eq!(idna2003("例え.jp"), None);
    }

    #[test]
    fn a_plain_authority_is_plain() {
        for text in [
            "http://example.com",
            "http://example.com/",
            "http://example.com:8080/a?b#c",
            "http://user@example.com/",
            "http://93.184.216.34:80/",
            "http://[::1]/",
        ] {
            assert_eq!(odd(text, "http", false), None, "{text}");
        }
    }

    #[test]
    fn an_odd_authority_is_found() {
        for text in [
            "http:example.com",
            "http:/example.com",
            "http:///example.com",
            "http:\\\\example.com",
            "http://\\example.com",
            "http://example.com\\@127.0.0.1/",
            "http://example.com\\",
            "http://%65xample.com/",
        ] {
            assert!(odd(text, "http", false).is_some(), "{text}");
        }
        assert!(odd("http://010.0.0.1/", "http", true).is_some());
        assert!(odd("http:", "http", false).is_some());
    }
}
