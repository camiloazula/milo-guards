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
