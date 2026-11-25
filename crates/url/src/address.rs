//! An address as the caller writes it, split into the address the URL parser
//! reads and what is around it: brackets, a port, an IPv6 zone. The address
//! itself is read by the parser, as the host of a URL is, so `judge_address`
//! and `judge` never read one spelling two ways.

/// The part of a caller's text that is the address, and which kind it must
/// be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written<'a> {
    /// What must be an IPv4 address, in any spelling the URL parser reads in
    /// a host (`127.0.0.1`, `0x7f.1`, `2130706433`), without its port.
    V4(&'a str),
    /// What must be an IPv6 address, without brackets, port or zone, and
    /// whether a zone was written after it.
    V6 {
        /// The address.
        address: &'a str,
        /// Whether it had a zone. A zone never makes an address safe: the
        /// caller judges it only on an address that is already a finding.
        zoned: bool,
    },
}

/// The address `text` holds, or `None` when what is around it is not one of
/// the forms read: `ADDRESS`, `IPV4:PORT`, `[IPV6]`, `[IPV6]:PORT`, an IPv6
/// address with no brackets, and an IPv6 address with a zone (`fe80::1%eth0`,
/// `[fe80::1%eth0]:443`). An IPv6 address has two colons at least, so one
/// colon is a port; with no brackets, every colon of an IPv6 address is part
/// of it, and it has no port.
pub(crate) fn split(text: &str) -> Option<Written<'_>> {
    if let Some(inside) = text.strip_prefix('[') {
        let (address, rest) = inside.split_once(']')?;
        if !rest.is_empty() && !rest.strip_prefix(':').is_some_and(port) {
            return None;
        }
        return unzoned(address);
    }
    match text.bytes().filter(|&b| b == b':').count() {
        0 => Some(Written::V4(text)),
        1 => {
            let (address, number) = text.split_once(':')?;
            port(number).then_some(Written::V4(address))
        }
        _ => unzoned(text),
    }
}

/// An IPv6 address with its zone, if it has one, taken off: `fe80::1%eth0`
/// is `fe80::1`, zoned. A zone names a link of this machine and is not
/// judged; it is one or more ASCII letters, digits, `-`, `_` or `.`, and
/// anything else after a `%` is not read.
fn unzoned(text: &str) -> Option<Written<'_>> {
    let Some((address, zone)) = text.split_once('%') else {
        return Some(Written::V6 {
            address: text,
            zoned: false,
        });
    };
    let named = !zone.is_empty()
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    named.then_some(Written::V6 {
        address,
        zoned: true,
    })
}

/// Whether `text` is a port as the URL parser reads one: ASCII digits, none
/// at all included, whose value is at most 65535.
fn port(text: &str) -> bool {
    let significant = text.trim_start_matches('0');
    text.bytes().all(|b| b.is_ascii_digit())
        && significant.len() <= 5
        && significant.parse::<u32>().map_or(true, |n| n <= 65_535)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_is_read_from_its_forms() {
        for (text, written) in [
            ("127.0.0.1", Written::V4("127.0.0.1")),
            ("0x7f.1", Written::V4("0x7f.1")),
            ("127.0.0.1:80", Written::V4("127.0.0.1")),
            ("127.0.0.1:", Written::V4("127.0.0.1")),
            ("127.0.0.1:00080", Written::V4("127.0.0.1")),
            ("example.com:443", Written::V4("example.com")),
            (
                "::1",
                Written::V6 {
                    address: "::1",
                    zoned: false,
                },
            ),
            (
                "::1:80",
                Written::V6 {
                    address: "::1:80",
                    zoned: false,
                },
            ),
            (
                "[::1]",
                Written::V6 {
                    address: "::1",
                    zoned: false,
                },
            ),
            (
                "[::1]:443",
                Written::V6 {
                    address: "::1",
                    zoned: false,
                },
            ),
            (
                "[::1]:",
                Written::V6 {
                    address: "::1",
                    zoned: false,
                },
            ),
            (
                "fe80::1%eth0",
                Written::V6 {
                    address: "fe80::1",
                    zoned: true,
                },
            ),
            (
                "fe80::1%25en0",
                Written::V6 {
                    address: "fe80::1",
                    zoned: true,
                },
            ),
            (
                "[fe80::1%en0.1]:443",
                Written::V6 {
                    address: "fe80::1",
                    zoned: true,
                },
            ),
            (
                "[127.0.0.1]",
                Written::V6 {
                    address: "127.0.0.1",
                    zoned: false,
                },
            ),
            ("", Written::V4("")),
        ] {
            assert_eq!(split(text), Some(written), "{text}");
        }
    }

    #[test]
    fn what_is_around_an_address_and_not_read_is_not_one() {
        for text in [
            "127.0.0.1:65536",
            "127.0.0.1:99999",
            "127.0.0.1:-1",
            "127.0.0.1:8o",
            "127.0.0.1: 80",
            "[::1",
            "[::1]x",
            "[::1]:80:80",
            "[::1]]",
            "[::1]:65536",
            "fe80::1%",
            "fe80::1%eth0:443",
            "fe80::1%eth 0",
            "fe80::1%eth0%1",
            "[fe80::1%]",
            "fe80::1%eth0]",
        ] {
            assert_eq!(split(text), None, "{text}");
        }
    }

    #[test]
    fn a_port_is_read_as_the_url_parser_reads_it() {
        for text in ["", "0", "80", "65535", "000000000000080", "0000"] {
            assert!(port(text), "{text}");
        }
        for text in [
            "65536",
            "100000",
            "1e3",
            "+80",
            "８０",
            "99999999999999999999",
        ] {
            assert!(!port(text), "{text}");
        }
    }
}
