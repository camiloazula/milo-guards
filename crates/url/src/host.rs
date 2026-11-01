//! Where a host points, judged by the host the parser read and never by how
//! the URL spelled it.
//!
//! The rule is a whitelist: a host is public only when it is a name that
//! could be on the public internet, or an address in none of the special
//! ranges (the IANA special-purpose registries). Anything this cannot place
//! is a finding, never safe.

use crate::tables::{Endpoint, LOOPBACK_NAME, METADATA, NETWORK_SUFFIXES, REBINDING};

/// Why a host is not public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// This machine: loopback, the unspecified address, `localhost`.
    ThisMachine,
    /// A machine on the local network: a private, link-local, shared or
    /// unique-local address, a name only a local network answers.
    Network,
    /// An address in a range no public host has (documentation, benchmarking,
    /// multicast, reserved).
    NotPublicAddress,
    /// A name that cannot be a public one.
    NotPublicName,
    /// A name from a service that answers with the address it is asked
    /// for.
    Rebinding,
}

impl Reach {
    /// The words of a reason.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::ThisMachine => "fetches your own machine",
            Self::Network => "fetches a machine on your own network",
            Self::NotPublicAddress => "fetches an address that is not on the public internet",
            Self::NotPublicName => "fetches a name that is not on the public internet",
            Self::Rebinding => "fetches a name that can point at your own network",
        }
    }
}

/// What a host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A public name or address.
    Public,
    /// Not public.
    Local(Reach),
    /// A cloud metadata service, and its provider.
    Metadata(&'static str),
    /// A name no client reads the same way; the words say why.
    Unreadable(&'static str),
}

/// The provider of the metadata service at `endpoint`, if it is one.
fn metadata(endpoint: Endpoint) -> Option<&'static str> {
    METADATA
        .iter()
        .find(|(row, _)| *row == endpoint)
        .map(|(_, provider)| *provider)
}

/// The provider of the metadata service called `name`, if it is one.
fn metadata_name(name: &str) -> Option<&'static str> {
    METADATA
        .iter()
        .find(|(row, _)| matches!(row, Endpoint::Name(known) if *known == name))
        .map(|(_, provider)| *provider)
}

/// An IPv4 address, as its four octets.
pub(crate) fn v4(octets: [u8; 4]) -> Verdict {
    if let Some(provider) = metadata(Endpoint::V4(octets)) {
        return Verdict::Metadata(provider);
    }
    let reach = match octets {
        // Unspecified: a connect to it reaches this machine.
        [0, 0, 0, 0] => Reach::ThisMachine,
        // The rest of 0.0.0.0/8, "this network".
        [0, ..] => Reach::NotPublicAddress,
        // Loopback.
        [127, ..] => Reach::ThisMachine,
        // Private use (RFC 1918), link-local (RFC 3927), shared address
        // space of carriers (RFC 6598, which VPN overlays use as well).
        [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [169, 254, ..] | [100, 64..=127, ..] => {
            Reach::Network
        }
        // IETF protocol assignments, the three documentation ranges, the
        // retired 6to4 relay anycast, and benchmarking, which VPN clients
        // also use to stand in for a name.
        [192, 0, 0 | 2, _]
        | [198, 51, 100, _]
        | [203, 0, 113, _]
        | [192, 88, 99, _]
        | [198, 18..=19, ..] => Reach::NotPublicAddress,
        // Multicast, the reserved block and the broadcast address.
        [224..=255, ..] => Reach::NotPublicAddress,
        _ => return Verdict::Public,
    };
    Verdict::Local(reach)
}

/// An IPv6 address, as its eight groups.
pub(crate) fn v6(s: [u16; 8]) -> Verdict {
    if let Some(provider) = metadata(Endpoint::V6(s)) {
        return Verdict::Metadata(provider);
    }
    // The ways an IPv4 address is carried inside an IPv6 one are judged by the
    // IPv4 address inside: a client that connects to them reaches it.
    if let Some(inside) = embedded_v4(s) {
        return v4(inside);
    }
    match s {
        // Unspecified and loopback.
        [0, 0, 0, 0, 0, 0, 0, 0 | 1] => Verdict::Local(Reach::ThisMachine),
        // Unique local (fc00::/7), link-local (fe80::/10) and the retired
        // site-local (fec0::/10).
        [first, ..]
            if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 || first & 0xffc0 == 0xfec0 =>
        {
            Verdict::Local(Reach::Network)
        }
        [first, second, ..] => {
            // Global unicast is 2000::/3. Inside it, these are not public
            // hosts: IETF assignments (2001::/23, which holds Teredo and
            // benchmarking), documentation (2001:db8::/32 and 3fff::/20),
            // the retired 6bone (3ffe::/16).
            let global = (0x2000..=0x3fff).contains(&first);
            let special = (first == 0x2001 && (second < 0x0200 || second == 0x0db8))
                || (first == 0x3fff && second & 0xf000 == 0)
                || first == 0x3ffe;
            if global && !special {
                Verdict::Public
            } else {
                Verdict::Local(Reach::NotPublicAddress)
            }
        }
    }
}

/// The IPv4 address an IPv6 one carries: mapped (`::ffff:a.b.c.d`),
/// compatible (`::a.b.c.d`), the well-known NAT64 prefix (`64:ff9b::/96`) and
/// 6to4 (`2002::/16`). Not `::` and `::1`, which are the IPv6 addresses
/// themselves. (Teredo is judged not public whatever it carries.)
fn embedded_v4(s: [u16; 8]) -> Option<[u8; 4]> {
    let octets = |high: u16, low: u16| {
        let [first, second] = high.to_be_bytes();
        let [third, fourth] = low.to_be_bytes();
        [first, second, third, fourth]
    };
    match s {
        [0, 0, 0, 0, 0, 0, 0, 0 | 1] => None,
        [0, 0, 0, 0, 0, 0xffff | 0, high, low] | [0x64, 0xff9b, 0, 0, 0, 0, high, low] => {
            Some(octets(high, low))
        }
        [0x2002, high, low, ..] => Some(octets(high, low)),
        _ => None,
    }
}

/// A DNS name, lower case and in ASCII as the parser leaves it.
pub(crate) fn name(name: &str) -> Verdict {
    // One trailing dot is the root: `localhost.` is `localhost`.
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Verdict::Unreadable("has a host name that cannot be read");
    }
    let labels: Vec<&str> = name.split('.').collect();
    // What the parser lets through that no resolver reads one way: an empty
    // label, an over-long one, a character that is not a letter, digit or
    // hyphen.
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        return Verdict::Unreadable("has a host name clients read differently");
    }
    if let Some(provider) = metadata_name(name) {
        return Verdict::Metadata(provider);
    }
    if name == LOOPBACK_NAME || ends_with_name(name, LOOPBACK_NAME) {
        return Verdict::Local(Reach::ThisMachine);
    }
    // A name with no dot is a name on a local network: every public one has
    // at least a registered name under a top-level one.
    if labels.len() == 1 || NETWORK_SUFFIXES.iter().any(|s| ends_with_name(name, s)) {
        return Verdict::Local(Reach::Network);
    }
    if REBINDING
        .iter()
        .any(|s| name == *s || ends_with_name(name, s))
    {
        return Verdict::Local(Reach::Rebinding);
    }
    // The top-level name must look like one: letters, or the `xn--` form of
    // an international one. (A name ending in a number is an IPv4 address
    // to the parser, never a name.)
    let top = labels.last().copied().unwrap_or_default();
    let letters = (2..=63).contains(&top.len()) && top.bytes().all(|b| b.is_ascii_lowercase());
    if letters || top.starts_with("xn--") {
        Verdict::Public
    } else {
        Verdict::Local(Reach::NotPublicName)
    }
}

/// Whether `name` is a name under `suffix`: it ends in a dot and `suffix`.
fn ends_with_name(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len()
        && name.ends_with(suffix)
        && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_of_the_metadata_table_is_a_metadata_service() {
        for (endpoint, provider) in METADATA {
            let verdict = match endpoint {
                Endpoint::V4(octets) => v4(octets),
                Endpoint::V6(groups) => v6(groups),
                Endpoint::Name(name) => self::name(name),
            };
            assert_eq!(verdict, Verdict::Metadata(provider), "{endpoint:?}");
            // Whatever the way to write it, the name is read whole.
            if let Endpoint::Name(name) = endpoint {
                assert_eq!(self::name(&format!("{name}.")), Verdict::Metadata(provider));
                assert_eq!(name, name.to_ascii_lowercase());
            }
        }
    }

    #[test]
    fn the_metadata_table_names_each_endpoint_once_with_a_provider() {
        for (index, (endpoint, provider)) in METADATA.iter().enumerate() {
            assert!(!provider.is_empty(), "{endpoint:?}");
            assert!(
                METADATA[..index].iter().all(|(other, _)| other != endpoint),
                "{endpoint:?} is listed twice"
            );
        }
    }

    #[test]
    fn the_edges_of_each_ipv4_range() {
        let local = |octets| matches!(v4(octets), Verdict::Local(_));
        // The last public address before a range, and the first one after.
        for octets in [
            [1, 0, 0, 0],
            [9, 255, 255, 255],
            [11, 0, 0, 0],
            [100, 63, 255, 255],
            [100, 128, 0, 0],
            [126, 255, 255, 255],
            [128, 0, 0, 0],
            [169, 253, 255, 255],
            [169, 255, 0, 0],
            [172, 15, 255, 255],
            [172, 32, 0, 0],
            [192, 0, 1, 0],
            [192, 0, 3, 0],
            [192, 167, 255, 255],
            [192, 169, 0, 0],
            [198, 17, 255, 255],
            [198, 20, 0, 0],
            [223, 255, 255, 255],
        ] {
            assert_eq!(v4(octets), Verdict::Public, "{octets:?}");
        }
        for octets in [
            [0, 0, 0, 0],
            [0, 255, 255, 255],
            [10, 0, 0, 0],
            [10, 255, 255, 255],
            [100, 64, 0, 0],
            [100, 127, 255, 255],
            [127, 0, 0, 0],
            [127, 255, 255, 255],
            [169, 254, 0, 0],
            [169, 254, 255, 255],
            [172, 16, 0, 0],
            [172, 31, 255, 255],
            [192, 0, 0, 0],
            [192, 0, 2, 0],
            [192, 88, 99, 0],
            [192, 168, 0, 0],
            [192, 168, 255, 255],
            [198, 18, 0, 0],
            [198, 19, 255, 255],
            [198, 51, 100, 0],
            [203, 0, 113, 0],
            [224, 0, 0, 0],
            [239, 255, 255, 255],
            [240, 0, 0, 0],
            [255, 255, 255, 255],
        ] {
            assert!(local(octets), "{octets:?}");
        }
    }

    #[test]
    fn the_ipv6_ranges() {
        for groups in [
            [0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946],
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888],
            [0x2001, 0x0200, 0, 0, 0, 0, 0, 1],
            [0x2a00, 0x1450, 0, 0, 0, 0, 0, 1],
            [0x3ffd, 0, 0, 0, 0, 0, 0, 1],
            [0x3fff, 0x1000, 0, 0, 0, 0, 0, 1],
        ] {
            assert_eq!(v6(groups), Verdict::Public, "{groups:x?}");
        }
        for groups in [
            [0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [0x2001, 0, 0, 0, 0, 0, 0, 1],
            [0x2001, 0x01ff, 0, 0, 0, 0, 0, 1],
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1],
            [0x3ffe, 0, 0, 0, 0, 0, 0, 1],
            [0x3fff, 0x0fff, 0, 0, 0, 0, 0, 1],
            [0x1fff, 0, 0, 0, 0, 0, 0, 1],
            [0x4000, 0, 0, 0, 0, 0, 0, 1],
            [0xfbff, 0, 0, 0, 0, 0, 0, 1],
            [0xfc00, 0, 0, 0, 0, 0, 0, 1],
            [0xfdff, 0, 0, 0, 0, 0, 0, 1],
            [0xfe80, 0, 0, 0, 0, 0, 0, 1],
            [0xfebf, 0, 0, 0, 0, 0, 0, 1],
            [0xfec0, 0, 0, 0, 0, 0, 0, 1],
            [0xff02, 0, 0, 0, 0, 0, 0, 1],
            [0x0064, 0xff9b, 0, 1, 0, 0, 0, 1],
            [0, 0, 0, 0, 0xffff, 0, 0x7f00, 1],
        ] {
            assert!(matches!(v6(groups), Verdict::Local(_)), "{groups:x?}");
        }
    }

    #[test]
    fn an_ipv4_address_carried_in_ipv6_is_judged_by_it() {
        // (groups, the IPv4 address inside)
        for (groups, inside) in [
            ([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], [127, 0, 0, 1]),
            ([0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808], [8, 8, 8, 8]),
            ([0, 0, 0, 0, 0, 0, 0x0a00, 1], [10, 0, 0, 1]),
            ([0, 0, 0, 0, 0, 0, 0x0808, 0x0808], [8, 8, 8, 8]),
            ([0x64, 0xff9b, 0, 0, 0, 0, 0xc0a8, 0x0101], [192, 168, 1, 1]),
            (
                [0x64, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe],
                [169, 254, 169, 254],
            ),
            ([0x2002, 0x7f00, 1, 0, 0, 0, 0, 1], [127, 0, 0, 1]),
            (
                [0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0],
                [169, 254, 169, 254],
            ),
        ] {
            assert_eq!(v6(groups), v4(inside), "{groups:x?}");
        }
    }

    #[test]
    fn the_names_a_local_network_answers() {
        for name in [
            "localhost",
            "localhost.",
            "a.localhost",
            "printer.local",
            "a.b.internal",
            "nas.home.arpa",
            "router.lan",
            "x.localdomain",
            "x.intranet",
            "x.corp",
            "x.home",
            "x.private",
            "x.test",
            "x.example",
            "kubernetes.default.svc",
            "localho.st",
            "a.localhost.direct",
            "1u.ms",
            "x.rbndr.us",
            "box",
            "a",
            "127.0.0.1.nip.io",
            "nip.io",
            "x.sslip.io",
            "a.b.localtest.me",
            "lvh.me",
        ] {
            assert!(matches!(self::name(name), Verdict::Local(_)), "{name}");
        }
    }

    #[test]
    fn the_names_that_are_public() {
        for name in [
            "example.com",
            "example.com.",
            "docs.rs",
            "a.b.c.example.org",
            "xn--r8jz45g.jp",
            "xn--e1afmkfd.xn--p1ai",
            "notlocalhost.com",
            "localhost.example.com",
            "local.example.com",
            "internal.example.com",
            "mylocal.com",
            "nip.io.example.com",
            "a-b.example.co.uk",
        ] {
            assert_eq!(self::name(name), Verdict::Public, "{name}");
        }
    }

    #[test]
    fn a_name_no_resolver_reads_one_way_is_unreadable() {
        for name in [
            "",
            ".",
            "..",
            "a..b",
            "localhost..",
            ".example.com",
            "exa_mple.com",
            "exa!mple.com",
            "exa mple.com",
            "EXAMPLE.com",
            &"a".repeat(64),
            &format!("{}.com", "a".repeat(64)),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(matches!(self::name(name), Verdict::Unreadable(_)), "{name}");
        }
    }

    #[test]
    fn a_top_level_name_must_look_like_one() {
        for name in [
            "example.c",
            "example.c0m",
            "example.com1",
            "foo.bar-baz",
            "example.x",
        ] {
            assert_eq!(
                self::name(name),
                Verdict::Local(Reach::NotPublicName),
                "{name}"
            );
        }
    }

    #[test]
    fn every_reach_has_a_reason() {
        for reach in [
            Reach::ThisMachine,
            Reach::Network,
            Reach::NotPublicAddress,
            Reach::NotPublicName,
            Reach::Rebinding,
        ] {
            assert!(reach.reason().starts_with("fetches "), "{reach:?}");
        }
    }
}
