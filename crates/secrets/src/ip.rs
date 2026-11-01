//! IP addresses that belong to someone: public ones.
//!
//! The standard library's address types are off limits to a guard (they sit
//! beside sockets), so the two forms are read here, by their spelling.

use crate::rows::Candidate;
use crate::text;

/// An IPv4 address of four plain numbers (no leading zero, none over 255)
/// that is not a piece of a longer dotted number, and is in no range a
/// public host cannot have: this network, private, shared, loopback,
/// link-local, protocol assignments, documentation, benchmarking, multicast,
/// reserved, broadcast.
pub(crate) fn is_public_v4(candidate: &Candidate<'_>) -> bool {
    let mut octets = [0u8; 4];
    let mut count = 0;
    for part in candidate.secret.split('.') {
        let leading_zero = part.len() > 1 && part.starts_with('0');
        let (Ok(number), Some(slot)) = (part.parse::<u8>(), octets.get_mut(count)) else {
            return false;
        };
        if leading_zero {
            return false;
        }
        *slot = number;
        count += 1;
    }
    let joined = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
    count == 4
        && !joined(text::before(candidate.text, candidate.start))
        && !joined(text::after(candidate.text, candidate.end))
        && !text::in_longer_number(candidate.text, candidate.start, candidate.end)
        && public_v4(octets)
}

fn public_v4([a, b, c, _]: [u8; 4]) -> bool {
    !matches!(
        (a, b, c),
        (0 | 10 | 127 | 224..=255, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0 | 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
    )
}

/// An IPv6 address, global unicast (`2000::/3`) and outside the ranges set
/// aside for documentation, protocol assignments and the 6to4 transition.
/// Loopback, link-local, unique-local and multicast addresses are outside
/// `2000::/3` and so are not.
pub(crate) fn is_public_v6(candidate: &Candidate<'_>) -> bool {
    let Some(groups) = parse_v6(candidate.secret) else {
        return false;
    };
    let joined = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == ':');
    !joined(text::before(candidate.text, candidate.start))
        && !joined(text::after(candidate.text, candidate.end))
        && public_v6(groups)
}

fn public_v6(groups: [u16; 8]) -> bool {
    let [a, b, ..] = groups;
    (0x2000..=0x3fff).contains(&a)
        && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
        && a != 0x2002
        && !(a == 0x3fff && b < 0x1000)
}

/// The eight groups of an IPv6 address written as hex groups, with at most
/// one `::`.
fn parse_v6(text: &str) -> Option<[u16; 8]> {
    let group = |part: &str| -> Option<u16> {
        if part.is_empty() || part.len() > 4 {
            return None;
        }
        u16::from_str_radix(part, 16).ok()
    };
    let groups = |text: &str| -> Option<Vec<u16>> {
        if text.is_empty() {
            return Some(Vec::new());
        }
        text.split(':').map(group).collect()
    };
    let mut out = [0u16; 8];
    if let Some((head, tail)) = text.split_once("::") {
        let (head, tail) = (groups(head)?, groups(tail)?);
        // `::` stands for at least one group.
        if head.len() + tail.len() > 7 {
            return None;
        }
        for (slot, value) in out.iter_mut().zip(&head) {
            *slot = *value;
        }
        let from = 8 - tail.len();
        for (slot, value) in out.iter_mut().skip(from).zip(&tail) {
            *slot = *value;
        }
        Some(out)
    } else {
        let all = groups(text)?;
        let all: [u16; 8] = all.try_into().ok()?;
        Some(all)
    }
}
