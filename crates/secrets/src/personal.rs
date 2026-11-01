//! Checks for personal data: a government id's own rules, an email address
//! that is not a placeholder, a phone number.

use crate::rows::Candidate;
use crate::text;

fn digits(text: &str) -> Vec<u32> {
    text.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| u32::from(b - b'0'))
        .collect()
}

/// A US social security number: `AAA-GG-SSSS`, where the area is not `000`,
/// `666` or `9xx`, the group is not `00` and the serial is not `0000`; and
/// no dash or digit joins it to a longer number.
pub(crate) fn is_ssn(candidate: &Candidate<'_>) -> bool {
    let parts: Vec<&str> = candidate.secret.split('-').collect();
    let [area, group, serial] = parts[..] else {
        return false;
    };
    let before = text::before(candidate.text, candidate.start);
    let after = text::after(candidate.text, candidate.end);
    let joined = |c: Option<char>| c.is_some_and(|c| c == '-' || c.is_ascii_alphanumeric());
    !joined(before)
        && !joined(after)
        && !text::in_longer_number(candidate.text, candidate.start, candidate.end)
        && area != "000"
        && area != "666"
        && !area.starts_with('9')
        && group != "00"
        && serial != "0000"
}

/// A UK national insurance number: two letters that are not one of the
/// prefixes never issued, six digits, a letter from A to D.
pub(crate) fn is_nino(candidate: &Candidate<'_>) -> bool {
    let prefix: String = candidate.secret.chars().take(2).collect();
    !matches!(
        prefix.as_str(),
        "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ"
    )
}

/// A Brazilian CPF: nine digits and two check digits.
pub(crate) fn is_cpf(candidate: &Candidate<'_>) -> bool {
    let digits = digits(candidate.secret);
    if digits.len() != 11 || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let check = |weights: &[u32]| {
        let sum: u32 = digits
            .iter()
            .zip(weights)
            .map(|(digit, weight)| digit * weight)
            .sum();
        let rest = (sum * 10) % 11;
        if rest == 10 {
            0
        } else {
            rest
        }
    };
    check(&[10, 9, 8, 7, 6, 5, 4, 3, 2]) == digits[9]
        && check(&[11, 10, 9, 8, 7, 6, 5, 4, 3, 2]) == digits[10]
}

/// An email address that someone could have: not a name reserved for
/// examples (RFC 2606), not the `@2x` of an image's file name, not the
/// `git@github.com` of a remote written `host:path`.
pub(crate) fn is_email(candidate: &Candidate<'_>) -> bool {
    let Some((local, domain)) = candidate.secret.rsplit_once('@') else {
        return false;
    };
    if local.len() > 64 || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    let domain = domain.to_ascii_lowercase();
    if domain.len() > 253
        || domain
            .split('.')
            .any(|l| l.starts_with('-') || l.ends_with('-'))
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let reserved_name = matches!(
        labels[labels.len().saturating_sub(2)..],
        ["example", "com" | "org" | "net"]
    );
    let reserved_top = matches!(
        labels.last(),
        Some(&("example" | "invalid" | "test" | "localhost"))
    );
    let retina = labels.first().is_some_and(|first| {
        first.len() == 2 && first.starts_with(|c: char| c.is_ascii_digit()) && first.ends_with('x')
    });
    let remote = text::after(candidate.text, candidate.end) == Some(':')
        && candidate
            .text
            .get(candidate.end + 1..)
            .and_then(|tail| tail.chars().next())
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '~' | '.' | '_'));
    !reserved_name
        && !reserved_top
        && !retina
        && !remote
        && !in_url_authority(candidate.text, candidate.start)
}

/// Whether the text just before `start` is the front of a URL (`scheme://`,
/// then what comes before the `@`): a user name or password there is the
/// address's own, and the URL rows judge it.
fn in_url_authority(text: &str, start: usize) -> bool {
    let mut from = start.saturating_sub(256);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    text.get(from..start)
        .and_then(|window| {
            window
                .rsplit(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')')
                })
                .next()
        })
        .is_some_and(|token| {
            token
                .rfind("://")
                .is_some_and(|at| !token[at + 3..].contains(['/', '?', '#']))
        })
}

/// A phone number in the international form: `+`, a country code and the
/// number, nine to fifteen digits (eight when written in groups), not a
/// piece of a longer token.
pub(crate) fn is_phone(candidate: &Candidate<'_>) -> bool {
    let count = digits(candidate.secret).len();
    let grouped = candidate
        .secret
        .bytes()
        .any(|b| !b.is_ascii_digit() && b != b'+');
    let enough = if grouped { count >= 8 } else { count >= 10 };
    // A `+` inside base64 (`a+b/c=`) or after a backslash is not a number's.
    let before = text::before(candidate.text, candidate.start);
    let after = text::after(candidate.text, candidate.end);
    enough
        && count <= 15
        && !before.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '\\'))
        && !after.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/'))
        && !text::in_longer_number(candidate.text, candidate.start, candidate.end)
}
