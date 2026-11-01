//! Small readings of a text that several detectors share. Every function
//! takes byte offsets on `char` boundaries and returns without slicing
//! through a character.

/// The character that ends just before byte `at`.
pub(crate) fn before(text: &str, at: usize) -> Option<char> {
    text.get(..at)?.chars().next_back()
}

/// The character that starts at byte `at`.
pub(crate) fn after(text: &str, at: usize) -> Option<char> {
    text.get(at..)?.chars().next()
}

/// Whether `text[start..end]` stands alone: no ASCII letter or digit touches
/// it on either side. A letter or digit beside a token means the token is a
/// piece of something longer (a base64 blob, an identifier), which is not
/// what the token's shape is.
///
/// Only ASCII counts, on purpose: text written without spaces (Chinese,
/// Japanese) runs words together, and a key must still be found beside it.
pub(crate) fn alone(text: &str, start: usize, end: usize) -> bool {
    !before(text, start).is_some_and(|c| c.is_ascii_alphanumeric())
        && !after(text, end).is_some_and(|c| c.is_ascii_alphanumeric())
}

/// Whether the last 16 characters of `secret` are varied enough to be
/// random. A key is random; a placeholder (`xxxxxxxx`, `00000000`,
/// `abababab`) is not, and writing one in a README is not a leak.
pub(crate) fn varied(secret: &str) -> bool {
    let mut tail: Vec<char> = secret.chars().rev().take(16).collect();
    tail.sort_unstable();
    tail.dedup();
    tail.len() >= 6
}

/// Whether `value` is no value at all but a stand-in for one: a reference to
/// a variable (`$TOKEN`, `${TOKEN}`, `{{ token }}`), a template field
/// (`<password>`, `%s`), a redaction (`[REDACTED]`) or a mask (`****`,
/// `xxxxxxxx`). Such a text names where a secret comes from, and holds none.
pub(crate) fn is_reference(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    if value.contains("${") || value.contains("{{") || value.contains("{%") {
        return true;
    }
    let last = value.chars().next_back().unwrap_or(first);
    match first {
        '$' => {
            let name = &value[1..];
            let name = name
                .strip_prefix('{')
                .and_then(|n| n.strip_suffix('}'))
                .unwrap_or(name);
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '-')
                && !name.starts_with(|c: char| c.is_ascii_digit())
        }
        '<' => last == '>',
        '{' => last == '}',
        '[' => last == ']',
        '%' => true,
        _ => is_mask(value),
    }
}

/// Whether `value` is three or more of one character, or only of the
/// characters people write a hidden value with: `xxxx`, `****`, `0000`.
fn is_mask(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    value.chars().count() >= 3
        && (chars.all(|c| c == first)
            || value
                .chars()
                .all(|c| matches!(c, '*' | 'x' | 'X' | '.' | '-' | '_' | '#' | '\u{2022}')))
}

/// Whether `text[start..end]` is a piece of a longer dotted number
/// (`1.2.3.4.5`, `4111111111111111.5`): a dot and a digit touch it.
pub(crate) fn in_longer_number(text: &str, start: usize, end: usize) -> bool {
    let dotted_before = before(text, start) == Some('.')
        && text
            .get(..start - 1)
            .and_then(|head| head.chars().next_back())
            .is_some_and(|c| c.is_ascii_digit());
    let dotted_after = after(text, end) == Some('.')
        && text
            .get(end + 1..)
            .and_then(|tail| tail.chars().next())
            .is_some_and(|c| c.is_ascii_digit());
    dotted_before || dotted_after
}
