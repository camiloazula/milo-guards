//! Just enough base64 to read a Basic header: the standard alphabet, with or
//! without padding.

/// The value of a base64 character.
fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The bytes `text` encodes, or `None` if it is not base64.
fn decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.trim_end_matches('=').as_bytes();
    // One digit left over carries no whole byte: not a valid encoding.
    if digits.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 4 * 3 + 2);
    let mut bits: u32 = 0;
    let mut held = 0;
    for &byte in digits {
        bits = (bits << 6) | u32::from(value(byte)?);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((bits >> held) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Whether `text` is the base64url of a number of 17 to 21 digits and
/// nothing else: the id of a user, as a Discord bot token begins. The URL-safe
/// alphabet (`-` and `_`), no padding. A word of code is base64 too, and
/// decodes to letters; an id decodes to digits only.
pub(crate) fn is_numeric_id(text: &str) -> bool {
    let standard: String = text
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let Some(bytes) = decode(&standard) else {
        return false;
    };
    (17..=21).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_digit)
}

/// Whether `text` is the base64 of `user:password`: printable text with a
/// colon in it. Any word is base64, so this is what tells a credential from
/// the word after the word "basic".
pub(crate) fn is_user_and_password(text: &str) -> bool {
    let Some(bytes) = decode(text) else {
        return false;
    };
    let Ok(decoded) = std::str::from_utf8(&bytes) else {
        return false;
    };
    // RFC 7617 writes its example with this pair, and every tutorial copies it.
    decoded.len() >= 3
        && decoded.contains(':')
        && !decoded.chars().any(char::is_control)
        && decoded != "Aladdin:open sesame"
}
