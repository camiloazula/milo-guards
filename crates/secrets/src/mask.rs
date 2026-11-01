//! What a finding shows of what it found: never the secret.

use crate::scan::Hit;

/// How much of what was found a finding's target shows.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mask {
    /// The public prefix of a key, at most this many characters, then the
    /// length: `AKIA… (20 chars)`. Only for a key whose first characters
    /// are the same on every key of its kind.
    Prefix(usize),
    /// The length alone: `… (8 chars)`. For what begins with the secret
    /// itself: a password, a card number, an address.
    Length,
    /// The text from the start of the match to this byte: the first line of
    /// a key block, which is the same on every key.
    Head(usize),
}

/// The target a finding carries for `hit`.
pub(crate) fn target(text: &str, hit: &Hit) -> String {
    let matched = text.get(hit.start..hit.end).unwrap_or_default();
    let length = matched.chars().count();
    let counted = |shown: &str| {
        let unit = if length == 1 { "char" } else { "chars" };
        format!("{shown}… ({length} {unit})")
    };
    match hit.mask {
        // A prefix is shown only when it is clearly a prefix: at most half
        // of what was found.
        Mask::Prefix(shown) if length >= 2 * shown => {
            counted(&matched.chars().take(shown).collect::<String>())
        }
        Mask::Prefix(_) | Mask::Length => counted(""),
        Mask::Head(end) => text.get(hit.start..end).unwrap_or_default().to_string(),
    }
}
