//! Wildcard patterns in a path: which entries of a folder one can match.
//!
//! A part of a path holding `*`, `?` or `[` stands for the entries that
//! match it. The resolver judges a pattern by the folder before its first
//! wildcard; [`shape`] says how much of that folder the pattern takes.

use crate::Flavour;

/// The characters that make a path part a pattern.
pub(crate) const WILDCARDS: [char; 3] = ['*', '?', '['];

/// Whether `text` holds a wildcard.
#[must_use]
pub fn has_wildcard(text: &str) -> bool {
    text.contains(WILDCARDS)
}

/// What a wildcard pattern matches inside the folder before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Shape {
    /// A part starting with `.` (`.g*`, `*/.git`): hidden entries, `.git`
    /// among them.
    Hidden,
    /// Its last part is a catch-all (`*`, `*/*`, `?*`): every entry.
    All,
    /// Its last part picks some names (`*.log`, `*/*.o`).
    Entries,
}

/// The shape of `text`, read from its first wildcard part to its end.
#[must_use]
pub fn shape(text: &str, flavour: Flavour) -> Shape {
    let parts: Vec<&str> = text
        .split(flavour.separators())
        .skip_while(|part| !has_wildcard(part))
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if parts
        .iter()
        .any(|part| part.starts_with('.') && *part != "..")
    {
        Shape::Hidden
    } else if parts.last().is_some_and(|last| catch_all(last)) {
        Shape::All
    } else {
        Shape::Entries
    }
}

/// Whether a wildcard pattern matches every entry of its folder (`*`, `**`,
/// `?*`, `[!.]*`): once its wildcards and classes are removed, nothing is
/// left to match against.
fn catch_all(part: &str) -> bool {
    if !part.contains('*') {
        return false;
    }
    let mut literal = String::new();
    let mut rest = part;
    while let Some(open) = rest.find('[') {
        literal.push_str(&rest[..open]);
        let Some(close) = rest[open..].find(']') else {
            rest = "";
            break;
        };
        rest = &rest[open + close + 1..];
    }
    literal.push_str(rest);
    literal.chars().all(|c| matches!(c, '*' | '?'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_takes_the_shape_of_its_last_part() {
        let posix = Flavour::Posix;
        assert_eq!(shape("*", posix), Shape::All);
        assert_eq!(shape("src/*/*", posix), Shape::All);
        assert_eq!(shape("?*", posix), Shape::All);
        assert_eq!(shape("[!.]*", posix), Shape::All);
        assert_eq!(shape("*.log", posix), Shape::Entries);
        assert_eq!(shape("src/*/*.o", posix), Shape::Entries);
        assert_eq!(shape(".g*", posix), Shape::Hidden);
        assert_eq!(shape("*/.git", posix), Shape::Hidden);
        assert_eq!(shape("a/*/../b", posix), Shape::Entries);
    }

    #[test]
    fn windows_patterns_split_at_both_separators() {
        assert_eq!(shape(r"src\*\.git", Flavour::Windows), Shape::Hidden);
        assert_eq!(shape(r"src\*\.git", Flavour::Posix), Shape::Entries);
        assert_eq!(shape(r"build\*", Flavour::Windows), Shape::All);
    }

    #[test]
    fn an_unclosed_class_swallows_the_rest_and_is_a_catch_all() {
        assert_eq!(shape("[*", Flavour::Posix), Shape::All);
    }

    #[test]
    fn a_part_is_a_pattern_when_it_holds_a_wildcard() {
        assert!(has_wildcard("a[b"));
        assert!(!has_wildcard("a.b"));
    }
}
