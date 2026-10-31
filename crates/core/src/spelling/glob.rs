//! Wildcard patterns in a path: which entries of a folder one can match.
//!
//! A part of a path holding `*`, `?` or `[` stands for the entries that
//! match it. The resolver judges a pattern by the folder before its first
//! wildcard; [`shape`] says how much of that folder the pattern takes, and
//! [`matches()`] tells whether one pattern part can match one name.

use crate::Flavour;

/// The characters that make a path part a pattern.
pub(crate) const WILDCARDS: [char; 3] = ['*', '?', '['];

/// Whether `text` holds a wildcard.
#[must_use]
pub fn has_wildcard(text: &str) -> bool {
    text.contains(WILDCARDS)
}

/// The hidden names the path model protects inside a workspace: a wildcard
/// part that can match one of them takes the protected place.
const PROTECTED: [&str; 1] = [".git"];

/// Whether the pattern part `pattern` matches the file name `name`.
///
/// `*` is any run of characters, `?` is one character, and `[...]` is one
/// character of a class (`[!x]` or `[^x]` is any other; `a-z` is a range;
/// a `]` first in the class is itself). A `[` with no `]` after it is just a
/// `[`. A part never holds a separator, so neither does a name.
///
/// `flavour` says how names compare: a Windows name compares without case.
/// `hidden` says whether a wildcard can match a name's leading dot, as
/// PowerShell and cmd wildcards do. When it is `false`, the POSIX rule holds:
/// a name that starts with `.` is matched only by a pattern that starts with
/// a literal `.`. (A POSIX shell with `dotglob` set matches like `true`.)
#[must_use]
pub fn matches(pattern: &str, name: &str, flavour: Flavour, hidden: bool) -> bool {
    let fold = flavour == Flavour::Windows;
    let tokens = tokens(pattern);
    let name: Vec<char> = name.chars().collect();
    if !hidden && name.first() == Some(&'.') && tokens.first() != Some(&Token::Literal('.')) {
        return false;
    }
    let (mut at, mut on) = (0, 0);
    // Where the last `*` was and the name position it has taken up to.
    let mut star: Option<(usize, usize)> = None;
    while on < name.len() {
        match tokens.get(at) {
            Some(Token::Star) => {
                star = Some((at, on));
                at += 1;
            }
            Some(token) if token.takes(name[on], fold) => {
                at += 1;
                on += 1;
            }
            _ => match star {
                Some((from, taken)) => {
                    star = Some((from, taken + 1));
                    at = from + 1;
                    on = taken + 1;
                }
                None => return false,
            },
        }
    }
    tokens[at..].iter().all(|token| *token == Token::Star)
}

/// One step of a pattern part.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Star,
    Any,
    Literal(char),
    Class {
        negated: bool,
        /// Inclusive ranges; a single character is a range of one.
        ranges: Vec<(char, char)>,
    },
}

impl Token {
    /// Whether the token (not a `*`) takes the one character `c`.
    fn takes(&self, c: char, fold: bool) -> bool {
        let same = |a: char, b: char| {
            if fold {
                a.eq_ignore_ascii_case(&b)
            } else {
                a == b
            }
        };
        match self {
            Self::Star => false,
            Self::Any => true,
            Self::Literal(literal) => same(*literal, c),
            Self::Class { negated, ranges } => {
                let inside = ranges.iter().any(|&(low, high)| {
                    let within = |c: char| low <= c && c <= high;
                    within(c)
                        || (fold
                            && (within(c.to_ascii_lowercase()) || within(c.to_ascii_uppercase())))
                });
                inside != *negated
            }
        }
    }
}

fn tokens(pattern: &str) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        match c {
            '*' => {
                // `**` is `*`.
                if out.last() != Some(&Token::Star) {
                    out.push(Token::Star);
                }
            }
            '?' => out.push(Token::Any),
            '[' => match class(&chars[at..]) {
                Some((token, used)) => {
                    out.push(token);
                    at += used;
                }
                None => out.push(Token::Literal('[')),
            },
            _ => out.push(Token::Literal(c)),
        }
    }
    out
}

/// The class that starts just after a `[`, and how many characters it takes
/// up to its `]`; `None` when no `]` closes it.
fn class(chars: &[char]) -> Option<(Token, usize)> {
    let negated = matches!(chars.first(), Some('!' | '^'));
    let mut at = usize::from(negated);
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let low = *chars.get(at)?;
        at += 1;
        if low == ']' && !first {
            return Some((Token::Class { negated, ranges }, at));
        }
        first = false;
        if chars.get(at) == Some(&'-') && chars.get(at + 1).is_some_and(|next| *next != ']') {
            ranges.push((low, chars[at + 1]));
            at += 2;
        } else {
            ranges.push((low, low));
        }
    }
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
    // A PowerShell or cmd wildcard matches a leading dot; a POSIX one only
    // when the pattern starts with it (and that is the first test here). The
    // last part, when it is a catch-all, is the `All` shape instead: it takes
    // the whole folder, which holds no `.git` of its own to protect. A
    // catch-all before the last part still picks a folder, and so can pick
    // `.git` (`*\objects`).
    let dots = flavour == Flavour::Windows;
    let hidden = |at: usize, part: &str| {
        (part.starts_with('.') && part != "..")
            || (has_wildcard(part)
                && !(at + 1 == parts.len() && catch_all(part))
                && PROTECTED
                    .iter()
                    .any(|name| matches(part, name, flavour, dots)))
    };
    if parts.iter().enumerate().any(|(at, part)| hidden(at, part)) {
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
    fn a_windows_wildcard_matches_a_leading_dot() {
        let windows = Flavour::Windows;
        for pattern in [
            "*git", "?git", "*", ".*", "*.git", "*.*", ".g*", "????", "[.]git", "[!x]git",
            "*[a-z]t",
        ] {
            assert!(matches(pattern, ".git", windows, true), "{pattern}");
        }
        for pattern in [
            "*.tmp", "?git2", "*x", "git", "???", "[a-z]git", "[!.]git", "*gi", "t*",
        ] {
            assert!(!matches(pattern, ".git", windows, true), "{pattern}");
        }
    }

    #[test]
    fn a_windows_wildcard_compares_without_case() {
        let windows = Flavour::Windows;
        assert!(matches("*GIT", ".git", windows, true));
        assert!(matches(".G?T", ".git", windows, true));
        assert!(matches("[A-Z]git", "xgit", windows, true));
        assert!(matches("[a-z]GIT", "Xgit", windows, true));
        assert!(!matches("[!A-Z]git", "xgit", windows, true));
        assert!(!matches("*GIT", ".git", Flavour::Posix, true));
    }

    #[test]
    fn a_posix_wildcard_skips_a_leading_dot_unless_the_pattern_has_one() {
        let posix = Flavour::Posix;
        for pattern in ["*git", "?git", "*", "*.*", "????", "[.]git", "[!x]git"] {
            assert!(!matches(pattern, ".git", posix, false), "{pattern}");
        }
        for pattern in [".git", ".g*", ".*", ".???", ".[a-z]it"] {
            assert!(matches(pattern, ".git", posix, false), "{pattern}");
        }
        assert!(matches("*git", "xgit", posix, false));
        assert!(matches("*", "x.git", posix, false));
    }

    #[test]
    fn the_hidden_flag_is_the_only_difference_for_dot_names() {
        // What `dotglob` will switch on for a POSIX shell.
        assert!(matches("*git", ".git", Flavour::Posix, true));
        assert!(!matches("*git", ".git", Flavour::Posix, false));
        assert!(!matches("*GIT", ".git", Flavour::Posix, true));
    }

    #[test]
    fn classes_ranges_and_negation() {
        let posix = Flavour::Posix;
        assert!(matches("[abc]x", "bx", posix, false));
        assert!(!matches("[abc]x", "dx", posix, false));
        assert!(matches("[a-c]x", "bx", posix, false));
        assert!(matches("[!a-c]x", "dx", posix, false));
        assert!(matches("[^a-c]x", "dx", posix, false));
        assert!(!matches("[!a-c]x", "bx", posix, false));
        // A `]` first in a class is a member; a trailing `-` is a dash.
        assert!(matches("[]a]x", "]x", posix, false));
        assert!(matches("[a-]x", "-x", posix, false));
        // A `[` with no `]` after it is a plain character.
        assert!(matches("[a", "[a", posix, false));
        assert!(matches("a[", "a[", posix, false));
        assert!(!matches("[a", "a", posix, false));
        assert!(matches("[!", "[!", posix, false));
    }

    #[test]
    fn stars_backtrack() {
        let posix = Flavour::Posix;
        assert!(matches("a*b*c", "aXbYbc", posix, false));
        assert!(matches("a**c", "ac", posix, false));
        assert!(matches("*b", "abb", posix, false));
        assert!(!matches("a*b", "abc", posix, false));
        assert!(!matches("a?", "a", posix, false));
        assert!(matches("*", "", posix, false));
        assert!(matches("", "", posix, false));
        assert!(!matches("", "a", posix, false));
    }

    #[test]
    fn a_windows_wildcard_part_that_can_match_git_is_hidden() {
        let windows = Flavour::Windows;
        assert_eq!(shape("*git", windows), Shape::Hidden);
        assert_eq!(shape("?git", windows), Shape::Hidden);
        assert_eq!(shape(r"src\*G?T\x", windows), Shape::Hidden);
        assert_eq!(shape("*.*", windows), Shape::Hidden);
        assert_eq!(shape("*.tmp", windows), Shape::Entries);
        assert_eq!(shape("*", windows), Shape::All);
        assert_eq!(shape(r"build\*", windows), Shape::All);
        // The same patterns on a POSIX shell skip the dot name.
        assert_eq!(shape("*git", Flavour::Posix), Shape::Entries);
        assert_eq!(shape("?git", Flavour::Posix), Shape::Entries);
    }

    #[test]
    fn a_part_is_a_pattern_when_it_holds_a_wildcard() {
        assert!(has_wildcard("a[b"));
        assert!(!has_wildcard("a.b"));
    }
}
