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

/// The hidden names the path model protects inside a workspace.
const PROTECTED: [&str; 1] = [".git"];

/// What a repository's `.git` folder holds at its top level: a pattern that
/// reaches one of these through `.git` takes the repository's history.
const GIT_ENTRIES: [&str; 18] = [
    "HEAD",
    "config",
    "index",
    "objects",
    "refs",
    "hooks",
    "info",
    "logs",
    "packed-refs",
    "modules",
    "lfs",
    "worktrees",
    "shallow",
    "ORIG_HEAD",
    "MERGE_HEAD",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
];

/// Files deeper in `.git` whose loss hurts as much (a branch's tip, the
/// repository's description, the last message, a pack): a name search of
/// every folder that finds one of these takes history with it.
const GIT_FILES: [&str; 7] = [
    "description",
    "COMMIT_EDITMSG",
    "FETCH_HEAD",
    "main",
    "master",
    "pack-0.pack",
    "pack-0.idx",
];

/// The 8.3 short names Windows gives the long names above on a drive that
/// creates them (the system drive does by default): cmd matches its wildcards
/// against these as well as the long names, which is why `*.pac` finds a pack.
/// A name of at most eight characters with an extension of at most three has
/// none.
const GIT_SHORT_NAMES: [&str; 12] = [
    "PACKED~1",
    "COMMIT~1",
    "DESCRI~1",
    "ORIG_H~1",
    "FETCH_~1",
    "MERGE_~1",
    "REBASE~1",
    "REBASE~2",
    "SEQUEN~1",
    "WORKTR~1",
    "PACK-0~1.PAC",
    "PACK-0~1.IDX",
];

/// Whether the name pattern `pattern` can match the name of something a
/// repository's `.git` holds: one of its top-level entries (`HEAD`, `config`,
/// `index`, `objects`, ...) or a well-known file deeper in (`description`,
/// `COMMIT_EDITMSG`, a pack, a branch named `main` or `master`).
///
/// It is for a search that goes into every folder below one (`del /s`), which
/// finds `.git`'s own files whatever folder they lie in. On Windows the
/// pattern is read as cmd reads it, which is not how PowerShell does:
/// - a trailing dot or space is not part of a name, so the pattern is read
///   both with and without it;
/// - a `.` followed only by `*` or `?` to the end of the pattern also matches
///   a name with no extension (`main.*` finds `main`, as `dir foo.*` lists
///   `foo`);
/// - a run of `?` at the end of the pattern, or just before a `.`, can match
///   nothing (`HEAD?` finds `HEAD`, `main?.x` finds `main.x`);
/// - the 8.3 short names of the long ones are tried as well (`PACKED~1`,
///   `*.pac`).
///
/// Only the names above and their short forms are tried: a pattern that
/// matches a branch or an object with some other name is not told.
///
/// `flavour` is as for [`matches()`]; a name is matched with `hidden` on.
#[must_use]
pub fn can_match_git_entry(pattern: &str, flavour: Flavour) -> bool {
    let names = GIT_ENTRIES.iter().chain(&GIT_FILES);
    if flavour != Flavour::Windows {
        return !pattern.is_empty()
            && names
                .clone()
                .any(|name| matches(pattern, name, flavour, true));
    }
    can_match_cmd(pattern, names.chain(&GIT_SHORT_NAMES))
}

/// The 8.3 short name of the `.git` folder itself on a drive that creates
/// them.
const GIT_FOLDER_SHORT_NAME: &str = "GIT~1";

/// Whether the name pattern `pattern` can match `GIT~1`, the 8.3 short name
/// of the `.git` folder, read as cmd reads a wildcard (see
/// [`can_match_git_entry`]).
///
/// It is for a search that hands its pattern to the file system's own
/// matching, as Windows PowerShell's `-Filter` does through `FindFirstFile`,
/// which compares a pattern with the short name as well as the long one: `g*`,
/// `*~1`, `GIT~?` and `?????` find `.git` there, though none matches the name
/// `.git`.
#[must_use]
pub fn can_match_git_short_name(pattern: &str) -> bool {
    can_match_cmd(pattern, [GIT_FOLDER_SHORT_NAME].iter())
}

/// Whether the cmd pattern `pattern` (or, without its trailing dots and
/// spaces, which are not part of a name) can match one of `names`.
fn can_match_cmd<'a>(pattern: &str, names: impl Iterator<Item = &'a &'a str> + Clone) -> bool {
    let trimmed = pattern.trim_end_matches(['.', ' ']);
    [pattern, trimmed].iter().any(|pattern| {
        if pattern.is_empty() {
            return false;
        }
        let (tokens, optional) = cmd_tokens(pattern);
        names
            .clone()
            .any(|name| matches_cmd(&tokens, &optional, name))
    })
}

/// The tokens of a cmd pattern and which of them can match nothing: a `?` in
/// a run at the end or just before a `.`, and a `.` followed only by `*` or
/// `?` to the end (a `*` can always match nothing).
fn cmd_tokens(pattern: &str) -> (Vec<Token>, Vec<bool>) {
    let tokens = tokens(pattern, Flavour::Windows);
    let mut optional = vec![false; tokens.len()];
    let wild = |token: &Token| matches!(token, Token::Star | Token::Any);
    // The tail of wildcards at the end, and the dot before it.
    let tail = tokens
        .iter()
        .rposition(|token| !wild(token))
        .map_or(0, |at| at + 1);
    optional[tail..].fill(true);
    if tail > 0 && tokens[tail - 1] == Token::Literal('.') {
        optional[tail - 1] = true;
    }
    for (at, token) in tokens.iter().enumerate() {
        if *token == Token::Literal('.') {
            let run = tokens[..at]
                .iter()
                .rev()
                .take_while(|token| **token == Token::Any)
                .count();
            optional[at - run..at].fill(true);
        }
    }
    (tokens, optional)
}

/// Whether the cmd pattern given as `tokens` (see [`cmd_tokens`]) matches
/// `name`, with no case and with the leading dot open to wildcards.
fn matches_cmd(tokens: &[Token], optional: &[bool], name: &str) -> bool {
    // The token positions the name read so far can stand at, after skipping
    // every token that can match nothing.
    let settle = |states: &mut Vec<bool>| {
        for at in 0..tokens.len() {
            if states[at] && (tokens[at] == Token::Star || optional[at]) {
                states[at + 1] = true;
            }
        }
    };
    let mut states = vec![false; tokens.len() + 1];
    states[0] = true;
    settle(&mut states);
    for c in name.chars() {
        let mut next = vec![false; tokens.len() + 1];
        for at in 0..tokens.len() {
            if !states[at] {
                continue;
            }
            if tokens[at] == Token::Star {
                next[at] = true;
            } else if tokens[at].takes(c, true) {
                next[at + 1] = true;
            }
        }
        settle(&mut next);
        states = next;
    }
    states[tokens.len()]
}

/// Whether the pattern part `pattern` matches the file name `name`.
///
/// `*` is any run of characters, `?` is one character, and `[...]` is one
/// character of a class (`a-z` is a range; a `]` first in the class is
/// itself). A `[` with no `]` after it is just a `[`. A part never holds a
/// separator, so neither does a name.
///
/// `flavour` says how the pattern is read and how names compare:
/// - `Posix`: `[!x]` and `[^x]` are any other character, and names compare
///   with case.
/// - `Windows`: PowerShell has no negation, so `!` and `^` are members of the
///   class; a backtick makes the next character itself (`` `* `` is a star);
///   names compare without case, by the Unicode lower and upper case of each
///   character, so that `ı` and `İ` count as an `i`.
///
/// `hidden` says whether a wildcard can match a name's leading dot, as
/// PowerShell and cmd wildcards do. When it is `false`, the POSIX rule holds:
/// a name that starts with `.` is matched only by a pattern that starts with
/// a literal `.`.
#[must_use]
pub fn matches(pattern: &str, name: &str, flavour: Flavour, hidden: bool) -> bool {
    let fold = flavour == Flavour::Windows;
    let tokens = tokens(pattern, flavour);
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

/// Whether the pattern, whose first part is directly inside a repository's
/// folder, can reach `.git`'s own entries: `parts` are the pattern's parts
/// from its first wildcard part on. That part must match `.git`. If it is
/// the last part it takes `.git` itself, unless it is a catch-all (the
/// whole folder is judged then). Otherwise the next part must match one of
/// `.git`'s own entries (`*\objects` does, `*\bin` does not). A pattern that
/// still holds a `..` is taken to reach it.
///
/// `hidden` is the same as for [`matches()`].
#[must_use]
pub fn reaches_git(parts: &[&str], flavour: Flavour, hidden: bool) -> bool {
    let [first, rest @ ..] = parts else {
        return false;
    };
    if !PROTECTED
        .iter()
        .any(|name| matches(first, name, flavour, hidden))
    {
        return false;
    }
    match rest.first() {
        None => !catch_all(first, flavour),
        Some(&"..") => true,
        Some(next) => GIT_ENTRIES
            .iter()
            .any(|entry| matches(next, entry, flavour, hidden)),
    }
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

/// `c` in the cases a Windows name compares by: its first lower and upper
/// case character.
fn cases(c: char) -> (char, char) {
    (
        c.to_lowercase().next().unwrap_or(c),
        c.to_uppercase().next().unwrap_or(c),
    )
}

impl Token {
    /// Whether the token (not a `*`) takes the one character `c`.
    fn takes(&self, c: char, fold: bool) -> bool {
        let same = |a: char, b: char| {
            a == b || (fold && (cases(a).0 == cases(b).0 || cases(a).1 == cases(b).1))
        };
        match self {
            Self::Star => false,
            Self::Any => true,
            Self::Literal(literal) => same(*literal, c),
            Self::Class { negated, ranges } => {
                let within = |c: char, low: char, high: char| low <= c && c <= high;
                let inside = ranges.iter().any(|&(low, high)| {
                    within(c, low, high)
                        || (fold && {
                            let (lower, upper) = cases(c);
                            within(lower, low, high)
                                || within(upper, low, high)
                                // A lone member compares like a literal.
                                || (low == high && same(low, c))
                        })
                });
                inside != *negated
            }
        }
    }
}

fn tokens(pattern: &str, flavour: Flavour) -> Vec<Token> {
    let windows = flavour == Flavour::Windows;
    let chars: Vec<char> = pattern.chars().collect();
    // A `[` after the last `]` has nothing to close it: it is a plain `[`.
    // Finding that once keeps a long run of `[` linear.
    let last_close = chars.iter().rposition(|c| *c == ']');
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        match c {
            '`' if windows && at < chars.len() => {
                out.push(Token::Literal(chars[at]));
                at += 1;
            }
            '*' => {
                // `**` is `*`.
                if out.last() != Some(&Token::Star) {
                    out.push(Token::Star);
                }
            }
            '?' => out.push(Token::Any),
            '[' if last_close.is_some_and(|close| at <= close) => {
                match class(&chars[at..], windows) {
                    Some((token, used)) => {
                        out.push(token);
                        at += used;
                    }
                    None => out.push(Token::Literal('[')),
                }
            }
            _ => out.push(Token::Literal(c)),
        }
    }
    out
}

/// The class that starts just after a `[`, and how many characters it takes
/// up to its `]`; `None` when no `]` closes it. On Windows `!` and `^` first
/// in it are members, and a backtick makes the next character a member.
fn class(chars: &[char], windows: bool) -> Option<(Token, usize)> {
    let negated = !windows && matches!(chars.first(), Some('!' | '^'));
    let mut at = usize::from(negated);
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let mut low = *chars.get(at)?;
        at += 1;
        if low == ']' && !first {
            return Some((Token::Class { negated, ranges }, at));
        }
        if windows && low == '`' {
            low = *chars.get(at)?;
            at += 1;
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
    if parts
        .iter()
        .any(|part| part.starts_with('.') && *part != "..")
    {
        Shape::Hidden
    } else if parts.last().is_some_and(|last| catch_all(last, flavour)) {
        Shape::All
    } else {
        Shape::Entries
    }
}

/// Whether a wildcard pattern matches every entry of its folder (`*`, `**`,
/// `?*`, `[!.]*`): once its wildcards and classes are removed, nothing is
/// left to match against. On Windows `*.*` is one too: it means every entry,
/// with or without an extension.
fn catch_all(part: &str, flavour: Flavour) -> bool {
    if flavour == Flavour::Windows && part == "*.*" {
        return true;
    }
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
    fn a_name_search_can_find_the_files_of_git() {
        let windows = Flavour::Windows;
        for pattern in [
            "HEAD",
            "head",
            "config",
            "index",
            "*",
            "*.*",
            "*.",
            "H*",
            "?????",
            "pack-*",
            "*.pack",
            "*.idx",
            "com*",
            "HEAD.",
            "ma?n",
            "[a-z]ndex",
            "main.*",
            "HEAD.*",
            "HEAD?",
            "main.?",
            "????????",
            "ma?n?.*",
            "*.pac",
            "COMMIT~1",
            "PACK-0~1.IDX",
        ] {
            assert!(can_match_git_entry(pattern, windows), "{pattern}");
        }
        for pattern in [
            "",
            ".",
            "..",
            "*.obj",
            "*.tmp",
            "*.log",
            "*.exe",
            "Thumbs.db",
            "a.txt",
            "x*y",
            "*.sample",
            "main.obj",
            "*.orig",
            "foo.*",
            "foo?.*",
            "HEAD?.x",
            "mainx.*",
        ] {
            assert!(!can_match_git_entry(pattern, windows), "{pattern}");
        }
        assert!(can_match_git_entry("HEAD", Flavour::Posix));
        assert!(!can_match_git_entry("head", Flavour::Posix));
        assert!(!can_match_git_entry("HEAD.", Flavour::Posix));
        assert!(!can_match_git_entry("main.*", Flavour::Posix));
        assert!(!can_match_git_entry("*.pac", Flavour::Posix));
    }

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
            "*git", "?git", "*", ".*", "*.git", "*.*", ".g*", "????", "[.]git", "[!.]git",
            "[^.]git", "*[a-z]t",
        ] {
            assert!(matches(pattern, ".git", windows, true), "{pattern}");
        }
        for pattern in [
            "*.tmp", "?git2", "*x", "git", "???", "[a-z]git", "[!x]git", "*gi", "t*",
        ] {
            assert!(!matches(pattern, ".git", windows, true), "{pattern}");
        }
    }

    #[test]
    fn a_windows_class_has_no_negation_and_a_backtick_escapes() {
        let windows = Flavour::Windows;
        // `!` and `^` are members of the class, as in PowerShell.
        assert!(matches("[!.]git", ".git", windows, true));
        assert!(matches("[^.]git", ".git", windows, true));
        assert!(matches("[!x]git", "!git", windows, true));
        assert!(!matches("[!x]git", "ygit", windows, true));
        assert!(matches("[a-]", "-", windows, true));
        // A backtick makes the next character itself.
        assert!(matches("`.gi?", ".git", windows, true));
        assert!(matches("`*git", "*git", windows, true));
        assert!(!matches("`*git", ".git", windows, true));
        assert!(matches("[`]]x", "]x", windows, true));
        assert!(matches("a`", "a`", windows, true));
        // POSIX keeps both as they are.
        assert!(matches("`a", "`a", Flavour::Posix, false));
        assert!(!matches("[!.]git", ".git", Flavour::Posix, true));
        assert!(matches("[!.]git", "xgit", Flavour::Posix, true));
    }

    #[test]
    fn a_windows_wildcard_compares_without_case() {
        let windows = Flavour::Windows;
        assert!(matches("*GIT", ".git", windows, true));
        assert!(matches(".G?T", ".git", windows, true));
        assert!(matches("[A-Z]git", "xgit", windows, true));
        assert!(matches("[a-z]GIT", "Xgit", windows, true));
        assert!(!matches("[A-Z]git", "!git", windows, true));
        assert!(!matches("*GIT", ".git", Flavour::Posix, true));
    }

    #[test]
    fn a_windows_name_compares_by_unicode_case() {
        let windows = Flavour::Windows;
        // A dotless `ı` and a dotted `İ` count as an `i`, to be safe.
        assert!(matches("*g\u{131}t", ".git", windows, true));
        assert!(matches("*G\u{130}T", ".git", windows, true));
        assert!(matches(".G\u{130}T", ".git", windows, true));
        assert!(matches("*\u{212a}", "k", windows, true));
        assert!(!matches("*g\u{131}t", ".git", Flavour::Posix, true));
        assert!(!matches("*g\u{e9}t", ".git", windows, true));
        // A class member folds too.
        assert!(matches("*g[\u{131}]t", ".git", windows, true));
        assert!(matches("*g[x\u{130}]t", ".git", windows, true));
        assert!(!matches("*g[x\u{e9}]t", ".git", windows, true));
        assert!(!matches("*g[\u{131}]t", ".git", Flavour::Posix, true));
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
    fn star_dot_star_is_a_catch_all_on_windows_only() {
        let windows = Flavour::Windows;
        assert_eq!(shape("*.*", windows), Shape::All);
        assert_eq!(shape(r"build\*.*", windows), Shape::All);
        assert_eq!(shape("*.*", Flavour::Posix), Shape::Entries);
        assert_eq!(shape("*.tmp", windows), Shape::Entries);
        assert_eq!(shape("*git", windows), Shape::Entries);
        assert_eq!(shape(r"build\*", windows), Shape::All);
    }

    #[test]
    fn a_pattern_in_the_workspace_folder_reaches_git_when_a_wildcard_can_match_it() {
        let windows = Flavour::Windows;
        let reaches = |parts: &[&str]| reaches_git(parts, windows, true);
        // The first part is the last: it must match `.git` and pick names.
        for parts in [&["*git"][..], &["?git"], &["*GIT"], &["????"], &["[!.]git"]] {
            assert!(reaches(parts), "{parts:?}");
        }
        for parts in [&["*"][..], &["*.*"], &["*.tmp"], &["*gitx"], &["?git2"]] {
            assert!(!reaches(parts), "{parts:?}");
        }
        // Otherwise the next part must match an entry of `.git`.
        for parts in [
            &["*", "objects"][..],
            &["*", "OBJECTS", "x"],
            &["????", "HEAD"],
            &["*git", "refs"],
            &["*", "*"],
            &["*", "*s"],
            &["*", "pack?d-refs"],
            &["*", "modules"],
            &["*", "LFS"],
            &["*", "worktrees"],
            &["*", "shallow"],
            &["*", "ORIG_HEAD"],
            &["*", "MERGE_HEAD"],
            &["*", "rebase-*"],
            &["*", "sequencer"],
            &["*", ".."],
        ] {
            assert!(reaches(parts), "{parts:?}");
        }
        for parts in [
            &["*", "bin"][..],
            &["*", "obj"],
            &["*", "*.o"],
            &["*", "dist", "objects"],
            &["*tmp", "objects"],
            &["x*", "HEAD"],
        ] {
            assert!(!reaches(parts), "{parts:?}");
        }
        assert!(!reaches(&[]));
    }

    #[test]
    fn a_posix_pattern_reaches_git_only_with_dotglob() {
        let posix = Flavour::Posix;
        assert!(!reaches_git(&["*git"], posix, false));
        assert!(!reaches_git(&["*", "objects"], posix, false));
        assert!(reaches_git(&["*git"], posix, true));
        assert!(reaches_git(&["*", "objects"], posix, true));
    }

    #[test]
    fn a_long_run_of_open_brackets_is_read() {
        let pattern = "[".repeat(60_000);
        for flavour in [Flavour::Posix, Flavour::Windows] {
            assert!(!matches(&pattern, ".git", flavour, true));
            assert_eq!(shape(&pattern, flavour), Shape::Entries);
        }
        let closed = format!("{pattern}]");
        assert!(!matches(&closed, ".git", Flavour::Windows, true));
        let spaced = "[]".repeat(30_000);
        assert!(!matches(&spaced, ".git", Flavour::Posix, true));
    }

    #[test]
    fn a_part_is_a_pattern_when_it_holds_a_wildcard() {
        assert!(has_wildcard("a[b"));
        assert!(!has_wildcard("a.b"));
    }
}
