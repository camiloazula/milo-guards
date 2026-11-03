//! zsh's `extendedglob`: the option, and how a word reads under it.
//!
//! With the option on, zsh reads `#`, `##`, `^` and `~` in an unquoted word
//! as parts of a pattern: `x#` is zero or more of `x`, `x##` one or more,
//! `^x` anything but `x`, and `x~y` what `x` matches but `y` does not. So
//! `rm -rf .gi#t` and `rm -rf .g^x` take `.git`, which the same words read as
//! plain names do not. This module reads the units that turn the option on
//! or off, or a zsh started with it; [`crate::unit::Split`] carries it to the
//! units after, and the POSIX walker reads each word again under it (see
//! [`reading`]).

use crate::unit::Arg;

/// zsh's reading of an option name: `Some(true)` for `extendedglob` in any
/// case and with any underscores, `Some(false)` for `noextendedglob`.
fn named(name: &str) -> Option<bool> {
    let name: String = name
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match name.as_str() {
        "extendedglob" => Some(true),
        "noextendedglob" => Some(false),
        _ => None,
    }
}

/// What the builtin `key` does to the option when run with `args`:
/// `Some(true)` turns it on, `Some(false)` off, `None` leaves it. `setopt`
/// and `unsetopt` name it (`extendedglob`, `EXTENDED_GLOB`,
/// `noextendedglob`), and `set` after `-o` or `+o`. On wins when a line names
/// it both ways. A name only known when it runs, and a `-m` pattern, which
/// may name it, count as on; so does `source` or `.`, whose file the guard
/// cannot read.
pub(crate) fn change(key: &str, args: &[Arg]) -> Option<bool> {
    match key {
        "setopt" => options(args, true),
        "unsetopt" => options(args, false),
        "set" => set(args),
        "source" | "." => Some(true),
        _ => None,
    }
}

/// Both changes at once, on winning.
fn and(change: Option<bool>, one: bool) -> bool {
    change.unwrap_or(false) || one
}

fn options(args: &[Arg], setting: bool) -> Option<bool> {
    let mut change = None;
    for arg in args {
        let one = match arg.known() {
            Some(flags) if flags.starts_with(['-', '+']) && flags.len() > 1 => {
                if flags.contains('m') {
                    true
                } else {
                    continue;
                }
            }
            Some(name) => match named(name) {
                Some(on) => on == setting,
                None => continue,
            },
            None => true,
        };
        change = Some(and(change, one));
    }
    change
}

fn set(args: &[Arg]) -> Option<bool> {
    let mut change = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let Some(sign) = text.chars().next().filter(|sign| matches!(sign, '-' | '+')) else {
            continue;
        };
        if text.len() < 2 || text.starts_with("--") || !text.contains('o') {
            continue;
        }
        let one = match iter.next().map(Arg::known) {
            Some(Some(name)) => match named(name) {
                Some(on) => on == (sign == '-'),
                None => continue,
            },
            Some(None) => true,
            None => continue,
        };
        change = Some(and(change, one));
    }
    change
}

/// Whether a shell's own flags turn the option on when it starts: zsh's `-o
/// extendedglob`, `--extendedglob`, `--extended-glob`. A name or flag only
/// known when it runs counts as on. Only the flags before the script are read.
pub(crate) fn starts_with(args: &[Arg]) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            return true;
        };
        if text == "--" || !text.starts_with(['-', '+']) || text.len() < 2 {
            return false;
        }
        let sign = text.chars().next().unwrap_or('-');
        if let Some(long) = text.strip_prefix("--") {
            if named(&long.replace('-', "")) == Some(true) {
                return true;
            }
            continue;
        }
        let flags = &text[1..];
        // bash's `-O` takes a name too, which is not this option.
        for flag in ['O', 'o'] {
            if !flags.contains(flag) {
                continue;
            }
            match iter.next().map(Arg::known) {
                Some(Some(name)) => {
                    if flag == 'o' && named(name) == Some(sign == '-') {
                        return true;
                    }
                }
                Some(None) => return true,
                None => {}
            }
        }
    }
    false
}

/// What a word reads as with the option on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reading {
    /// A plain pattern (`*`, `?`, `[…]`) that matches every name the word
    /// can, and maybe more.
    Pattern(String),
    /// A pattern no plain one stands for: a leading dot repeated (`.#git`
    /// is `git` and `.git`), a group (`(a|b)#`).
    Unknown,
}

/// The ranges of `chars` that are one element of a pattern each: a bracket
/// expression as a whole (`[!.]`, `[[:alpha:]#]`), anything else one
/// character. A quoted or escaped `[` opens nothing.
fn elements(chars: &[(char, bool)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let end = if chars[at] == ('[', true) {
            bracket_end(chars, at).unwrap_or(at)
        } else {
            at
        };
        out.push((at, end + 1));
        at = end + 1;
    }
    out
}

/// Where the bracket expression that opens at `open` closes: a `]` first in
/// it (after a `!` or `^`) is a member, `[:alpha:]` inside it is one, and a
/// `/` ends the part, so no bracket goes past one. `None` when nothing closes
/// it, and the `[` is itself.
fn bracket_end(chars: &[(char, bool)], open: usize) -> Option<usize> {
    let mut at = open + 1;
    if matches!(chars.get(at), Some(('!' | '^', _))) {
        at += 1;
    }
    if matches!(chars.get(at), Some((']', _))) {
        at += 1;
    }
    while let Some(&(c, _)) = chars.get(at) {
        match c {
            ']' => return Some(at),
            '/' => return None,
            '[' if matches!(chars.get(at + 1), Some((':', _))) => {
                let close = (at + 2..chars.len().saturating_sub(1))
                    .find(|&j| chars[j].0 == ':' && chars[j + 1].0 == ']')?;
                at = close + 2;
            }
            _ => at += 1,
        }
    }
    None
}

/// How zsh reads a word with `extendedglob` on, as a plain pattern that
/// matches at least every name zsh's own does; `None` when the option changes
/// nothing in it. `chars` are the word's characters, each with whether the
/// shell reads it as written: a quoted or escaped one is itself.
///
/// - `x~y` matches what `x` does and `y` does not: the word is read as `x`.
///   A `~` that starts the word is the home directory.
/// - `x#` and `x##` are any number of `x`: read as `*`. When `x` is the dot
///   that starts a name (`.#git`), the pattern can match a hidden name and a
///   name that is not one, which no plain pattern does: [`Reading::Unknown`].
/// - `^x` is any name but `x`, to the end of its part: read as `*`.
/// - A group (`(a|b)`) with any of them is [`Reading::Unknown`].
pub(crate) fn reading(chars: &[(char, bool)]) -> Option<Reading> {
    let elements = elements(chars);
    let single = |(start, end): (usize, usize)| (end == start + 1).then(|| chars[start]);
    // What a `~` past the first character leaves out is not read.
    let cut = elements
        .iter()
        .position(|&element| element.0 > 0 && single(element) == Some(('~', true)));
    let mut changed = cut.is_some();
    let kept = &elements[..cut.unwrap_or(elements.len())];
    let mut group = false;
    let mut out = String::with_capacity(chars.len());
    // Where the part being read starts in `out`, where its last element
    // starts, and whether a `^` has taken the rest of it.
    let (mut part, mut last, mut negated) = (0, None::<usize>, false);
    let mut at = 0;
    while at < kept.len() {
        let element = kept[at];
        at += 1;
        let text: String = chars[element.0..element.1].iter().map(|(c, _)| c).collect();
        match single(element) {
            Some(('/', _)) => {
                out.push('/');
                part = out.len();
                last = None;
                negated = false;
            }
            _ if negated => {}
            Some(('#', true)) => {
                changed = true;
                let start = last.unwrap_or(out.len());
                if start == part && &out[start..] == "." {
                    return Some(Reading::Unknown);
                }
                out.truncate(start);
                if !out[part..].ends_with('*') {
                    out.push('*');
                }
                last = Some(out.len() - 1);
                // `##`
                if kept
                    .get(at)
                    .is_some_and(|&next| single(next) == Some(('#', true)))
                {
                    at += 1;
                }
            }
            Some(('^', true)) => {
                changed = true;
                negated = true;
                if !out[part..].ends_with('*') {
                    out.push('*');
                }
            }
            Some(('(' | ')' | '|', true)) => {
                group = true;
                last = Some(out.len());
                out.push_str(&text);
            }
            _ => {
                last = Some(out.len());
                out.push_str(&text);
            }
        }
    }
    match (changed, group) {
        (false, _) => None,
        (true, true) => Some(Reading::Unknown),
        (true, false) => Some(Reading::Pattern(out)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<Arg> {
        words
            .iter()
            .map(|word| {
                if word.starts_with('$') {
                    Arg::Unknown((*word).to_string())
                } else {
                    Arg::Known((*word).to_string())
                }
            })
            .collect()
    }

    /// A word as typed: `\` makes the next character itself, and so does
    /// anything inside `'…'`.
    fn word(text: &str) -> Vec<(char, bool)> {
        let mut out = Vec::new();
        let (mut quoted, mut escaped) = (false, false);
        for c in text.chars() {
            if escaped {
                out.push((c, false));
                escaped = false;
            } else if c == '\\' && !quoted {
                escaped = true;
            } else if c == '\'' {
                quoted = !quoted;
            } else {
                out.push((c, !quoted));
            }
        }
        out
    }

    fn read(text: &str) -> Option<Reading> {
        reading(&word(text))
    }

    fn pattern(text: &str) -> Reading {
        Reading::Pattern(text.to_string())
    }

    #[test]
    fn options_name_the_flag_in_any_case_and_with_underscores() {
        for (key, words, want) in [
            ("setopt", &["extendedglob"][..], Some(true)),
            ("setopt", &["EXTENDED_GLOB"], Some(true)),
            ("setopt", &["extended_glob"], Some(true)),
            ("setopt", &["noextendedglob"], Some(false)),
            ("setopt", &["NO_EXTENDED_GLOB"], Some(false)),
            ("setopt", &["globdots", "extendedglob"], Some(true)),
            ("setopt", &["extendedglob", "noextendedglob"], Some(true)),
            ("setopt", &["$option"], Some(true)),
            ("setopt", &["-m", "*glob"], Some(true)),
            ("setopt", &["globdots"], None),
            ("setopt", &["-L"], None),
            ("setopt", &[], None),
            ("unsetopt", &["extendedglob"], Some(false)),
            ("unsetopt", &["noextendedglob"], Some(true)),
            ("unsetopt", &["$option"], Some(true)),
            ("set", &["-o", "extendedglob"], Some(true)),
            ("set", &["-eo", "EXTENDED_GLOB"], Some(true)),
            ("set", &["+o", "extendedglob"], Some(false)),
            ("set", &["-o", "noextendedglob"], Some(false)),
            ("set", &["+o", "noextendedglob"], Some(true)),
            ("set", &["-o", "$option"], Some(true)),
            ("set", &["-o", "pipefail"], None),
            ("set", &["-o"], None),
            ("set", &["--", "-o", "extendedglob"], None),
            ("set", &["-e"], None),
            ("source", &["./env.sh"], Some(true)),
            (".", &["./env.sh"], Some(true)),
            ("echo", &["extendedglob"], None),
        ] {
            assert_eq!(change(key, &args(words)), want, "{key} {words:?}");
        }
    }

    #[test]
    fn a_shell_starts_with_the_option_when_its_flags_say_so() {
        for (words, want) in [
            (&["-o", "extendedglob", "-c", "x"][..], true),
            (&["-o", "EXTENDED_GLOB", "-c", "x"], true),
            (&["--extendedglob", "-c", "x"], true),
            (&["--extended-glob", "-c", "x"], true),
            (&["-o", "$option", "-c", "x"], true),
            (&["-O", "extglob", "-o", "extendedglob", "-c", "x"], true),
            (&["-c", "x"], false),
            (&["-o", "globdots", "-c", "x"], false),
            (&["+o", "extendedglob", "-c", "x"], false),
            (&["-o", "noextendedglob", "-c", "x"], false),
            (&["-O", "extendedglob", "-c", "x"], false),
            (&["-c", "x", "-o", "extendedglob"], false),
            (&["--", "-o", "extendedglob"], false),
            (&[], false),
        ] {
            assert_eq!(starts_with(&args(words)), want, "{words:?}");
        }
    }

    #[test]
    fn a_word_reads_as_a_pattern_that_takes_what_zsh_matches() {
        for (text, want) in [
            (".gi#t", pattern(".g*t")),
            (".gi##t", pattern(".g*t")),
            (".g^x", pattern(".g*")),
            ("*.o~*.c", pattern("*.o")),
            (".git~x", pattern(".git")),
            ("~/.gi#t", pattern("~/.g*t")),
            ("~/x~y", pattern("~/x")),
            ("/~x", pattern("/")),
            ("a~b/c", pattern("a")),
            ("src/^x/.gi#t", pattern("src/*/.g*t")),
            ("^x", pattern("*")),
            ("^x/y", pattern("*/y")),
            ("a#b", pattern("*b")),
            ("#x", pattern("*x")),
            ("x*#", pattern("x*")),
            ("[.x]#git", pattern("*git")),
            (".[a-z]#", pattern(".*")),
            ("--grep=^fix", pattern("--grep=*")),
            ("x^y^z", pattern("x*")),
        ] {
            assert_eq!(read(text), Some(want), "{text}");
        }
    }

    #[test]
    fn a_word_whose_reading_no_plain_pattern_takes_is_unknown() {
        for text in [".#git", ".##git", "x/.#git", "(a|b)#", "(#i).git"] {
            assert_eq!(read(text), Some(Reading::Unknown), "{text}");
        }
    }

    #[test]
    fn a_word_without_an_active_operator_reads_as_written() {
        for text in [
            "plain",
            "*.o",
            "~",
            "~/x",
            "'.gi#t'",
            ".gi\\#t",
            "'*.o~*.c'",
            "x\\^y",
            "[#^~]",
            "[^x]git",
            "[]~]",
            "[[:alpha:]~]",
            "",
        ] {
            assert_eq!(read(text), None, "{text}");
        }
    }
}
