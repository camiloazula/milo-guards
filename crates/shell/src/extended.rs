//! zsh's `extendedglob`: the option, and how a word reads under it; and the
//! reading of a zsh option the line turns on, which `autocd` shares.
//!
//! With the option on, zsh reads `#`, `##`, `^` and `~` in an unquoted word
//! as parts of a pattern: `x#` is zero or more of `x`, `x##` one or more,
//! `^x` anything but `x`, and `x~y` what `x` matches but `y` does not. So
//! `rm -rf .gi#t` and `rm -rf .g^x` take `.git`, which the same words read as
//! plain names do not. This module reads the units that turn the option on
//! or off, or a zsh started with it; [`crate::unit::Split`] carries it to the
//! units after, and the POSIX walker reads each word again under it (see
//! [`reading`]). `autocd`, which runs a command that is one word naming a
//! folder as a `cd` to it, is read on and off the same way (see
//! [`AUTO_CD`]).

use crate::unit::Arg;

/// A zsh option, read wherever the line may turn it on or off: its name, as
/// zsh spells it with no underscores and in lower case, and the letter that
/// stands for it among the flags of `set`, `setopt` and a zsh it starts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ZshOption {
    name: &'static str,
    letter: Option<char>,
}

/// `extendedglob`, which has no letter.
pub(crate) const EXTENDED_GLOB: ZshOption = ZshOption {
    name: "extendedglob",
    letter: None,
};

/// `autocd`, `-J`.
pub(crate) const AUTO_CD: ZshOption = ZshOption {
    name: "autocd",
    letter: Some('J'),
};

/// zsh's reading of an option name: `Some(true)` for the option's name in
/// any case and with any underscores, `Some(false)` for it with `no` before.
fn named(option: ZshOption, name: &str) -> Option<bool> {
    let name: String = name
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if name == option.name {
        Some(true)
    } else if name.strip_prefix("no") == Some(option.name) {
        Some(false)
    } else {
        None
    }
}

/// Whether `flags`, the letters of one word after its `-` or `+`, hold the
/// option's letter.
fn lettered(option: ZshOption, flags: &str) -> bool {
    option.letter.is_some_and(|letter| flags.contains(letter))
}

/// What the builtin `key` does to the option when run with `args`:
/// `Some(true)` turns it on, `Some(false)` off, `None` leaves it. `setopt`
/// and `unsetopt` name it (`extendedglob`, `EXTENDED_GLOB`,
/// `noextendedglob`) or give its letter (`setopt -J`), and `set` and
/// `emulate` after `-o` or `+o`, or by its letter (`set -J`). On wins
/// when a line names it both ways. A name only known when it runs, and a `-m` pattern, which
/// may name it, count as on; so does `source` or `.`, whose file the guard
/// cannot read.
pub(crate) fn change(option: ZshOption, key: &str, args: &[Arg]) -> Option<bool> {
    match key {
        "setopt" => options(option, args, true),
        "unsetopt" => options(option, args, false),
        "set" => set(option, args),
        // `emulate zsh -o extendedglob`: the pairs before its `-c` script.
        "emulate" => set(option, script_flags(args)),
        "source" | "." => Some(true),
        _ => None,
    }
}

/// The words of `emulate` before its `-c` (alone or in a group, `-Lc`):
/// what comes after is the script it runs and that script's words.
fn script_flags(args: &[Arg]) -> &[Arg] {
    let end = args
        .iter()
        .position(|arg| {
            arg.known().is_some_and(|text| {
                text.starts_with('-') && !text.starts_with("--") && text.contains('c')
            })
        })
        .unwrap_or(args.len());
    &args[..end]
}

/// Whether an assignment to zsh's `options` table turns the option on:
/// `options[extendedglob]=on`, where the key is the option's name in any
/// case and with any underscores, or only known when it runs, and the value
/// is not the one that turns it off; and `options=(…)` or `options+=(…)`
/// that names it or holds a word only known when it runs. `name` is the
/// assignment's name as written, `values` its value's words.
pub(crate) fn assigns(option: ZshOption, name: &str, values: &[Arg]) -> bool {
    if name == "options" {
        return values.iter().any(|value| {
            value
                .known()
                .is_none_or(|word| named(option, word).is_some())
        });
    }
    let Some(key) = name
        .strip_prefix("options[")
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return false;
    };
    let on = if key.contains(['$', '`', '"', '\'', '\\']) {
        None
    } else {
        named(option, key)
    };
    let off = match on {
        Some(true) => "off",
        Some(false) => "on",
        None if key.contains(['$', '`', '"', '\'', '\\']) => "",
        None => return false,
    };
    values
        .first()
        .is_none_or(|value| value.known().is_none_or(|word| word != off))
}

/// Both changes at once, on winning.
fn and(change: Option<bool>, one: bool) -> bool {
    change.unwrap_or(false) || one
}

fn options(option: ZshOption, args: &[Arg], setting: bool) -> Option<bool> {
    let mut change = None;
    for arg in args {
        let one = match arg.known() {
            Some(flags) if flags.starts_with(['-', '+']) && flags.len() > 1 => {
                if flags.contains('m') {
                    true
                } else if lettered(option, &flags[1..]) {
                    // `setopt +J` turns it off, as `unsetopt -J` does.
                    (flags.starts_with('-')) == setting
                } else {
                    continue;
                }
            }
            Some(name) => match named(option, name) {
                Some(on) => on == setting,
                None => continue,
            },
            None => true,
        };
        change = Some(and(change, one));
    }
    change
}

fn set(option: ZshOption, args: &[Arg]) -> Option<bool> {
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
        if text.len() < 2 || text.starts_with("--") {
            continue;
        }
        if lettered(option, &text[1..]) {
            change = Some(and(change, sign == '-'));
        }
        if !text.contains('o') {
            continue;
        }
        let one = match iter.next().map(Arg::known) {
            Some(Some(name)) => match named(option, name) {
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
/// extendedglob`, `--extendedglob`, `--extended-glob`, or its letter (`zsh
/// -J`). A name or flag only known when it runs counts as on. Only the flags
/// before the script are read.
pub(crate) fn starts_with(option: ZshOption, args: &[Arg]) -> bool {
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
            if named(option, &long.replace('-', "")) == Some(true) {
                return true;
            }
            continue;
        }
        let flags = &text[1..];
        if sign == '-' && lettered(option, flags) {
            return true;
        }
        // bash's `-O` takes a name too, which is not this option.
        for flag in ['O', 'o'] {
            if !flags.contains(flag) {
                continue;
            }
            match iter.next().map(Arg::known) {
                Some(Some(name)) => {
                    if flag == 'o' && named(option, name) == Some(sign == '-') {
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
    /// Two plain patterns that take every name the word can between them:
    /// one for the names that start with a dot, and one for the rest
    /// (`x#.git` is `.git`, and `*.git`).
    Either(String, String),
    /// A pattern no plain one stands for: a leading dot repeated (`.#git`
    /// is `git` and `.git`), a group (`(a|b)#`).
    Unknown,
}

/// The ranges of `chars` that are one element of a pattern each: a bracket
/// expression as a whole (`[!.]`, `[[:alpha:]#]`), anything else one
/// character. A quoted or escaped `[` opens nothing. Linear in the word: a
/// run of `[` that never closes does not scan to its end at each one.
fn elements(chars: &[(char, bool)]) -> Vec<(usize, usize)> {
    let closes = closes(chars);
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let end = if chars[at] == ('[', true) {
            bracket_end(chars, &closes, at).unwrap_or(at)
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
/// it, and the `[` is itself. `closes` is [`closes`] of `chars`.
fn bracket_end(chars: &[(char, bool)], closes: &[Option<usize>], open: usize) -> Option<usize> {
    let mut at = open + 1;
    if matches!(chars.get(at), Some(('!' | '^', _))) {
        at += 1;
    }
    if matches!(chars.get(at), Some((']', _))) {
        at += 1;
    }
    closes.get(at).copied().flatten()
}

/// For each place in `chars`, and the end, the `]` that a bracket expression
/// read on from there closes at: the first `]`, past whole `[:alpha:]`-style
/// elements, before a `/` or the end; `None` when there is none. Read from
/// the end, so each place is read once.
fn closes(chars: &[(char, bool)]) -> Vec<Option<usize>> {
    let len = chars.len();
    // The first `:]` at or after each place.
    let mut class_end = vec![None; len + 1];
    for at in (0..len).rev() {
        class_end[at] = if chars[at].0 == ':' && chars.get(at + 1).is_some_and(|c| c.0 == ']') {
            Some(at)
        } else {
            class_end[at + 1]
        };
    }
    let mut closes = vec![None; len + 1];
    for at in (0..len).rev() {
        closes[at] = match chars[at].0 {
            ']' => Some(at),
            '/' => None,
            '[' if chars.get(at + 1).is_some_and(|c| c.0 == ':') => class_end
                .get(at + 2)
                .copied()
                .flatten()
                .and_then(|close| closes.get(close + 2).copied().flatten()),
            _ => closes[at + 1],
        };
    }
    closes
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
///   A single `#` on a plain character that starts a name, or that only such
///   ones come before, may leave them all out, and a dot after then starts
///   the name: `x#.git` matches `.git` and `x.git`, so it reads as
///   [`Reading::Either`], `.git` and `*.git`. A wildcard or a bracket that
///   starts a name never matches its dot, even repeated (`[x]#.git` is not
///   `.git`). A second such place in the word is [`Reading::Unknown`].
/// - `^x` is any name but `x`, to the end of its part: read as `*`.
/// - A group (`(a|b)`) with any of them is [`Reading::Unknown`].
pub(crate) fn reading(chars: &[(char, bool)]) -> Option<Reading> {
    read(chars, true)
}

/// [`reading`], where `may_split` says whether the word may still be read
/// as [`Reading::Either`]: once only, so the word is read at most twice.
fn read(chars: &[(char, bool)], mut may_split: bool) -> Option<Reading> {
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
    // Whether what the part holds so far can be left out (`x#`, `x#y#`),
    // so that what follows may start the name; and that for what came before
    // its last element, with whether that element is one plain character.
    let (mut open, mut open_before, mut plain) = (true, true, false);
    // Where the part starts in `chars`, and the reading of the word with the
    // names that start with a dot, once it splits.
    let (mut part_chars, mut hidden) = (0, None::<String>);
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
                open = true;
                part_chars = element.1;
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
                let twice = kept
                    .get(at)
                    .is_some_and(|&next| single(next) == Some(('#', true)));
                if twice {
                    at += 1;
                }
                // `x#.git`: the `x` may be left out, and the dot then starts
                // the name.
                open = !twice && open_before && plain;
                let dot = kept
                    .get(at)
                    .filter(|&&next| single(next).is_some_and(|(c, _)| c == '.'));
                if let Some(&(dot, _)) = dot.filter(|_| open) {
                    if !may_split {
                        return Some(Reading::Unknown);
                    }
                    may_split = false;
                    // The word with what can be left out left out: its names
                    // that start with a dot.
                    let mut rest = chars[..part_chars].to_vec();
                    rest.extend_from_slice(&chars[dot..]);
                    hidden = Some(match read(&rest, false) {
                        None => rest.iter().map(|(c, _)| c).collect(),
                        Some(Reading::Pattern(text)) => text,
                        Some(_) => return Some(Reading::Unknown),
                    });
                }
            }
            Some(('^', true)) => {
                changed = true;
                negated = true;
                open = false;
                if !out[part..].ends_with('*') {
                    out.push('*');
                }
            }
            Some(('(' | ')' | '|', true)) => {
                group = true;
                last = Some(out.len());
                out.push_str(&text);
                (open_before, open, plain) = (open, false, false);
            }
            other => {
                last = Some(out.len());
                out.push_str(&text);
                let wild = matches!(other, None | Some(('*' | '?', true)));
                (open_before, open, plain) = (open, false, !wild);
            }
        }
    }
    match (changed, group, hidden) {
        (false, _, _) => None,
        (true, true, _) => Some(Reading::Unknown),
        (true, false, Some(hidden)) => Some(Reading::Either(hidden, out)),
        (true, false, None) => Some(Reading::Pattern(out)),
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
            ("emulate", &["zsh", "-o", "extendedglob"], Some(true)),
            ("emulate", &["-L", "zsh", "-o", "EXTENDED_GLOB"], Some(true)),
            (
                "emulate",
                &["-LR", "zsh", "+o", "extendedglob"],
                Some(false),
            ),
            ("emulate", &["zsh", "-o", "$option"], Some(true)),
            ("emulate", &["zsh"], None),
            ("emulate", &["zsh", "-c", "set -o extendedglob"], None),
            ("emulate", &["zsh", "-Lc", "x", "-o", "extendedglob"], None),
            ("source", &["./env.sh"], Some(true)),
            (".", &["./env.sh"], Some(true)),
            ("echo", &["extendedglob"], None),
        ] {
            assert_eq!(
                change(EXTENDED_GLOB, key, &args(words)),
                want,
                "{key} {words:?}"
            );
        }
    }

    #[test]
    fn an_assignment_to_the_options_table_names_the_flag() {
        for (name, words, want) in [
            ("options[extendedglob]", &["on"][..], true),
            ("options[EXTENDED_GLOB]", &["on"], true),
            ("options[extendedglob]", &["$value"], true),
            ("options[extendedglob]", &[], true),
            ("options[$name]", &["on"], true),
            ("options[noextendedglob]", &["off"], true),
            ("options", &["extendedglob", "on"], true),
            ("options", &["$x"], true),
            ("options[extendedglob]", &["off"], false),
            ("options[noextendedglob]", &["on"], false),
            ("options[globdots]", &["on"], false),
            ("options", &["globdots", "on"], false),
            ("option[extendedglob]", &["on"], false),
            ("extendedglob", &["on"], false),
        ] {
            assert_eq!(
                assigns(EXTENDED_GLOB, name, &args(words)),
                want,
                "{name} {words:?}"
            );
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
            assert_eq!(starts_with(EXTENDED_GLOB, &args(words)), want, "{words:?}");
        }
    }

    #[test]
    fn autocd_is_read_by_its_name_and_its_letter() {
        for (key, words, want) in [
            ("setopt", &["autocd"][..], Some(true)),
            ("setopt", &["AUTO_CD"], Some(true)),
            ("setopt", &["noautocd"], Some(false)),
            ("setopt", &["-J"], Some(true)),
            ("setopt", &["+J"], Some(false)),
            ("unsetopt", &["-J"], Some(false)),
            ("unsetopt", &["+J"], Some(true)),
            ("unsetopt", &["NO_AUTO_CD"], Some(true)),
            ("set", &["-J"], Some(true)),
            ("set", &["-eJ"], Some(true)),
            ("set", &["+J"], Some(false)),
            ("set", &["-o", "auto_cd"], Some(true)),
            ("set", &["-e"], None),
            ("setopt", &["extendedglob"], None),
        ] {
            assert_eq!(change(AUTO_CD, key, &args(words)), want, "{key} {words:?}");
        }
        assert_eq!(change(EXTENDED_GLOB, "set", &args(&["-J"])), None);
        for (words, want) in [
            (&["-J", "-c", "x"][..], true),
            (&["-o", "autocd", "-c", "x"], true),
            (&["--auto-cd", "-c", "x"], true),
            (&["+J", "-c", "x"], false),
            (&["-c", "x"], false),
        ] {
            assert_eq!(starts_with(AUTO_CD, &args(words)), want, "{words:?}");
        }
        assert!(assigns(AUTO_CD, "options[autocd]", &args(&["on"])));
        assert!(!assigns(AUTO_CD, "options[autocd]", &args(&["off"])));
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
            // A leading `x#` before no dot, `x##`, and a wildcard or a
            // bracket repeated, none of which starts a name with a dot.
            ("x#git", pattern("*git")),
            ("x##.git", pattern("*.git")),
            ("[x]#.git", pattern("*.git")),
            ("?#.git", pattern("*.git")),
            ("ax#.git", pattern("a*.git")),
            ("x#[.]git", pattern("*[.]git")),
        ] {
            assert_eq!(read(text), Some(want), "{text}");
        }
    }

    #[test]
    fn a_word_whose_leading_part_may_be_left_out_before_a_dot_reads_two_ways() {
        for (text, hidden, rest) in [
            ("x#.git", ".git", "*.git"),
            ("g#.git", ".git", "*.git"),
            ("x#.gi#t", ".g*t", "*.g*t"),
            ("src/g#.git", "src/.git", "src/*.git"),
            ("~/x#.ssh/id_rsa", "~/.ssh/id_rsa", "~/*.ssh/id_rsa"),
            ("x#y#.git", ".git", "*.git"),
            ("\\x#.git", ".git", "*.git"),
            ("x#'.'git", ".git", "*.git"),
            ("x#.git~y", ".git", "*.git"),
        ] {
            assert_eq!(
                read(text),
                Some(Reading::Either(hidden.to_string(), rest.to_string())),
                "{text}"
            );
        }
    }

    #[test]
    fn a_word_whose_reading_no_plain_pattern_takes_is_unknown() {
        for text in [
            ".#git",
            ".##git",
            "x/.#git",
            "(a|b)#",
            "(#i).git",
            "x#.git/y#.ssh",
            "x#.#git",
            "x#.(a|b)",
        ] {
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
