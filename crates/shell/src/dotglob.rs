//! The shell options that let a wildcard match a name's leading dot: bash's
//! `dotglob`, zsh's `globdots`, and a non-empty `GLOBIGNORE`.
//!
//! While one is on, `rm -rf *git` takes `.git`, so the rest of the line is
//! judged as if every wildcard could match a hidden name. This module reads
//! the one unit that changes the option; [`crate::unit::Split`] carries it to
//! the units after.

use crate::unit::Arg;

/// What a unit does to the option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    On,
    Off,
}

/// The variable whose value, when not empty, turns `dotglob` on.
pub(crate) const GLOBIGNORE: &str = "GLOBIGNORE";

/// Whether a value given to `GLOBIGNORE` switches the option on: anything
/// that is not known to be empty.
pub(crate) fn globignore(value: Option<&Arg>) -> bool {
    value.is_some_and(|value| value.known() != Some(""))
}

/// Whether a `GLOBIGNORE=…` argument, as `env` and `sudo` take them, sets it.
pub(crate) fn assigns_globignore(arg: &Arg) -> bool {
    arg.known()
        .and_then(|text| text.strip_prefix(GLOBIGNORE))
        .and_then(|rest| rest.strip_prefix('='))
        .is_some_and(|value| !value.is_empty())
}

/// What the builtin `key` (`shopt`, `setopt`, `unsetopt`, `set`) does to the
/// option when run with `args`. A name that is only known when it runs is
/// taken to switch it on.
pub(crate) fn change(key: &str, args: &[Arg]) -> Option<Change> {
    match key {
        "shopt" => shopt(args),
        "setopt" => options(args, true),
        "unsetopt" => options(args, false),
        "set" => set(args),
        _ => None,
    }
}

/// Whether a word names the option: `dotglob`, or zsh's `globdots`, which
/// ignores case and underscores.
pub(crate) fn names_option(word: &str) -> bool {
    word == "dotglob" || zsh(word).is_some()
}

/// zsh's reading of an option name: `Some(true)` for `globdots` in any case
/// and with any underscores, `Some(false)` for `noglobdots`.
fn zsh(name: &str) -> Option<bool> {
    let name: String = name
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match name.as_str() {
        "globdots" => Some(true),
        "noglobdots" => Some(false),
        _ => None,
    }
}

/// `shopt -s dotglob` turns it on, `shopt -u dotglob` off. Any `-s`, or an
/// argument only known when it runs, counts as on.
fn shopt(args: &[Arg]) -> Option<Change> {
    let (mut set, mut unset, mut unknown, mut named) = (false, false, false, false);
    let mut options = true;
    for arg in args {
        match arg.known() {
            Some("--") if options => options = false,
            Some(flags) if options && flags.starts_with('-') && flags.len() > 1 => {
                set |= flags.contains('s');
                unset |= flags.contains('u');
            }
            Some(name) => named |= name == "dotglob",
            None => unknown = true,
        }
    }
    if unknown || (set && named) {
        Some(Change::On)
    } else if unset && named {
        Some(Change::Off)
    } else {
        None
    }
}

/// `setopt globdots` turns it on and `unsetopt globdots` off; `noglobdots`
/// is the other way round. On wins when a line names it both ways.
fn options(args: &[Arg], setting: bool) -> Option<Change> {
    let mut change = None;
    for arg in args {
        let on = match arg.known() {
            Some(flag) if flag.starts_with(['-', '+']) => continue,
            Some(name) => match zsh(name) {
                Some(on) => on == setting,
                None => continue,
            },
            None => true,
        };
        change = match (change, on) {
            (Some(Change::On), _) | (_, true) => Some(Change::On),
            (_, false) => Some(Change::Off),
        };
    }
    change
}

/// `set -o globdots` turns it on and `set +o globdots` off. The option name
/// is the argument after a bundle holding `o` (`-o`, `-eo`).
fn set(args: &[Arg]) -> Option<Change> {
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
        let on = match iter.next().map(|name| name.known()) {
            Some(Some(name)) => match zsh(name) {
                Some(on) => on == (sign == '-'),
                None => continue,
            },
            Some(None) => true,
            None => continue,
        };
        change = match (change, on) {
            (Some(Change::On), _) | (_, true) => Some(Change::On),
            (_, false) => Some(Change::Off),
        };
    }
    change
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

    #[test]
    fn shopt_changes_dotglob_only() {
        let on = Some(Change::On);
        let off = Some(Change::Off);
        for (words, want) in [
            (&["-s", "dotglob"][..], on),
            (&["-s", "dotglob", "nullglob"], on),
            (&["-s", "nullglob", "dotglob"], on),
            (&["-sq", "dotglob"], on),
            (&["-s", "--", "dotglob"], on),
            (&["-s", "$option"], on),
            (&["$flag", "dotglob"], on),
            (&["-u", "dotglob"], off),
            (&["-u", "nullglob", "dotglob"], off),
            (&["-s", "nullglob"], None),
            (&["-u", "nullglob"], None),
            (&["-q", "dotglob"], None),
            (&["dotglob"], None),
            (&["-p"], None),
            (&[], None),
        ] {
            assert_eq!(change("shopt", &args(words)), want, "shopt {words:?}");
        }
    }

    #[test]
    fn zsh_options_ignore_case_and_underscores() {
        let on = Some(Change::On);
        let off = Some(Change::Off);
        for (key, words, want) in [
            ("setopt", &["globdots"][..], on),
            ("setopt", &["GLOB_DOTS"], on),
            ("setopt", &["glob_dots"], on),
            ("setopt", &["GlobDots"], on),
            ("setopt", &["extendedglob", "globdots"], on),
            ("setopt", &["noglobdots"], off),
            ("setopt", &["NO_GLOB_DOTS"], off),
            ("setopt", &["$option"], on),
            ("setopt", &["extendedglob"], None),
            ("setopt", &[], None),
            ("unsetopt", &["globdots"], off),
            ("unsetopt", &["GLOB_DOTS"], off),
            ("unsetopt", &["noglobdots"], on),
            ("unsetopt", &["$option"], on),
            ("unsetopt", &["extendedglob"], None),
            ("set", &["-o", "globdots"], on),
            ("set", &["-o", "GLOB_DOTS"], on),
            ("set", &["-eo", "globdots"], on),
            ("set", &["+o", "globdots"], off),
            ("set", &["-o", "noglobdots"], off),
            ("set", &["+o", "noglobdots"], on),
            ("set", &["-o", "$option"], on),
            ("set", &["-e", "-o", "pipefail"], None),
            ("set", &["-o"], None),
            ("set", &["-e", "--", "-o", "globdots"], None),
            ("set", &[], None),
            ("echo", &["globdots"], None),
        ] {
            assert_eq!(change(key, &args(words)), want, "{key} {words:?}");
        }
    }

    #[test]
    fn globignore_is_set_by_any_value_that_is_not_empty() {
        assert!(globignore(Some(&Arg::Known("x".to_string()))));
        assert!(globignore(Some(&Arg::Unknown("$x".to_string()))));
        assert!(!globignore(Some(&Arg::Known(String::new()))));
        assert!(!globignore(None));
        for (word, want) in [
            ("GLOBIGNORE=x", true),
            ("GLOBIGNORE=", false),
            ("GLOBIGNORE", false),
            ("GLOBIGNOREX=x", false),
            ("OTHER=x", false),
        ] {
            assert_eq!(
                assigns_globignore(&Arg::Known(word.to_string())),
                want,
                "{word}"
            );
        }
    }

    #[test]
    fn a_word_names_the_option_by_its_spelling() {
        for word in ["dotglob", "globdots", "GLOB_DOTS", "noglobdots"] {
            assert!(names_option(word), "{word}");
        }
        for word in ["DOTGLOB", "nullglob", "extendedglob"] {
            assert!(!names_option(word), "{word}");
        }
    }
}
