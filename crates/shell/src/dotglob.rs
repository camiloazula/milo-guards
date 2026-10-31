//! The shell options that let a wildcard match a name's leading dot: bash's
//! `dotglob`, zsh's `globdots` (also spelled `dotglob`), and a non-empty
//! `GLOBIGNORE`.
//!
//! While one is on, `rm -rf *git` takes `.git`, so the rest of the line is
//! judged as if every wildcard could match a hidden name. This module reads
//! the one unit that changes the option, or a shell started with it on;
//! [`crate::unit::Split`] carries it to the units after.

use crate::unit::Arg;

/// What a unit does to the option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    On,
    Off,
}

/// The variable whose value, when not empty, turns `dotglob` on.
pub(crate) const GLOBIGNORE: &str = "GLOBIGNORE";

/// The variable a bash reads its `shopt` options from when it starts.
const BASHOPTS: &str = "BASHOPTS";

/// The wrappers a unit may sit behind and still change this shell's options:
/// each runs the builtin itself. Any other (`env`, `nohup`, `timeout`,
/// `find -exec`) starts a process of its own.
const IN_SHELL: [&str; 3] = ["command", "builtin", "time"];

/// Whether a unit behind `wrappers` runs in this shell.
pub(crate) fn in_shell(wrappers: &[String]) -> bool {
    wrappers
        .iter()
        .all(|wrapper| IN_SHELL.contains(&wrapper.as_str()))
}

/// Whether giving the variable `name` the value `value` switches the option
/// on: a `GLOBIGNORE` that is not known to be empty, or a `BASHOPTS` that
/// lists `dotglob` or is not known.
pub(crate) fn hides(name: &str, value: Option<&Arg>) -> bool {
    match (name, value) {
        (GLOBIGNORE, value) => value.is_some_and(|value| value.known() != Some("")),
        (BASHOPTS, Some(Arg::Known(list))) => list.split(':').any(|name| name == "dotglob"),
        (BASHOPTS, Some(_)) => true,
        _ => false,
    }
}

/// Whether an argument that is a `NAME=value` assignment (`env`, `export`,
/// `declare`, `let`) switches the option on.
pub(crate) fn assigns_hiding(arg: &Arg) -> bool {
    let text = match arg {
        Arg::Known(text) => text.as_str(),
        // The source text, quotes and all.
        Arg::Unknown(text) => text.trim_start_matches(['"', '\'']),
        Arg::Input => return false,
    };
    let Some((name, value)) = text.split_once('=') else {
        return false;
    };
    let value = if let Arg::Known(_) = arg {
        Arg::Known(value.to_string())
    } else {
        let value = value.trim_end_matches(['"', '\'']);
        if value.is_empty() {
            Arg::Known(String::new())
        } else {
            Arg::Unknown(value.to_string())
        }
    };
    hides(name, Some(&value))
}

/// What the builtin `key` does to the option when run with `args`. A name
/// only known when it runs is taken to switch it on. `source` and `.` run a
/// file the guard cannot read, which may.
pub(crate) fn change(key: &str, args: &[Arg]) -> Option<Change> {
    match key {
        "shopt" => shopt(args),
        "setopt" => options(args, true),
        "unsetopt" => options(args, false),
        "set" => set(args),
        "source" | "." => Some(Change::On),
        _ => None,
    }
}

/// zsh's reading of an option name: `Some(true)` for `globdots` or `dotglob`
/// in any case and with any underscores, `Some(false)` for the `no` forms.
fn zsh(name: &str) -> Option<bool> {
    let name: String = name
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match name.as_str() {
        "globdots" | "dotglob" => Some(true),
        "noglobdots" | "nodotglob" => Some(false),
        _ => None,
    }
}

/// Whether a shell's own flags turn the option on when it starts: bash's `-O
/// dotglob`, zsh's `-o globdots` or `-o dotglob`, `-4`, `--globdots`. A name
/// or flag only known when it runs counts as on. Only the flags before the
/// script are read.
pub(crate) fn starts_with(args: &[Arg]) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            // An option value or flag only known when it runs.
            return true;
        };
        if text == "--" || !text.starts_with(['-', '+']) || text.len() < 2 {
            return false;
        }
        let sign = text.chars().next().unwrap_or('-');
        if let Some(long) = text.strip_prefix("--") {
            if zsh(&long.replace('-', "")) == Some(true) {
                return true;
            }
            continue;
        }
        let flags = &text[1..];
        if sign == '-' && flags.contains('4') {
            return true;
        }
        for (flag, shopt) in [('O', true), ('o', false)] {
            if !flags.contains(flag) {
                continue;
            }
            match iter.next().map(Arg::known) {
                Some(Some(name)) if shopt => {
                    if sign == '-' && name == "dotglob" {
                        return true;
                    }
                }
                Some(Some(name)) => {
                    if zsh(name) == Some(sign == '-') {
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
/// is the other way round, and `dotglob` is another name for `globdots`. On
/// wins when a line names it both ways. `-4` is the flag for it (`+4` undoes
/// it) and a `-m` pattern may name it, so both count as on.
fn options(args: &[Arg], setting: bool) -> Option<Change> {
    let mut change = None;
    for arg in args {
        let on = match arg.known() {
            Some(flags) if flags.starts_with(['-', '+']) && flags.len() > 1 => {
                let minus = flags.starts_with('-');
                if flags.contains('m') {
                    true
                } else if flags.contains('4') {
                    minus == setting
                } else {
                    continue;
                }
            }
            Some(name) => match zsh(name) {
                Some(on) => on == setting,
                None => continue,
            },
            None => true,
        };
        change = Some(merge(change, on));
    }
    change
}

/// `set -o globdots` turns it on and `set +o globdots` off, `set -4` and
/// `set +4` likewise. The option name is the argument after a bundle holding
/// `o` (`-o`, `-eo`).
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
        if text.len() < 2 || text.starts_with("--") {
            continue;
        }
        if text.contains('4') {
            change = Some(merge(change, sign == '-'));
        }
        if !text.contains('o') {
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
        change = Some(merge(change, on));
    }
    change
}

/// `change` with one more result: on wins.
fn merge(change: Option<Change>, on: bool) -> Change {
    match (change, on) {
        (Some(Change::On), _) | (_, true) => Change::On,
        (_, false) => Change::Off,
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
            ("setopt", &["dotglob"], on),
            ("setopt", &["DOT_GLOB"], on),
            ("setopt", &["extendedglob", "globdots"], on),
            ("setopt", &["noglobdots"], off),
            ("setopt", &["NO_GLOB_DOTS"], off),
            ("setopt", &["nodotglob"], off),
            ("setopt", &["$option"], on),
            ("setopt", &["-4"], on),
            ("setopt", &["+4"], off),
            ("setopt", &["-m", "*dots"], on),
            ("setopt", &["extendedglob"], None),
            ("setopt", &["-L"], None),
            ("setopt", &[], None),
            ("unsetopt", &["globdots"], off),
            ("unsetopt", &["GLOB_DOTS"], off),
            ("unsetopt", &["dotglob"], off),
            ("unsetopt", &["noglobdots"], on),
            ("unsetopt", &["nodotglob"], on),
            ("unsetopt", &["$option"], on),
            ("unsetopt", &["-4"], off),
            ("unsetopt", &["-m", "*dots"], on),
            ("unsetopt", &["extendedglob"], None),
            ("set", &["-o", "globdots"], on),
            ("set", &["-o", "GLOB_DOTS"], on),
            ("set", &["-o", "dotglob"], on),
            ("set", &["-eo", "globdots"], on),
            ("set", &["+o", "globdots"], off),
            ("set", &["-o", "noglobdots"], off),
            ("set", &["+o", "noglobdots"], on),
            ("set", &["-o", "nodotglob"], off),
            ("set", &["-o", "$option"], on),
            ("set", &["-4"], on),
            ("set", &["+4"], off),
            ("set", &["-e4"], on),
            ("set", &["-e", "-o", "pipefail"], None),
            ("set", &["-o"], None),
            ("set", &["-e", "--", "-o", "globdots"], None),
            ("set", &[], None),
            ("echo", &["globdots"], None),
            ("source", &["./env.sh"], on),
            (".", &["./env.sh"], on),
        ] {
            assert_eq!(change(key, &args(words)), want, "{key} {words:?}");
        }
    }

    #[test]
    fn a_shell_starts_with_the_option_when_its_flags_say_so() {
        for (words, want) in [
            (&["-O", "dotglob", "-c", "x"][..], true),
            (&["-O", "nullglob", "-O", "dotglob", "-c", "x"], true),
            (&["-O", "$option", "-c", "x"], true),
            (&["-o", "globdots", "-c", "x"], true),
            (&["-o", "dotglob", "-c", "x"], true),
            (&["-o", "GLOB_DOTS", "-c", "x"], true),
            (&["-o", "$option", "-c", "x"], true),
            (&["-4", "-c", "x"], true),
            (&["-c4", "x"], true),
            (&["--globdots", "-c", "x"], true),
            (&["--glob-dots", "-c", "x"], true),
            (&["-c", "x"], false),
            (&["-O", "nullglob", "-c", "x"], false),
            (&["+O", "dotglob", "-c", "x"], false),
            (&["-o", "pipefail", "-c", "x"], false),
            (&["-o", "noglobdots", "-c", "x"], false),
            (&["--noglobdots", "-c", "x"], false),
            (&["+4", "-c", "x"], false),
            (&["-c", "x", "-O", "dotglob"], false),
            (&["--", "-O", "dotglob"], false),
            (&[], false),
        ] {
            assert_eq!(starts_with(&args(words)), want, "{words:?}");
        }
    }

    #[test]
    fn globignore_and_bashopts_are_set_by_a_value_that_can_be_a_name() {
        assert!(hides(GLOBIGNORE, Some(&Arg::Known("x".to_string()))));
        assert!(hides(GLOBIGNORE, Some(&Arg::Unknown("$x".to_string()))));
        assert!(!hides(GLOBIGNORE, Some(&Arg::Known(String::new()))));
        assert!(!hides(GLOBIGNORE, None));
        assert!(hides(BASHOPTS, Some(&Arg::Known("dotglob".to_string()))));
        assert!(hides(
            BASHOPTS,
            Some(&Arg::Known("extglob:dotglob".to_string()))
        ));
        assert!(hides(BASHOPTS, Some(&Arg::Unknown("$x".to_string()))));
        assert!(!hides(BASHOPTS, Some(&Arg::Known("extglob".to_string()))));
        assert!(!hides("PATH", Some(&Arg::Known("x".to_string()))));
        for (arg, want) in [
            (Arg::Known("GLOBIGNORE=x".to_string()), true),
            (Arg::Known("GLOBIGNORE=".to_string()), false),
            (Arg::Known("GLOBIGNORE".to_string()), false),
            (Arg::Known("GLOBIGNOREX=x".to_string()), false),
            (Arg::Known("OTHER=x".to_string()), false),
            (Arg::Known("BASHOPTS=dotglob".to_string()), true),
            (Arg::Known("BASHOPTS=extglob".to_string()), false),
            (Arg::Unknown("\"GLOBIGNORE=$x\"".to_string()), true),
            (Arg::Unknown("\"GLOBIGNORE=\"".to_string()), false),
            (Arg::Input, false),
        ] {
            assert_eq!(assigns_hiding(&arg), want, "{arg:?}");
        }
    }

    #[test]
    fn a_unit_changes_this_shell_only_through_the_builtins_that_run_in_it() {
        let wrappers = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_string()).collect()
        };
        assert!(in_shell(&[]));
        assert!(in_shell(&wrappers(&["command", "builtin", "time"])));
        for name in ["env", "nohup", "timeout", "nice", "stdbuf", "find", "sudo"] {
            assert!(!in_shell(&wrappers(&[name])), "{name}");
        }
    }
}
