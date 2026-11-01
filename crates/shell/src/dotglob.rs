//! The shell options that let a wildcard match a name's leading dot: bash's
//! `dotglob`, zsh's `globdots` (also spelled `dotglob`), and a non-empty
//! `GLOBIGNORE`.
//!
//! While one is on, `rm -rf *git` takes `.git`, so the rest of the line is
//! judged as if every wildcard could match a hidden name. This module reads
//! the one unit that changes the option, or a shell started with it on;
//! [`crate::unit::Split`] carries it to the units after.

use crate::unit::{Arg, Flag};

/// What a unit does to the option. A shell has two of them, bash's and zsh's,
/// and an off switch of one shell is an error in the other, so each is kept
/// apart: `Some(true)` turns a flag on, `Some(false)` off, `None` leaves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Change {
    pub(crate) bash: Option<bool>,
    pub(crate) zsh: Option<bool>,
}

impl Change {
    pub(crate) const BASH_ON: Self = Self::new(Some(true), None);
    pub(crate) const BASH_OFF: Self = Self::new(Some(false), None);
    pub(crate) const ZSH_ON: Self = Self::new(None, Some(true));
    #[cfg(test)]
    pub(crate) const ZSH_OFF: Self = Self::new(None, Some(false));
    /// What a name or file only known when it runs may do.
    pub(crate) const BOTH_ON: Self = Self::new(Some(true), Some(true));

    const fn new(bash: Option<bool>, zsh: Option<bool>) -> Self {
        Self { bash, zsh }
    }

    /// `zsh_on` for zsh's flag.
    const fn zsh(on: bool) -> Self {
        Self::new(None, Some(on))
    }

    /// Both changes at once, on winning for each flag.
    fn and(self, other: Self) -> Self {
        fn flag(a: Option<bool>, b: Option<bool>) -> Option<bool> {
            match (a, b) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), _) | (_, Some(false)) => Some(false),
                (None, None) => None,
            }
        }
        Self::new(flag(self.bash, other.bash), flag(self.zsh, other.zsh))
    }
}

/// `change` with one more result folded in.
fn fold(change: Option<Change>, one: Change) -> Change {
    change.map_or(one, |change| change.and(one))
}

/// The variable whose value, when not empty, turns `dotglob` on.
pub(crate) const GLOBIGNORE: &str = "GLOBIGNORE";

/// The variable a bash reads its `shopt` options from when it starts.
const BASHOPTS: &str = "BASHOPTS";

/// zsh's precommand modifiers, which run the builtin after them in zsh. In
/// bash and sh they are not words the shell knows, so nothing runs behind
/// them.
const ZSH_MODIFIERS: [&str; 3] = ["noglob", "nocorrect", "-"];

/// Whether a unit behind `wrappers` runs in the shell whose `flag` it
/// changes. `time` is the keyword, which runs the line in this shell, only as
/// the first word; anywhere else it is the program of that name. zsh's
/// `command` looks up programs only, so with it among the wrappers the builtin
/// after it never runs in zsh. `nocorrect` is a reserved word there, so like
/// `time` it counts only in front: first, or after a leading `time` or
/// `nocorrect`. After any other wrapper zsh looks it up as a command and fails.
pub(crate) fn in_shell(wrappers: &[String], flag: Flag) -> bool {
    wrappers
        .iter()
        .enumerate()
        .all(|(at, wrapper)| match wrapper.as_str() {
            "time" => at == 0,
            "command" => !matches!(flag, Flag::Zsh),
            "builtin" => true,
            "nocorrect" => {
                matches!(flag, Flag::Zsh)
                    && wrappers[..at]
                        .iter()
                        .all(|before| matches!(before.as_str(), "time" | "nocorrect"))
            }
            modifier => matches!(flag, Flag::Zsh) && ZSH_MODIFIERS.contains(&modifier),
        })
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
        Arg::Unknown(text) | Arg::Template { source: text, .. } => {
            text.trim_start_matches(['"', '\''])
        }
        Arg::Input | Arg::Null => return false,
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

/// Whether an argument of `let`, which reads each one as arithmetic as
/// `(( ))` does, gives `GLOBIGNORE` a value: `GLOBIGNORE=1`, `GLOBIGNORE+=1`
/// (any operator in front of the `=`), `GLOBIGNORE++`, `--GLOBIGNORE`, in
/// any of the comma-separated parts of it or inside another one's value
/// (`x=GLOBIGNORE++`, `x=GLOBIGNORE=1`). An empty variable is 0 for each, so
/// the result is a number and never empty.
pub(crate) fn arithmetic_hides(arg: &Arg) -> bool {
    let text = match arg {
        Arg::Known(text) => text.as_str(),
        Arg::Unknown(text) | Arg::Template { source: text, .. } => text.trim_matches(['"', '\'']),
        Arg::Input | Arg::Null => return false,
    };
    let chars: Vec<char> = text.chars().collect();
    let name: Vec<char> = GLOBIGNORE.chars().collect();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    // Whether `GLOBIGNORE` stands at `at` as a name of its own.
    let named = |at: usize| {
        chars.get(at..at + name.len()) == Some(&name)
            && !at
                .checked_sub(1)
                .and_then(|before| chars.get(before))
                .is_some_and(|c| word(*c))
            && !chars.get(at + name.len()).is_some_and(|c| word(*c))
    };
    // Whether the text right of `from` (to the right) or left of it (to
    // the left) is `++` or `--`, spaces aside.
    let step = |from: usize, right: bool| {
        let near: Vec<char> = if right {
            chars[from..]
                .iter()
                .copied()
                .filter(|c| *c != ' ')
                .take(2)
                .collect()
        } else {
            let mut near: Vec<char> = chars[..from]
                .iter()
                .rev()
                .copied()
                .filter(|c| *c != ' ')
                .take(2)
                .collect();
            near.reverse();
            near
        };
        near == ['+', '+'] || near == ['-', '-']
    };
    let steps = (0..chars.len())
        .filter(|at| named(*at))
        .any(|at| step(at + name.len(), true) || step(at, false));
    // `GLOBIGNORE[0]` is the first element; skip a subscript.
    let assigned = (0..chars.len()).filter(|at| chars[*at] == '=').any(|at| {
        let previous = at.checked_sub(1).map(|before| chars[before]);
        let doubled = chars.get(at + 1) == Some(&'=');
        if doubled || matches!(previous, Some('=' | '!')) {
            return false;
        }
        let mut end = at;
        match previous {
            Some('<' | '>') => {
                // `<<=` and `>>=` assign; a single `<=` or `>=` compares.
                if at < 2 || chars[at - 2] != previous.unwrap_or(' ') {
                    return false;
                }
                end = at - 2;
            }
            Some('+' | '-' | '*' | '/' | '%' | '&' | '|' | '^') => end = at - 1,
            _ => {}
        }
        let mut start = end;
        while start > 0 && chars[start - 1] == ' ' {
            start -= 1;
        }
        if start > 0 && chars[start - 1] == ']' {
            let Some(open) = chars[..start].iter().rposition(|c| *c == '[') else {
                return false;
            };
            start = open;
        }
        start >= name.len()
            && named(start - name.len())
            && chars[at + 1..]
                .iter()
                .any(|c| !c.is_whitespace() && !"\"'".contains(*c))
    });
    steps || assigned
}

/// What the builtin `key` does to the option when run with `args`: `shopt`
/// is bash's, `setopt`, `unsetopt` and `set` are zsh's. A name only known when
/// it runs is taken to switch both on. `source` and `.` run a file the guard
/// cannot read, which may switch either on.
pub(crate) fn change(key: &str, args: &[Arg]) -> Option<Change> {
    match key {
        "shopt" => shopt(args),
        "setopt" => options(args, true),
        "unsetopt" => options(args, false),
        "set" => set(args),
        "source" | "." => Some(Change::BOTH_ON),
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

/// `shopt -s dotglob` turns bash's flag on, `shopt -u dotglob` off. An
/// argument only known when it runs counts as both on.
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
    if unknown {
        Some(Change::BOTH_ON)
    } else if set && named {
        Some(Change::BASH_ON)
    } else if unset && named {
        Some(Change::BASH_OFF)
    } else {
        None
    }
}

/// `setopt globdots` turns zsh's flag on and `unsetopt globdots` off;
/// `noglobdots` is the other way round, and `dotglob` is another name for
/// `globdots`. On wins when a line names it both ways. `-4` is the flag for
/// it (`+4` undoes it) and a `-m` pattern may name it, so both count as on. A
/// name only known when it runs counts as both flags on.
fn options(args: &[Arg], setting: bool) -> Option<Change> {
    let mut change = None;
    for arg in args {
        let one = match arg.known() {
            Some(flags) if flags.starts_with(['-', '+']) && flags.len() > 1 => {
                if flags.contains('m') {
                    Change::ZSH_ON
                } else if flags.contains('4') {
                    Change::zsh(flags.starts_with('-') == setting)
                } else {
                    continue;
                }
            }
            Some(name) => match zsh(name) {
                Some(on) => Change::zsh(on == setting),
                None => continue,
            },
            None => Change::BOTH_ON,
        };
        change = Some(fold(change, one));
    }
    change
}

/// `set -o globdots` turns zsh's flag on and `set +o globdots` off, `set -4`
/// and `set +4` likewise. The option name is the argument after a bundle
/// holding `o` (`-o`, `-eo`).
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
            change = Some(fold(change, Change::zsh(sign == '-')));
        }
        if !text.contains('o') {
            continue;
        }
        let one = match iter.next().map(|name| name.known()) {
            Some(Some(name)) => match zsh(name) {
                Some(on) => Change::zsh(on == (sign == '-')),
                None => continue,
            },
            Some(None) => Change::BOTH_ON,
            None => continue,
        };
        change = Some(fold(change, one));
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
    fn shopt_changes_bashs_flag_only() {
        let on = Some(Change::BASH_ON);
        let off = Some(Change::BASH_OFF);
        let both = Some(Change::BOTH_ON);
        for (words, want) in [
            (&["-s", "dotglob"][..], on),
            (&["-s", "dotglob", "nullglob"], on),
            (&["-s", "nullglob", "dotglob"], on),
            (&["-sq", "dotglob"], on),
            (&["-s", "--", "dotglob"], on),
            (&["-s", "$option"], both),
            (&["$flag", "dotglob"], both),
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
        let on = Some(Change::ZSH_ON);
        let off = Some(Change::ZSH_OFF);
        let both = Some(Change::BOTH_ON);
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
            ("setopt", &["$option"], both),
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
            ("unsetopt", &["$option"], both),
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
            ("set", &["-o", "$option"], both),
            ("set", &["-4"], on),
            ("set", &["+4"], off),
            ("set", &["-e4"], on),
            ("set", &["-e", "-o", "pipefail"], None),
            ("set", &["-o"], None),
            ("set", &["-e", "--", "-o", "globdots"], None),
            ("set", &[], None),
            ("echo", &["globdots"], None),
            ("source", &["./env.sh"], both),
            (".", &["./env.sh"], both),
        ] {
            assert_eq!(change(key, &args(words)), want, "{key} {words:?}");
        }
    }

    #[test]
    fn changes_to_both_flags_combine_with_on_winning() {
        assert_eq!(
            options(&args(&["globdots", "-4"]), false),
            Some(Change::ZSH_OFF)
        );
        assert_eq!(
            options(&args(&["globdots", "noglobdots"]), true),
            Some(Change::ZSH_ON)
        );
        assert_eq!(
            Change::BASH_ON.and(Change::ZSH_OFF),
            Change::new(Some(true), Some(false))
        );
        assert_eq!(Change::BASH_OFF.and(Change::BASH_ON), Change::BASH_ON);
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
        for flag in [Flag::Bash, Flag::Zsh] {
            assert!(in_shell(&[], flag));
            assert!(in_shell(&wrappers(&["time", "builtin"]), flag));
            assert!(in_shell(&wrappers(&["builtin"]), flag));
            assert!(in_shell(&wrappers(&["time"]), flag));
            // Only the first word is the keyword; later, `time` is a program.
            for later in [["builtin", "time"], ["command", "time"]] {
                assert!(!in_shell(&wrappers(&later), flag), "{later:?}");
            }
            for name in [
                "env", "nohup", "timeout", "nice", "stdbuf", "find", "sudo", "coproc",
            ] {
                assert!(!in_shell(&wrappers(&[name]), flag), "{name}");
            }
        }
    }

    /// `noglob`, `nocorrect` and `-` are zsh's: in bash the command after them
    /// is not found, so the builtin never runs.
    #[test]
    fn zsh_modifiers_run_the_builtin_in_zsh_only() {
        for name in ["noglob", "nocorrect", "-"] {
            let wrappers = vec![name.to_string()];
            assert!(in_shell(&wrappers, Flag::Zsh), "{name}");
            assert!(!in_shell(&wrappers, Flag::Bash), "{name}");
            let mixed = vec!["command".to_string(), name.to_string()];
            assert!(!in_shell(&mixed, Flag::Zsh), "command {name}");
            assert!(!in_shell(&mixed, Flag::Bash), "command {name}");
            let before = vec![name.to_string(), "command".to_string()];
            assert!(!in_shell(&before, Flag::Zsh), "{name} command");
            let timed = vec!["time".to_string(), name.to_string()];
            assert!(in_shell(&timed, Flag::Zsh), "time {name}");
            // `nocorrect` is a reserved word, found only in front; the
            // other two are looked up as commands and work after `builtin`.
            let built = vec!["builtin".to_string(), name.to_string()];
            assert_eq!(
                in_shell(&built, Flag::Zsh),
                name != "nocorrect",
                "builtin {name}"
            );
            let after = vec![name.to_string(), "time".to_string()];
            assert!(!in_shell(&after, Flag::Zsh), "{name} time");
        }
    }

    /// `nocorrect` counts only in front: alone, or after a leading `time` or
    /// `nocorrect`. After `noglob`, `-` or `builtin` zsh fails to find it.
    #[test]
    fn nocorrect_counts_only_in_front() {
        let wrappers = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_string()).collect()
        };
        for ok in [
            &["nocorrect"][..],
            &["time", "nocorrect"],
            &["nocorrect", "nocorrect"],
            &["time", "nocorrect", "nocorrect"],
        ] {
            assert!(in_shell(&wrappers(ok), Flag::Zsh), "{ok:?}");
            assert!(!in_shell(&wrappers(ok), Flag::Bash), "{ok:?}");
        }
        for bad in [
            &["noglob", "nocorrect"][..],
            &["-", "nocorrect"],
            &["builtin", "nocorrect"],
            &["builtin", "-", "nocorrect"],
            &["time", "builtin", "nocorrect"],
        ] {
            assert!(!in_shell(&wrappers(bad), Flag::Zsh), "{bad:?}");
        }
        // `noglob` and `-` still count behind `builtin`, `noglob` or `-`.
        for ok in [
            &["builtin", "noglob"][..],
            &["noglob", "-"],
            &["-", "noglob"],
            &["builtin", "-"],
        ] {
            assert!(in_shell(&wrappers(ok), Flag::Zsh), "{ok:?}");
        }
    }

    /// zsh's `command` looks up programs only; bash's runs the builtin.
    #[test]
    fn command_runs_the_builtin_in_bash_only() {
        let wrappers = vec!["command".to_string()];
        assert!(in_shell(&wrappers, Flag::Bash));
        assert!(!in_shell(&wrappers, Flag::Zsh));
    }
}
