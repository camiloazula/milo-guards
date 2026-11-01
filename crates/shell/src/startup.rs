//! Shell variables whose value a shell runs later: `PS4` (expanded, with
//! command substitution, each time `set -x` prints a trace line) and
//! `BASH_ENV` (expanded the same way, then run as a script by every
//! non-interactive bash). An assignment is read where it is written: a value
//! with code in it is a script that runs later, a value only known when it
//! runs is a script nobody can read, and a `BASH_ENV` file is a script the
//! shell it is handed to runs.

use crate::unit::{self, Arg, Split};
use crate::{Rule, Shell};

/// The variables read here.
pub(crate) const VARIABLES: [&str; 2] = ["PS4", "BASH_ENV"];

/// Variables whose value is a number, a place or a name the shell sets
/// itself: in a `PS4` they are text, not code (`"+ $LINENO: "`).
const PLAIN: [&str; 14] = [
    "LINENO",
    "BASH_SOURCE",
    "BASH_LINENO",
    "FUNCNAME",
    "SECONDS",
    "RANDOM",
    "EPOCHSECONDS",
    "EPOCHREALTIME",
    "SHLVL",
    "PPID",
    "BASHPID",
    "HOME",
    "PWD",
    "TMPDIR",
];

/// Read the assignment `name=value`: the findings it carries, and the file
/// `BASH_ENV` names when it names one the guard can read.
pub(crate) fn read(split: &mut Split, name: &str, value: &Arg, depth: usize) -> Option<Arg> {
    if !VARIABLES.contains(&name) {
        return None;
    }
    let bash_env = name == "BASH_ENV";
    let text = match value {
        Arg::Known(text) | Arg::Template { text, .. } => text.as_str(),
        // An ANSI-C string holds its escapes undecoded, so it is not read.
        Arg::Unknown(_) | Arg::Input => "",
    };
    let code = text.contains("$(") || text.contains('`');
    if code {
        later(split, text, depth);
    }
    // A `PS4` of text and the shell's own numbers is a prompt; any other
    // expansion can hold code, which the shell runs each time.
    let unknown = value.is_unknown() && (bash_env || !plain(value));
    // The file `BASH_ENV` names goes through the same expansion.
    let expanded = bash_env && text.contains(['$', '`']);
    if unknown || expanded {
        split.problem(
            Rule::Unknown,
            "sets a variable the shell runs later to a value only known when it runs",
            Some(value.text()),
        );
    }
    match value {
        Arg::Known(file) if bash_env && !code && !file.is_empty() => Some(value.clone()),
        _ => None,
    }
}

/// The assignments among the words of `env` (`env PS4=… cmd`): the files
/// `BASH_ENV` names.
pub(crate) fn env(split: &mut Split, words: &[Arg], depth: usize) -> Vec<Arg> {
    words
        .iter()
        .filter_map(word)
        .filter_map(|(name, value)| read(split, &name, &value, depth))
        .collect()
}

/// A word that is a `NAME=value` assignment (`env 'PS4=…'`, `export
/// "PS4=…"`): the name and the value.
pub(crate) fn word(arg: &Arg) -> Option<(String, Arg)> {
    match arg {
        Arg::Known(text) => text
            .split_once('=')
            .map(|(name, value)| (name.to_string(), Arg::Known(value.to_string()))),
        Arg::Template { text, source } => text.split_once('=').map(|(name, value)| {
            let written = source
                .split_once('=')
                .map_or(source.as_str(), |(_, value)| value);
            (
                name.to_string(),
                Arg::Template {
                    text: value.to_string(),
                    source: written.to_string(),
                },
            )
        }),
        Arg::Unknown(_) | Arg::Input => None,
    }
}

/// Whether a command sets a variable of [`VARIABLES`] by reading it in or
/// printing into it (`read PS4`, `printf -v PS4 …`): to a value the line does
/// not show.
pub(crate) fn read_into(program: &str, args: &[Arg]) -> bool {
    let names = |at: usize| {
        args.get(at)
            .and_then(Arg::known)
            .is_some_and(|name| VARIABLES.contains(&name))
    };
    match program {
        "read" | "mapfile" | "readarray" => (0..args.len()).any(names),
        "printf" => args.iter().enumerate().any(|(at, arg)| {
            arg.known().is_some_and(|word| {
                word == "-v" && names(at + 1)
                    || word
                        .strip_prefix("-v")
                        .is_some_and(|n| VARIABLES.contains(&n))
            })
        }),
        _ => false,
    }
}

/// Whether the expansions in `value`, as written, are all of variables the
/// shell sets to plain text.
fn plain(value: &Arg) -> bool {
    let Arg::Template { source, .. } = value else {
        return false;
    };
    if source.contains('`') {
        return false;
    }
    let mut rest = source.as_str();
    while let Some((_, after)) = rest.split_once('$') {
        // `$$`, the shell's own number.
        if let Some(next) = after.strip_prefix('$') {
            rest = next;
            continue;
        }
        let (name, next) = if let Some(braced) = after.strip_prefix('{') {
            let Some((name, next)) = braced.split_once('}') else {
                return false;
            };
            (subscripted(name), next)
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            after.split_at(end)
        };
        if !PLAIN.contains(&name) {
            return false;
        }
        rest = next;
    }
    true
}

/// `FUNCNAME[0]` as `FUNCNAME`: a number, `@` or `*` as the subscript. Any
/// other subscript is arithmetic, which can hold code.
fn subscripted(name: &str) -> &str {
    match name.split_once('[') {
        Some((base, index))
            if index.strip_suffix(']').is_some_and(|index| {
                index == "@" || index == "*" || index.chars().all(|c| c.is_ascii_digit())
            }) =>
        {
            base
        }
        Some(_) => "[",
        None => name,
    }
}

/// Read `text`, the value of a variable the shell expands later, as the
/// script its `$(…)` and backticks are: in double quotes, as the shell
/// expands it, the text around them harmless. It runs when something
/// happens, in this shell or a subshell that has moved.
fn later(split: &mut Split, text: &str, depth: usize) {
    let mut quoted = String::with_capacity(text.len() + 4);
    quoted.push_str(": \"");
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    split.branches += 1;
    split.bodies += 1;
    let began = split.begin_later();
    unit::script_in(split, &quoted, Shell::Posix, depth + 1, false);
    split.branches -= 1;
    split.bodies -= 1;
    split.end_later(began, true);
}
