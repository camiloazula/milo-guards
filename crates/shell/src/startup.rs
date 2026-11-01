//! Shell variables whose value a shell runs later: `PS4` (expanded, with
//! command substitution, each time `set -x` prints a trace line) and
//! `BASH_ENV` (expanded the same way, then run as a script by every
//! non-interactive bash). An assignment is read where it is written: a value
//! with code in it is a script that runs later, a value only known when it
//! runs is a script nobody can read, and a `BASH_ENV` file is a script the
//! shell it is handed to runs.

use std::borrow::Cow;
use std::rc::Rc;

use crate::unit::{self, Arg, Split};
use crate::{Rule, Shell};

/// The variables read here.
pub(crate) const VARIABLES: [&str; 2] = ["PS4", "BASH_ENV"];

/// How many different `BASH_ENV` files a line may set before it is too many to
/// judge each shell against: past it the line is `unknown`.
const MOST: usize = 16;

/// A file `BASH_ENV` names, and where it was named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Startup {
    pub(crate) file: Arg,
    /// Whether the name went through an expansion (`$PWD/e.sh`): the shell
    /// that assigned it resolved it where the assignment ran, not where the
    /// shell that runs the file is. A name written out is the child's to
    /// resolve.
    pub(crate) expanded: bool,
    /// The folder the line had moved to when it was assigned.
    pub(crate) assigned: Option<Arg>,
}

/// Add `entry` to `list` unless it is there already: `false` when the list
/// is full, so the line has more files than are read.
pub(crate) fn push(list: &mut Rc<Vec<Startup>>, entry: Startup) -> bool {
    if list.contains(&entry) {
        return true;
    }
    if list.len() >= MOST {
        return false;
    }
    Rc::make_mut(list).push(entry);
    true
}

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

/// The variable an assignment to `name` sets, when it is one of
/// [`VARIABLES`]: `PS4[0]` is `PS4`, as is any subscript that may be the
/// first element, which is the variable's value (`PS4[i]`, `PS4[$n]`); only
/// a number other than zero is another element.
pub(crate) fn variable(name: &str) -> &str {
    let Some((base, rest)) = name.split_once('[') else {
        return name;
    };
    match rest.strip_suffix(']') {
        Some(index)
            if !index.is_empty()
                && index.chars().all(|c| c.is_ascii_digit())
                && index.chars().any(|c| c != '0') =>
        {
            name
        }
        Some(_) => base,
        None => name,
    }
}

/// Whether `text`, a value the shell expands, holds code it runs: `$(…)`, a
/// backtick, or a funsub (`${ cmd; }`, `${| cmd; }`), which bash 5.3 runs as
/// a command.
fn runs(text: &str) -> bool {
    text.contains("$(")
        || text.contains('`')
        || text
            .match_indices("${")
            .any(|(at, _)| matches!(text[at + 2..].chars().next(), Some(' ' | '\t' | '\n' | '|')))
}

/// `text` as bash prints a prompt from it: a `\NNN` escape, three octal
/// digits, is the character with that code, decoded before the expansion
/// that finds `$(` in it. `\\` is a backslash, which ends no escape.
fn prompt(text: &str) -> Cow<'_, str> {
    if !text.contains('\\') {
        return Cow::Borrowed(text);
    }
    let mut decoded = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            decoded.push(c);
            continue;
        }
        let mut ahead = chars.clone();
        let digits: Vec<u32> = ahead
            .by_ref()
            .take(3)
            .map_while(|digit| digit.to_digit(8))
            .collect();
        if digits.len() == 3 {
            let code = digits.iter().fold(0, |code, digit| code * 8 + digit);
            decoded.push(char::from(u8::try_from(code & 0xff).unwrap_or(b'?')));
            chars = ahead;
        } else {
            decoded.push(c);
            if let Some(next) = chars.next() {
                decoded.push(next);
            }
        }
    }
    Cow::Owned(decoded)
}

/// Read the assignment `name=value`: the findings it carries, and the file
/// `BASH_ENV` names when it names one the guard can read. `expanded` is
/// whether the name was written with an expansion in it.
pub(crate) fn read(
    split: &mut Split,
    name: &str,
    value: &Arg,
    depth: usize,
    expanded: bool,
) -> Option<Startup> {
    if !VARIABLES.contains(&name) {
        return None;
    }
    let bash_env = name == "BASH_ENV";
    let text = match value {
        Arg::Known(text) | Arg::Template { text, .. } => text.as_str(),
        // An ANSI-C string holds its escapes undecoded, so it is not read.
        Arg::Unknown(_) | Arg::Input => "",
    };
    // `PS4='\044(cmd)'`: the prompt's escapes are decoded first.
    let text = if bash_env {
        Cow::Borrowed(text)
    } else {
        prompt(text)
    };
    let code = runs(&text);
    if code {
        later(split, &text, depth);
    }
    // A `PS4` of text and the shell's own numbers is a prompt; any other
    // expansion can hold code, which the shell runs each time.
    let unknown = value.is_unknown() && (bash_env || !plain(value));
    // The file `BASH_ENV` names goes through the same expansion.
    let named_by_expansion = bash_env && text.contains(['$', '`']);
    if unknown || named_by_expansion {
        split.problem(
            Rule::Unknown,
            "sets a variable the shell runs later to a value only known when it runs",
            Some(value.text()),
        );
    }
    match value {
        Arg::Known(file) if bash_env && !code && !file.is_empty() => Some(Startup {
            file: value.clone(),
            expanded,
            assigned: split.directory(),
        }),
        _ => None,
    }
}

/// The assignments among the words of `env` (`env PS4=… cmd`): the files
/// `BASH_ENV` names.
pub(crate) fn env(split: &mut Split, words: &[Arg], depth: usize) -> Vec<Startup> {
    words
        .iter()
        .filter_map(word)
        // `env -C DIR` runs the command elsewhere, so a name is taken as
        // one an expansion made.
        .filter_map(|(name, value)| read(split, &name, &value, depth, true))
        .collect()
}

/// The name and the value of `text`, an assignment: the name ends at the
/// first `=` outside a subscript (`a[i=1]=x`), without the `+` of `+=`.
fn assignment(text: &str) -> Option<(&str, &str)> {
    let mut depth = 0_usize;
    for (at, c) in text.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                let name = &text[..at];
                return Some((name.strip_suffix('+').unwrap_or(name), &text[at + 1..]));
            }
            _ => {}
        }
    }
    None
}

/// A word that is a `NAME=value` assignment (`env 'PS4=…'`, `export
/// "PS4=…"`): the name and the value.
pub(crate) fn word(arg: &Arg) -> Option<(String, Arg)> {
    match arg {
        Arg::Known(text) => assignment(text)
            .map(|(name, value)| (variable(name).to_string(), Arg::Known(value.to_string()))),
        Arg::Template { text, source } => assignment(text).map(|(name, value)| {
            let written = assignment(source).map_or(source.as_str(), |(_, value)| value);
            (
                variable(name).to_string(),
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
            .is_some_and(|name| VARIABLES.contains(&variable(name)))
    };
    match program {
        "read" | "mapfile" | "readarray" => (0..args.len()).any(names),
        "printf" => args.iter().enumerate().any(|(at, arg)| {
            arg.known().is_some_and(|word| {
                word == "-v" && names(at + 1)
                    || word
                        .strip_prefix("-v")
                        .is_some_and(|n| VARIABLES.contains(&variable(n)))
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
