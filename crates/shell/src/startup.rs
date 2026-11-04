//! Shell variables whose value a shell runs later: `PS4` (expanded, with
//! command substitution, each time `set -x` prints a trace line) and
//! `BASH_ENV` (expanded the same way, then run as a script by every
//! non-interactive bash). An assignment is read where it is written: a value
//! with code in it is a script that runs later, a value only known when it
//! runs is a script nobody can read, and a `BASH_ENV` file is a script the
//! shell it is handed to runs. `ENV` names a file an interactive POSIX `sh`
//! runs the same way, so it is read only as the file it names.

use std::borrow::Cow;
use std::rc::Rc;

use crate::unit::{self, Arg, Split};
use crate::{Rule, Shell};

/// The variables read here.
pub(crate) const VARIABLES: [&str; 2] = ["PS4", "BASH_ENV"];

/// How many different `BASH_ENV` files a line may set before it is too many to
/// judge each shell against: past it the line is `unknown`.
const MOST: usize = 16;

/// The most digits a subscript may have to be read as the number it spells:
/// eighteen digits are below 2^63, so they cannot wrap.
const MOST_DIGITS: usize = 18;

/// The POSIX special builtins: an assignment in front of one stays set after
/// it, and is exported (in POSIX mode, and for the `EXIT` and `RETURN` traps
/// bash runs after it).
pub(crate) const SPECIAL: [&str; 15] = [
    ":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set",
    "shift", "times", "trap", "unset",
];

/// The variable that names a file a POSIX `sh` runs before it reads its
/// commands, when it is interactive (dash, ksh and the like; bash only when
/// it is `sh`): every other program leaves it be, and it is a name many
/// programs give their own setting (`ENV=production`).
pub(crate) const SH_ENV: &str = "ENV";

/// The shells that run the file [`SH_ENV`] names.
pub(crate) const SH_SHELLS: [&str; 10] = [
    "sh", "dash", "ash", "ksh", "ksh93", "mksh", "pdksh", "oksh", "yash", "posh",
];

/// A file `BASH_ENV` or `ENV` names, and where it was named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Startup {
    /// The file, or a value only known when it runs that names it.
    pub(crate) file: Arg,
    /// Whether `ENV` names it, which only the shells of [`SH_SHELLS`] run.
    pub(crate) sh_only: bool,
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
const PLAIN: [&str; 11] = [
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
];

/// Places the shell sets, plain text until the line sets them: `HOME` and
/// `TMPDIR` when the line does not assign them, `PWD` as well while the line
/// has not moved to a name that may hold code (see [`Split::pwd_is_plain`]).
const PLACES: [&str; 3] = ["HOME", "PWD", "TMPDIR"];

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
                && index.len() <= MOST_DIGITS
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
pub(crate) fn runs(text: &str) -> bool {
    text.contains("$(")
        || text.contains('`')
        || text
            .match_indices("${")
            .any(|(at, _)| matches!(text[at + 2..].chars().next(), Some(' ' | '\t' | '\n' | '|')))
}

/// A prompt as bash prints it: the text, and whether it holds an escape the
/// guard cannot decode.
pub(crate) struct Prompt<'a> {
    pub(crate) text: Cow<'a, str>,
    /// An escape whose output is only known when it prints (`\D{fmt}` is
    /// `strftime`'s output), left as written.
    pub(crate) undecoded: bool,
}

/// `text` as bash prints a prompt from it, before the expansion that finds
/// `$(` in it: `\N`, `\NN` and `\NNN`, one to three octal digits, are the
/// character with that code (`\0` is nothing), and `\[` and `\]` are nothing
/// (bash prints them as readline's markers, or as nothing without line
/// editing: nothing is the reading that finds code). bash 3.2, the
/// `/bin/bash` of a Mac, decodes only three-digit escapes (`\44(` prints as
/// written); newer bash reads one to three digits. The code is found under
/// the reading that decodes more, which holds the code of the other too.
/// `\$` is read as `$` (`#` for root, which holds no code). bash 3.2 keeps
/// it as an escaped `$` that starts no code by itself (`PS4='\$(rm -rf ~)'`
/// runs nothing there), but other versions are not known to, so a `$(`
/// after it is read as code: the safe side. What the `$` joins with is
/// [`quote`]'s to settle (`\$$(rm -rf ~)` runs the `$(`). `\\` is a
/// backslash, which ends no escape. `\D{fmt}` is the output of `strftime`,
/// which may be any text: it is left as written and reported. Any other
/// escape prints a name or a number, never a `$`, `(` or backtick, and is
/// left as written.
pub(crate) fn prompt(text: &str) -> Prompt<'_> {
    if !text.contains('\\') {
        return Prompt {
            text: Cow::Borrowed(text),
            undecoded: false,
        };
    }
    let mut decoded = String::with_capacity(text.len());
    let mut undecoded = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            decoded.push(c);
            continue;
        }
        let digits: Vec<u32> = chars
            .clone()
            .take(3)
            .map_while(|digit| digit.to_digit(8))
            .collect();
        if !digits.is_empty() {
            let code = digits.iter().fold(0, |code, digit| code * 8 + digit);
            // `\0` is the NUL character, which a prompt drops.
            if code & 0xff != 0 {
                decoded.push(char::from(u8::try_from(code & 0xff).unwrap_or(b'?')));
            }
            chars.nth(digits.len() - 1);
            continue;
        }
        match chars.clone().next() {
            Some('[' | ']') => {
                chars.next();
            }
            Some('$') => {
                chars.next();
                decoded.push('$');
            }
            Some(next) => {
                undecoded |= next == 'D' && chars.as_str().starts_with("D{");
                decoded.push(c);
                decoded.push(next);
                chars.next();
            }
            None => decoded.push(c),
        }
    }
    Prompt {
        text: Cow::Owned(decoded),
        undecoded,
    }
}

/// How an assignment was written.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Written {
    /// Whether the name was written with an expansion in it.
    pub(crate) expanded: bool,
    /// Whether the value may hold `$PWD`: it is judged against every `cd` of
    /// the line, wherever it sits (see [`Split::pwd_used`]).
    pub(crate) pwd: bool,
}

/// Whether an assignment to `name` is read here: one of [`VARIABLES`], or
/// [`SH_ENV`].
pub(crate) fn read_here(name: &str) -> bool {
    VARIABLES.contains(&name) || name == SH_ENV
}

/// Whether `name`, in any case, names a file a shell runs first: `BASH_ENV`
/// or [`SH_ENV`].
pub(crate) fn named_file(name: &str) -> bool {
    name.eq_ignore_ascii_case("BASH_ENV") || name.eq_ignore_ascii_case(SH_ENV)
}

/// Note `value`, given to the variable `name` by PowerShell (`$env:BASH_ENV
/// = …`, `Set-Item Env:BASH_ENV …`, .NET) or cmd (`set BASH_ENV=…`), when the
/// variable names a file a shell the line starts runs (see [`entry`]).
pub(crate) fn environment(split: &mut Split, name: Option<&str>, value: Arg) {
    if let Some(entry) = entry(split, name, value) {
        split.add_startup(entry);
    }
}

/// The file `value` names for a shell, given to the variable `name` in
/// PowerShell or cmd, when the variable names a file a shell the line starts
/// runs: the name in any case, as on Windows. Its code is not read: the
/// shell it is handed to runs the file, which the line does not show. `None`
/// for a name that may be any variable, which is taken for `BASH_ENV`. An
/// empty value and `$null` remove the variable, and name no file.
pub(crate) fn entry(split: &Split, name: Option<&str>, value: Arg) -> Option<Startup> {
    let sh_only = match name {
        None => false,
        Some(name) if name.eq_ignore_ascii_case("BASH_ENV") => false,
        Some(name) if name.eq_ignore_ascii_case(SH_ENV) => true,
        Some(_) => return None,
    };
    if matches!(value, Arg::Null) || value.known().is_some_and(str::is_empty) {
        return None;
    }
    Some(Startup {
        file: value,
        sh_only,
        expanded: false,
        assigned: split.directory(),
    })
}

/// Read the assignment `name=value`: the findings it carries, and the file
/// `BASH_ENV` or `ENV` names when it names one.
pub(crate) fn read(
    split: &mut Split,
    name: &str,
    value: &Arg,
    depth: usize,
    written: Written,
) -> Option<Startup> {
    // `CDPATH=x cd sub` moves to a folder the line made: `PWD` is its name.
    if name == "CDPATH" {
        split.reassign(name);
    }
    // `ENV=x.sh sh -c true`: the file, whatever its value, as only a shell
    // that reads it is judged by it.
    if name == SH_ENV {
        return (!value.known().is_some_and(str::is_empty)).then(|| Startup {
            file: value.clone(),
            sh_only: true,
            expanded: written.expanded,
            assigned: split.directory(),
        });
    }
    if !VARIABLES.contains(&name) {
        return None;
    }
    let Written { expanded, pwd } = written;
    let bash_env = name == "BASH_ENV";
    let text = match value {
        Arg::Known(text) | Arg::Template { text, .. } => text.as_str(),
        // An ANSI-C string holds its escapes undecoded, so it is not read.
        Arg::Unknown(_) | Arg::Input | Arg::Null => "",
    };
    // `PS4='\044(cmd)'`: the prompt's escapes are decoded first.
    let Prompt { text, undecoded } = if bash_env {
        Prompt {
            text: Cow::Borrowed(text),
            undecoded: false,
        }
    } else {
        prompt(text)
    };
    let code = runs(&text);
    if code {
        later(split, &text, depth);
    }
    // A `PS4` of text and the shell's own numbers is a prompt; any other
    // expansion can hold code, which the shell runs each time.
    // An escape the guard cannot decode may print the `$` of a `$(`, or the
    // `(` that follows one, so beside those characters it is not read.
    let unknown = value.is_unknown() && (bash_env || !plain(value, split))
        || undecoded && text.contains(['$', '(', '`']);
    // The file `BASH_ENV` names goes through the same expansion.
    let named_by_expansion = bash_env && text.contains(['$', '`']);
    if unknown || named_by_expansion {
        split.problem(
            Rule::Unknown,
            "sets a variable the shell runs later to a value only known when it runs",
            Some(value.text()),
        );
    }
    if pwd && !unknown && !named_by_expansion {
        split.pwd_used(value.text());
    }
    match value {
        Arg::Known(file) if bash_env && !code && !file.is_empty() => Some(Startup {
            file: value.clone(),
            sh_only: false,
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
        // The words are values already, so the line can no longer say
        // whether `$PWD` was one of them: it is taken as if it was.
        .filter_map(|(name, value)| {
            read(
                split,
                &name,
                &value,
                depth,
                Written {
                    expanded: false,
                    pwd: true,
                },
            )
        })
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
        Arg::Template { text, source, runs } => assignment(text).map(|(name, value)| {
            let written = assignment(source).map_or(&**source, |(_, value)| value);
            (
                variable(name).to_string(),
                Arg::Template {
                    text: value.to_string(),
                    source: written.into(),
                    runs: *runs,
                },
            )
        }),
        Arg::Unknown(_) | Arg::Input | Arg::Null => None,
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
fn plain(value: &Arg, split: &Split) -> bool {
    let Arg::Template { source, .. } = value else {
        return false;
    };
    if source.contains('`') {
        return false;
    }
    let mut rest: &str = source;
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
        let place = PLACES.contains(&name)
            && !split.reassigned(name)
            && (name != "PWD" || split.pwd_is_plain());
        if !(PLAIN.contains(&name) || place) {
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
///
/// Only the text around the code is quoted. Inside `$(…)` and backticks the
/// shell reads a script of its own, in which a quote or a backslash means
/// what it means anywhere (`$(rm -rf "$HOME")`), so it is kept as written.
fn later(split: &mut Split, text: &str, depth: usize) {
    let Some(quoted) = quote(text) else {
        split.problem(
            Rule::Unreadable,
            "sets a variable the shell runs later to code the guard cannot read to its end",
            Some(text),
        );
        return;
    };
    split.branches += 1;
    split.bodies += 1;
    let began = split.begin_later();
    unit::script_in(split, &quoted, Shell::Posix, depth + 1, false);
    split.branches -= 1;
    split.bodies -= 1;
    split.end_later(began, true);
}

/// How deep `$(…)`, `${…}`, backticks and quotes may nest in a value before
/// it is not read.
const NESTING: usize = 32;

/// `text` as a command that quotes the text around its code and keeps the
/// code, or `None` when where a piece of code ends is not certain: a piece
/// the guard would cut short could hide the rest of it. The code is read to
/// its end by the quotes, `${…}` and nested `$(…)` it holds; one it holds a
/// here-document, a `case`, a comment or a funsub in is not read.
pub(crate) fn quote(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut quoted = String::with_capacity(text.len() + 4);
    quoted.push_str(": \"");
    let mut at = 0;
    while at < bytes.len() {
        let end = match bytes[at] {
            b'$' if bytes.get(at + 1) == Some(&b'(') => {
                Some(skip(bytes, at + 2, Closer::Paren, 0)?)
            }
            b'`' => Some(skip(bytes, at + 1, Closer::Back, 0)?),
            _ => None,
        };
        if let Some(end) = end {
            quoted.push_str(&text[at..end]);
            at = end;
            continue;
        }
        // One character, which may be more than one byte.
        let width = text[at..].chars().next().map_or(1, char::len_utf8);
        // A `$` that opens no code is text: written `\$` it cannot join the
        // `$(` that follows it into a `$$` (the shell's number) and a `(`.
        // `${` stays, so a funsub is still seen.
        let text_dollar = bytes[at] == b'$' && bytes.get(at + 1) != Some(&b'{');
        if text_dollar || matches!(bytes[at], b'"' | b'\\') {
            quoted.push('\\');
        }
        quoted.push_str(&text[at..at + width]);
        at += width;
    }
    quoted.push('"');
    Some(quoted)
}

/// What closes the construct [`skip`] reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Closer {
    /// `)` of `$(`.
    Paren,
    /// `}` of `${`.
    Brace,
    /// `"`.
    Double,
    /// The closing backtick.
    Back,
}

/// The index after what closes the construct opened just before `at`, which
/// is read as the shell does: a backslash takes the next character, quotes
/// and `${…}`, `$(…)` and backticks are read to their ends. `None` when it
/// does not end, is nested too deep, or holds what the guard does not read
/// to its end (see [`quote`]).
fn skip(text: &[u8], start: usize, closer: Closer, depth: usize) -> Option<usize> {
    if depth > NESTING {
        return None;
    }
    let mut parens = 0_usize;
    let mut at = start;
    while at < text.len() {
        let c = text[at];
        let before = at.checked_sub(1).map(|prior| text[prior]);
        match (c, closer) {
            (b'\\', _) => at += 2,
            // Backticks end at the next quote of their own kind, as bash
            // reads them.
            (b'\'' | b'"', Closer::Back) => at = quoted(text, at)?,
            (b'\'', Closer::Paren | Closer::Brace) => at = quoted(text, at)?,
            (b'"', Closer::Double) => return Some(at + 1),
            (b'"', _) => at = skip(text, at + 1, Closer::Double, depth + 1)?,
            (b'`', Closer::Back) => return Some(at + 1),
            (b'`', _) => at = skip(text, at + 1, Closer::Back, depth + 1)?,
            (b'$', Closer::Back) => at += 1,
            (b'$', _) => match text.get(at + 1) {
                Some(b'(') => at = skip(text, at + 2, Closer::Paren, depth + 1)?,
                // A funsub: code that ends at a `}` the guard cannot place.
                Some(b'{') if matches!(text.get(at + 2), Some(b' ' | b'\t' | b'\n' | b'|')) => {
                    return None;
                }
                Some(b'{') => at = skip(text, at + 2, Closer::Brace, depth + 1)?,
                // `$'…'`: a quoted string in which `\'` is a quote.
                Some(b'\'') if closer != Closer::Double => at = ansi(text, at + 2)?,
                _ => at += 1,
            },
            (b'}', Closer::Brace) | (b')', Closer::Paren) if parens == 0 => return Some(at + 1),
            (b'(', Closer::Paren) => {
                parens += 1;
                at += 1;
            }
            (b')', Closer::Paren) => {
                parens -= 1;
                at += 1;
            }
            // Code with a here-document, a comment or a `case` has a `)`
            // or a line that is not its own.
            (b'<', Closer::Paren) if text.get(at + 1) == Some(&b'<') => return None,
            (b'#', Closer::Paren)
                if before.is_none_or(|prior| {
                    prior.is_ascii_whitespace() || matches!(prior, b';' | b'&' | b'|' | b'(')
                }) =>
            {
                return None;
            }
            (b'c', Closer::Paren)
                if text[at..].starts_with(b"case")
                    && !before.is_some_and(letter)
                    && !text.get(at + 4).copied().is_some_and(letter) =>
            {
                return None;
            }
            _ => at += 1,
        }
    }
    None
}

/// Whether `byte` is part of a word.
fn letter(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The index after the quote that closes the one opened at `at`: `'` ends at
/// the next `'`, `"` at the next `"` a backslash does not take.
fn quoted(text: &[u8], at: usize) -> Option<usize> {
    let quote = text[at];
    let mut rest = at + 1;
    while rest < text.len() {
        match text[rest] {
            b'\\' if quote == b'"' => rest += 2,
            byte if byte == quote => return Some(rest + 1),
            _ => rest += 1,
        }
    }
    None
}

/// The index after the `'` that ends the `$'…'` string whose text begins at
/// `at`: a backslash takes the next character.
fn ansi(text: &[u8], at: usize) -> Option<usize> {
    let mut rest = at;
    while rest < text.len() {
        match text[rest] {
            b'\\' => rest += 2,
            b'\'' => return Some(rest + 1),
            _ => rest += 1,
        }
    }
    None
}
