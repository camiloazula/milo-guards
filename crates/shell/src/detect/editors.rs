//! The rules about `ex` and `vim`: the files they edit, the files their
//! commands and options write, and the commands they run that the guard
//! does not read.

use super::Checker;
use crate::unit::{may_split, unknown_start, Arg, Unit};
use crate::Rule;

/// What a command or a script the guard does not read says.
const UNREAD: &str = "runs editor commands the guard does not read";

/// What the options of an editor's line give it to do.
#[derive(Default)]
struct Line<'a> {
    /// The files it edits.
    files: Vec<&'a Arg>,
    /// The files an option writes (`-w`, `--startuptime`, a viminfo file).
    written: Vec<Arg>,
    /// The ex commands it runs (`-c`, `+cmd`, `--cmd`): the text, or the
    /// argument when it is only known when it runs.
    commands: Vec<Result<&'a str, &'a Arg>>,
    /// The first argument that runs what the guard does not read: a script
    /// `-S` or `-s` reads, a vimrc `-u` names, keys `--remote-send` sends,
    /// an argument only known when it runs that may be an option.
    unread: Option<&'a Arg>,
}

impl Checker<'_> {
    /// `ex`, `vi`, `vim`, `nvim`, `view`, `vimdiff` and `gvim`: each file it
    /// is given may be written, with or without a command that says so (an
    /// editor's input may hold `:wq` too), and so may each file an ex command
    /// on the line names (`-c 'w /etc/x'`). A command the guard does not read
    /// (`!`, `call`, `source`, `normal`, `edit`) is code it does not read.
    pub(super) fn editor(&mut self, unit: &Unit, key: &str) {
        let shell = unit.shell;
        let line = editor_line(unit, key);
        for file in &line.files {
            self.write(shell, unit.scope(), file, "edits");
        }
        for file in &line.written {
            self.write(shell, unit.scope(), file, "writes to");
        }
        let mut unread = line.unread.map(Some);
        for command in &line.commands {
            match command {
                Ok(text) => match ex_writes(text, false) {
                    Some(files) => {
                        for file in &files {
                            self.write(shell, unit.scope(), file, "writes to");
                        }
                    }
                    None => unread = unread.or(Some(None)),
                },
                Err(arg) => unread = unread.or(Some(Some(*arg))),
            }
        }
        if let Some(target) = unread {
            self.add(Rule::Unknown, UNREAD, target);
        }
    }
}

/// Reads an editor's arguments as vim does: options until `--` or, with
/// `+cmd`, anywhere; a bundle of letters (`-es`, `-sc wq`) is read one letter
/// at a time, and a letter that takes a value takes the rest of the bundle
/// or the next argument. `-s` is silent mode in ex mode (`ex`, after `-e` or
/// `-E`), and otherwise the script of keys to type.
fn editor_line<'a>(unit: &'a Unit, key: &str) -> Line<'a> {
    let args = unit.args.as_slice();
    let mut line = Line::default();
    let mut ex = key == "ex";
    let mut options = true;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known().filter(|_| options) else {
            // An argument only known when it runs may be an option, when it
            // may split or starts with one.
            let option = options
                && (may_split(arg, unit.shell)
                    || unknown_start(arg, unit.shell)
                        .is_some_and(|start| start.starts_with(['-', '+'])));
            if option {
                line.unread = line.unread.or(Some(arg));
            } else {
                line.files.push(arg);
            }
            continue;
        };
        if text == "--" {
            options = false;
        } else if let Some(command) = text.strip_prefix('+') {
            // `+`, `+N` and `+/pattern` only move the cursor.
            let moves = command.is_empty()
                || command.starts_with('/')
                || command.bytes().all(|b| b.is_ascii_digit());
            if !moves {
                line.commands.push(Ok(command));
            }
        } else if let Some(long) = text.strip_prefix("--") {
            match long {
                "cmd" => line.commands.extend(iter.next().map(command)),
                "startuptime" | "log" => line.written.extend(iter.next().cloned()),
                "remote-send" | "remote-expr" => {
                    line.unread = line.unread.or(iter.next()).or(Some(arg));
                }
                "servername" | "listen" | "server" => {
                    iter.next();
                }
                _ => {}
            }
        } else if let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) {
            for (at, letter) in bundle.char_indices() {
                let rest = &bundle[at + letter.len_utf8()..];
                let takes = match letter {
                    'e' | 'E' => {
                        ex = true;
                        false
                    }
                    's' => !ex,
                    'w' => !rest.starts_with(|c: char| c.is_ascii_digit()),
                    'c' | 'S' | 'u' | 'U' | 'i' | 'W' | 'T' | 't' | 'q' => true,
                    _ => false,
                };
                if !takes {
                    continue;
                }
                let value = if rest.is_empty() { iter.next() } else { None };
                let given = value
                    .and_then(Arg::known)
                    .or((!rest.is_empty()).then_some(rest));
                match letter {
                    'c' => line.commands.push(given.ok_or(value.unwrap_or(arg))),
                    's' | 'S' => line.unread = line.unread.or(value).or(Some(arg)),
                    'u' | 'U' if !matches!(given, Some("NONE" | "NORC" | "DEFAULTS")) => {
                        line.unread = line.unread.or(value).or(Some(arg));
                    }
                    'i' | 'w' | 'W' if given != Some("NONE") => {
                        let attached = (!rest.is_empty()).then(|| Arg::Known(rest.to_string()));
                        line.written.extend(value.cloned().or(attached));
                    }
                    _ => {}
                }
                break;
            }
        } else if text != "-" {
            line.files.push(arg);
        }
    }
    line
}

/// An ex command given as an argument: its text, or the argument when it is
/// only known when it runs.
fn command(arg: &Arg) -> Result<&str, &Arg> {
    arg.known().ok_or(arg)
}

/// What an ex command does, by its name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ex {
    /// Writes the file it names, or the file it edits (`w`, `wq`, `x`,
    /// `saveas`, `update`).
    Write,
    /// Works on the lines of the file and writes nothing (`d`, `j`, `q`).
    Plain,
    /// Substitutes text, with code only in a `\=` expression.
    Substitute,
    /// Runs its command on each line that matches (`g`, `v`).
    Global,
}

/// The ex commands the guard reads: the full name, the shortest
/// abbreviation vim takes, and what it does.
const EX_COMMANDS: [(&str, usize, Ex); 25] = [
    ("write", 1, Ex::Write),
    ("wq", 2, Ex::Write),
    ("wqall", 3, Ex::Write),
    ("wall", 2, Ex::Write),
    ("xit", 1, Ex::Write),
    ("xall", 2, Ex::Write),
    ("exit", 3, Ex::Write),
    ("update", 2, Ex::Write),
    ("saveas", 3, Ex::Write),
    ("quit", 1, Ex::Plain),
    ("qall", 2, Ex::Plain),
    ("quitall", 5, Ex::Plain),
    ("cquit", 2, Ex::Plain),
    ("substitute", 1, Ex::Substitute),
    ("delete", 1, Ex::Plain),
    ("join", 1, Ex::Plain),
    ("move", 1, Ex::Plain),
    ("copy", 2, Ex::Plain),
    ("t", 1, Ex::Plain),
    ("print", 1, Ex::Plain),
    ("number", 2, Ex::Plain),
    ("list", 1, Ex::Plain),
    ("sort", 3, Ex::Plain),
    ("global", 1, Ex::Global),
    ("vglobal", 1, Ex::Global),
];

/// The files a list of ex commands writes by name (`w /etc/x`, `saveas f`),
/// each a file only known when it runs when vim expands it (`%`, `$X`, a
/// wildcard); `None` when it holds a command the guard does not read, or
/// a write through a program (`w !sh`). `nested` is a `:g` command's own,
/// where another `:g` is not read.
fn ex_writes(text: &str, nested: bool) -> Option<Vec<Arg>> {
    let mut files = Vec::new();
    let mut rest = text;
    loop {
        rest = skip_range(rest.trim_start_matches([' ', '\t', ':', '|']));
        if rest.is_empty() {
            return Some(files);
        }
        let length = match rest.as_bytes()[0] {
            byte if byte.is_ascii_alphabetic() => {
                rest.bytes().take_while(u8::is_ascii_alphabetic).count()
            }
            b'&' if rest.starts_with("&&") => 2,
            b'&' | b'~' | b'#' | b'=' => 1,
            byte @ (b'<' | b'>') => rest.bytes().take_while(|&b| b == byte).count(),
            b'|' => 0,
            _ => return None,
        };
        let (name, after) = rest.split_at(length);
        let after = after.strip_prefix('!').unwrap_or(after);
        let kind = match name {
            "" | "<" | ">" | "#" | "=" => Ex::Plain,
            "&" | "&&" | "~" => Ex::Substitute,
            name if name.starts_with(['<', '>']) => Ex::Plain,
            name => {
                EX_COMMANDS
                    .iter()
                    .find(|(full, least, _)| name.len() >= *least && full.starts_with(name))?
                    .2
            }
        };
        if kind == Ex::Global {
            if nested {
                return None;
            }
            // The rest of the text, bars and all, is the command `:g` runs
            // on each line its pattern matches.
            let after = after.trim_start();
            let delimiter = after.chars().next()?;
            if delimiter.is_ascii_alphanumeric() || matches!(delimiter, '"' | '|' | '\\') {
                return None;
            }
            let inner = skip_pattern(&after[delimiter.len_utf8()..], delimiter);
            files.extend(ex_writes(inner, true)?);
            return Some(files);
        }
        let (argument, next) = split_bar(after);
        match kind {
            Ex::Write => files.extend(write_target(argument)?),
            Ex::Substitute if argument.contains("\\=") => return None,
            _ => {}
        }
        rest = next;
    }
}

/// The file a write command's argument names, past its `++opt` words and a
/// `>>`, if any: `None` for a write through a program (`w !sh`), and none
/// when it names no file.
fn write_target(argument: &str) -> Option<Vec<Arg>> {
    let mut text = argument.trim();
    while let Some(option) = text.strip_prefix("++") {
        text = option
            .split_once([' ', '\t'])
            .map_or("", |(_, rest)| rest)
            .trim_start();
    }
    let text = text.strip_prefix(">>").unwrap_or(text).trim();
    if text.starts_with('!') {
        return None;
    }
    if text.is_empty() {
        return Some(Vec::new());
    }
    let expanded = text.contains(['%', '#', '<', '`', '$', '*', '?', '[', '{', '\\']);
    Some(vec![if expanded {
        Arg::Unknown(text.to_string())
    } else {
        Arg::Known(text.to_string())
    }])
}

/// The text past an ex range: line numbers, `.`, `$`, `%`, marks (`'a`),
/// patterns (`/x/`, `?x?`) and the `,`, `;`, `+` and `-` between them.
fn skip_range(mut text: &str) -> &str {
    loop {
        let Some(first) = text.chars().next() else {
            return text;
        };
        text = match first {
            '%' | '$' | '.' | ',' | ';' | '+' | '-' | ' ' | '\t' => &text[1..],
            digit if digit.is_ascii_digit() => &text[1..],
            '\'' => {
                let mark = text[1..].chars().next().map_or(0, char::len_utf8);
                &text[1 + mark..]
            }
            '/' | '?' => skip_pattern(&text[1..], first),
            '\\' if text[1..].starts_with(['/', '?', '&']) => &text[2..],
            _ => return text,
        };
    }
}

/// The text past a pattern that ends at `delimiter`, a `\` escaping the
/// character after it; all of it when the pattern does not end.
fn skip_pattern(text: &str, delimiter: char) -> &str {
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if c == delimiter {
            return &text[at + c.len_utf8()..];
        }
    }
    ""
}

/// An ex command's argument, up to the first `|` a `\` does not escape, and
/// the text after that bar.
fn split_bar(text: &str) -> (&str, &str) {
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if c == '|' {
            return (&text[..at], &text[at + 1..]);
        }
    }
    (text, "")
}
