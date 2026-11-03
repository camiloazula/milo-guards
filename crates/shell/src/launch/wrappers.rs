//! The wrappers that run another program or script: `env`, `xargs`,
//! `rsync -e`, `tmux`, `cmd /c`, `powershell -Command`, `Start-Process`,
//! cmd's `start` and the package runners (`npx`, `uvx`, `bunx`, ...).

use std::rc::Rc;

use super::interpreters::{reads_input, BUN_VALUES, DENO_VALUES};
use super::npm::{call_script, npm_word, npx_start, prefix_folder, NPM_VALUES};
use super::{after_options, after_options_by, is_stdin, join, Launch, Word};
use crate::powershell::{native, Params};
use crate::unit::{self, has_flag, Arg, Reads, Unit};
use crate::Shell;

/// The command `rsync -e` (`--rsh`) runs: also at the end of a bundle
/// (`-avze 'ssh -p 22'`) or joined (`-essh`, `--rsh=ssh`).
pub(super) fn rsh(args: &[Arg]) -> Option<Arg> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if let Some(command) = text.strip_prefix("--rsh=") {
            return Some(Arg::Known(command.to_string()));
        }
        if text == "--rsh" {
            return iter.next().cloned();
        }
        if let Some(bundle) = text
            .strip_prefix('-')
            .filter(|bundle| !bundle.starts_with('-'))
        {
            if bundle.ends_with('e') {
                return iter.next().cloned();
            }
            if let Some(command) = bundle.strip_prefix('e').filter(|rest| !rest.is_empty()) {
                return Some(Arg::Known(command.to_string()));
            }
        }
    }
    None
}

/// `env`: assignments and options, then the program. `-C DIR` (`--chdir`)
/// starts it in `DIR`. `-S STRING` (`--split-string`) splits `STRING` into
/// words and reads them again as `env`'s own arguments, in its place: the
/// options in it too (`env -S '-C / rm -rf etc'`). The options are read as
/// GNU `getopt_long` reads them: in a bundle (`-iC DIR`), with the value
/// joined (`-CDIR`, `-S'…'`) and a long one by any prefix that names it
/// alone (`--ch DIR`, `--chd=DIR`).
pub(super) fn env(unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let mut folder = None;
    let mut options = true;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") if options => {
                options = false;
                at += 1;
            }
            // `-` alone is `-i`.
            Some("-") if options => at += 1,
            Some(text) if options && text.len() > 1 && text.starts_with('-') => {
                let (word, option) = getopt(text, args.get(at + 1), &ENV_OPTIONS);
                let used = if matches!(word, Word::Value) { 2 } else { 1 };
                match option {
                    Some(("chdir", value)) => folder = value,
                    Some(("split-string", value)) => {
                        return split_string(unit, at, used, value, folder);
                    }
                    _ => {}
                }
                at += used;
            }
            Some(text) if text.contains('=') && !text.starts_with('=') => at += 1,
            _ => return in_folder(folder, Launch::Runs(at)),
        }
    }
    Launch::Itself
}

/// `env -S STRING` at `at`, the option and its value taking `used` words:
/// `env` again, with the words of the string in their place. A string only
/// known when it runs, or one with a `${NAME}` that `env` fills in from its
/// environment, runs a command only known when it runs. A string `env`
/// refuses to split (another `$`, an escape it does not know, a quote left
/// open) runs nothing, as `env` stops there; it is still read as the shell
/// line it looks like, so a line that only differs from a working one by a
/// typo is not taken as safe.
fn split_string(
    unit: &Unit,
    at: usize,
    used: usize,
    value: Option<Arg>,
    folder: Option<Arg>,
) -> Launch {
    let Some(value) = value else {
        return Launch::Itself;
    };
    let Some(text) = value.known() else {
        return in_folder(folder, Launch::Script(Shell::Posix, value));
    };
    let words = match env_split(text) {
        Ok(words) => words,
        Err(Unsplit::Expands) => {
            return in_folder(
                folder,
                Launch::Script(Shell::Posix, Arg::Unknown(text.to_string())),
            );
        }
        Err(Unsplit::Refused) => return in_folder(folder, Launch::Script(Shell::Posix, value)),
    };
    let mut again = unit.clone();
    again.args = unit.args[..at]
        .iter()
        .cloned()
        .chain(words.into_iter().map(Arg::Known))
        .chain(
            unit.args
                .get(at + used..)
                .unwrap_or_default()
                .iter()
                .cloned(),
        )
        .collect();
    Launch::Replace(Box::new(again))
}

/// Why `env -S` gives no words known before the line runs.
enum Unsplit {
    /// The string fills in a variable, `${NAME}`, from `env`'s environment.
    Expands,
    /// `env` refuses the string and runs nothing: a `$` not followed by
    /// `{NAME}`, an escape it does not know, a quote left open.
    Refused,
}

/// The words `env -S` splits `text` into: at blanks, with `'…'` and `"…"`
/// quoting, the escapes of `\`, a `#` that starts a word ending the string,
/// and `\c` ending it too. GNU's and BSD's `env` both refuse a string they
/// cannot split so, and both fill in `${NAME}` outside single quotes.
fn env_split(text: &str) -> Result<Vec<String>, Unsplit> {
    let mut words = Vec::new();
    let mut word = String::new();
    // Whether a word has started, though it may be empty (`''`).
    let mut started = false;
    // Whether a `${NAME}` is filled in, read on to the end all the same:
    // `env` refuses the whole string for a fault after it too.
    let mut expands = false;
    let mut quote = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (None, '#') if !started => break,
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (Some(open), c) if c == open => quote = None,
            (Some('\''), '\\') => match chars.next().ok_or(Unsplit::Refused)? {
                c @ ('\\' | '\'') => word.push(c),
                c => {
                    word.push('\\');
                    word.push(c);
                }
            },
            (Some('\''), c) => word.push(c),
            (_, '$') => {
                variable(&mut chars)?;
                expands = true;
                started = true;
            }
            (_, '\\') => {
                let escaped = match chars.next().ok_or(Unsplit::Refused)? {
                    c @ ('\\' | '\'' | '"' | '#' | '$') => c,
                    '_' if quote.is_none() => {
                        if started {
                            words.push(std::mem::take(&mut word));
                            started = false;
                        }
                        continue;
                    }
                    '_' => ' ',
                    'c' if quote.is_none() => break,
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'v' => '\u{b}',
                    _ => return Err(Unsplit::Refused),
                };
                word.push(escaped);
                started = true;
            }
            (_, c) => {
                word.push(c);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(Unsplit::Refused);
    }
    if expands {
        return Err(Unsplit::Expands);
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

/// Reads the `{NAME}` after a `$` in an `env -S` string from `chars`: a
/// name that starts with a letter or `_` and goes on with letters, digits
/// and `_`, closed by `}`. Anything else `env` refuses.
fn variable(chars: &mut std::str::Chars<'_>) -> Result<(), Unsplit> {
    if chars.next() != Some('{') {
        return Err(Unsplit::Refused);
    }
    let mut first = true;
    loop {
        match chars.next() {
            Some('}') if !first => return Ok(()),
            Some(c) if c == '_' || c.is_ascii_alphabetic() || (!first && c.is_ascii_digit()) => {
                first = false;
            }
            _ => return Err(Unsplit::Refused),
        }
    }
}

/// How a program that reads its options as GNU `getopt_long` does reads
/// them: the short options that take a value, each with the name of the
/// long one it stands for, and the long options, each with whether it
/// takes a value.
pub(super) struct Getopt {
    pub(super) short: &'static [(char, &'static str)],
    pub(super) long: &'static [(&'static str, bool)],
}

/// `env`'s options (GNU coreutils, and BSD's `-C` and `-S`).
const ENV_OPTIONS: Getopt = Getopt {
    short: &[
        ('a', "argv0"),
        ('C', "chdir"),
        ('S', "split-string"),
        ('u', "unset"),
    ],
    long: &[
        ("argv0", true),
        ("block-signal", false),
        ("chdir", true),
        ("debug", false),
        ("default-signal", false),
        ("help", false),
        ("ignore-environment", false),
        ("ignore-signal", false),
        ("list-signal-handling", false),
        ("null", false),
        ("split-string", true),
        ("unset", true),
        ("version", false),
    ],
};

/// How the program `spec` describes reads the word `text`, which starts
/// with a dash, given the word `next` after it: whether it takes `next`,
/// and the option that takes a value in it, by its long name, with that
/// value. A bundle of short options ends at the first that takes a value,
/// the rest of the word being the value (`-iCDIR`) or, when there is none,
/// the next word. A long option is named by any prefix of it that no other
/// starts with, and given its value after `=` or in the next word.
pub(super) fn getopt(
    text: &str,
    next: Option<&Arg>,
    spec: &Getopt,
) -> (Word, Option<(&'static str, Option<Arg>)>) {
    if let Some(long) = text.strip_prefix("--") {
        let (name, joined) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (long, None),
        };
        let mut prefixed = spec.long.iter().filter(|(full, _)| full.starts_with(name));
        let found = spec
            .long
            .iter()
            .find(|(full, _)| *full == name)
            .or_else(|| prefixed.next().filter(|_| prefixed.next().is_none()));
        return match (found, joined) {
            (Some(&(full, true)), Some(value)) if !name.is_empty() => (
                Word::Flag,
                Some((full, Some(Arg::Known(value.to_string())))),
            ),
            (Some(&(full, true)), None) if !name.is_empty() => {
                (Word::Value, Some((full, next.cloned())))
            }
            _ => (Word::Flag, None),
        };
    }
    let bundle = text.strip_prefix('-').unwrap_or(text);
    for (at, c) in bundle.char_indices() {
        if let Some(&(_, name)) = spec.short.iter().find(|(short, _)| *short == c) {
            let rest = &bundle[at + c.len_utf8()..];
            return if rest.is_empty() {
                (Word::Value, Some((name, next.cloned())))
            } else {
                (Word::Flag, Some((name, Some(Arg::Known(rest.to_string())))))
            };
        }
    }
    (Word::Flag, None)
}

/// `launch`, started in `folder` when there is one (see [`Launch::In`]).
pub(super) fn in_folder(folder: Option<Arg>, launch: Launch) -> Launch {
    match folder {
        Some(folder) => Launch::In(folder, Box::new(launch)),
        None => launch,
    }
}

/// The folder the last of the options `names` gives among `args`, a
/// wrapper's own options before what it runs, each other option read as
/// `read` says (see [`Word`]): `--dir DIR` and `--dir=DIR` for a long name,
/// `-C DIR` for a short one, and also `-CDIR` when `joined`. The words that
/// do not start with a dash (a subcommand, `exec`) are passed over.
pub(super) fn folder_option(
    args: &[Arg],
    names: &[&str],
    joined: bool,
    read: impl Fn(&str, Option<&Arg>) -> Word,
) -> Option<Arg> {
    let mut folder = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            at += 1;
            continue;
        };
        if text == "--" {
            break;
        }
        if names.contains(&text) {
            folder = args.get(at + 1).cloned();
            at += 2;
            continue;
        }
        let attached = names.iter().find_map(|name| {
            if name.starts_with("--") {
                text.strip_prefix(name)?.strip_prefix('=')
            } else if joined && name.len() == 2 {
                text.strip_prefix(name).filter(|rest| !rest.is_empty())
            } else {
                None
            }
        });
        if let Some(value) = attached {
            folder = Some(Arg::Known(value.to_string()));
            at += 1;
            continue;
        }
        at += if text.len() > 1 && text.starts_with('-') {
            match read(text, args.get(at + 1)) {
                Word::Flag | Word::Operand => 1,
                Word::Value => 2,
            }
        } else {
            1
        };
    }
    folder
}

/// The variables `env` sets (`X=1`) or unsets (`-u X`) for the program it
/// runs, read as [`env`] reads its arguments.
pub(super) fn env_sets(args: &[Arg]) -> Vec<String> {
    let mut names = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-S" | "--split-string") => break,
            Some("-u" | "--unset") => {
                names.extend(args.get(at + 1).map(|name| name.text().to_string()));
                at += 2;
            }
            Some("-C" | "--chdir") => at += 2,
            Some(text) if text.starts_with("--unset=") => {
                names.push(text["--unset=".len()..].to_string());
                at += 1;
            }
            // `-uPATH`, and `-iu PATH` (which `env` reads as `-iu` and then
            // a program called `PATH`): the name is attached or next.
            Some(text)
                if text.starts_with('-') && !text.starts_with("--") && text.contains('u') =>
            {
                let rest = text.split_once('u').map_or("", |(_, rest)| rest);
                if rest.is_empty() {
                    names.extend(args.get(at + 1).map(|name| name.text().to_string()));
                } else {
                    names.push(rest.to_string());
                }
                at += 1;
            }
            Some(text) if text.starts_with('-') => at += 1,
            Some(text) if text.contains('=') && !text.starts_with('=') => {
                names.extend(text.split('=').next().map(str::to_string));
                at += 1;
            }
            _ => break,
        }
    }
    names
}

/// The values `NODE_OPTIONS` is given by the wrapper's own arguments, the
/// ones before the program at `start` (`env NODE_OPTIONS=… node`, `sudo
/// NODE_OPTIONS=… node`).
pub(super) fn node_options(args: &[Arg], start: usize) -> Vec<Arg> {
    args.iter()
        .take(start)
        .filter_map(Arg::known)
        .filter_map(|text| text.strip_prefix("NODE_OPTIONS="))
        .map(|value| Arg::Known(value.to_string()))
        .collect()
}

/// The values `PYTHONPATH` is given by the wrapper's own arguments, as
/// [`node_options`] reads `NODE_OPTIONS`.
pub(super) fn python_path(args: &[Arg], start: usize) -> Vec<Arg> {
    args.iter()
        .take(start)
        .filter_map(Arg::known)
        .filter_map(|text| text.strip_prefix("PYTHONPATH="))
        .map(|value| Arg::Known(value.to_string()))
        .collect()
}

/// `xargs`: its options, then the program its input is handed to.
pub(super) fn xargs(args: &[Arg]) -> Launch {
    let mut replace = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            break;
        };
        match text {
            "-I" => {
                replace = args.get(at + 1).and_then(Arg::known).map(str::to_string);
                at += 2;
            }
            "-J" => {
                replace = args.get(at + 1).and_then(Arg::known).map(str::to_string);
                at += 2;
            }
            "-n" | "-P" | "-L" | "-s" | "-d" | "-E" | "-a" | "-R" | "-S" | "--max-args"
            | "--max-procs" | "--max-lines" | "--max-chars" | "--delimiter" | "--eof"
            | "--arg-file" | "--process-slot-var" => at += 2,
            text if text.starts_with("-I") => {
                replace = Some(text[2..].to_string());
                at += 1;
            }
            text if text.starts_with("--replace=") => {
                replace = Some(text["--replace=".len()..].to_string());
                at += 1;
            }
            text if text.starts_with("-i") => {
                replace = Some(if text.len() > 2 {
                    text[2..].to_string()
                } else {
                    "{}".to_string()
                });
                at += 1;
            }
            text if text.starts_with('-') && text.len() > 1 => at += 1,
            _ => break,
        }
    }
    if at < args.len() {
        Launch::Input { start: at, replace }
    } else {
        Launch::Itself
    }
}

/// The file `xargs -a FILE` (`--arg-file`) reads the arguments from,
/// instead of its input.
pub(super) fn arg_file(args: &[Arg]) -> Option<Arg> {
    let mut iter = args.iter();
    let mut file = None;
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if matches!(text, "-a" | "--arg-file") {
            file = iter.next().cloned();
        } else if let Some(value) = text
            .strip_prefix("--arg-file=")
            .or_else(|| text.strip_prefix("-a").filter(|value| !value.is_empty()))
        {
            file = Some(Arg::Known(value.to_string()));
        }
    }
    file
}

/// `tmux` runs a command through the user's shell in its sessions and
/// windows: the last operand of such a subcommand is that command.
pub(super) fn tmux(args: &[Arg]) -> Launch {
    let runs = args.iter().filter_map(Arg::known).any(|text| {
        matches!(
            text,
            "new"
                | "new-session"
                | "neww"
                | "new-window"
                | "splitw"
                | "split-window"
                | "respawnp"
                | "respawn-pane"
                | "respawnw"
                | "respawn-window"
                | "send-keys"
                | "send"
        )
    });
    match args
        .iter()
        .rev()
        .find(|arg| arg.known().is_some_and(|text| !text.starts_with('-')))
    {
        Some(command) if runs => Launch::Script(Shell::Posix, command.clone()),
        _ => Launch::Itself,
    }
}

/// `cmd /c …` or `cmd /k …` runs the rest of the line in cmd; without
/// either, cmd reads commands from its input.
pub(super) fn cmd(args: &[Arg]) -> Launch {
    for (at, arg) in args.iter().enumerate() {
        let Some(text) = arg.known() else { continue };
        let lower = text.to_ascii_lowercase();
        if lower == "/c" || lower == "/k" || lower == "/r" {
            return Launch::Script(Shell::Cmd, join(&args[at + 1..]));
        }
        if let Some(rest) = ["/c", "/k", "/r"]
            .iter()
            .find_map(|switch| lower.strip_prefix(switch))
        {
            if !rest.starts_with(' ') && !rest.is_empty() && !rest.starts_with(':') {
                let mut script = vec![Arg::Known(text[2..].to_string())];
                script.extend(args[at + 1..].iter().cloned());
                return Launch::Script(Shell::Cmd, join(&script));
            }
        }
    }
    if unit::plain(args).is_empty() {
        Launch::Reads(Reads::Shell)
    } else {
        Launch::Itself
    }
}

/// `powershell` and `pwsh`: `-Command` (or, in Windows PowerShell, a first
/// argument that is not a parameter) runs the rest; `-EncodedCommand` runs
/// what cannot be read; `-File` runs a script file; with none of them it
/// reads commands from its input.
/// `-WorkingDirectory` (`-wd`) starts the script in a folder of its own.
pub(super) fn powershell(args: &[Arg]) -> Launch {
    let (entry, folder) = powershell_entry(args);
    match entry {
        Entry::Launch(launch @ Launch::Script(..)) => in_folder(folder, launch),
        Entry::Launch(launch) => launch,
        Entry::File(_) => Launch::Itself,
        Entry::Rest(rest, _) => in_folder(folder, Launch::Script(Shell::PowerShell, join(rest))),
    }
}

/// The script file `powershell` or `pwsh` runs from its arguments: the one
/// `-File` names, or the first word that is not a parameter (which `pwsh`
/// runs as a file and Windows PowerShell as a command). `None` when it is not
/// known now, or no file is run.
pub(crate) fn powershell_file(args: &[Arg]) -> Option<Arg> {
    match powershell_entry(args).0 {
        Entry::File(file) => Some(file),
        Entry::Rest([first, ..], moved) => first.known().map(|file| file_arg(file, moved)),
        Entry::Launch(_) | Entry::Rest(..) => None,
    }
}

/// How `powershell` and `pwsh` start, before it is a [`Launch`].
enum Entry<'a> {
    /// What the arguments make it do.
    Launch(Launch),
    /// `-File name`, with the name known now: it runs that script file.
    File(Arg),
    /// A first word that is not a parameter, with the words after it: run as
    /// a command.
    Rest(&'a [Arg], bool),
}

/// [`Entry`], with the folder `-WorkingDirectory` (`-wd`) names, the last
/// one given before the entry.
fn powershell_entry(args: &[Arg]) -> (Entry<'_>, Option<Arg>) {
    let mut folder = None;
    let entry = powershell_entry_in(args, &mut folder);
    (entry, folder)
}

fn powershell_entry_in<'a>(args: &'a [Arg], folder: &mut Option<Arg>) -> Entry<'a> {
    let mut at = 0;
    // Whether `-WorkingDirectory` has moved the folder a file is read from.
    let mut moved = false;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            return Entry::Rest(&args[at..], moved);
        };
        let Some(name) = text.strip_prefix('-').or_else(|| text.strip_prefix('/')) else {
            return Entry::Rest(&args[at..], moved);
        };
        // `-File:name`: the value joined to the parameter.
        if let Some((param, value)) = name.split_once(':') {
            let param = param.to_ascii_lowercase();
            if !value.is_empty() && !param.is_empty() && "file".starts_with(&param) {
                return Entry::File(file_arg(value, moved));
            }
            // `-wd:DIR`, `-wo:DIR`.
            if !value.is_empty() && working_directory(&param) {
                *folder = Some(Arg::Known(value.to_string()));
                moved = true;
                at += 1;
                continue;
            }
        }
        let name = name.trim_end_matches(':').to_ascii_lowercase();
        if name.is_empty() {
            return Entry::Launch(Launch::Reads(Reads::Shell));
        }
        if matches!(name.as_str(), "help" | "h" | "?") {
            return Entry::Launch(Launch::Itself);
        }
        // `-Version 2` picks the engine and the command after it still runs;
        // `-Version` alone prints the version.
        if name == "v" || (name.len() >= 2 && "version".starts_with(&name)) {
            let value = args
                .get(at + 1)
                .and_then(Arg::known)
                .is_some_and(|next| !next.starts_with(['-', '/']));
            if !value {
                return Entry::Launch(Launch::Itself);
            }
            at += 2;
        } else if matches!(name.as_str(), "ex" | "ep")
            || (name.len() >= 3 && "executionpolicy".starts_with(&name))
        {
            at += 2;
        } else if name == "e"
            || name == "ec"
            || (name.len() >= 2 && "encodedcommand".starts_with(&name))
        {
            return Entry::Launch(Launch::Encoded);
        } else if "command".starts_with(&name) {
            let rest = &args[at + 1..];
            return Entry::Launch(match rest {
                [] => Launch::Itself,
                [only] if only.known() == Some("-") => Launch::Reads(Reads::Shell),
                rest => Launch::Script(Shell::PowerShell, join(rest)),
            });
        } else if "file".starts_with(&name) {
            return match args.get(at + 1) {
                Some(Arg::Known(stdin)) if is_stdin(stdin) => {
                    Entry::Launch(Launch::Reads(Reads::Shell))
                }
                Some(Arg::Known(file)) => Entry::File(file_arg(file, moved)),
                None => Entry::Launch(Launch::Itself),
                Some(script) => Entry::Launch(Launch::Script(Shell::PowerShell, script.clone())),
            };
        } else if working_directory(&name)
            || matches!(
                name.as_str(),
                "windowstyle"
                    | "w"
                    | "win"
                    | "configurationname"
                    | "outputformat"
                    | "of"
                    | "o"
                    | "inputformat"
                    | "if"
                    | "settingsfile"
                    | "custompipename"
            )
        {
            if working_directory(&name) {
                moved = true;
                *folder = args.get(at + 1).cloned();
            }
            at += 2;
        } else {
            at += 1;
        }
    }
    Entry::Launch(Launch::Reads(Reads::Shell))
}

/// Whether `name`, a parameter of `pwsh` or `powershell` in lower case,
/// is `-WorkingDirectory`: `-wd`, or any prefix of it from `-wo` on, as
/// pwsh matches it.
fn working_directory(name: &str) -> bool {
    name == "wd"
        || (name.len() >= 2 && name.starts_with("wo") && "workingdirectory".starts_with(name))
}

/// The script `file` names. After `-WorkingDirectory` it is read from a
/// folder the line gives, so it is only known when it runs.
fn file_arg(file: &str, moved: bool) -> Arg {
    if moved {
        Arg::Unknown(file.to_string())
    } else {
        Arg::Known(file.to_string())
    }
}

/// `Start-Process`: the program in `-FilePath` (or its aliases `-Path` and
/// `-PSPath`; or first), its arguments in `-ArgumentList` (or after it), split
/// again by the program (see [`native::words`]), and `-Verb RunAs` to run it
/// elevated. Every other parameter that takes a value takes it
/// (`-WindowStyle Hidden`).
pub(super) fn start_process(unit: &Unit) -> Launch {
    let params = Params::start_process(&unit.args);
    let mut positional = params.positional.iter();
    let program = params
        .values(&["filepath"])
        .first()
        .copied()
        .or_else(|| positional.next().copied());
    let Some(program) = program else {
        return Launch::Itself;
    };
    // The arguments are joined into one command line, which the program
    // splits by its own rules: a run of strings known now is split as one.
    let key = program
        .known()
        .map(|program| unit::key(program, Shell::PowerShell))
        .unwrap_or_default();
    let mut args = Vec::new();
    let mut line: Vec<&str> = Vec::new();
    for arg in params
        .values(&["argumentlist"])
        .into_iter()
        .chain(positional.copied())
    {
        if let Arg::Known(text) = arg {
            line.push(text);
            continue;
        }
        let words = native::words(&key, &args, &line.join(" "));
        args.extend(words.into_iter().map(Arg::Known));
        line.clear();
        args.push(arg.clone());
    }
    let words = native::words(&key, &args, &line.join(" "));
    args.extend(words.into_iter().map(Arg::Known));
    let mut wrappers = unit.wrappers.clone();
    wrappers.push("start-process".to_string());
    if params.values(&["verb"]).iter().any(|verb| {
        verb.known()
            .is_some_and(|verb| verb.eq_ignore_ascii_case("runas"))
    }) {
        wrappers.push("runas".to_string());
    }
    // `-WorkingDirectory` starts the program in a folder of its own.
    let folder = params
        .values(&["workingdirectory"])
        .last()
        .map(|folder| (*folder).clone());
    let launch = Launch::Replace(Box::new(Unit {
        shell: unit.shell,
        program: program.clone(),
        args,
        wrappers,
        stage: unit.stage,
        reads: Reads::Nothing,
        stdin: None,
        dir: None,
        elsewhere: Vec::new(),
        stayed: Vec::new(),
        hidden: false,
        startup: Rc::default(),
        repeated: false,
        downloaded: false,
        relocates: false,
        listings: Vec::new(),
        unread_item: false,
        listed: Vec::new(),
        depth: unit.depth,
    }));
    in_folder(folder, launch)
}

/// The file `Start-Process -RedirectStandardInput` (or `-RSI`, or a start
/// of it no other parameter has) feeds the program it starts, as
/// `program < file` does.
pub(super) fn standard_input(unit: &Unit) -> Option<Arg> {
    Params::start_process(&unit.args)
        .values(&["redirectstandardinput"])
        .first()
        .map(|file| (*file).clone())
}

/// cmd's `start`: a quoted title first, its `/` options, then the program,
/// which `/d DIR` (also `/dDIR`) starts in `DIR`.
pub(super) fn start(args: &[Arg]) -> Launch {
    let mut folder = None;
    let mut at = 0;
    if args
        .first()
        .and_then(Arg::known)
        .is_some_and(|title| title.is_empty() || title.contains(char::is_whitespace))
    {
        at = 1;
    }
    while let Some(arg) = args.get(at) {
        match arg.known().map(str::to_ascii_lowercase) {
            Some(text) if text == "/d" => {
                folder = args.get(at + 1).cloned();
                at += 2;
            }
            Some(text) if matches!(text.as_str(), "/affinity" | "/node") => at += 2,
            Some(text) if text.starts_with("/d") => {
                folder = arg.known().map(|text| Arg::Known(text[2..].to_string()));
                at += 1;
            }
            Some(text) if text.starts_with('/') => at += 1,
            _ => return in_folder(folder, Launch::Runs(at)),
        }
    }
    Launch::Itself
}

/// The package runners, by the name they stand under in a unit's wrappers.
/// What a runner starts is a program, never a builtin of the shell.
pub(crate) const RUNNERS: [&str; 13] = [
    "npx", "npm", "pnpm", "pnpx", "pnx", "yarn", "bunx", "bun", "uvx", "uv", "pipx", "deno", "dx",
];

/// The commands of `pnpm` and their aliases (`pnpm --help`, pnpm.io/cli),
/// with the npm commands it passes on. `pnpm NAME` for any other name runs
/// NAME as a script of the project or, when there is none, as a program: it
/// is read as `pnpm exec NAME`.
const PNPM_COMMANDS: &[&str] = &[
    "add",
    "approve-builds",
    "audit",
    "bin",
    "cat-file",
    "cat-index",
    "completion",
    "config",
    "c",
    "create",
    "dedupe",
    "deploy",
    "dlx",
    "doctor",
    "env",
    "exec",
    "fetch",
    "find-hash",
    "i",
    "ignored-builds",
    "import",
    "init",
    "install",
    "install-test",
    "it",
    "licenses",
    "link",
    "ln",
    "list",
    "ls",
    "la",
    "ll",
    "multi",
    "m",
    "outdated",
    "pack",
    "patch",
    "patch-commit",
    "patch-remove",
    "prune",
    "publish",
    "rb",
    "rebuild",
    "recursive",
    "remove",
    "restart",
    "rm",
    "root",
    "run",
    "run-script",
    "sbom",
    "self-update",
    "server",
    "setup",
    "start",
    "stop",
    "store",
    "t",
    "test",
    "tst",
    "un",
    "uninstall",
    "unlink",
    "up",
    "update",
    "upgrade",
    "why",
    // npm commands pnpm passes on.
    "access",
    "bugs",
    "deprecate",
    "dist-tag",
    "docs",
    "edit",
    "home",
    "info",
    "issues",
    "login",
    "logout",
    "owner",
    "ping",
    "prefix",
    "profile",
    "repo",
    "search",
    "set-script",
    "show",
    "star",
    "stars",
    "team",
    "token",
    "unpublish",
    "v",
    "version",
    "view",
    "whoami",
];

/// The words that stand for pnpm's `-r` (`pnpm recursive exec`,
/// pnpm.io/cli/recursive): they run the command in every project.
const PNPM_RECURSIVE: [&str; 3] = ["recursive", "multi", "m"];

/// The delete tools that come as packages: a package runner or a package
/// manager's bin directory starts them.
pub(crate) const DELETERS: [&str; 5] = ["rimraf", "del", "del-cli", "premove", "rmrf"];

/// The options of `pnpm`, before and after `dlx` and `exec`, that take the
/// next argument: its own string and number settings, `exec`'s
/// `--resume-from` and `dlx`'s `--allow-build`. It also reads npm's settings
/// as options (see [`Opts::Pnpm`]).
const PNPM_VALUES: &[&str] = &[
    "-C",
    "--dir",
    "-F",
    "--filter",
    "--filter-prod",
    "--reporter",
    "--loglevel",
    "-p",
    "--package",
    "--registry",
    "--config",
    "--store-dir",
    "--virtual-store-dir",
    "--modules-dir",
    "--lockfile-dir",
    "--cache-dir",
    "--global-dir",
    "--state-dir",
    "--workspace-concurrency",
    "--network-concurrency",
    "--child-concurrency",
    "--test-pattern",
    "--changed-files-ignore-pattern",
    "--node-linker",
    "--package-import-method",
    "--resolution-mode",
    "--resume-from",
    "--allow-build",
];

/// The options of `yarn` (version 1), before and after `dlx` and `exec`, that
/// take the next argument: `--cwd`, `-p`, `--package` and the global options
/// of `yarn --help` that name a folder, a host, a number or a type.
const YARN_VALUES: &[&str] = &[
    "--cwd",
    "-p",
    "--package",
    "--cache-folder",
    "--modules-folder",
    "--global-folder",
    "--link-folder",
    "--preferred-cache-folder",
    "--mutex",
    "--network-timeout",
    "--network-concurrency",
    "--registry",
    "--proxy",
    "--https-proxy",
    "--otp",
    "--use-yarnrc",
];

/// The options of `bunx` and `bun x` that take the next argument.
const BUN_X_VALUES: [&str; 2] = ["-p", "--package"];

/// The options of `deno x` and `dx` that take the next argument.
const DENO_X_VALUES: [&str; 2] = ["-p", "--package"];

/// The options of `uv`, `uvx`, `uv run` and `uv tool run` that take the next
/// argument. `--from` names the package, the program follows it.
///
/// Besides the options `uv run --help` lists, the hidden ones that real uv
/// still takes a value for: `--python-preference`, `--python-fetch`,
/// `--max-recursion-depth`, `--preview-feature(s)` and `--trusted-host`.
const UV_VALUES: &[&str] = &[
    "--from",
    "--with",
    "-w",
    "--with-requirements",
    "--with-editable",
    "-p",
    "--python",
    "--index",
    "--default-index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-c",
    "--constraints",
    "--overrides",
    "--env-file",
    "--config-file",
    "--directory",
    "--project",
    "--cache-dir",
    "--refresh-package",
    "--reinstall-package",
    "-P",
    "--upgrade-package",
    "--index-strategy",
    "--keyring-provider",
    "--resolution",
    "--prerelease",
    "--exclude-newer",
    "--link-mode",
    "--config-setting",
    "-C",
    "--allow-insecure-host",
    "--build-constraints",
    "--color",
    "--python-platform",
    "--package",
    "--extra",
    "--no-extra",
    "--group",
    "--no-group",
    "--only-group",
    "--no-editable-package",
    "--upgrade-group",
    "--prerelease-package",
    "--fork-strategy",
    "--exclude-newer-package",
    "--no-sources-package",
    "--config-settings-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-binary-package",
    "-b",
    "--torch-backend",
    "--python-preference",
    "--python-fetch",
    "--max-recursion-depth",
    "--preview-feature",
    "--preview-features",
    "--trusted-host",
];

/// The options of `pipx` and `pipx run` that take the next argument.
/// `--fetch-missing-python` is a flag, not among them.
const PIPX_VALUES: &[&str] = &[
    "--spec",
    "--python",
    "-i",
    "--index-url",
    "--pip-args",
    "--fetch-python",
    "--backend",
    "--cooldown",
    "--python-args",
    "--with",
    "--preinstall",
];

/// How a runner reads the options in front of its program.
#[derive(Clone, Copy)]
enum Opts {
    /// The options listed take the next argument; any other option does not.
    List(&'static [&'static str]),
    /// `npx`: its own pass over the words, then npm's, see [`npx_start`].
    Npx,
    /// npm's option parser, see [`npm_word`].
    Npm,
    /// `pnpm`: the options it lists, and npm's settings, which it reads too.
    Pnpm,
}

impl Opts {
    /// The index of the first argument that is not an option.
    fn after(self, args: &[Arg]) -> Option<usize> {
        match self {
            Opts::List(values) => after_options(args, values),
            Opts::Npx => npx_start(args),
            Opts::Npm => after_options_by(args, npm_word),
            Opts::Pnpm => after_options_by(args, |text, _| pnpm_word(text)),
        }
    }
}

/// How `pnpm` reads one word that starts with a dash: the options it lists,
/// and npm's settings, take the next word.
fn pnpm_word(text: &str) -> Word {
    // `-w` is `--workspace-root` for pnpm, not npm's `--workspace`.
    let npm = text
        .strip_prefix("--")
        .is_some_and(|key| key != "workspace" && NPM_VALUES.contains(&key));
    if npm || PNPM_VALUES.contains(&text) {
        Word::Value
    } else {
        Word::Flag
    }
}

/// `launch`, which the runner `key` runs from its arguments `args`, with
/// the program (or the script) at `end`, started in the folder the runner's
/// own options before it name: pnpm's `--dir` (`-C`), yarn's and bun's
/// `--cwd`, uv's `--directory`. `uv run --project DIR` finds its project in
/// `DIR` and, by the uv in use, may run the command there or where the line
/// is, so both are judged. So are npm's and npx's `--prefix` (`-C`): it
/// names the project, and whether `npm exec` runs the command there or
/// where the line is has changed between versions of npm (npm 11 runs it
/// where the line is).
pub(super) fn runner_in(key: &str, args: &[Arg], end: usize, launch: Launch) -> Launch {
    let own = args.get(..end).unwrap_or_default();
    let listed = |names: &[&str], values: &[&str]| {
        folder_option(own, names, false, |text, _| {
            if values.contains(&text) {
                Word::Value
            } else {
                Word::Flag
            }
        })
    };
    let either = match key {
        "uv" => listed(&["--project"], UV_VALUES),
        "npx" | "npm" => prefix_folder(own, key == "npx"),
        _ => None,
    };
    let launch = match either {
        Some(project) => Launch::Either(
            Box::new(Launch::In(project, Box::new(launch.clone()))),
            Box::new(launch),
        ),
        None => launch,
    };
    let folder = match key {
        "pnpm" | "pnpx" | "pnx" => {
            folder_option(own, &["-C", "--dir"], false, |text, _| pnpm_word(text))
        }
        "yarn" => listed(&["--cwd"], YARN_VALUES),
        "bun" => listed(&["--cwd"], &BUN_VALUES),
        "uv" | "uvx" => listed(&["--directory"], UV_VALUES),
        _ => None,
    };
    in_folder(folder, launch)
}

/// Where the program of a package runner starts: the words that lead to it
/// (each with the options that may stand before it), then the options of
/// the runner. The first index is where the runner's own options start,
/// the second the program, when there is one.
fn locate(args: &[Arg], steps: &[(Opts, &[&str])], own: Opts) -> Option<(usize, Option<usize>)> {
    let mut from = 0;
    for (opts, words) in steps {
        let at = from + opts.after(args.get(from..)?)?;
        if !args
            .get(at)?
            .known()
            .is_some_and(|text| words.contains(&text))
        {
            return None;
        }
        from = at + 1;
    }
    let program = args
        .get(from..)
        .and_then(|rest| own.after(rest))
        .map(|at| from + at);
    Some((from, program))
}

/// A package runner: `npx`, `npm exec`, `pnpm dlx`, `pnpm exec`,
/// `yarn dlx`, `yarn exec`, `bunx`, `bun x`, `deno x`, `dx`, `uvx`,
/// `uv tool run`, `uv run`, `pipx run`. It runs the program it names, so
/// that program is judged, with a version after the package taken off
/// (`rimraf@5`). Where the runner names the package apart from the program
/// (`npx -p pkg prog`, `uvx --from pkg prog`) the program is the one after
/// the options. `npx -c`, `pnpm -c exec` and `yarn exec` run a shell command
/// instead. `pnpm` and `yarn` also start a delete tool of the project by its
/// name (`pnpm rimraf dist`).
pub(super) fn runner(key: &str, unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let found = match key {
        "npx" => Some((0, Opts::Npx.after(args))),
        "bunx" => Some((0, Opts::List(&BUN_X_VALUES).after(args))),
        "uvx" => Some((0, Opts::List(UV_VALUES).after(args))),
        "dx" => Some((0, Opts::List(&DENO_X_VALUES).after(args))),
        // npm reads an abbreviation of a command (`npm exe`) too.
        "npm" => locate(args, &[(Opts::Npm, &["exec", "exe", "x"])], Opts::Npm),
        // `pnpx` and `pnx` are `pnpm dlx`.
        "pnpx" | "pnx" => Some((0, Opts::Pnpm.after(args))),
        // `recursive`, `multi` and `m` are pnpm's own spellings of `-r`, so
        // `pnpm recursive exec` is `pnpm -r exec`.
        "pnpm" => locate(
            args,
            &[
                (Opts::Pnpm, &PNPM_RECURSIVE),
                (Opts::Pnpm, &["dlx", "exec"]),
            ],
            Opts::Pnpm,
        )
        .or_else(|| locate(args, &[(Opts::Pnpm, &["dlx", "exec"])], Opts::Pnpm))
        .or_else(|| pnpm_direct(args)),
        "yarn" => locate(
            args,
            &[(Opts::List(YARN_VALUES), &["dlx", "exec"])],
            Opts::List(YARN_VALUES),
        )
        .or_else(|| direct(args, Opts::List(YARN_VALUES)))
        // `yarn rimraf` is short for `yarn run rimraf`.
        .or_else(|| {
            locate(
                args,
                &[(Opts::List(YARN_VALUES), &["run"])],
                Opts::List(YARN_VALUES),
            )
            .filter(|(_, program)| {
                program
                    .and_then(|at| args[at].known())
                    .is_some_and(|name| DELETERS.contains(&name))
            })
        }),
        // `x` after bun's options, which may take a value (`bun --cwd DIR
        // x`), or as the first word with no dash, as bun finds its
        // subcommand (`bun -F x echo` runs `bunx echo`).
        "bun" => locate(
            args,
            &[(Opts::List(&BUN_VALUES), &["x"])],
            Opts::List(&BUN_X_VALUES),
        )
        .or_else(|| {
            locate(
                args,
                &[(Opts::List(&[]), &["x"])],
                Opts::List(&BUN_X_VALUES),
            )
        }),
        "deno" => locate(
            args,
            &[(Opts::List(&DENO_VALUES), &["x"])],
            Opts::List(&DENO_X_VALUES),
        ),
        "uv" => locate(
            args,
            &[
                (Opts::List(UV_VALUES), &["tool"]),
                (Opts::List(&[]), &["run"]),
            ],
            Opts::List(UV_VALUES),
        )
        .or_else(|| uv_run(args)),
        "pipx" => locate(
            args,
            &[(Opts::List(&[]), &["run"])],
            Opts::List(PIPX_VALUES),
        ),
        _ => None,
    };
    let Some((from, program)) = found else {
        return Launch::Itself;
    };
    let end = program.unwrap_or(args.len());
    let own = args.get(from..end).unwrap_or_default();
    // A script handed to npm or pnpm runs in the system shell: cmd on
    // Windows, whichever shell the line is for.
    let shell = if unit.shell == Shell::Posix {
        Shell::Posix
    } else {
        Shell::Cmd
    };
    match key {
        // `-c` (`--call`) runs a script in place of a program, wherever the
        // option stands among npm's: in a bundle (`-yc`), spelt `--c`, with
        // its value after `=`, and for npm also before `exec`.
        "npx" | "npm" => {
            let options = if key == "npm" {
                &args[..program.unwrap_or(args.len())]
            } else {
                own
            };
            if let Some(script) = call_script(options, key == "npx") {
                return runner_in(key, args, end, Launch::Script(shell, script));
            }
        }
        // pnpm reads its options wherever they stand: `pnpm -c exec 'cmd'`
        // is shell mode as much as `pnpm exec -c 'cmd'`.
        "pnpm" | "pnpx" | "pnx"
            if has_flag(
                &args[..program.unwrap_or(from)],
                Some('c'),
                Some("shell-mode"),
            ) =>
        {
            if let Some(program) = program {
                return runner_in(
                    key,
                    args,
                    end,
                    Launch::Script(shell, join(&args[program..])),
                );
            }
        }
        // `yarn exec` runs its arguments as a script, in yarn's own shell.
        "yarn" if from > 0 && args[from - 1].known() == Some("exec") => {
            if let Some(program) = program {
                return runner_in(
                    key,
                    args,
                    end,
                    Launch::Script(shell, join(&args[program..])),
                );
            }
        }
        // `uv run file.py` and `uv run --script file` run Python on the file,
        // and `uv run -` on its input: read like `python file`.
        "uv" if program.is_some() && uv_script(args).is_some() => return Launch::Itself,
        "uv" if program.is_some_and(|at| reads_input(&args[at])) && uv_run(args).is_some() => {
            return runner_in(key, args, end, Launch::Reads(Reads::Interpreter));
        }
        _ => {}
    }
    let Some(program) = program else {
        return Launch::Itself;
    };
    let mut run = running_package(unit, key, program);
    // `npm exec` takes the first `--` for itself, before the program or
    // after it (`npm exec sh -- -c 'cmd'` runs `sh -c 'cmd'`); `npx` hands
    // it on.
    if key == "npm" && args[program - 1].known() != Some("--") {
        if let Some(at) = run.args.iter().position(|arg| arg.known() == Some("--")) {
            run.args.remove(at);
        }
    }
    runner_in(key, args, end, Launch::Replace(Box::new(run)))
}

/// `uv run`: its options, then the command (also after `uv`'s own options).
fn uv_run(args: &[Arg]) -> Option<(usize, Option<usize>)> {
    locate(
        args,
        &[(Opts::List(UV_VALUES), &["run"])],
        Opts::List(UV_VALUES),
    )
}

/// The file `uv run` hands to Python: the command when it is a `.py` or
/// `.pyw` file, or whatever follows `--script`, `-s` or `--gui-script`.
/// `None` for anything else, and for a module (`-m`).
pub(crate) fn uv_script(args: &[Arg]) -> Option<&Arg> {
    let (from, at) = uv_run(args)?;
    let at = at?;
    let program = &args[at];
    let own = &args[from..at];
    let is_flag = |text: &str| {
        text == "--script"
            || text == "--gui-script"
            || text
                .strip_prefix('-')
                .is_some_and(|bundle| !bundle.starts_with('-') && bundle.contains('s'))
    };
    if own
        .iter()
        .filter_map(Arg::known)
        .any(|text| text == "-m" || text == "--module")
    {
        return None;
    }
    let file = program.known().is_some_and(|text| {
        std::path::Path::new(text)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyw"))
    });
    (file || own.iter().filter_map(Arg::known).any(is_flag)).then_some(program)
}

/// `pnpm NAME args` where NAME is no command of pnpm: it runs the script
/// NAME of the project and, with none by that name, the program (pnpm's
/// own words: "pnpm will execute the command as a shell script"), so it is
/// read as `pnpm exec NAME args`. A command of pnpm is its own business.
fn pnpm_direct(args: &[Arg]) -> Option<(usize, Option<usize>)> {
    let mut at = Opts::Pnpm.after(args)?;
    // `pnpm recursive NAME` is `pnpm -r NAME`.
    if args
        .get(at)?
        .known()
        .is_some_and(|name| PNPM_RECURSIVE.contains(&name))
    {
        at += 1 + Opts::Pnpm.after(args.get(at + 1..)?)?;
    }
    let name = args.get(at)?.known()?;
    (!PNPM_COMMANDS.contains(&name)).then_some((at, Some(at)))
}

/// `yarn rimraf dist`: the project's own delete tool.
fn direct(args: &[Arg], opts: Opts) -> Option<(usize, Option<usize>)> {
    let at = opts.after(args)?;
    let name = args.get(at)?.known()?;
    DELETERS.contains(&name).then_some((at, Some(at)))
}

/// The unit a runner runs: the program at `program`, as a package without
/// its version, with the arguments after it.
pub(super) fn running(unit: &Unit, key: &str, program: usize) -> Unit {
    let mut wrappers = unit.wrappers.clone();
    wrappers.push(key.to_string());
    Unit {
        shell: unit.shell,
        program: without_version(&unit.args[program]),
        args: unit.args[program + 1..].to_vec(),
        wrappers,
        stage: unit.stage,
        reads: Reads::Nothing,
        stdin: unit.stdin.clone(),
        dir: None,
        elsewhere: Vec::new(),
        stayed: Vec::new(),
        hidden: false,
        startup: Rc::clone(&unit.startup),
        repeated: false,
        downloaded: false,
        relocates: false,
        listings: Vec::new(),
        unread_item: false,
        listed: Vec::new(),
        depth: unit.depth,
    }
}

/// [`running`], where deno names the package as `npm:rimraf@5`: the
/// program is the package.
pub(super) fn running_package(unit: &Unit, key: &str, program: usize) -> Unit {
    let mut run = running(unit, key, program);
    if matches!(key, "deno" | "dx") {
        if let Arg::Known(text) = &run.program {
            let name = text.trim_start_matches("npm:");
            run.program = without_version(&Arg::Known(name.to_string()));
        }
    }
    run
}

/// `rimraf@5` and `@scope/tool@1.2` name a package and its version: the
/// program is the package. A path or a URL is left as it is.
pub(super) fn without_version(program: &Arg) -> Arg {
    let Arg::Known(text) = program else {
        return program.clone();
    };
    if !text.starts_with('@') && text.contains(['/', '\\', ':']) {
        return program.clone();
    }
    let from = if text.starts_with('@') {
        text.find('/').map_or(text.len(), |at| at + 1)
    } else {
        0
    };
    match text[from..].find('@') {
        Some(at) if from + at > 0 => Arg::Known(text[..from + at].to_string()),
        _ => program.clone(),
    }
}
