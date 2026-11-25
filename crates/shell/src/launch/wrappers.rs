//! The wrappers that run another program or script: `env`, `xargs`,
//! `rsync -e`, `tmux`, `cmd /c`, `powershell -Command`, `Start-Process`,
//! cmd's `start` and the package runners (`npx`, `uvx`, `bunx`, ...).

use std::rc::Rc;

use super::interpreters::{reads_input, BUN_VALUES, DENO_VALUES};
use super::npm::{call_script, npm_word, npx_start, prefix_folder, NPM_VALUES};
use super::packages::{self, MISE_VALUES, PIXI_EXEC_VALUES};
use super::{after_options, after_options_by, is_stdin, join, Launch, Word, MAX_FORKS};
use crate::located::Source;
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
/// known when it runs runs a command only known when it runs, and a word
/// with a `${NAME}` that `env` fills in from its environment is a word only
/// known when it runs (`rm -rf ${HOME}` deletes a path only known when it
/// runs). A string `env` refuses to split (another `$`, an escape it does not know, a quote left
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
        return in_folder(folder, Launch::Script(Shell::Posix, value, Source::NONE));
    };
    let Ok(words) = env_split(text) else {
        return in_folder(folder, Launch::Script(Shell::Posix, value, Source::NONE));
    };
    let mut again = unit.clone();
    again.args = unit.args[..at]
        .iter()
        .cloned()
        .chain(words)
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

/// `env` refuses an `env -S` string and runs nothing: a `$` not followed by
/// `{NAME}`, an escape it does not know, a quote left open.
struct Refused;

/// The words `env -S` splits `text` into: at blanks, with `'…'` and `"…"`
/// quoting, the escapes of `\`, a `#` that starts a word ending the string,
/// and `\c` ending it too. GNU's and BSD's `env` both refuse a string they
/// cannot split so, and both fill in `${NAME}` outside single quotes, in
/// the word it stands in: such a word is only known when it runs.
fn env_split(text: &str) -> Result<Vec<Arg>, Refused> {
    let mut words = Vec::new();
    let mut word = String::new();
    // Whether a word has started, though it may be empty (`''`).
    let mut started = false;
    // Whether the word fills in a `${NAME}`.
    let mut expands = false;
    let mut end = |word: &mut String, expands: &mut bool| {
        let word = std::mem::take(word);
        words.push(if std::mem::take(expands) {
            Arg::Unknown(word)
        } else {
            Arg::Known(word)
        });
    };
    let mut quote = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, c) if c.is_whitespace() => {
                if started {
                    end(&mut word, &mut expands);
                    started = false;
                }
            }
            (None, '#') if !started => break,
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (Some(open), c) if c == open => quote = None,
            (Some('\''), '\\') => match chars.next().ok_or(Refused)? {
                c @ ('\\' | '\'') => word.push(c),
                c => {
                    word.push('\\');
                    word.push(c);
                }
            },
            (Some('\''), c) => word.push(c),
            (_, '$') => {
                word.push_str(&variable(&mut chars)?);
                expands = true;
                started = true;
            }
            (_, '\\') => {
                let escaped = match chars.next().ok_or(Refused)? {
                    c @ ('\\' | '\'' | '"' | '#' | '$') => c,
                    '_' if quote.is_none() => {
                        if started {
                            end(&mut word, &mut expands);
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
                    _ => return Err(Refused),
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
        return Err(Refused);
    }
    if started {
        end(&mut word, &mut expands);
    }
    Ok(words)
}

/// Reads the `{NAME}` after a `$` in an `env -S` string from `chars`: a
/// name that starts with a letter or `_` and goes on with letters, digits
/// and `_`, closed by `}`. Anything else `env` refuses. It gives `${NAME}`
/// back, as written.
fn variable(chars: &mut std::str::Chars<'_>) -> Result<String, Refused> {
    if chars.next() != Some('{') {
        return Err(Refused);
    }
    let mut name = String::from("${");
    loop {
        match chars.next() {
            Some('}') if name.len() > 2 => {
                name.push('}');
                return Ok(name);
            }
            Some(c)
                if c == '_'
                    || c.is_ascii_alphabetic()
                    || (name.len() > 2 && c.is_ascii_digit()) =>
            {
                name.push(c);
            }
            _ => return Err(Refused),
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

/// `env`'s options (GNU coreutils, and BSD's `-C` and `-S`). BSD's `-P
/// altpath` and FreeBSD's `-L` and `-U user[/class]` also take a value; they
/// have no long form, so they stand under names no long option has.
const ENV_OPTIONS: Getopt = Getopt {
    short: &[
        ('a', "argv0"),
        ('C', "chdir"),
        ('L', "bsd-login-class"),
        ('P', "bsd-altpath"),
        ('S', "split-string"),
        ('U', "bsd-user-class"),
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
        Some(folder) => Launch::In(folder, None, Box::new(launch)),
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
        // The words of an `env -S` string are read again as `env`'s own,
        // in its place (see [`env`]).
        if arg.known().is_some_and(|text| {
            text.starts_with('-')
                && matches!(
                    getopt(text, None, &ENV_OPTIONS).1,
                    Some(("split-string", _))
                )
        }) {
            break;
        }
        match arg.known() {
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

/// The values `ZIPOPT` and `ZIP` are given by the wrapper's own arguments,
/// by name and in order, as [`node_options`] reads `NODE_OPTIONS`.
pub(super) fn zip_env(args: &[Arg], start: usize) -> Vec<(&str, Arg)> {
    args.iter()
        .take(start)
        .filter_map(Arg::known)
        .filter_map(|text| text.split_once('='))
        .filter(|(name, _)| matches!(*name, "ZIPOPT" | "ZIP"))
        .map(|(name, value)| (name, Arg::Known(value.to_string())))
        .collect()
}

/// The values `TF_CLI_ARGS` and `TF_CLI_ARGS_<command>` are given by the
/// wrapper's own arguments, by name, as [`node_options`] reads
/// `NODE_OPTIONS` (`env TF_CLI_ARGS=-destroy terraform apply`). One only
/// known when it runs is kept as it is.
pub(super) fn tf_cli_args(args: &[Arg], start: usize) -> Vec<(String, Arg)> {
    args.iter()
        .take(start)
        .filter_map(|arg| {
            let (name, value) = match arg {
                Arg::Known(text) => {
                    let (name, value) = text.split_once('=')?;
                    (name, Arg::Known(value.to_string()))
                }
                Arg::Unknown(_) | Arg::Template { .. } => {
                    let (name, _) = arg.text().trim_start_matches(['"', '\'']).split_once('=')?;
                    (name, arg.clone())
                }
                Arg::Input | Arg::Null => return None,
            };
            unit::read_as_arguments(name).then(|| (name.to_string(), value))
        })
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
            "--replace" => {
                replace = Some("{}".to_string());
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
            // A cluster of flags that ends in one that takes a value
            // (`-0a FILE`, `-tn 1`) takes the next word as that value, and
            // one with it attached (`-0aFILE`) takes none. `-e`, `-i` and
            // `-l` take only the rest of their word, so the cluster ends at
            // the first of them.
            text if text.starts_with('-') && !text.starts_with("--") && text.len() > 1 => {
                let bundle = &text[1..];
                let valued = bundle
                    .char_indices()
                    .find(|(_, letter)| "adEILnPsRSJeil".contains(*letter));
                at += match valued {
                    Some((place, letter @ ('I' | 'J'))) => {
                        // The string `-I` and `-J` put each word in place of:
                        // the rest of the word, or the next one.
                        let rest = &bundle[place + letter.len_utf8()..];
                        if rest.is_empty() {
                            replace = args.get(at + 1).and_then(Arg::known).map(str::to_string);
                            2
                        } else {
                            replace = Some(rest.to_string());
                            1
                        }
                    }
                    // `-i` takes only the rest of its word as its string, and
                    // `{}` without one.
                    Some((place, 'i')) => {
                        let rest = &bundle[place + 1..];
                        replace = Some(if rest.is_empty() {
                            "{}".to_string()
                        } else {
                            rest.to_string()
                        });
                        1
                    }
                    Some((place, letter))
                        if place + letter.len_utf8() == bundle.len()
                            && !matches!(letter, 'e' | 'i' | 'l') =>
                    {
                        2
                    }
                    _ => 1,
                };
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
    // The short options that take a value, attached or as the next word;
    // `-e`, `-i` and `-l` take one only attached.
    unit::option_values(args, "a", &["arg-file"], "adEILnPs").pop()
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
        Some(command) if runs => {
            Launch::Script(Shell::Posix, command.clone(), Source::arg(command))
        }
        _ => Launch::Itself,
    }
}

/// `cmd /c …` or `cmd /k …` runs the rest of the line in cmd; without
/// either, cmd reads commands from its input. A line that is not cmd's hands
/// cmd its words as one command line (see [`command_line`]), which cmd reads
/// by its own rules.
pub(super) fn cmd(args: &[Arg], shell: Shell) -> Launch {
    // MSYS2 and Git Bash hand a word that starts with `//` to a Windows
    // program with one `/` off, so a POSIX line writes cmd's switches so
    // (`cmd //c "rd /s /q x"`, `cmd //c del //q x`).
    let unescaped: Vec<Arg>;
    let args = if shell == Shell::Posix {
        unescaped = args
            .iter()
            .map(
                |arg| match arg.known().and_then(|text| text.strip_prefix('/')) {
                    Some(rest) if rest.starts_with('/') => Arg::Known(rest.to_string()),
                    _ => arg.clone(),
                },
            )
            .collect();
        unescaped.as_slice()
    } else {
        args
    };
    let line;
    let args = if shell == Shell::Cmd {
        args
    } else {
        line = command_line(args, shell);
        line.as_slice()
    };
    for (at, arg) in args.iter().enumerate() {
        let Some(text) = arg.known() else { continue };
        let lower = text.to_ascii_lowercase();
        if lower == "/c" || lower == "/k" || lower == "/r" {
            return Launch::Script(
                Shell::Cmd,
                join(&args[at + 1..]),
                Source::joined(&args[at + 1..]),
            );
        }
        if let Some(rest) = ["/c", "/k", "/r"]
            .iter()
            .find_map(|switch| lower.strip_prefix(switch))
        {
            if !rest.starts_with(' ') && !rest.is_empty() && !rest.starts_with(':') {
                let mut script = vec![Arg::Known(text[2..].to_string())];
                script.extend(args[at + 1..].iter().cloned());
                return Launch::Script(Shell::Cmd, join(&script), Source::NONE);
            }
        }
    }
    if unit::plain(args).is_empty() {
        Launch::Reads(Reads::Shell)
    } else {
        Launch::Itself
    }
}

/// The words `args` as `cmd` reads them when a PowerShell or POSIX line
/// starts it: the shell builds one command line, putting a word that holds
/// white space in double quotes, and cmd splits it again, keeping the
/// quotes, by its own rule for those around the command after `/c` (see
/// [`native::words`]). So `cmd /c bash -c "rm -rf ~"` runs `bash -c "rm -rf
/// ~"` from any shell, not `bash -c rm -rf ~`. PowerShell quotes a word with
/// white space outside the quotes it holds and leaves those as they are (as
/// it does for `cmd.exe` in every mode of passing arguments); a POSIX shell
/// on Windows (Cygwin, MSYS2) quotes one with white space or a quote, and
/// puts `\` before each quote in it, as the C runtime reads them. A word only
/// known when it runs stays one, where it stands.
fn command_line(args: &[Arg], shell: Shell) -> Vec<Arg> {
    let mut words = Vec::new();
    let mut line: Vec<String> = Vec::new();
    for arg in args {
        if let Some(text) = arg.known() {
            line.push(quoted_for_cmd(text, shell));
            continue;
        }
        let split = native::words("cmd", &words, &line.join(" "));
        words.extend(split.into_iter().map(Arg::Known));
        line.clear();
        words.push(arg.clone());
    }
    let split = native::words("cmd", &words, &line.join(" "));
    words.extend(split.into_iter().map(Arg::Known));
    words
}

/// `word` as `shell` writes it on the command line it hands `cmd` (see
/// [`command_line`]).
fn quoted_for_cmd(word: &str, shell: Shell) -> String {
    let powershell = shell == Shell::PowerShell;
    let mut inside = false;
    let quote = word.is_empty()
        || word.chars().any(|c| {
            if c == '"' {
                inside = !inside;
                !powershell
            } else {
                c.is_whitespace() && !(powershell && inside)
            }
        });
    if !quote {
        return word.to_string();
    }
    if powershell {
        return format!("\"{word}\"");
    }
    // The C runtime's escapes: the backslashes before a quote doubled and
    // one more for the quote, and those at the end doubled before the
    // closing quote.
    let mut text = String::with_capacity(word.len() + 2);
    text.push('"');
    let mut backslashes = 0;
    for c in word.chars() {
        if c == '"' {
            text.extend(std::iter::repeat_n('\\', backslashes + 1));
        }
        backslashes = if c == '\\' { backslashes + 1 } else { 0 };
        text.push(c);
    }
    text.extend(std::iter::repeat_n('\\', backslashes));
    text.push('"');
    text
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
        Entry::Rest(rest, _) => in_folder(
            folder,
            Launch::Script(Shell::PowerShell, join(rest), Source::joined(rest)),
        ),
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
        // pwsh takes `--wd` as `-wd`: a second dash after the first is
        // dropped before the name is matched.
        let Some(name) = text
            .strip_prefix('-')
            .map(|name| name.strip_prefix('-').unwrap_or(name))
            .or_else(|| text.strip_prefix('/'))
        else {
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
                rest => Launch::Script(Shell::PowerShell, join(rest), Source::joined(rest)),
            });
        } else if "file".starts_with(&name) {
            return match args.get(at + 1) {
                Some(Arg::Known(stdin)) if is_stdin(stdin) => {
                    Entry::Launch(Launch::Reads(Reads::Shell))
                }
                Some(Arg::Known(file)) => Entry::File(file_arg(file, moved)),
                None => Entry::Launch(Launch::Itself),
                Some(script) => Entry::Launch(Launch::Script(
                    Shell::PowerShell,
                    script.clone(),
                    Source::arg(script),
                )),
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
        adrift: false,
        rerun: Rc::default(),
        hidden: false,
        // `-Environment @{ BASH_ENV = … }` is for the program it starts.
        startup: Rc::clone(&unit.startup),
        repeated: false,
        downloaded: false,
        relocates: false,
        followed: false,
        autocd: false,
        aliased: false,
        listings: Vec::new(),
        unread_item: false,
        listed: Vec::new(),
        joined: Vec::new(),
        argument_variables: unit::Noted::default(),
        depth: unit.depth,
        names: unit.names.clone(),
        place: unit.place.clone(),
        // Its arguments are not the unit's.
        words: crate::located::Worded::default(),
        spelled: false,
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

/// The options of `gem exec` that take the next word.
const GEM_EXEC_VALUES: &[&str] = &[
    "-g",
    "--gem",
    "-v",
    "--version",
    "--platform",
    "--source",
    "--config-file",
];

/// The package runners, by the name they stand under in a unit's wrappers.
/// What a runner starts is a program, never a builtin of the shell.
pub(crate) const RUNNERS: [&str; 35] = [
    "npx",
    "npm",
    "pnpm",
    "pnpx",
    "pnx",
    "yarn",
    "bunx",
    "bun",
    "uvx",
    "uv",
    "pipx",
    "deno",
    "dx",
    "poetry",
    "pdm",
    "hatch",
    "conda",
    "mamba",
    "micromamba",
    "pixi",
    "rye",
    "volta",
    "mise",
    "pipenv",
    "bundle",
    "bundler",
    "rbenv",
    "asdf",
    "rvm",
    "rvm-exec",
    "chruby-exec",
    "gem",
    "corepack",
    "shx",
    "cross-env",
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
        // `bundle exec --gemfile DIR/Gemfile` sets up the bundle there,
        // which may run the command there too, as `uv run --project` may.
        "bundle" | "bundler" => {
            let values = packages::run_values(key).unwrap_or_default();
            listed(&["--gemfile"], values).map(|gemfile| gemfile_folder(&gemfile))
        }
        "npx" | "npm" => prefix_folder(own, key == "npx"),
        _ => None,
    };
    let launch = match either {
        Some(project) => Launch::Either(
            Box::new(Launch::In(project, None, Box::new(launch.clone()))),
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
        let rest = args.get(from..)?;
        // A listed runner's options may also take a word its table misses
        // (see [`subcommand`]); npm's and pnpm's are read by their parsers.
        let at = if let Opts::List(values) = opts {
            subcommand(rest, values, words)?
        } else {
            let at = opts.after(rest)?;
            if !rest[at].known().is_some_and(|text| words.contains(&text)) {
                return None;
            }
            at
        };
        from += at + 1;
    }
    let program = args
        .get(from..)
        .and_then(|rest| own.after(rest))
        .map(|at| from + at);
    Some((from, program))
}

/// Where the subcommand among `words` stands in `args`, past the options
/// `values` lists as taking the next word. An option the table does not
/// list may take the word after it or not, so when the word after the
/// options is no subcommand but one is where such an option takes a word
/// (`micromamba --log-level info run`), that one is: the reading that runs
/// a command is the one judged. `None` when neither reading finds one.
pub(super) fn subcommand(args: &[Arg], values: &[&str], words: &[&str]) -> Option<usize> {
    let names = |at: &usize| args[*at].known().is_some_and(|text| words.contains(&text));
    let at = after_options(args, values)?;
    if names(&at) {
        return Some(at);
    }
    programs(args, 0, values).into_iter().find(names)
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
    // `yarn workspace NAME CMD` and `yarn workspaces foreach … CMD` run
    // `yarn CMD`.
    if key == "yarn" {
        if let Some(args) = packages::yarn_workspace(&unit.args, YARN_VALUES) {
            let mut inner = unit.clone();
            inner.args = args;
            return package_runner(key, &inner);
        }
    }
    package_runner(key, unit)
}

/// [`runner`], once yarn's workspace words are off.
fn package_runner(key: &str, unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    // A script handed to npm or pnpm runs in the system shell: cmd on
    // Windows, whichever shell the line is for.
    let shell = if unit.shell == Shell::Posix {
        Shell::Posix
    } else {
        Shell::Cmd
    };
    // `npm explore PKG -- CMD` runs CMD in the system shell, in the
    // package's folder.
    if key == "npm" {
        if let Some(line) = npm_explore(args) {
            return Launch::Script(shell, line, Source::NONE);
        }
    }
    // A word of rvm only known when it runs, before its `do` or `exec`, may
    // be a command.
    if key == "rvm" {
        for arg in args {
            match arg.known() {
                Some("do" | "exec") => break,
                None => return Launch::Unread(arg.clone()),
                Some(_) => {}
            }
        }
    }
    // A subcommand only known when it runs may be `exec`.
    if matches!(key, "bundle" | "bundler" | "rbenv" | "gem" | "asdf" | "rvm") {
        let values = packages::run_values(key).unwrap_or(match key {
            "gem" => GEM_EXEC_VALUES,
            _ => &[],
        });
        if let (_, Some(word)) = bundle_word(args, values) {
            if word.known().is_none() {
                return Launch::Unread(word.clone());
            }
        }
    }
    // `bundle console` reads its input as irb does.
    if matches!(key, "bundle" | "bundler") && bundle_console(args) {
        return Launch::Reads(Reads::Interpreter);
    }
    let found = located(key, args);
    let Some((from, program)) = found else {
        return Launch::Itself;
    };
    let end = program.unwrap_or(args.len());
    let own = args.get(from..end).unwrap_or_default();
    match key {
        // `bundle exec 'rm -rf ~'`: a word that holds white space or a
        // shell's characters is no program bundler finds, and it hands the
        // word to the system's shell.
        "bundle" | "bundler" if program.is_some_and(|at| at + 1 == args.len()) => {
            let word = &args[program.unwrap_or_default()];
            if word.known().is_some_and(|text| {
                text.contains(char::is_whitespace)
                    || text.contains([
                        ';', '&', '|', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', '*', '?',
                        '[', ']', '{', '}', '~', '!', '#',
                    ])
            }) {
                return runner_in(
                    key,
                    args,
                    end,
                    Launch::Script(shell, word.clone(), Source::arg(word)),
                );
            }
        }
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
                return runner_in(key, args, end, Launch::Script(shell, script, Source::NONE));
            }
            // The `npm_config_call` the line sets is the same setting.
            if let Some((_, script)) = unit
                .argument_variables
                .iter()
                .rev()
                .find(|(name, _)| unit::npm_call(name))
            {
                return runner_in(
                    key,
                    args,
                    end,
                    Launch::Script(shell, script.clone(), Source::NONE),
                );
            }
        }
        // `mise exec -c 'cmd'` runs a shell line.
        "mise" => {
            if let Some(script) = packages::mise_command(own) {
                return Launch::Script(shell, script, Source::NONE);
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
                    Launch::Script(
                        shell,
                        join(&args[program..]),
                        Source::joined(&args[program..]),
                    ),
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
                    Launch::Script(
                        shell,
                        join(&args[program..]),
                        Source::joined(&args[program..]),
                    ),
                );
            }
        }
        // `uv run file.py` and `uv run --script file` run Python on the file,
        // and `uv run -` on its input: read like `python file`.
        "uv" if program.is_some() && uv_script(args, unit.shell).is_some() => {
            return Launch::Itself
        }
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
    // An option the runner's table does not list may take the word after
    // it or not, so the program is one of the words it may be, and each is
    // judged.
    let others = list_values(key, args, from)
        .map(|values| programs(args, from, values))
        .unwrap_or_default();
    let others: Vec<usize> = others
        .into_iter()
        .filter_map(|at| {
            if key == "hatch" {
                packages::past_selectors(args, at)
            } else {
                Some(at)
            }
        })
        .filter(|at| *at != program)
        .collect();
    // Past the forks a line may make it is unreadable whatever the readings
    // hold, so they are not built.
    if others.len() > MAX_FORKS {
        return Launch::Opaque("reads in too many ways to judge each");
    }
    let launch = others
        .into_iter()
        .rev()
        .fold(Launch::Replace(Box::new(run)), |rest, at| {
            Launch::Either(
                Box::new(rest),
                Box::new(Launch::Replace(Box::new(running_package(unit, key, at)))),
            )
        });
    runner_in(key, args, end, launch)
}

/// Where the program a runner `key` starts is among `args`: the first word
/// past the runner's own options and subcommand, and that program, when
/// the runner names one.
fn located(key: &str, args: &[Arg]) -> Option<(usize, Option<usize>)> {
    match key {
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
        // `yarn cdk` is short for `yarn run cdk`, which runs the script or
        // the program of the project by that name.
        .or_else(|| {
            locate(
                args,
                &[(Opts::List(YARN_VALUES), &["run"])],
                Opts::List(YARN_VALUES),
            )
            .filter(|(_, program)| program.is_some_and(|at| yarn_program(args, at)))
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
        // `hatch run CMD` and `hatch env run [--] CMD`, past the matrix
        // variables in front of the command (`+py=3.12`).
        "hatch" => {
            let values = packages::run_values(key).unwrap_or_default();
            locate(args, &[(Opts::List(values), &["run"])], Opts::List(values))
                .or_else(|| {
                    locate(
                        args,
                        &[(Opts::List(values), &["env"]), (Opts::List(&[]), &["run"])],
                        Opts::List(values),
                    )
                })
                .map(|(from, program)| {
                    (
                        from,
                        program.and_then(|at| packages::past_selectors(args, at)),
                    )
                })
        }
        // `pixi run CMD`, and `pixi exec CMD`, which installs the packages
        // its `-s` names (or the command's) and runs the command, as `uvx`
        // does.
        "pixi" => {
            let values = packages::run_values(key).unwrap_or_default();
            locate(args, &[(Opts::List(values), &["run"])], Opts::List(values)).or_else(|| {
                locate(
                    args,
                    &[(Opts::List(values), &["exec"])],
                    Opts::List(PIXI_EXEC_VALUES),
                )
            })
        }
        // `bundle exec CMD` runs CMD with the gems of the bundle set up (its
        // `RUBYOPT`, its `PATH`).
        // `bundle exec CMD` (`bundler` too), past the version RubyGems lets
        // a gem's program be started at (`bundle _2.4.0_ exec`).
        "bundle" | "bundler" => {
            let values = packages::run_values(key).unwrap_or_default();
            let skip = usize::from(args.first().and_then(Arg::known).is_some_and(|word| {
                word.len() > 2 && word.starts_with('_') && word.ends_with('_')
            }));
            locate(
                &args[skip..],
                &[(Opts::List(values), &["exec", "exe", "ex", "e"])],
                Opts::List(values),
            )
            .map(|(from, program)| (from + skip, program.map(|at| at + skip)))
        }
        // `rbenv exec CMD` runs CMD with the Ruby it picks on `PATH`.
        "rbenv" => locate(args, &[(Opts::List(&[]), &["exec"])], Opts::List(&[])),
        // `asdf exec CMD`, and `asdf env PLUGIN CMD`, which runs CMD with the
        // plugin's environment.
        "asdf" => locate(args, &[(Opts::List(&[]), &["exec"])], Opts::List(&[])).or_else(|| {
            let at = args.iter().position(|arg| arg.known() == Some("env"))? + 2;
            Some((at, Some(at).filter(|at| *at < args.len())))
        }),
        // `rvm-exec 3.3 CMD`.
        "rvm-exec" => {
            let at = after_options(args, &[])? + 1;
            Some((at, Some(at).filter(|at| *at < args.len())))
        }
        // `rvm 3.3 do CMD` and `rvm all exec CMD` run CMD with the Ruby they
        // pick, and `chruby-exec 3.3 -- CMD` does the same.
        // `rvm 3.3 ruby ARGS` runs the ruby of the version, as itself.
        "rvm" => args
            .iter()
            .position(|arg| match arg.known() {
                Some("do" | "exec") => true,
                // Not the word of an rvm command (`rvm install ruby`).
                Some("ruby") => !args
                    .first()
                    .and_then(Arg::known)
                    .is_some_and(|first| RVM_COMMANDS.contains(&first)),
                _ => false,
            })
            .map(|at| {
                let start = if args[at].known() == Some("ruby") {
                    at
                } else {
                    at + 1
                };
                (start, Some(start).filter(|at| *at < args.len()))
            }),
        "chruby-exec" => args
            .iter()
            .position(|arg| arg.known() == Some("--"))
            .map(|at| (at + 1, Some(at + 1).filter(|at| *at < args.len()))),
        // `gem exec PROGRAM`, which installs the gem first when it is not, as
        // `npx` does.
        "gem" => locate(
            args,
            &[(Opts::List(GEM_EXEC_VALUES), &["exec", "exe", "ex"])],
            Opts::List(GEM_EXEC_VALUES),
        ),
        // `mise exec TOOLS -- CMD`: the command is the one after `--`.
        "mise" => locate(
            args,
            &[(Opts::List(MISE_VALUES), &["exec", "x"])],
            Opts::List(&[]),
        )
        .map(|(from, _)| {
            let program = args[from..]
                .iter()
                .position(|arg| arg.known() == Some("--"))
                .map(|at| from + at + 1)
                .filter(|at| *at < args.len());
            (from, program)
        }),
        key => packages::run_values(key)
            .and_then(|values| locate(args, &[(Opts::List(values), &["run"])], Opts::List(values))),
    }
}

/// The table of options a runner whose own options are listed reads in
/// front of its program, which starts at `from` in `args`: `None` for npm
/// and pnpm, whose option parsers are read as they are, and for `mise
/// exec`, whose command follows `--`.
fn list_values(key: &str, args: &[Arg], from: usize) -> Option<&'static [&'static str]> {
    let subcommand = from
        .checked_sub(1)
        .and_then(|at| args.get(at))
        .and_then(Arg::known);
    match key {
        "pixi" if subcommand == Some("exec") => Some(PIXI_EXEC_VALUES),
        "bunx" | "bun" => Some(&BUN_X_VALUES),
        "uvx" | "uv" => Some(UV_VALUES),
        "dx" | "deno" => Some(&DENO_X_VALUES),
        "yarn" => Some(YARN_VALUES),
        "pipx" => Some(PIPX_VALUES),
        "gem" => Some(GEM_EXEC_VALUES),
        "rbenv" | "asdf" | "rvm" | "rvm-exec" | "chruby-exec" => Some(&[]),
        key => packages::run_values(key),
    }
}

/// Every word from `from` on that may be the program after the options:
/// an option `values` lists takes the next word, and one it does not may
/// take it or not (a word that looks like an option is never taken).
fn programs(args: &[Arg], from: usize, values: &[&str]) -> Vec<usize> {
    let mut found = Vec::new();
    // Where the reading may go on: each word is reached once.
    let mut reached = vec![false; args.len() + 1];
    let mut stack = vec![from];
    while let Some(at) = stack.pop() {
        if at >= args.len() || std::mem::replace(&mut reached[at], true) {
            continue;
        }
        match args[at].known() {
            Some("--") => found.push(at + 1),
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                if values.contains(&text) {
                    stack.push(at + 2);
                } else {
                    stack.push(at + 1);
                    let taken = args
                        .get(at + 1)
                        .is_some_and(|next| !next.text().starts_with('-'));
                    if !text.contains('=') && taken {
                        stack.push(at + 2);
                    }
                }
            }
            _ => found.push(at),
        }
    }
    found.retain(|at| *at < args.len());
    found.sort_unstable();
    found.dedup();
    found
}

/// `npm explore PKG [--] CMD`: the shell line it runs in the package's
/// folder (npm's own abbreviations of `explore` too). `None` without one.
fn npm_explore(args: &[Arg]) -> Option<Arg> {
    let (_, package) = locate(
        args,
        &[(Opts::Npm, &["explore", "explo", "explor"])],
        Opts::Npm,
    )?;
    let mut rest = args.get(package? + 1..)?;
    if rest.first().and_then(Arg::known) == Some("--") {
        rest = &rest[1..];
    }
    (!rest.is_empty()).then(|| join(rest))
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
pub(crate) fn uv_script(args: &[Arg], shell: Shell) -> Option<&Arg> {
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
        // Read as the shell's system reads it and as a POSIX one does, so a
        // word whose last name is only the extension on Windows (`C:.py` is
        // the name `.py` there) is still the Python file the line wrote.
        [shell, Shell::Posix].into_iter().any(|shell| {
            crate::path::extension(text, shell).is_some_and(|ext| {
                ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyw")
            })
        })
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

/// `yarn NAME args` where NAME is no command of yarn: it runs the script
/// NAME of the project or the program of that name the project has (`yarn
/// rimraf dist`, `yarn cdk destroy`), read as that program.
fn direct(args: &[Arg], opts: Opts) -> Option<(usize, Option<usize>)> {
    let at = opts.after(args)?;
    yarn_program(args, at).then_some((at, Some(at)))
}

/// Whether the word at `at`, after `yarn` or `yarn run`, is read as a
/// program: it is no command of yarn, and words follow it (`yarn cdk
/// destroy`) or it is a delete tool (`yarn rimraf`). A name alone (`yarn
/// format`, `yarn shutdown`) runs the project's script by that name first,
/// which is the project's own business.
fn yarn_program(args: &[Arg], at: usize) -> bool {
    args.get(at).and_then(Arg::known).is_some_and(|name| {
        !packages::yarn_command(name) && (at + 1 < args.len() || DELETERS.contains(&name))
    })
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
        adrift: false,
        rerun: Rc::default(),
        hidden: false,
        startup: Rc::clone(&unit.startup),
        repeated: false,
        downloaded: false,
        relocates: false,
        followed: false,
        autocd: false,
        aliased: false,
        listings: Vec::new(),
        unread_item: false,
        listed: Vec::new(),
        joined: Vec::new(),
        argument_variables: unit::Noted::default(),
        depth: unit.depth,
        names: unit.names.clone(),
        place: unit.place.clone(),
        words: unit.words.after(program),
        spelled: false,
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
    if key == "hatch" {
        run.program = packages::hatch_command(&run.program);
    }
    run.program = packages::package_program(key, run.program);
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

/// The folder of the project a runner sets up from its file, whose code the
/// runner runs (a `Gemfile` is Ruby; uv builds a project, running its build
/// backend): `bundle exec`, `install` and the like with `--gemfile
/// DIR/Gemfile` (`bundler`, and `BUNDLE_GEMFILE`), `uv run
/// --project DIR` and `uv --directory DIR`, which finds the project there.
/// Where the line names none, the folder is `.`, the one the line runs in:
/// that runner finds its project there. `None` for a runner that sets none
/// up.
pub(super) fn project_folders(key: &str, unit: &Unit) -> Vec<(Arg, bool)> {
    let mut found = project_folder(key, unit);
    // `RUBYGEMS_GEMDEPS` names the file RubyGems evaluates in any Ruby it
    // starts (`-`: the `Gemfile` found from the folder it runs in).
    if key != "uv" {
        let moved = ruby_moved(key, unit);
        for (value, other_case) in variable_values(unit, "RUBYGEMS_GEMDEPS") {
            let folder = match value.known() {
                Some("-") => moved.clone().unwrap_or_else(|| Arg::Known(".".to_string())),
                _ => joined(moved.as_ref(), gemfile_folder(&value), unit.shell),
            };
            found.push((folder, other_case));
        }
    }
    found
}

/// The folder the Ruby `key` runs in once every `-C` and `-X` has moved it,
/// from the one the line runs in; `None` when none does. Each moves from
/// where the one before it moved to.
pub(crate) fn ruby_moved(key: &str, unit: &Unit) -> Option<Arg> {
    if !super::is_ruby(key) {
        return None;
    }
    let dirs = super::options(key, &unit.args).dirs;
    // Past a count the folders joined are too long to be read again for
    // each of them: where it lands is only known when it runs.
    if dirs.len() > MOST_MOVES {
        return Some(Arg::Unknown("where ruby moves to".to_string()));
    }
    dirs.into_iter().fold(None, |at: Option<Arg>, dir| {
        Some(joined(at.as_ref(), dir, unit.shell))
    })
}

/// The most `-C`, `-X` and `-x` folders of a Ruby that are placed one after
/// the other.
pub(crate) const MOST_MOVES: usize = 32;

/// `path` from the folder `moved` to, when one moved.
fn joined(moved: Option<&Arg>, path: Arg, shell: Shell) -> Arg {
    match moved {
        Some(_) => crate::path::within(moved, &path, shell),
        None => path,
    }
}

/// The folders of the projects a runner sets up (see [`project_folder`]'s
/// reading), each with whether it is only so when the machine reads the
/// names of variables in any case (a Windows one): a variable named in
/// another case than the one Ruby's tools read on a POSIX machine.
fn project_folder(key: &str, unit: &Unit) -> Vec<(Arg, bool)> {
    // `gem install -g FILE` and `gem build FILE.gemspec` evaluate the file.
    if super::is_gem(key) {
        if let Some(file) = gem_file(&unit.args) {
            return vec![(gemfile_folder(&file), false)];
        }
    }
    // Any other program may start a Ruby that evaluates the `Gemfile` the
    // variable names, a binstub or a script that requires `bundler` or its
    // `bundler/setup` among them; that evaluates the one of the folder the
    // Ruby runs in (after `-C`) when none is named.
    if !matches!(key, "uv" | "bundle" | "bundler") {
        let moved = ruby_moved(key, unit);
        let mut found: Vec<(Arg, bool)> = variable_values(unit, "BUNDLE_GEMFILE")
            .into_iter()
            .map(|(gemfile, other)| {
                (
                    joined(moved.as_ref(), gemfile_folder(&gemfile), unit.shell),
                    other,
                )
            })
            .collect();
        if let Some(other) = requires_bundler(key, unit) {
            if !found.iter().any(|(_, other)| !other) {
                found.push((moved.unwrap_or_else(|| Arg::Known(".".to_string())), other));
            }
        }
        return found;
    }
    let args = unit.args.as_slice();
    let values = |list: &'static [&'static str]| {
        move |text: &str, _: Option<&Arg>| {
            if list.contains(&text) {
                Word::Value
            } else {
                Word::Flag
            }
        }
    };
    if key == "uv" {
        let Some((_, program)) = located(key, args) else {
            return Vec::new();
        };
        let own = args
            .get(..program.unwrap_or(args.len()))
            .unwrap_or_default();
        // `uv run` builds the project of the folder it runs in; `uv tool
        // run` runs a tool of its own.
        let runs = locate(args, &[(Opts::List(&[]), &["run"])], Opts::List(UV_VALUES))
            .or_else(|| uv_run(args))
            .is_some();
        let directory = folder_option(own, &["--directory"], false, values(UV_VALUES));
        let project = folder_option(own, &["--project"], false, values(UV_VALUES));
        let folder = match (directory, project) {
            (Some(directory), Some(project)) => {
                Some(crate::path::within(Some(&directory), &project, unit.shell))
            }
            (directory, project) => project
                .or(directory)
                .or_else(|| runs.then(|| Arg::Known(".".to_string()))),
        };
        return folder.map(|folder| (folder, false)).into_iter().collect();
    }
    // `bundle exec CMD` and every other subcommand but `version`, `help`,
    // `config` and `init`, and none (`install`), set up the bundle the
    // `Gemfile` names, past the version RubyGems lets a gem's program be
    // started at (`bundle _2.4.0_ exec`). `bundle init --gemspec FILE`
    // evaluates the gemspec.
    let values_list = packages::run_values(key).unwrap_or_default();
    let (rest, word) = bundle_word(args, values_list);
    let help = rest
        .iter()
        .any(|arg| matches!(arg.known(), Some("-h" | "--help")));
    // `-v` and `--version` are the version where a subcommand would stand:
    // after one they take a value (`add rails -v 7.0`).
    let version = rest
        .first()
        .is_some_and(|arg| matches!(arg.known(), Some("-v" | "--version")));
    if help || version {
        return Vec::new();
    }
    let own = if let Some((_, program)) = located(key, args) {
        let Some(own) = args.get(..program.unwrap_or(args.len())) else {
            return Vec::new();
        };
        own
    } else {
        match word.and_then(Arg::known).and_then(bundle_command) {
            Some("version" | "help" | "config") => return Vec::new(),
            Some("init") => {
                let gemspec = folder_option(args, &["--gemspec"], false, values(values_list));
                return gemspec
                    .map(|gemspec| (gemfile_folder(&gemspec), false))
                    .into_iter()
                    .collect();
            }
            _ => args,
        }
    };
    if let Some(gemfile) = folder_option(own, &["--gemfile"], false, values(values_list)) {
        return vec![(gemfile_folder(&gemfile), false)];
    }
    let mut found: Vec<(Arg, bool)> = variable_values(unit, "BUNDLE_GEMFILE")
        .into_iter()
        .map(|(gemfile, other)| (gemfile_folder(&gemfile), other))
        .collect();
    if !found.iter().any(|(_, other)| !other) {
        found.push((Arg::Known(".".to_string()), false));
    }
    found
}

/// `rvm-shell VERSION -c TEXT` runs TEXT in a shell, with the Ruby the version
/// picks first on `PATH`.
pub(super) fn rvm_shell(args: &[Arg]) -> Launch {
    match args
        .iter()
        .position(|arg| arg.known() == Some("-c"))
        .and_then(|at| args.get(at + 1))
    {
        Some(text) => Launch::Script(Shell::Posix, text.clone(), Source::arg(text)),
        None => Launch::Itself,
    }
}

/// The file `gem install -g` (`--file`) and `gem build` evaluate: a list of
/// gems that is Ruby, and a gemspec.
fn gem_file(args: &[Arg]) -> Option<Arg> {
    // RubyGems' own `-C DIR` moves to DIR before the command runs.
    let mut moved = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-C") => {
                moved = args.get(at + 1).cloned();
                at += 2;
            }
            Some(text) if text.starts_with("-C") => {
                moved = Some(Arg::Known(text[2..].to_string()));
                at += 1;
            }
            // The configuration file it reads, which takes its value.
            Some("--config-file") => at += 2,
            Some(text) if text.starts_with('-') => at += 1,
            _ => break,
        }
    }
    let file = gem_command_file(&args[at.min(args.len())..])?;
    let Some(dir) = moved else {
        return Some(file);
    };
    match (dir.known(), file.known()) {
        (Some(_), Some(text)) if text.starts_with(['/', '~']) => Some(file),
        (Some(dir), Some(text)) => {
            Some(Arg::Known(format!("{}/{text}", dir.trim_end_matches('/'))))
        }
        _ => Some(dir),
    }
}

/// The files `gem`'s global `--config-file` names (`--config-file=FILE`
/// too): code the guard does not read where it is not the workspace's own.
pub(crate) fn gem_config_files(args: &[Arg]) -> Vec<Arg> {
    let mut found = Vec::new();
    let mut at = 0;
    // `gem` looks at every argument, to the `--`, wherever the command is.
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => break,
            Some("--config-file") => {
                found.extend(args.get(at + 1).cloned());
                at += 2;
            }
            Some(text) if text.starts_with("--config-file=") => {
                found.push(Arg::Known(text["--config-file=".len()..].to_string()));
                at += 1;
            }
            _ => at += 1,
        }
    }
    found
}

/// [`gem_file`], for the arguments from the command on.
fn gem_command_file(args: &[Arg]) -> Option<Arg> {
    let (rest, word) = bundle_word(args, GEM_EXEC_VALUES);
    let word = word?;
    let at = rest.iter().position(|arg| std::ptr::eq(arg, word))?;
    let mut iter = rest[at + 1..].iter().peekable();
    // The word after an option that may have a value, when it is not an
    // option itself (`-g FILE`).
    fn placed(iter: &mut std::iter::Peekable<std::slice::Iter<'_, Arg>>) -> Option<Arg> {
        match iter.peek() {
            Some(next) if next.known().is_none_or(|text| !text.starts_with('-')) => {
                iter.next().cloned()
            }
            _ => None,
        }
    }
    match gem_command(word.known()?)? {
        // `install` and `update` read the gems a file lists with `-g`, which
        // is read as OptionParser reads it: in a bundle (`-Ng FILE`), joined
        // (`-gFILE`), by a start of its long name (`--fil`).
        "install" | "update" => {
            let mut flagged = false;
            let mut file = None;
            while let Some(arg) = iter.next() {
                let Some(text) = arg.known() else { continue };
                if text == "--" {
                    break;
                }
                if let Some(long) = text.strip_prefix("--") {
                    let (name, joined) = long
                        .split_once('=')
                        .map_or((long, None), |(name, joined)| (name, Some(joined)));
                    if name.len() >= 2 && "file".starts_with(name) {
                        flagged = true;
                        file = joined
                            .map(|joined| Arg::Known(joined.to_string()))
                            .or_else(|| placed(&mut iter));
                    } else if joined.is_none() && GEM_FILE_VALUES.contains(&text) {
                        iter.next();
                    }
                } else if let Some(bundle) = text.strip_prefix('-').filter(|b| !b.is_empty()) {
                    for (at, letter) in bundle.char_indices() {
                        let after = &bundle[at + letter.len_utf8()..];
                        match letter {
                            'g' => {
                                flagged = true;
                                file = if after.is_empty() {
                                    placed(&mut iter)
                                } else {
                                    Some(Arg::Known(after.to_string()))
                                };
                                break;
                            }
                            'i' | 'n' | 'v' | 's' | 'P' | 'C' => {
                                if after.is_empty() {
                                    iter.next();
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
            // `-g` alone is the `Gemfile` of the folder the line runs in.
            flagged.then(|| file.unwrap_or_else(|| Arg::Known("Gemfile".to_string())))
        }
        // `build` evaluates the gemspec it is given, the one of the folder
        // when none (RubyGems 3.4 builds it from `-C DIR`).
        "build" => {
            let mut dir = None;
            let mut operand = None;
            while let Some(arg) = iter.next() {
                match arg.known() {
                    Some("-C") => dir = iter.next().cloned(),
                    Some(text) if text.starts_with("-C") => {
                        dir = Some(Arg::Known(text[2..].to_string()));
                    }
                    Some(text) if GEM_FILE_VALUES.contains(&text) => {
                        iter.next();
                    }
                    Some(text) if text.starts_with('-') => {}
                    _ => {
                        operand.get_or_insert_with(|| arg.clone());
                    }
                }
            }
            match (dir, operand) {
                (Some(dir), _) => Some(match dir.known() {
                    Some(text) => Arg::Known(format!("{}/gemspec", text.trim_end_matches('/'))),
                    None => dir,
                }),
                (None, Some(file)) => Some(file),
                (None, None) => Some(Arg::Known("Gemfile".to_string())),
            }
        }
        _ => None,
    }
}

/// The options of `gem install` and `gem build` that take the next word.
const GEM_FILE_VALUES: &[&str] = &[
    "-g",
    "--file",
    "-i",
    "--install-dir",
    "-n",
    "--bindir",
    "-o",
    "--output",
    "-C",
    "-v",
    "--version",
    "--platform",
    "--source",
    "-s",
    "--config-file",
    "--http-proxy",
    "-P",
    "--trust-policy",
];

/// The commands of `rvm`, one of which as the first word is no version.
const RVM_COMMANDS: [&str; 27] = [
    "use",
    "install",
    "uninstall",
    "reinstall",
    "remove",
    "list",
    "reload",
    "get",
    "info",
    "help",
    "gemset",
    "env",
    "cleanup",
    "current",
    "default",
    "alias",
    "implode",
    "upgrade",
    "repair",
    "rubygems",
    "requirements",
    "tools",
    "docs",
    "version",
    "fetch",
    "prepare",
    "mount",
];

/// The commands of `gem`.
const GEM_COMMANDS: [&str; 36] = [
    "build",
    "cert",
    "check",
    "cleanup",
    "contents",
    "dependency",
    "environment",
    "exec",
    "fetch",
    "generate_index",
    "help",
    "info",
    "install",
    "list",
    "lock",
    "mirror",
    "open",
    "outdated",
    "owner",
    "pristine",
    "push",
    "query",
    "rdoc",
    "rebuild",
    "search",
    "server",
    "signin",
    "signout",
    "sources",
    "specification",
    "stale",
    "uninstall",
    "unpack",
    "update",
    "which",
    "yank",
];

/// The commands of `bundle`.
const BUNDLE_COMMANDS: [&str; 31] = [
    "add", "binstubs", "cache", "check", "clean", "config", "console", "doctor", "env", "exec",
    "fund", "gem", "help", "info", "init", "inject", "install", "issue", "licenses", "list",
    "lock", "open", "outdated", "platform", "plugin", "pristine", "remove", "show", "update",
    "version", "viz",
];

/// The command of `names` that `word` is, as written or by the start of its
/// name only one has (`RubyGems` and Thor accept `inst` for `install`); `None`
/// for a word that starts none, or more than one.
fn command_of(word: &str, names: &[&'static str]) -> Option<&'static str> {
    if let Some(exact) = names.iter().find(|name| **name == word) {
        return Some(exact);
    }
    let mut starts = names
        .iter()
        .filter(|name| !word.is_empty() && name.starts_with(word));
    let first = starts.next()?;
    starts.next().is_none().then_some(*first)
}

/// Whether the subcommand of `bundle` in `args` is `console`, or the start of
/// its name that is no other command's.
fn bundle_console(args: &[Arg]) -> bool {
    let values = packages::run_values("bundle").unwrap_or_default();
    bundle_word(args, values)
        .1
        .and_then(Arg::known)
        .and_then(bundle_command)
        == Some("console")
}

/// The command of `gem` a word stands for.
fn gem_command(word: &str) -> Option<&'static str> {
    match word {
        "i" => Some("install"),
        "login" => Some("signin"),
        "logout" => Some("signout"),
        word => command_of(word, &GEM_COMMANDS),
    }
}

/// The command of `bundle` a word stands for, with its aliases.
fn bundle_command(word: &str) -> Option<&'static str> {
    match word {
        "c" => Some("check"),
        "i" => Some("install"),
        "ls" => Some("list"),
        "package" | "pack" => Some("cache"),
        word => command_of(word, &BUNDLE_COMMANDS),
    }
}

/// Whether the Ruby `key` starts requires `bundler` first (`bundler/setup`
/// evaluates the `Gemfile`), by `-r` or by the `RUBYOPT` the line gives, in
/// any case and with `./` and doubled `/` dropped from the name: `Some(true)`
/// when only by a variable named in another case than the one a POSIX
/// machine reads.
fn requires_bundler(key: &str, unit: &Unit) -> Option<bool> {
    if super::loads_ruby_libraries(key)
        && super::options(key, &unit.args)
            .requires
            .iter()
            .any(|library| library.known().is_some_and(names_bundler))
    {
        return Some(false);
    }
    let mut found = None;
    for (value, other_case) in variable_values(unit, "RUBYOPT") {
        let Some(text) = value.known() else { continue };
        if crate::detect::rubyopt_loads(text).is_some_and(|loads| {
            loads
                .iter()
                .any(|(is_list, library)| !is_list && names_bundler(library))
        }) {
            if !other_case {
                return Some(false);
            }
            found = Some(true);
        }
    }
    found
}

/// Whether the library `name` may be `bundler` or one of its files: in any
/// case, as Ruby expands each candidate path (`.` and `..` and doubled `/`
/// dropped, `\` as `/`). A name that still holds `..` after that, or a `~`
/// past its start (a short name of Windows, `bundle~1`), may be.
fn names_bundler(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let mut parts: Vec<&str> = Vec::new();
    for part in name.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return true;
                }
            }
            part if part.get(1..).is_some_and(|rest| rest.contains('~')) => return true,
            part => parts.push(part),
        }
    }
    parts
        .first()
        .is_some_and(|first| first.starts_with("bundler"))
}

/// Every value of the variable `name` the line gives, each once, with
/// whether it is one given in another case than `name`: a machine that reads
/// the names of variables in any case (a Windows one) hands Ruby one of
/// those. Each is judged, for the line may have set it where it need not run
/// (`… || export NAME=…`, in a group, in a function); the list holds few (see
/// [`MOST_RUBY_VALUES`](crate::unit)).
fn variable_values(unit: &Unit, name: &str) -> Vec<(Arg, bool)> {
    let mut found: Vec<(Arg, bool)> = Vec::new();
    for (written, value) in unit.argument_variables.ruby_values() {
        if !written.eq_ignore_ascii_case(name) {
            continue;
        }
        let other = written != name;
        if !found
            .iter()
            .any(|(known, was)| known == value && *was == other)
        {
            found.push((value.clone(), other));
        }
    }
    // Past what the list notes, a value that is only known when it runs.
    let (over, over_other) = unit.argument_variables.ruby_overflow();
    for (is_over, other) in [(over, false), (over_other, true)] {
        if is_over {
            found.push((
                Arg::Unknown("variables set past what is read".to_string()),
                other,
            ));
        }
    }
    found
}

/// The arguments of `bundle` past the version `RubyGems` lets a gem's program
/// be started at (`bundle _2.4.0_ exec`), and its subcommand, the first word
/// past its options.
fn bundle_word<'a>(args: &'a [Arg], values: &[&str]) -> (&'a [Arg], Option<&'a Arg>) {
    let skip = usize::from(
        args.first()
            .and_then(Arg::known)
            .is_some_and(|word| word.len() > 2 && word.starts_with('_') && word.ends_with('_')),
    );
    let rest = &args[skip..];
    let word = after_options(rest, values).map(|at| &rest[at]);
    (rest, word)
}

/// Why `bundle` or `asdf` with these arguments does what the line does not
/// show, when it does: `bundle plugin install` and `asdf plugin add`
/// download a plugin and run it, and `bundle config` writes the settings of
/// the user, which every project's bundle reads, unless it is `--local`
/// (`bundle config set path x` too, `--delete`, and the old `config KEY
/// VALUE`).
pub(super) fn bundle_note(key: &str, unit: &Unit) -> Option<&'static str> {
    if key == "asdf" {
        let (rest, word) = bundle_word(&unit.args, &[]);
        let word = word?;
        let at = rest.iter().position(|arg| std::ptr::eq(arg, word))?;
        let adds = match word.known()? {
            "plugin-add" => true,
            "plugin" => rest[at + 1..]
                .iter()
                .find(|arg| arg.known().is_none_or(|text| !text.starts_with('-')))
                .is_some_and(|arg| arg.known().is_none_or(|text| text == "add")),
            _ => false,
        };
        return adds.then_some("installs a plugin, code that is downloaded and run");
    }
    if super::is_gem(key) {
        let (_, word) = bundle_word(&unit.args, GEM_EXEC_VALUES);
        // The command is the first word that is one (`gem -C DIR install x`
        // has a word of an option before it).
        let places = unit
            .args
            .iter()
            .filter_map(Arg::known)
            .any(|word| gem_command(word).is_some());
        return word
            .and_then(Arg::known)
            .filter(|_| !places)
            .map(|_| "runs a command of gem that the guard cannot place");
    }
    if !matches!(key, "bundle" | "bundler") {
        return None;
    }
    let values = packages::run_values(key).unwrap_or_default();
    let (rest, word) = bundle_word(&unit.args, values);
    let word = word?;
    let at = rest.iter().position(|arg| std::ptr::eq(arg, word))?;
    // The words after the subcommand, each only known when it runs a word.
    let after: Vec<Option<&str>> = rest[at + 1..]
        .iter()
        .filter(|arg| arg.known().is_none_or(|text| !text.starts_with('-')))
        .map(Arg::known)
        .collect();
    let flag = |name: &str| {
        rest.iter().any(|arg| {
            arg.known().is_some_and(|text| {
                text == name
                    || text
                        .strip_prefix(name)
                        .is_some_and(|more| more.starts_with('='))
            })
        })
    };
    // A word that starts no command of bundler, or starts more than one, is
    // one the guard cannot place.
    let command = word.known().map(bundle_command)?;
    match command {
        None => Some("runs a command of bundler that the guard cannot place"),
        Some("plugin") if matches!(after.first(), Some(Some(word)) if "install".starts_with(word)) => {
            Some("installs a plugin, code that is downloaded and run")
        }
        Some("config") => {
            let reads = matches!(after.first(), Some(Some("get" | "list")));
            let writes = flag("--delete")
                || matches!(after.first(), Some(Some("set" | "unset")))
                || after.len() >= 2;
            (writes && !reads && !flag("--local"))
                .then_some("writes the settings every bundle of the user reads")
        }
        _ => None,
    }
}

/// The folder a `Gemfile`'s path names it in: a path written with `/`, or
/// with `\` where it has no `/` (`C:\Users\me\x\Gemfile`, `..\x\Gemfile`).
fn gemfile_folder(gemfile: &Arg) -> Arg {
    match gemfile.known() {
        Some(text) => {
            let separator = if text.contains('/') { '/' } else { '\\' };
            Arg::Known(match text.rsplit_once(separator) {
                Some(("", _)) => separator.to_string(),
                Some((folder, _)) if folder.ends_with(':') => format!("{folder}{separator}"),
                Some((folder, _)) => folder.to_string(),
                None => ".".to_string(),
            })
        }
        None => gemfile.clone(),
    }
}
