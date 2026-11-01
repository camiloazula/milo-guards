//! Code an interpreter is given inline: `python3 -c`, `node -e`, a
//! here-document fed to `python3 -`. It is read with the language's own
//! tree-sitter grammar, apart from the shell splitters, and what it does to
//! files and what it runs comes out in the units and paths the rules
//! already read, so no rule learns a language.
//!
//! The readers ([`python`], [`javascript`]) find the calls that delete,
//! write and run, and the paths they name. They give back [`Act`]s, which
//! [`apply`] turns into the shell's own terms: a delete is `rm -rf PATH`, a
//! move `mv`, a command line a script `sh -c` reads, a literal argument list
//! a unit. What the reader cannot follow is an [`Act::Unread`], which
//! comes back as `unknown`.

use crate::launch::{self, Launch};
use crate::unit::{self, Arg, Reads, Split, Unit};
use crate::{Rule, Shell};

mod javascript;
mod python;

/// The languages whose code is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    Python,
    JavaScript,
}

/// The language of the code a program runs, by its name.
pub(crate) fn language(key: &str) -> Option<Language> {
    match key {
        "python" | "python2" | "python3" => Some(Language::Python),
        "node" | "nodejs" | "bun" | "deno" => Some(Language::JavaScript),
        key if key.starts_with("python3.") => Some(Language::Python),
        _ => None,
    }
}

/// What reading code found, in the order the code gives it.
#[derive(Debug)]
pub(super) enum Act {
    /// `rm -rf PATH`: a file or a whole tree goes.
    Remove(Arg),
    /// Writes into a file, makes one, or truncates it.
    Write(Arg),
    /// `mv FROM TO`.
    Move { from: Arg, to: Arg },
    /// `ln TARGET LINK`.
    Link { target: Arg, link: Arg },
    /// `chmod MODE PATH`; `mode` is in octal where the code gives a number.
    Chmod { path: Arg, mode: Arg },
    /// `chown OWNER PATH`.
    Chown(Arg),
    /// The process moves to another directory: the paths after it are read
    /// from there.
    Chdir(Arg),
    /// A command line a shell runs: `os.system`, `child_process.exec`.
    Script(Arg),
    /// A program and its arguments, run without a shell.
    Program(Vec<Arg>),
    /// Code the code runs from a literal (`exec("…")`).
    Code(Language, String),
    /// Something the reader cannot follow, as a short piece of the code.
    Unread(String),
}

/// Everything one piece of code does.
#[derive(Debug, Default)]
pub(super) struct Reading {
    pub(super) acts: Vec<Act>,
    /// Whether the code nests too deeply to read in full.
    pub(super) deep: bool,
}

impl Reading {
    fn unread(&mut self, code: &str) {
        self.acts.push(Act::Unread(shorten(code)));
    }
}

/// A piece of code short enough to show in a prompt: its first line, cut.
fn shorten(code: &str) -> String {
    let line = code.lines().next().unwrap_or_default().trim();
    let mut short: String = line.chars().take(60).collect();
    if short.len() < line.len() {
        short.push('…');
    }
    short
}

/// A path as the shell's rules take it: its text when the code gives it,
/// and what it is made of when only known when it runs.
fn path(value: Option<String>, code: &str) -> Arg {
    match value {
        Some(text) => Arg::Known(text),
        None => Arg::Unknown(shorten(code)),
    }
}

/// `next` joined to `base` as `os.path.join` and `path.join` do: an absolute
/// `next` stands alone. A `~` is the home directory wherever it comes in the
/// code, as the shell reads it: code in a double-quoted argument had `$HOME`
/// put in as `~`, so a literal tilde cannot be told from it.
fn join(base: &str, next: &str) -> String {
    if next.starts_with(['/', '~']) || base.is_empty() {
        next.to_string()
    } else if base.ends_with('/') {
        format!("{base}{next}")
    } else {
        format!("{base}/{next}")
    }
}

/// The directory an environment variable names, where one is known: the
/// home directory, the working directory, the temporary one.
fn environment(name: &str) -> Option<String> {
    match name {
        "HOME" | "USERPROFILE" => Some("~".to_string()),
        "PWD" => Some(".".to_string()),
        "TMPDIR" | "TEMP" | "TMP" => Some("/tmp".to_string()),
        _ => None,
    }
}

/// An integer literal as the octal digits `chmod` takes: `0o755`, `0755`,
/// `493`, `0x1ED`.
fn mode(literal: &str) -> Option<String> {
    let text = literal.replace('_', "");
    let lower = text.to_ascii_lowercase();
    let number = if let Some(digits) = lower.strip_prefix("0o") {
        u32::from_str_radix(digits, 8)
    } else if let Some(digits) = lower.strip_prefix("0x") {
        u32::from_str_radix(digits, 16)
    } else if let Some(digits) = lower.strip_prefix("0b") {
        u32::from_str_radix(digits, 2)
    } else if lower.len() > 1 && lower.starts_with('0') {
        u32::from_str_radix(&lower[1..], 8)
    } else {
        lower.parse()
    };
    number.ok().map(|number| format!("{number:o}"))
}

/// The value of a quoted-style mode argument (`open`'s `'w'`, `fs.openSync`'s
/// flags): whether it writes. `None` mode is the default, which reads.
fn writes(mode: Option<&str>) -> bool {
    mode.is_some_and(|mode| mode.contains(['w', 'a', 'x', '+']))
}

/// The inline code an interpreter's own arguments hold, when they say where
/// it is: `python3 -c CODE`, `node -e CODE`, `bun -e CODE`, `deno eval CODE`.
/// `None` when they do not, or when what comes before it cannot be told from
/// the code's own arguments; the caller then reads the line as it did before.
pub(crate) fn code(key: &str, args: &[Arg]) -> Option<Arg> {
    match language(key)? {
        Language::Python => python_code(args),
        Language::JavaScript if key == "deno" => deno_code(args),
        Language::JavaScript => script_code(args),
    }
}

/// `python -c CODE`, also in a bundle (`-Sc`) and with the code attached
/// (`-cCODE`); options that take a value are skipped.
fn python_code(args: &[Arg]) -> Option<Arg> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let text = arg.known()?;
        if text == "-" || text.starts_with("--") || !text.starts_with('-') {
            return None;
        }
        for (at, letter) in text.char_indices().skip(1) {
            let rest = &text[at + letter.len_utf8()..];
            match letter {
                'c' if rest.is_empty() => return iter.next().cloned(),
                'c' => return Some(Arg::Known(rest.to_string())),
                'm' => return None,
                'W' | 'X' | 'Q' => {
                    if rest.is_empty() {
                        iter.next();
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    None
}

/// `node -e CODE`, `-p`, `--eval`, `--print` (and `--eval=CODE`), `-pe`;
/// the options that take a value are skipped. The same options carry code
/// for bun.
fn script_code(args: &[Arg]) -> Option<Arg> {
    const VALUES: [&str; 7] = [
        "require",
        "import",
        "loader",
        "experimental-loader",
        "conditions",
        "input-type",
        "env-file",
    ];
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let text = arg.known()?;
        if text == "-" || !text.starts_with('-') {
            return None;
        }
        if let Some(long) = text.strip_prefix("--") {
            if long.is_empty() {
                return None;
            }
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match (name, value) {
                ("eval" | "print", Some(value)) => return Some(Arg::Known(value.to_string())),
                ("eval" | "print", None) => return iter.next().cloned(),
                (name, None) if VALUES.contains(&name) => {
                    iter.next();
                }
                _ => {}
            }
        } else if text[1..].chars().all(|letter| matches!(letter, 'e' | 'p')) {
            return iter.next().cloned();
        } else if matches!(text, "-r" | "-C") {
            iter.next();
        }
    }
    None
}

/// `deno eval [OPTIONS] CODE`.
fn deno_code(args: &[Arg]) -> Option<Arg> {
    const VALUES: [&str; 10] = [
        "--ext",
        "--config",
        "-c",
        "--cert",
        "--import-map",
        "--location",
        "--seed",
        "--v8-flags",
        "--env-file",
        "--reload",
    ];
    let mut iter = args.iter();
    let mut evals = false;
    while let Some(arg) = iter.next() {
        let text = arg.known()?;
        if text == "--" {
            return evals.then(|| iter.next().cloned()).flatten();
        }
        if text.starts_with('-') {
            if VALUES.contains(&text) {
                iter.next();
            }
        } else if evals {
            return Some(arg.clone());
        } else if text == "eval" {
            evals = true;
        } else {
            return None;
        }
    }
    None
}

/// `bun` and `deno`: inline code is read; a file or a subcommand is the
/// workspace's own business.
pub(crate) fn runner(key: &str, args: &[Arg]) -> Launch {
    if let Some(source) = code(key, args) {
        return Launch::Inline(Language::JavaScript, source);
    }
    let evals = args.iter().any(|arg| {
        arg.known().is_some_and(|text| match key {
            "deno" => text == "eval",
            _ => matches!(text, "-e" | "-p" | "--eval" | "--print") || text.starts_with("--eval="),
        })
    });
    if evals {
        Launch::Reads(Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// Read `code` in `language`, run `depth` levels deep, and add what it does
/// to the split.
pub(crate) fn apply(split: &mut Split, language: Language, code: &str, depth: usize) {
    if !unit::within_limits(split, code, depth) {
        return;
    }
    let reading = match language {
        Language::Python => python::read(code),
        Language::JavaScript => javascript::read(code),
    };
    if reading.deep {
        split.problem(Rule::Unreadable, "nests too deeply to read", None);
    }
    // A `chdir` in the code moves its own process, not the line.
    let outer = split.dir_snapshot();
    for act in reading.acts {
        match act {
            Act::Remove(path) => run(split, "rm", vec![flag("-rf"), flag("--"), path], depth),
            Act::Write(path) => split.write(Shell::Posix, path),
            Act::Move { from, to } => run(split, "mv", vec![flag("--"), from, to], depth),
            Act::Link { target, link } => {
                run(
                    split,
                    "ln",
                    vec![flag("-s"), flag("--"), target, link],
                    depth,
                );
            }
            Act::Chmod { path, mode } => {
                run(split, "chmod", vec![flag("--"), mode, path], depth);
            }
            Act::Chown(path) => run(
                split,
                "chown",
                vec![flag("--"), Arg::Known("user".to_string()), path],
                depth,
            ),
            Act::Chdir(path) => run(split, "cd", vec![flag("--"), path], depth),
            Act::Script(script) => run(split, "sh", vec![flag("-c"), script], depth),
            Act::Program(mut words) => {
                if !words.is_empty() {
                    let program = words.remove(0);
                    launch::add(split, Unit::new(Shell::Posix, program, words, None), depth);
                }
            }
            Act::Code(language, text) => apply(split, language, &text, depth + 1),
            Act::Unread(code) => split.problem(
                Rule::Unknown,
                "runs code the guard does not read",
                Some(&code),
            ),
        }
    }
    split.restore_dir(outer);
}

fn flag(text: &str) -> Arg {
    Arg::Known(text.to_string())
}

/// Add the unit `program args…`, as if the line had run it.
fn run(split: &mut Split, program: &str, args: Vec<Arg>, depth: usize) {
    launch::add(
        split,
        Unit::new(Shell::Posix, flag(program), args, None),
        depth,
    );
}
