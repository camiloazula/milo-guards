//! Code an interpreter is given inline: `python3 -c`, `node -e`, a
//! here-document fed to `python3 -`. The code itself is read by
//! `milo-guards-code`, with the language's own tree-sitter grammar; what it
//! does to files and what it runs comes out in the units and paths the rules
//! already read, so no rule learns a language.
//!
//! This module finds the code on a line: which program is an interpreter,
//! where its code is among the options, whether the interpreter is told to
//! load more code before it (`--import`, `NODE_OPTIONS`, `PYTHONPATH`), and
//! whether it is only asked to print its version. What the reader found is
//! turned into the shell's own terms in `apply`, behind the `inline`
//! feature; without it `off` says every inline line is `unknown`.

#[cfg(feature = "inline")]
use milo_guards_code::{is_data_url, is_foreign_module};

use crate::launch;
use crate::unit::Arg;

#[cfg(feature = "inline")]
mod apply;
#[cfg(not(feature = "inline"))]
mod off;

#[cfg(feature = "inline")]
pub(crate) use apply::{apply_all, apply_input};
#[cfg(feature = "inline")]
pub(crate) use milo_guards_code::Language;
#[cfg(not(feature = "inline"))]
pub(crate) use off::{apply_all, apply_input, is_data_url, is_foreign_module, Language};

/// The language of the code a program runs, by its name. TypeScript is read
/// with the JavaScript grammar: what it does not parse is not read whole.
pub(crate) fn language(key: &str) -> Option<Language> {
    match key {
        "bun" | "deno" => Some(Language::JavaScript),
        key if launch::is_node(key) => Some(Language::JavaScript),
        key if launch::is_python(key) && launch::is_interpreter(key) => Some(Language::Python),
        _ => None,
    }
}

/// Whether the code of the interpreter `key` is never read whole: `ipython`
/// runs the startup files of its profile first, and `tsx` and `ts-node` read
/// a `tsconfig.json`, which can name modules to load: code the line does not
/// show.
fn never_whole(key: &str) -> bool {
    key == "tsx" || launch::is_ts_node(key) || launch::is_ipython(key)
}

/// Whether the Python `key` names may be Python 2, or one whose built-in
/// modules are not known to be the ones of `python3`: `python2` (and
/// `python2.7`), `python` (Python 2 on some systems), every `pypy`,
/// `micropython`, and `py` unless its first word picks Python 3.
fn maybe_python2(key: &str, args: &[Arg]) -> bool {
    match key {
        "python" => true,
        "py" => !launch::py_picks_three(args),
        key => {
            key.starts_with("python2") || key.starts_with("pypy") || key.starts_with("micropython")
        }
    }
}

/// A piece of code short enough to show in a prompt: its first line, cut.
pub(crate) fn shorten(code: &str) -> String {
    let line = code.lines().next().unwrap_or_default().trim();
    let mut short: String = line.chars().take(60).collect();
    if short.len() < line.len() {
        short.push('…');
    }
    short
}

/// The inline code an interpreter is given, and where it runs.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Code {
    /// Every piece of code the options name: `node -e A -e B` runs both, the
    /// second after the first, so each is read.
    pub(crate) pieces: Vec<Arg>,
    /// The directory the interpreter is told to work from first
    /// (`bun --cwd DIR`), which the code's relative paths are read from.
    pub(crate) dir: Option<Arg>,
    /// Whether the interpreter goes on to read code from its input once the
    /// code it is given has run (`python3 -i -c`, `node -i -e`): code the
    /// guard does not read, so the line is unknown, as a bare interpreter is.
    pub(crate) input: bool,
    /// Whether the code is all the interpreter is given: its flag and one
    /// piece of code written whole on the line, no other option and no
    /// argument. A line is only safe for code read whole (see
    /// `milo_guards_code::understand`).
    pub(crate) plain: bool,
    /// Whether the interpreter may be Python 2 (`python2`, and `python`,
    /// which is Python 2 on some systems), which has only `sys` and `errno`
    /// built in: every other module, `time` and `itertools` too, is a file
    /// the working folder is searched for first.
    pub(crate) python2: bool,
}

/// The inline code an interpreter's own arguments hold, when they say where
/// it is: `python3 -c CODE`, `node -e CODE`, `bun -e CODE`, `deno eval CODE`.
/// `None` when they do not, or when what comes before it cannot be told from
/// the code's own arguments; the caller then reads the line as it did before.
pub(crate) fn code(key: &str, args: &[Arg]) -> Option<Code> {
    let python2 = maybe_python2(key, args);
    let args = launch::own_args(key, args);
    let found = match language(key)? {
        Language::Python => python_code(args),
        Language::JavaScript if key == "deno" => deno_code(args),
        Language::JavaScript => script_code(args, launch::is_node(key)),
    }?;
    Some(Code {
        plain: !never_whole(key) && is_plain(key, args),
        python2,
        ..found
    })
}

/// Whether `args` are exactly the flag that carries code and the code:
/// `python3 -c CODE`, `node -e CODE` (`-p`, `--eval`, `--print`), `bun` the
/// same, `deno eval CODE`.
fn is_plain(key: &str, args: &[Arg]) -> bool {
    let [flag, code] = args else {
        return false;
    };
    let flags: &[&str] = match key {
        "bun" => &["-e", "-p", "--eval", "--print"],
        "deno" => &["eval"],
        key if launch::is_node(key) => &["-e", "-p", "--eval", "--print"],
        key if launch::is_python(key) => &["-c"],
        _ => &[],
    };
    code.known().is_some() && flag.known().is_some_and(|flag| flags.contains(&flag))
}

/// `python -c CODE`, also in a bundle (`-Sc`) and with the code attached
/// (`-cCODE`); options that take a value are skipped. The first `-c` ends
/// the options, so there is one piece of code. `-i` (alone or in a bundle,
/// before the code) makes Python read code from its input after the code has
/// run; `-I` is isolated mode, which does not.
fn python_code(args: &[Arg]) -> Option<Code> {
    let mut interactive = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let text = arg.known()?;
        if text == "-" || text.starts_with("--") || !text.starts_with('-') {
            return None;
        }
        for (at, letter) in text.char_indices().skip(1) {
            let rest = &text[at + letter.len_utf8()..];
            match letter {
                'c' if rest.is_empty() => {
                    return iter
                        .next()
                        .cloned()
                        .map(|piece| code_of(piece, interactive));
                }
                'c' => return Some(code_of(Arg::Known(rest.to_string()), interactive)),
                'i' => interactive = true,
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

fn code_of(piece: Arg, input: bool) -> Code {
    Code {
        pieces: vec![piece],
        dir: None,
        input,
        plain: false,
        python2: false,
    }
}

/// `node -e CODE`, `-p`, `--eval`, `--print` (and `--eval=CODE`), `-pe`;
/// the options that take a value are skipped. The same options carry code
/// for bun, which also takes `--cwd DIR`. Every `-e` and `-p` has code of
/// its own and the last one runs, so all are collected: reading only the
/// first would let a second one do anything. `-p` takes the next word as
/// code unless that is an option, as `node -p -e CODE` has it (`-p` alone,
/// then the code of `-e`). Node's `-i` and `--interactive`, anywhere among
/// the options, read code from its input once the code has run (`node`
/// only: bun's `-i` installs). Node reads an underscore in the name of an
/// option as a hyphen.
fn script_code(args: &[Arg], node: bool) -> Option<Code> {
    const VALUES: [&str; 7] = [
        "require",
        "import",
        "loader",
        "experimental-loader",
        "conditions",
        "input-type",
        "env-file",
    ];
    if loads_foreign_code(args) {
        return None;
    }
    let mut found = Code::default();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let text = arg.known()?;
        if text == "-" || !text.starts_with('-') {
            break;
        }
        // Whether the word after this option is its code.
        let mut takes = None;
        if let Some(long) = text.strip_prefix("--") {
            if long.is_empty() {
                break;
            }
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let name = name.replace('_', "-");
            match (name.as_str(), value) {
                ("eval" | "print", Some(value)) => {
                    found.pieces.push(Arg::Known(value.to_string()));
                }
                ("interactive", _) => found.input |= node,
                ("eval", None) => takes = Some(true),
                ("print", None) => takes = Some(false),
                ("cwd", Some(value)) => found.dir = Some(Arg::Known(value.to_string())),
                ("cwd", None) => found.dir = Some(iter.next()?.clone()),
                (name, None) if VALUES.contains(&name) => {
                    iter.next();
                }
                _ => {}
            }
        } else if text[1..].chars().all(|letter| matches!(letter, 'e' | 'p')) {
            takes = Some(text.contains('e'));
        } else if matches!(text, "-r" | "-C") {
            iter.next();
        } else if text == "-i" {
            found.input |= node;
        }
        match takes {
            // `-e CODE`, whatever the code starts with.
            Some(true) => found.pieces.push(iter.next()?.clone()),
            // `-p CODE`, but `-p -e CODE` is a flag and then the next option.
            Some(false)
                if iter.peek().is_some_and(|next| {
                    !next.known().is_some_and(|text| text.starts_with('-'))
                }) =>
            {
                found.pieces.extend(iter.next().cloned());
            }
            Some(false) | None => {}
        }
    }
    (!found.pieces.is_empty()).then_some(found)
}

/// Whether a module specifier is code that node runs where the reader does
/// not see it: a `data:` URL (whose code runs where it is written), a module
/// from the network, or one outside the workspace.
fn foreign(specifier: &str) -> bool {
    is_data_url(specifier) || is_foreign_module(specifier)
}

/// Whether node is told to load a module before its own code (`--import`,
/// `--loader`, `--experimental-loader`, `--require`, `-r`) from a `data:`
/// URL, the network, or a file outside the workspace: code that runs where it
/// is written or that the guard does not read, so the line is unknown. A
/// value only known when it runs may be one too.
pub(crate) fn loads_foreign_code(args: &[Arg]) -> bool {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        // The options end at the script, or at a word only known when it runs.
        let Some(text) = arg.known() else {
            return false;
        };
        if text == "-" || !text.starts_with('-') || text == "--" {
            return false;
        }
        let Some(long) = text.strip_prefix("--") else {
            // `-e CODE`, `-p CODE` (unless an option follows), `-r MODULE`.
            let letters = &text[1..];
            if letters.chars().all(|letter| matches!(letter, 'e' | 'p')) {
                if letters.contains('e')
                    || iter
                        .peek()
                        .is_some_and(|next| next.known().is_some_and(|word| !word.starts_with('-')))
                {
                    iter.next();
                }
            } else if text == "-r" {
                // `-r MODULE` is `--require`.
                if iter
                    .next()
                    .is_some_and(|value| value.known().is_none_or(foreign))
                {
                    return true;
                }
            } else if text == "-C" {
                iter.next();
            }
            continue;
        };
        let (name, value) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (long, None),
        };
        let name = name.replace('_', "-");
        let found = match (name.as_str(), value) {
            ("import" | "loader" | "experimental-loader" | "require", Some(value)) => {
                foreign(value)
            }
            ("import" | "loader" | "experimental-loader" | "require", None) => iter
                .next()
                .is_some_and(|value| value.known().is_none_or(foreign)),
            // The options whose value is the next word, which is not an
            // option of its own.
            ("eval" | "print" | "cwd" | "conditions" | "input-type" | "env-file", None) => {
                iter.next();
                false
            }
            _ => false,
        };
        if found {
            return true;
        }
    }
    false
}

/// Whether the values `NODE_OPTIONS` is given in front of node (a prefix
/// assignment, `env NODE_OPTIONS=…`, an `export` before it) load a module from
/// a `data:` URL: node reads the variable's words as it does its own
/// options. A value only known when it runs may.
pub(crate) fn options_load_foreign_code(values: &[Arg]) -> bool {
    values
        .iter()
        .any(|value| match value.known().and_then(node_options_words) {
            Some(words) => {
                let words: Vec<Arg> = words.into_iter().map(Arg::Known).collect();
                loads_foreign_code(&words)
            }
            None => true,
        })
}

/// The words node reads a `NODE_OPTIONS` value as, split as its
/// `ParseNodeOptionsEnvVar` does: at a space outside double quotes; a `"`
/// turns quoting on and off and is dropped; inside quotes a backslash takes
/// the next character as it is. `None` when the value ends in a backslash
/// inside quotes or a quote is left open: node does not start then, and
/// what it would have read cannot be told.
pub(crate) fn node_options_words(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut quoted = false;
    let mut new_word = true;
    let mut chars = text.chars();
    while let Some(mut c) = chars.next() {
        if c == '\\' && quoted {
            c = chars.next()?;
        } else if c == ' ' && !quoted {
            new_word = true;
            continue;
        } else if c == '"' {
            quoted = !quoted;
            continue;
        }
        if new_word {
            words.push(String::new());
            new_word = false;
        }
        if let Some(word) = words.last_mut() {
            word.push(c);
        }
    }
    (!quoted).then_some(words)
}

/// Whether a value `NODE_OPTIONS` is given loads a module (`--require`,
/// `-r`, `--import`, `--loader`, `--experimental-loader`): node loads it
/// before any script, in every node the program it is set for starts. The
/// value is split as node splits it ([`node_options_words`]); a value only
/// known when it runs, or one node cannot split, may load one.
pub(crate) fn preloads(value: &Arg) -> bool {
    let Some(words) = value.known().and_then(node_options_words) else {
        return true;
    };
    words.iter().any(|word| {
        let name = word
            .strip_prefix("--")
            .map(|long| long.split_once('=').map_or(long, |(name, _)| name))
            .map(|name| name.replace('_', "-"));
        (word.starts_with("-r") && !word.starts_with("--"))
            || matches!(
                name.as_deref(),
                Some("require" | "import" | "loader" | "experimental-loader")
            )
    })
}

/// Whether the values `PYTHONPATH` is given in front of python (a prefix
/// assignment, `env PYTHONPATH=…`, an `export` before it) name a folder
/// outside the workspace: python looks there for an import, and runs the
/// `sitecustomize` it finds there before any code it is given, as it does a
/// module `sys.path.insert` adds. An entry is split at `:`; an empty one is
/// the working directory. A value only known when it runs may be one.
pub(crate) fn path_loads_foreign_code(values: &[Arg]) -> bool {
    values.iter().any(|value| match value.known() {
        Some(text) => text.split(':').any(is_foreign_module),
        None => true,
    })
}

/// `deno eval [OPTIONS] CODE [ARGS]`: every word after `eval` that is not an
/// option is read as code, and so is all that follows `--`. Only the first
/// is the code and the rest are the arguments `Deno.args` holds, which read
/// as code come out harmless or unreadable. Deno's options with a value that
/// only comes after `=` (`--reload`, `--v8-flags`, `--env-file`, `-A=…`) and
/// the ones that take the next word (`-L info`) are not told apart: telling
/// them apart wrongly would skip the code, so a value is read as code too
/// and a path that is not code makes the line unreadable.
fn deno_code(args: &[Arg]) -> Option<Code> {
    let mut found = Code::default();
    let mut evals = false;
    let mut options = true;
    for arg in args {
        // A word only known when it runs is code once `eval` came, and
        // before it could be anything.
        let Some(text) = arg.known() else {
            if evals {
                found.pieces.push(arg.clone());
                continue;
            }
            return None;
        };
        if options && text == "--" {
            options = false;
        } else if options && text.starts_with('-') {
            continue;
        } else if evals {
            found.pieces.push(arg.clone());
        } else if text == "eval" {
            evals = true;
        } else {
            return None;
        }
    }
    (!found.pieces.is_empty()).then_some(found)
}

/// Whether an interpreter is only asked to print its version or its help and
/// exit (`python3 --version`, `node -v`, `deno --help`): it reads no code
/// from its input and runs none. The flags differ: `-v` is the version for
/// node and bun and verbose mode for python, which then reads its input. A
/// flag that is the value of the option before it (`python -W --version`) is
/// not one, and neither is any after `--`, where the script's name comes.
pub(crate) fn prints(key: &str, args: &[Arg]) -> bool {
    const VALUES: [&str; 14] = [
        "-W",
        "-X",
        "-Q",
        "-r",
        "-C",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--conditions",
        "--input-type",
        "--env-file",
        "--cwd",
        "--check-hash-based-pycs",
    ];
    // Options of perl, ruby, php and lua that take the next word as their
    // value, even one that starts with a dash (`perl -I --version`). Any of
    // them ahead of a print flag may have taken it, so the line reads its
    // input; an option of another interpreter named here only errs that way.
    // So does any long option of theirs, below.
    const OTHER_VALUES: [&str; 14] = [
        "-I", "-E", "-d", "-c", "-z", "-f", "-l", "-e", "-B", "-R", "-F", "-S", "-t", "-a",
    ];
    let mut others = false;
    let flags: &[&str] = if launch::is_python(key) {
        &["--version", "-V", "-VV", "--help", "-h"]
    } else if launch::is_node(key) {
        &["--version", "-v", "--help", "-h"]
    } else {
        match key {
            "bun" => &["--version", "-v", "--help", "-h"],
            "deno" => &["--version", "-V", "--help", "-h"],
            _ => {
                others = true;
                &["--version", "--help", "-h"]
            }
        }
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("--") | None => return false,
            Some(text) if flags.contains(&text) => return true,
            Some(text) if VALUES.contains(&text) || (others && OTHER_VALUES.contains(&text)) => {
                iter.next();
            }
            // Their long options too: ruby's `--enable`, `--disable`,
            // `--dump`, `--encoding`, php's `--define`, `--php-ini`,
            // `--zend-extension` take the next word whatever it starts with,
            // and the rest of them are not known one by one. A long option
            // with its value joined (`--enable=gems`) takes none.
            Some(text) if others && text.starts_with("--") && !text.contains('=') => {
                iter.next();
            }
            Some(_) => {}
        }
    }
    false
}
