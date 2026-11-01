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

use tree_sitter::Node;

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
#[derive(Debug, Clone)]
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
    /// What a call that starts a program does, run from the directory its
    /// `cwd` option names: judged as if the line had moved there first, and
    /// back where it was after.
    In(Arg, Vec<Act>),
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

/// A node above the one a [`walk`] is at, and the field it fills in its own
/// parent.
#[derive(Clone, Copy)]
pub(super) struct Ancestor<'t> {
    pub(super) node: Node<'t>,
    pub(super) field: Option<&'static str>,
}

/// Visit every node under `root`, in the order the code reads, without
/// recursion so a deep tree cannot overflow the stack. `visit` is given the
/// node, the field it fills in its parent, and the nodes above it (the root
/// first), so no reader asks the tree for a node's parent, which walks it from
/// the top; it returns whether to go on.
pub(super) fn walk<'t>(
    root: Node<'t>,
    mut visit: impl FnMut(Node<'t>, Option<&'static str>, &[Ancestor<'t>]) -> bool,
) {
    let mut cursor = root.walk();
    let mut above: Vec<Ancestor<'t>> = Vec::new();
    loop {
        let node = cursor.node();
        let field = cursor.field_name();
        if !visit(node, field, &above) {
            return;
        }
        if cursor.goto_first_child() {
            above.push(Ancestor { node, field });
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
            above.pop();
        }
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

/// The inline code an interpreter is given, and where it runs.
#[derive(Debug, Default, Clone)]
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
}

/// The inline code an interpreter's own arguments hold, when they say where
/// it is: `python3 -c CODE`, `node -e CODE`, `bun -e CODE`, `deno eval CODE`.
/// `None` when they do not, or when what comes before it cannot be told from
/// the code's own arguments; the caller then reads the line as it did before.
pub(crate) fn code(key: &str, args: &[Arg]) -> Option<Code> {
    match language(key)? {
        Language::Python => python_code(args),
        Language::JavaScript if key == "deno" => deno_code(args),
        Language::JavaScript => script_code(args, matches!(key, "node" | "nodejs")),
    }
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
    if loads_data_url(args) {
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

/// Whether a module specifier is a `data:` URL, whose code runs where it is
/// written: as the URL parser reads it, leading control characters and
/// spaces and any tab or newline are dropped, and the scheme has no case.
pub(crate) fn data_url(specifier: &str) -> bool {
    let cleaned: String = specifier
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .take(5)
        .collect();
    cleaned.eq_ignore_ascii_case("data:")
}

/// Whether node is told to load a module from a `data:` URL before its own
/// code (`--import`, `--loader`, `--experimental-loader`): code that runs
/// where it is written and is not read, so the line is unknown. A value only
/// known when it runs may be one too.
pub(crate) fn loads_data_url(args: &[Arg]) -> bool {
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
            } else if matches!(text, "-r" | "-C") {
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
            ("import" | "loader" | "experimental-loader", Some(value)) => data_url(value),
            ("import" | "loader" | "experimental-loader", None) => iter
                .next()
                .is_some_and(|value| value.known().is_none_or(data_url)),
            // The options whose value is the next word, which is not an
            // option of its own.
            (
                "eval" | "print" | "require" | "cwd" | "conditions" | "input-type" | "env-file",
                None,
            ) => {
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
pub(crate) fn options_load_data_url(values: &[Arg]) -> bool {
    values.iter().any(|value| match value.known() {
        Some(text) => {
            // Node splits on spaces and drops the double quotes; every kind of
            // white space splits here, which finds at least what it does.
            let words: Vec<Arg> = text
                .split(char::is_whitespace)
                .map(|word| word.replace('"', ""))
                .filter(|word| !word.is_empty())
                .map(Arg::Known)
                .collect();
            loads_data_url(&words)
        }
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

/// `bun` and `deno`: inline code is read; a file or a subcommand is the
/// workspace's own business. Code read from the input (`bun -`, `deno run -`,
/// a REPL) is the caller's to see, or the here-document it is handed.
pub(crate) fn runner(key: &str, args: &[Arg]) -> Launch {
    if let Some(source) = code(key, args) {
        return Launch::Inline(Language::JavaScript, source);
    }
    let known = |test: &dyn Fn(&str) -> bool| args.iter().any(|arg| arg.known().is_some_and(test));
    let evals = known(&|text| match key {
        "deno" => text == "eval",
        _ => matches!(text, "-e" | "-p" | "--eval" | "--print") || text.starts_with("--eval="),
    });
    let first = args
        .iter()
        .filter_map(Arg::known)
        .find(|text| !text.starts_with('-'));
    // `deno --version` and `deno --help` print and exit: no subcommand and
    // none of these reads the input, which is the REPL.
    let prints =
        key == "deno" && known(&|text| matches!(text, "--version" | "-V" | "--help" | "-h"));
    let repl = first == Some("repl") || (key == "deno" && first.is_none() && !prints);
    if evals || repl || known(&|text| text == "-") {
        Launch::Reads(Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// Read `pieces` of code in `language`, run `depth` levels deep, from the
/// directory the interpreter is told to work in, and add what they do to the
/// split.
pub(crate) fn apply_all(split: &mut Split, language: Language, code: &Code, depth: usize) {
    let outer = split.dir_snapshot();
    match &code.dir {
        Some(dir @ Arg::Known(_)) => run(split, "cd", vec![flag("--"), dir.clone()], depth),
        Some(other) => split.problem(
            Rule::Unknown,
            "runs code from a directory only known when it runs",
            Some(other.text()),
        ),
        None => {}
    }
    if code.input {
        split.problem(
            Rule::Unknown,
            "reads code from its input after its own",
            None,
        );
    }
    for piece in &code.pieces {
        match piece {
            Arg::Known(text) => apply(split, language, text, depth),
            other => split.problem(
                Rule::Unknown,
                "runs code only known when it runs",
                Some(other.text()),
            ),
        }
    }
    split.restore_dir(outer);
}

/// Read code an interpreter takes from its input (a here-document or
/// here-string), run `depth` levels deep, and add what it does to the split.
/// Python reads its input as bytes, and honours a coding declaration in the
/// first two lines that decodes them to other text than the reader sees: such
/// code is not read.
pub(crate) fn apply_input(split: &mut Split, language: Language, code: &str, depth: usize) {
    if language == Language::Python && python::declares_other_encoding(code) {
        split.problem(
            Rule::Unknown,
            "runs code the guard does not read",
            Some(&shorten(code)),
        );
    }
    apply(split, language, code, depth);
}

/// Read `code` in `language`, run `depth` levels deep, and add what it does
/// to the split.
pub(crate) fn apply(split: &mut Split, language: Language, code: &str, depth: usize) {
    if !unit::within_limits(split, code, depth) {
        return;
    }
    let reading = read(language, code);
    if reading.deep {
        split.problem(Rule::Unreadable, "nests too deeply to read", None);
    }
    // A `chdir` in the code moves its own process, not the line.
    let outer = split.dir_snapshot();
    let places = places(&reading.acts, depth);
    if places.len() == 1 {
        for act in reading.acts {
            perform(split, act, depth);
        }
    } else {
        // The code can be in any of these places when it runs an act: a
        // function is defined before the `chdir` and called after it, a loop's
        // second pass follows the first pass's `chdir`, an action registered
        // for later runs when the code ends. So each act is judged from
        // each place, and from nowhere known where that cannot be told.
        for act in reading.acts {
            if matches!(act, Act::Chdir(_)) {
                // Only where it goes is read here; the places hold the rest.
                perform(split, act, depth);
                split.restore_dir(outer.clone());
                continue;
            }
            for place in &places {
                for dir in place {
                    run(split, "cd", vec![flag("--"), dir.clone()], depth);
                }
                perform(split, act.clone(), depth);
                split.restore_dir(outer.clone());
            }
        }
    }
    split.restore_dir(outer);
}

/// Read `code` in `language`.
fn read(language: Language, code: &str) -> Reading {
    match language {
        Language::Python => python::read(code),
        Language::JavaScript => javascript::read(code),
    }
}

/// Whether nested code (`exec("…")`, `eval("…")`), run `depth` levels deep,
/// may change the directory: it is read, with its own language and at any
/// depth, and holds a `chdir`. Code the reader cannot follow, or that is too
/// long or too deep to read, may.
fn changes_directory(language: Language, code: &str, depth: usize) -> bool {
    if depth > unit::MAX_DEPTH || code.len() > unit::MAX_LEN {
        return true;
    }
    let reading = read(language, code);
    reading.deep
        || reading.acts.iter().any(|act| match act {
            Act::Chdir(_) | Act::Unread(_) => true,
            Act::Code(language, text) => changes_directory(*language, text, depth + 1),
            _ => false,
        })
}

/// The most places code is judged from: past it, from none known.
const MAX_PLACES: usize = 12;

/// Where the code may be when it runs an act: each is the `cd`s that lead
/// there from where the code starts. Just the start (one place, no `cd`s)
/// when the code never changes directory. Else the start, each `chdir`'s
/// target and the places the `chdir`s lead to one after another as they are
/// written: a target that is an absolute folder is where the code is, and one
/// below where it was (`sub`) is another folder below the start, so those
/// places hold wherever the code can be. When the targets mix the two, one
/// goes up (`..`) or is only known when it runs, or a nested piece of code
/// holds a `chdir` (read, not searched for, at any depth) or cannot be read,
/// the code may be anywhere, and a relative path is only known when it runs.
fn places(acts: &[Act], depth: usize) -> Vec<Vec<Arg>> {
    let mut targets = Vec::new();
    let mut hidden = false;
    for act in acts {
        match act {
            Act::Chdir(target) => targets.push(target.clone()),
            Act::Code(language, text) => {
                hidden |= changes_directory(*language, text, depth + 1);
            }
            _ => {}
        }
    }
    if targets.is_empty() && !hidden {
        return vec![Vec::new()];
    }
    let (mut absolute, mut below, mut unknown) = (false, false, hidden);
    for target in &targets {
        match target.known() {
            Some(dir) if dir.starts_with(['/', '~']) => absolute = true,
            Some(dir) if !dir.split('/').any(|part| part == "..") => below = true,
            _ => unknown = true,
        }
    }
    let mut places = vec![Vec::new()];
    for (at, target) in targets.iter().enumerate() {
        places.push(vec![target.clone()]);
        if at > 0 {
            places.push(targets[..=at].to_vec());
        }
    }
    if unknown || (absolute && below) || places.len() > MAX_PLACES {
        places = vec![Vec::new(), vec![Arg::Unknown("a directory".to_string())]];
    }
    places
}

/// Add what one act does to the split, as the shell command that does the
/// same.
fn perform(split: &mut Split, act: Act, depth: usize) {
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
        Act::In(dir, acts) => {
            let outer = split.dir_snapshot();
            run(split, "cd", vec![flag("--"), dir], depth);
            for act in acts {
                perform(split, act, depth);
            }
            split.restore_dir(outer);
        }
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
