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

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::launch;
use crate::unit::{self, Arg, Split, Unit};
use crate::{Finding, Rule, Shell};

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
    /// Reads a file (`open(path)`, `readFileSync(path)`, the source of a
    /// copy): judged as `cat PATH` is, so a key it names is a read of one.
    Read(Arg),
    /// Reads a folder and everything under it (`TarFile.add`, the folder
    /// `shutil.make_archive` packs): judged as `grep -r` is, so a folder that
    /// holds a key, or the home directory, is a read of one.
    ReadTree(Arg),
    /// A path handed to a call the reader does not know: it may read it,
    /// write it or delete it, so the line is `unknown`, unless the path is a
    /// key, which is judged as `cat PATH` is (`read_secret`).
    Opaque(Arg),
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

/// A string the code gives, as far as the reader knows it: the text up to
/// the first part only known when it runs, and whether that was all of it.
/// A concatenation, a join and a template keep the start they know
/// (`'/home/me/.ssh/' + name`), as a shell word with `$name` in it does.
#[derive(Debug, Default)]
pub(super) struct Parts {
    pub(super) text: String,
    pub(super) whole: bool,
}

impl Parts {
    pub(super) fn whole(text: String) -> Self {
        Self { text, whole: true }
    }

    pub(super) fn partial(text: String) -> Self {
        Self { text, whole: false }
    }

    /// Nothing is known of it.
    pub(super) fn unknown() -> Self {
        Self::default()
    }

    /// The text when it is the whole string.
    pub(super) fn value(self) -> Option<String> {
        self.whole.then_some(self.text)
    }
}

/// The place a string names when the code hands it to a call, for a string
/// that is one: an absolute path, one in the home directory, one that goes up
/// from where the code runs, or a `file:` URL (whose path is the place, and
/// is only known when it runs if it holds an escape). A bare name is the
/// workspace's own, and the rest of the strings are words.
pub(super) fn named_path(text: &str) -> Option<Arg> {
    if text.contains('\n') {
        return None;
    }
    if text.is_char_boundary(5) && text[..5].eq_ignore_ascii_case("file:") {
        let rest = &text[5..];
        let rest = match rest.strip_prefix("//") {
            Some(after) => after.find('/').map_or("", |at| &after[at..]),
            None => rest,
        };
        return Some(if rest.is_empty() || rest.contains('%') {
            Arg::Unknown(shorten(text))
        } else {
            Arg::Known(rest.to_string())
        });
    }
    (text.starts_with(['/', '~']) || text == ".." || text.starts_with("../"))
        .then(|| Arg::Known(text.to_string()))
}

/// A read of a path that starts as `known` says and ends in something only
/// known when it runs: the folder it is under, with the rest left open
/// (`'/home/me/.ssh/id_' + n` is a file in `/home/me/.ssh/`), as `cat
/// ~/.ssh/$n` is read. `None` when no folder is known.
fn under(known: &str, code: &str) -> Option<Arg> {
    let end = known.rfind('/')? + 1;
    Some(Arg::Template {
        text: format!("{}{}", &known[..end], crate::posix::OPAQUE),
        source: shorten(code),
    })
}

/// A path read from the start of `parts`: its text when whole, the folder it
/// is under when only the start is known, else a path only known when the
/// code runs.
fn read_path(parts: Parts, code: &str) -> Arg {
    if parts.whole {
        Arg::Known(parts.text)
    } else {
        under(&parts.text, code).unwrap_or_else(|| Arg::Unknown(shorten(code)))
    }
}

/// The longest string worked out from names the code sets: a longer one is
/// no string the reader knows. A name set to a string built from itself, or
/// from another that was (`a = a + a`, repeated), doubles it with each line,
/// so without a limit a few hundred bytes of code take seconds and gigabytes.
/// Only where a name is put back as its strings, which is where that
/// growth comes from; a path is not longer than this.
pub(super) const MAX_STRING: usize = 4 * 1024;

/// The most bytes of strings noted for all names together: past it the name
/// that went over is dropped, not read as any string. A few times the
/// longest line, so the strings a line writes out are all noted.
const MAX_NOTED: usize = 4 * unit::MAX_LEN;

/// The most paths one piece of code reads out of names: past it the read is
/// of code the reader does not follow. A name read with every string it holds
/// is that many reads, and so is every use of it.
const MAX_EXPANDED: usize = 1024;

/// The strings the code sets one name to.
#[derive(Debug, Default)]
struct Noted {
    strings: Vec<String>,
    seen: HashSet<String>,
    /// Folders the name stands for a path somewhere below
    /// (`for p in Path(d).glob('*')`).
    folders: Vec<String>,
    /// Whether the name was set to more than the reader keeps: it stands for
    /// a string it does not know.
    dropped: bool,
}

/// What a name is read as.
#[derive(Debug)]
pub(super) enum Holds {
    /// The code sets it to no string the reader knows.
    Nothing,
    /// Exactly one string.
    One(String),
    /// A path under a folder.
    Below(String),
    /// Strings that were dropped, or too many to give one: no string.
    Lost,
}

/// The paths a read of a name may be.
#[derive(Debug)]
pub(super) enum Expansion {
    /// The name is none the reader noted a string for.
    Nothing,
    /// Every path it may be.
    Paths(Vec<Arg>),
    /// Some it does not know.
    Lost,
}

/// The strings each name is set to in the code, as the reader knows them,
/// for the reads of files. Every string is kept, up to a number of bytes in
/// all; a name that went over it, or was set to a string longer than
/// [`MAX_STRING`], is dropped, and a read of it is code the reader does not
/// follow.
#[derive(Debug, Default)]
pub(super) struct Constants {
    names: HashMap<String, Noted>,
    bytes: usize,
    expanded: usize,
    /// Evaluations made, one for each choice of a string for each name that
    /// holds more than one, in all.
    evaluations: usize,
    /// The names that hold more than one string which the value being worked
    /// out used, in the order it met them, and the string each is read as in
    /// this evaluation.
    multi: Vec<String>,
    picks: HashMap<String, usize>,
    /// Set when what was just worked out used a string that was dropped, or
    /// was cut at [`MAX_STRING`]: a read of it is then not read in full.
    pub(super) lost: bool,
}

/// The most times one value is worked out again for a choice of strings, and
/// the most times in all for a piece of code.
const MAX_CHOICES: usize = 256;
const MAX_EVALUATIONS: usize = 64 * 1024;

impl Constants {
    /// Note `value` as a string `name` is set to.
    pub(super) fn note(&mut self, name: &str, value: String) {
        let noted = self.names.entry(name.to_string()).or_default();
        if noted.dropped || noted.seen.contains(&value) {
            return;
        }
        if value.len() > MAX_STRING || self.bytes + 2 * value.len() > MAX_NOTED {
            self.drop_name(name);
            return;
        }
        self.bytes += 2 * value.len();
        noted.seen.insert(value.clone());
        noted.strings.push(value);
    }

    /// Note that `name` stands for a path somewhere under `folder`.
    pub(super) fn note_folder(&mut self, name: &str, folder: String) {
        let noted = self.names.entry(name.to_string()).or_default();
        if noted.dropped || noted.folders.contains(&folder) {
            return;
        }
        if folder.len() > MAX_STRING || self.bytes + folder.len() > MAX_NOTED {
            self.drop_name(name);
            return;
        }
        self.bytes += folder.len();
        noted.folders.push(folder);
    }

    /// Whether `text`, a string being built where names are put back as their
    /// strings (`on`), is longer than [`MAX_STRING`]: it is then no string the
    /// reader knows. Asked at each step of a loop that builds one, so a
    /// join of thousands of long names is never built.
    pub(super) fn over(&mut self, on: bool, text: &str) -> bool {
        let over = on && text.len() > MAX_STRING;
        self.lost |= over;
        over
    }

    /// `name` is set to something the reader cannot hold: it stands for no
    /// string, whatever else it is set to.
    pub(super) fn drop_name(&mut self, name: &str) {
        let noted = self.names.entry(name.to_string()).or_default();
        let freed: usize = noted
            .strings
            .iter()
            .map(|text| 2 * text.len())
            .sum::<usize>()
            + noted.folders.iter().map(String::len).sum::<usize>();
        self.bytes = self.bytes.saturating_sub(freed);
        *noted = Noted {
            dropped: true,
            ..Noted::default()
        };
    }

    /// What `name` is, where a string is wanted from it (an operand of a
    /// `+`, a join, a template). Sets [`Self::lost`] when it is a name that
    /// holds strings the reader does not give.
    pub(super) fn holds(&mut self, name: &str) -> Holds {
        let Some(noted) = self.names.get(name) else {
            return Holds::Nothing;
        };
        if let Some(string) = self.picks.get(name).and_then(|at| noted.strings.get(*at)) {
            return Holds::One(string.clone());
        }
        match (
            noted.dropped,
            noted.strings.as_slice(),
            noted.folders.as_slice(),
        ) {
            (true, _, _) => {
                self.lost = true;
                Holds::Lost
            }
            (false, [one], []) => Holds::One(one.clone()),
            (false, [], [folder]) => Holds::Below(folder.clone()),
            (false, [], []) => Holds::Nothing,
            // More than one string: the value is worked out again for each,
            // by [`Self::advance`]; for now it is none.
            (false, [_, _, ..], []) => {
                if !self.multi.iter().any(|met| met == name) {
                    self.multi.push(name.to_string());
                }
                Holds::Nothing
            }
            _ => {
                self.lost = true;
                Holds::Lost
            }
        }
    }

    /// Start working a value out: no name that holds more than one string is
    /// read as any of them yet.
    pub(super) fn begin(&mut self) {
        self.multi.clear();
        self.picks.clear();
    }

    /// Whether the evaluation just made met a name that holds more than one
    /// string and was not read as one of them: its result is not a value.
    pub(super) fn pending(&self) -> bool {
        self.multi.iter().any(|name| !self.picks.contains_key(name))
    }

    /// Move to the next choice of one string for each name that holds more
    /// than one, the last name first. `false` when every choice has been
    /// made, or when there are more than [`MAX_CHOICES`] of them (or the
    /// piece of code has asked for [`MAX_EVALUATIONS`]), which sets
    /// [`Self::lost`].
    pub(super) fn advance(&mut self) -> bool {
        if self.multi.is_empty() {
            return false;
        }
        self.evaluations += 1;
        if self.evaluations > MAX_EVALUATIONS {
            self.lost = true;
            return false;
        }
        // A name met for the first time is read as its first string, and
        // the same choice is worked out again.
        let mut met = false;
        for name in &self.multi {
            if !self.picks.contains_key(name) {
                self.picks.insert(name.clone(), 0);
                met = true;
            }
        }
        if met {
            return true;
        }
        let total: usize = self
            .multi
            .iter()
            .map(|name| self.names.get(name).map_or(1, |noted| noted.strings.len()))
            .fold(1, usize::saturating_mul);
        if total > MAX_CHOICES {
            self.lost = true;
            return false;
        }
        for name in self.multi.iter().rev() {
            let count = self.names.get(name).map_or(1, |noted| noted.strings.len());
            let at = self.picks.get(name).copied().unwrap_or(0);
            if at + 1 < count {
                self.picks.insert(name.clone(), at + 1);
                return true;
            }
            self.picks.insert(name.clone(), 0);
        }
        false
    }

    /// Count `count` more paths read out of names: `false` when that is more
    /// than a piece of code may read ([`MAX_EXPANDED`]), which they are not.
    pub(super) fn spend(&mut self, count: usize) -> bool {
        if self.expanded + count > MAX_EXPANDED {
            return false;
        }
        self.expanded += count;
        true
    }

    /// Every path a read of `name` may be, when the code sets it to
    /// strings.
    pub(super) fn paths(&mut self, name: &str, code: &str) -> Expansion {
        let Some(noted) = self.names.get(name) else {
            return Expansion::Nothing;
        };
        if noted.dropped {
            return Expansion::Lost;
        }
        let count = noted.strings.len() + noted.folders.len();
        if count == 0 {
            return Expansion::Nothing;
        }
        if self.expanded + count > MAX_EXPANDED {
            return Expansion::Lost;
        }
        self.expanded += count;
        let strings = noted.strings.iter().map(|text| Arg::Known(text.clone()));
        let folders = noted
            .folders
            .iter()
            .filter_map(|folder| under(folder, code));
        Expansion::Paths(strings.chain(folders).collect())
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

/// The process id a literal gives, as the decimal text `kill` takes: `9`,
/// `-1`, `(-1)`, `0x1`, `- 1`, `1_0`. `None` for a value only known when it
/// runs, a float, and a number with a leading zero (an octal in one language
/// and no number in the other).
fn pid(literal: &str) -> Option<String> {
    let mut text: String = literal.chars().filter(|c| !c.is_whitespace()).collect();
    while text.len() > 1 && text.starts_with('(') && text.ends_with(')') {
        text = text[1..text.len() - 1].to_string();
    }
    let mut negative = false;
    while let Some(rest) = text.strip_prefix(['-', '+']) {
        negative ^= text.starts_with('-');
        text = rest.to_string();
    }
    let lower = text.replace('_', "").to_ascii_lowercase();
    let number = if let Some(digits) = lower.strip_prefix("0x") {
        i64::from_str_radix(digits, 16)
    } else if let Some(digits) = lower.strip_prefix("0o") {
        i64::from_str_radix(digits, 8)
    } else if let Some(digits) = lower.strip_prefix("0b") {
        i64::from_str_radix(digits, 2)
    } else if lower.len() > 1 && lower.starts_with('0')
        || !lower.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    } else {
        lower.parse()
    };
    let number = number.ok()?;
    Some(if negative { -number } else { number }.to_string())
}

/// What `os.kill(PID, …)` and `process.kill(PID, …)` do: the `kill` command
/// with that process id. A process id only known when it runs may be every
/// process (`-1`) or the first (`1`), so it comes back as code the guard does
/// not read.
fn kill(literal: &str) -> Act {
    match pid(literal) {
        Some(pid) => Act::Program(vec![flag("kill"), flag("--"), Arg::Known(pid)]),
        None => Act::Unread(shorten(literal)),
    }
}

/// The value of a quoted-style mode argument (`open`'s `'w'`, `fs.openSync`'s
/// flags): whether it writes. `None` mode is the default, which reads.
fn writes(mode: Option<&str>) -> bool {
    mode.is_some_and(|mode| mode.contains(['w', 'a', 'x', '+']))
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
    let flags: &[&str] = if key.starts_with("python") {
        &["--version", "-V", "-VV", "--help", "-h"]
    } else {
        match key {
            "node" | "nodejs" | "bun" => &["--version", "-v", "--help", "-h"],
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
        Act::Read(path) => {
            let whole = matches!(path, Arg::Known(_));
            let doubt = (!whole).then_some(PARTIAL);
            opened(split, "cat", vec![flag("--")], path, doubt, depth);
        }
        Act::ReadTree(path) => {
            let whole = matches!(path, Arg::Known(_));
            let args = vec![flag("-r"), flag("--"), Arg::Known("x".to_string())];
            let doubt = (!whole).then_some(PARTIAL);
            opened(split, "grep", args, path, doubt, depth);
        }
        Act::Opaque(path) => opened(split, "cat", vec![flag("--")], path, Some(HANDED), depth),
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

/// Why a read of a file is `unknown`: the path is only known when the code
/// runs, or in part.
const PARTIAL: &str = "opens a file whose path is only known when the code runs";

/// Why a path handed to a call the reader does not know is `unknown`.
const HANDED: &str = "gives a path to a call the guard does not read";

/// Add the unit `program args… path`, which opens the file the code names.
/// Only a path the code gives whole is a path the guard knows. One only
/// known when the code runs, or known in part, is a read of a file the guard
/// cannot name: the line is `unknown` for the `doubt` it carries, unless the
/// part of the path it does know already lies in a place that holds a key,
/// which the unit finds and says (`read_secret`). Deletes and writes fail
/// closed the same way.
fn opened(
    split: &mut Split,
    program: &str,
    mut args: Vec<Arg>,
    path: Arg,
    doubt: Option<&str>,
    depth: usize,
) {
    let shown = path.text().to_string();
    args.push(path);
    let before = split.units.len();
    run(split, program, args, depth);
    let Some(reason) = doubt else {
        return;
    };
    let finding = Finding {
        rule: Rule::Unknown,
        reason: reason.to_string(),
        target: Some(shown),
    };
    let unit = split.units.get(before..).and_then(|added| {
        added
            .iter()
            .position(|unit| unit.key().as_deref() == Some(program))
    });
    match unit {
        Some(at) => {
            split.loose.insert(before + at, finding);
        }
        // The program was not added as itself: nothing says what the file is.
        None => split.findings.push(finding),
    }
}

/// Add the unit `program args…`, as if the line had run it.
fn run(split: &mut Split, program: &str, args: Vec<Arg>, depth: usize) {
    launch::add(
        split,
        Unit::new(Shell::Posix, flag(program), args, None),
        depth,
    );
}
