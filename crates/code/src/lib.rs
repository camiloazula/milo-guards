//! Reads code of another language and says what it is certain to do:
//! [`read`] and [`understand`].
//!
//! A shell line can hand an interpreter code (`python3 -c`, `node -e`), and
//! an agent can write a script or run a snippet directly. The code does what
//! the shell commands that do the same would do, so what matters to a guard
//! is which files it deletes, writes, reads and moves, and what it runs. This
//! crate reads Python and JavaScript (Node, Bun and Deno) with their own
//! tree-sitter grammars and answers two questions of a piece of code:
//!
//! - **What is it certain to do?** [`read`] gives the [`Act`]s the code
//!   makes, in the order it makes them: a delete, a write, a read, a move, a
//!   program started, an environment changed, each with the paths it names.
//!   What the reader cannot follow comes out as an [`Act::Unread`] and the
//!   other acts of code it does not run as written (a call it has no row
//!   for, code loaded from the network), never left out.
//! - **Does it understand the code?** [`understand`] holds the code to a
//!   strict allow-list: a few plain statements whose every call, name and
//!   import is on a short list that only computes. Code outside it is
//!   [`Understanding::NotUnderstood`], and a caller must not take "no acts"
//!   for "does nothing" for such code. The acts are kept whatever the code
//!   looks like; that it is understood is what makes finding none safe.
//!
//! The reader judges nothing. Whether a delete of a path is risky is the
//! caller's, which turns an act into what it already judges: a delete is
//! `rm -rf PATH`, a write a write to that path, a command line a script a
//! shell reads. It does no I/O and reads no environment: a path is the text
//! the code gives, never what is on disk, and the same code gives the same
//! answer on every machine. Code it cannot read is not understood, never
//! understood by default, and nothing it is given makes it panic or run past
//! its limits (see [`MAX_DEPTH`], [`MAX_TREE_DEPTH`] and [`MAX_LEN`]).
//!
//! ```
//! use milo_guards_code::{read, understand, Act, Arg, Language, Understanding};
//!
//! // A snippet that computes is understood, and does nothing to a file.
//! let code = "print(1 + 1)";
//! assert!(read(Language::Python, code).acts.is_empty());
//! assert_eq!(
//!     understand(Language::Python, code),
//!     Understanding::Understood { imports: true },
//! );
//!
//! // A delete is an act with the path it names, kept whatever the code is.
//! let code = "import shutil\nshutil.rmtree('/home/me')";
//! let reading = read(Language::Python, code);
//! assert!(matches!(&reading.acts[..], [Act::Remove(Arg::Known(path))] if path == "/home/me"));
//! assert_eq!(understand(Language::Python, code), Understanding::NotUnderstood);
//!
//! // A name only known when the code runs is an argument it does not know.
//! let reading = read(Language::JavaScript, "require('fs').rmSync(process.argv[1])");
//! assert!(matches!(&reading.acts[..], [Act::Remove(Arg::Unknown(_))]));
//! ```

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

mod javascript;
mod python;
mod strict;
mod unit;

pub use unit::{Arg, MAX_DEPTH, MAX_LEN, MAX_TREE_DEPTH};

/// The languages whose code is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// Python, as the reference interpreter reads it.
    Python,
    /// JavaScript, as Node, Bun and Deno read it.
    JavaScript,
}

/// What reading code found, in the order the code gives it.
#[derive(Debug, Clone)]
pub enum Act {
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
    /// write it or delete it, so the caller cannot take the code for
    /// understood, unless the path is a key, which is judged as `cat PATH` is.
    Opaque(Arg),
    /// `mv FROM TO`.
    Move {
        /// What moves.
        from: Arg,
        /// Where it goes.
        to: Arg,
    },
    /// `ln TARGET LINK`.
    Link {
        /// What the link points to.
        target: Arg,
        /// The link itself.
        link: Arg,
    },
    /// `chmod MODE PATH`; `mode` is in octal where the code gives a number.
    Chmod {
        /// The path whose permissions change.
        path: Arg,
        /// The mode it is given.
        mode: Arg,
    },
    /// `chown OWNER PATH`.
    Chown(Arg),
    /// The process moves to another directory: the paths after it are read
    /// from there.
    Chdir(Arg),
    /// What a call that starts a program does, run from the directory its
    /// `cwd` option names: judged as if the code had moved there first, and
    /// back where it was after.
    In(Arg, Vec<Act>),
    /// A command line a shell runs: `os.system`, `child_process.exec`.
    Script(Arg),
    /// A program and its arguments, run without a shell: the program first.
    Program(Vec<Arg>),
    /// Code the code runs from a literal (`exec("…")`), to be read in its own
    /// language.
    Code(Language, String),
    /// Something the reader cannot follow, as a short piece of the code.
    Unread(String),
    /// Code loaded from the network (`import … from 'https://…'`): it is
    /// downloaded and run, and not read.
    Downloaded(String),
    /// Code loaded from a file outside the workspace (`require('/tmp/x.js')`,
    /// `fork('../x.js')`), which is not the workspace's own and is not read.
    Loads(String),
    /// A write to the environment of the process itself (`os.environ[...] =`,
    /// `os.putenv`, `process.env.X =`): a program the code starts after it
    /// is given the variable.
    Environment,
    /// What a call that starts a program does, given an environment the code
    /// sets: it may hold a variable that loads code (`PYTHONPATH`,
    /// `NODE_OPTIONS`), so the caller cannot take the program for the one it
    /// reads.
    Started(Vec<Act>),
}

/// Variables, by name, that make a program load code that is not its own or
/// run other than it says.
const LOADING: [&str; 17] = [
    "PYTHONPATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PATH",
    "PYTHONSTARTUP",
    "SHELLOPTS",
    "PROMPT_COMMAND",
    "PS4",
    "IFS",
    "CDPATH",
    "HOME",
];

/// Whether the variable `name` is one a caller judges: one of [`LOADING`],
/// or one of a family that loads code (`LD_*`, `DYLD_*`, `PYTHON*`, `NODE_*`,
/// `BASH_FUNC_*`, `GIT_*`).
pub(crate) fn judged_variable(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    LOADING.contains(&name.as_str())
        || ["LD_", "DYLD_", "PYTHON", "NODE_", "BASH_FUNC_", "GIT_"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Mark the programs `acts` start as given an environment, when the code
/// writes to its own environment anywhere (a function may be called after
/// the write, a loop's second pass follows the first).
pub(crate) fn mark_environment(acts: Vec<Act>) -> Vec<Act> {
    fn writes(act: &Act) -> bool {
        match act {
            Act::Environment => true,
            Act::In(_, acts) | Act::Started(acts) => acts.iter().any(writes),
            _ => false,
        }
    }
    fn mark(act: Act) -> Act {
        match act {
            Act::Program(_) | Act::Script(_) => Act::Started(vec![act]),
            Act::In(dir, acts) => Act::In(dir, acts.into_iter().map(mark).collect()),
            other => other,
        }
    }
    if acts.iter().any(writes) {
        acts.into_iter().map(mark).collect()
    } else {
        acts
    }
}

/// Everything one piece of code does.
#[derive(Debug, Default)]
pub struct Reading {
    /// What the code does, in the order it does it.
    pub acts: Vec<Act>,
    /// Whether the code nests too deeply to read in full.
    pub deep: bool,
}

impl Reading {
    fn unread(&mut self, code: &str) {
        self.acts.push(Act::Unread(shorten(code)));
    }
}

/// Read `code` in `language`: what it does to files and what it runs.
///
/// What the reader finds is kept wherever the code comes from and however it
/// is written; that it found nothing says nothing of whether the code does
/// nothing (see [`understand`]).
pub fn read(language: Language, code: &str) -> Reading {
    let mut reading = match language {
        Language::Python => python::read(code),
        Language::JavaScript => javascript::read(code),
    };
    reading.acts = mark_environment(std::mem::take(&mut reading.acts));
    reading
}

/// Whether the code is read whole (see [`understand`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Understanding {
    /// Something in the code is outside the allow-list: it does not parse,
    /// holds no statement, or has a function, a loop, a call or an import the
    /// reader has no row for.
    NotUnderstood,
    /// The code is a few plain statements that compute, and its only acts are
    /// the ones [`read`] gives.
    Understood {
        /// Whether the code may load a module, which looks in the folder the
        /// code runs in first: all Python code does, with or without an
        /// `import` (an uncaught exception imports `traceback`), so it is
        /// understood only when that folder is the caller's own. JavaScript
        /// that is understood has no import at all.
        imports: bool,
    },
}

/// Whether `code` is read whole: nothing in it is outside the allow-list.
///
/// The code is held to a strict subset, for Python and JavaScript alike:
///
/// - it parses, and holds at least one statement;
/// - its statements are expression statements, assignments to a plain name
///   and `if`/`else`, so the code runs straight through;
/// - its calls are on a short list that only computes (`print`, `len`, `str`,
///   `json.dumps`, `console.log`, `Math.max`, the methods of a string or a
///   list), or `open` in Python, which the reader judges by its path and
///   mode;
/// - its imports are the modules built into the interpreter binary (`sys`,
///   `builtins`, `errno`, `itertools`, `time`) in Python, which no file in
///   the folder the code runs in can stand in for, and it has no import,
///   `require` or `eval` in JavaScript;
/// - it names nothing that is not a name it set, a call on the list or a
///   module on the list that it imported, and sets none of those;
/// - it reaches into nothing: no attribute that starts with an underscore,
///   and in JavaScript no member other than `length` and the methods on the
///   list.
///
/// The list is an allow-list of what the grammar may hold, never a list of
/// what is known to be dangerous: code with anything else in it is
/// [`Understanding::NotUnderstood`] because the reader has no row for what it
/// does, whatever [`read`] found in it.
pub fn understand(language: Language, code: &str) -> Understanding {
    match strict::reads_whole(language, code) {
        None => Understanding::NotUnderstood,
        Some(imports) => Understanding::Understood { imports },
    }
}

/// Whether Python, when it reads `code` as bytes (from its input, or the
/// bytes literal given to `exec`, `eval` or `compile`), honours a coding
/// declaration that decodes it to other text than the reader sees: it
/// always reads the text as UTF-8. UTF-8 itself, and the ASCII-compatible
/// encodings for a text that is all ASCII, read the same. Such code is not
/// read: a caller that hands Python code its input does not take it for
/// understood.
pub fn declares_other_encoding(code: &str) -> bool {
    python::declares_other_encoding(code)
}

/// A node above the one a [`walk`] is at, and the field it fills in its own
/// parent.
#[derive(Clone, Copy)]
pub(crate) struct Ancestor<'t> {
    pub(crate) node: Node<'t>,
    pub(crate) field: Option<&'static str>,
}

/// Visit every node under `root`, in the order the code reads, without
/// recursion so a deep tree cannot overflow the stack. `visit` is given the
/// node, the field it fills in its parent, and the nodes above it (the root
/// first), so no reader asks the tree for a node's parent, which walks it from
/// the top; it returns whether to go on.
pub(crate) fn walk<'t>(
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

/// A path as a caller's rules take it: its text when the code gives it,
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
pub(crate) struct Parts {
    pub(crate) text: String,
    pub(crate) whole: bool,
}

impl Parts {
    pub(crate) fn whole(text: String) -> Self {
        Self { text, whole: true }
    }

    pub(crate) fn partial(text: String) -> Self {
        Self { text, whole: false }
    }

    /// Nothing is known of it.
    pub(crate) fn unknown() -> Self {
        Self::default()
    }

    /// The text when it is the whole string.
    pub(crate) fn value(self) -> Option<String> {
        self.whole.then_some(self.text)
    }
}

/// The place a string names when the code hands it to a call, for a string
/// that is one: an absolute path, one in the home directory, one that goes up
/// from where the code runs, or a `file:` URL (whose path is the place, and
/// is only known when it runs if it holds an escape). A bare name is the
/// workspace's own, and the rest of the strings are words.
pub(crate) fn named_path(text: &str) -> Option<Arg> {
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
/// (`'/home/me/.ssh/id_' + n` is a file in `/home/me/.ssh/`). `None` when no
/// folder is known.
fn under(known: &str, code: &str) -> Option<Arg> {
    let end = known.rfind('/')? + 1;
    Some(Arg::Below {
        folder: known[..end].to_string(),
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

/// The argument lists a call that starts a program may run with, when a word
/// of the list may be any of several strings (a name a loop sets to each of
/// them): one list for each choice of one string for each word, so each is
/// judged. Past [`MAX_CHOICES`] lists the words that are left are each one
/// word only known when it runs. A word with no choice is one only known
/// when it runs too.
pub(crate) fn argument_lists(words: Vec<Vec<Arg>>) -> Vec<Vec<Arg>> {
    let mut lists: Vec<Vec<Arg>> = vec![Vec::new()];
    for choices in words {
        let choices =
            if choices.is_empty() || lists.len().saturating_mul(choices.len()) > MAX_CHOICES {
                let shown = choices.first().map_or("an argument", Arg::text);
                vec![Arg::Unknown(shorten(shown))]
            } else {
                choices
            };
        lists = lists
            .iter()
            .flat_map(|list| {
                choices.iter().map(move |choice| {
                    let mut next = list.clone();
                    next.push(choice.clone());
                    next
                })
            })
            .collect();
    }
    lists
}

/// The longest string worked out from names the code sets: a longer one is
/// no string the reader knows. A name set to a string built from itself, or
/// from another that was (`a = a + a`, repeated), doubles it with each line,
/// so without a limit a few hundred bytes of code take seconds and gigabytes.
/// Only where a name is put back as its strings, which is where that
/// growth comes from; a path is not longer than this.
pub(crate) const MAX_STRING: usize = 4 * 1024;

/// The most bytes of strings noted for all names together: past it the name
/// that went over is dropped, not read as any string. A few times the
/// longest line, so the strings a line writes out are all noted.
const MAX_NOTED: usize = 4 * MAX_LEN;

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
pub(crate) enum Holds {
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
pub(crate) enum Expansion {
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
pub(crate) struct Constants {
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
    pub(crate) lost: bool,
    /// The names bound in a way the reader does not work out whole (set to a
    /// value it cannot give, unpacked, looped over, a parameter, `del`eted,
    /// bound by nested code): whatever strings it noted for one, the name may
    /// stand for another, so a read of it is a path that is not fully known.
    unresolved: HashSet<String>,
    /// The names a value was worked out from in this round: one marked
    /// unresolved after that makes the round stale.
    consulted: HashSet<String>,
    /// Whether a name was marked unresolved after a value was worked out from
    /// it in this round, which makes that value stale.
    changed: bool,
    /// Set when the rounds did not settle, or nested code binds names the
    /// reader cannot list: every name is then unresolved.
    everything: bool,
}

/// The most rounds of noting strings: one more is only needed when a name is
/// found to be unresolved after a value was worked out from it, and each round
/// marks one more name, so past this every name is taken as unresolved.
pub(crate) const MAX_ROUNDS: usize = 6;

/// The most times one value is worked out again for a choice of strings, and
/// the most times in all for a piece of code.
const MAX_CHOICES: usize = 256;
const MAX_EVALUATIONS: usize = 64 * 1024;

impl Constants {
    /// Note `value` as a string `name` is set to.
    pub(crate) fn note(&mut self, name: &str, value: String) {
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
    pub(crate) fn note_folder(&mut self, name: &str, folder: String) {
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
    pub(crate) fn over(&mut self, on: bool, text: &str) -> bool {
        let over = on && text.len() > MAX_STRING;
        self.lost |= over;
        over
    }

    /// `name` is set to something the reader cannot hold: it stands for no
    /// string, whatever else it is set to.
    pub(crate) fn drop_name(&mut self, name: &str) {
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
    pub(crate) fn holds(&mut self, name: &str) -> Holds {
        // A name that may be another string than the ones noted is no value
        // any path worked out from it is read as.
        if self.everything || self.unresolved.contains(name) {
            self.lost = true;
        } else {
            self.consulted.insert(name.to_string());
        }
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

    /// `name` is bound in a way the reader does not work out whole. When a
    /// value was already worked out from it in this round, that value is stale
    /// and the round is made again.
    pub(crate) fn mark(&mut self, name: &str) {
        if self.unresolved.insert(name.to_string()) && self.consulted.contains(name) {
            self.changed = true;
        }
    }

    /// Every name is unresolved: nested code binds names that cannot be
    /// listed, or the rounds did not settle.
    pub(crate) fn everything(&mut self) {
        self.everything = true;
    }

    /// Whether the round just made worked a value out from a name that was
    /// marked unresolved after it.
    pub(crate) fn stale(&self) -> bool {
        self.changed
    }

    /// Note the strings again from nothing, keeping what is unresolved.
    pub(crate) fn start_round(&mut self) {
        self.names.clear();
        self.bytes = 0;
        self.evaluations = 0;
        self.consulted.clear();
        self.changed = false;
        self.lost = false;
        self.begin();
    }

    /// Start working a value out: no name that holds more than one string is
    /// read as any of them yet.
    pub(crate) fn begin(&mut self) {
        self.multi.clear();
        self.picks.clear();
    }

    /// Whether the evaluation just made met a name that holds more than one
    /// string and was not read as one of them: its result is not a value.
    pub(crate) fn pending(&self) -> bool {
        self.multi.iter().any(|name| !self.picks.contains_key(name))
    }

    /// Move to the next choice of one string for each name that holds more
    /// than one, the last name first. `false` when every choice has been
    /// made, or when there are more than [`MAX_CHOICES`] of them (or the
    /// piece of code has asked for [`MAX_EVALUATIONS`]), which sets
    /// [`Self::lost`].
    pub(crate) fn advance(&mut self) -> bool {
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
    pub(crate) fn spend(&mut self, count: usize) -> bool {
        if self.expanded + count > MAX_EXPANDED {
            return false;
        }
        self.expanded += count;
        true
    }

    /// Every path a read of `name` may be, when the code sets it to
    /// strings.
    pub(crate) fn paths(&mut self, name: &str, code: &str) -> Expansion {
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
        // Bound another way as well: the name may be a path not known at all,
        // besides the ones noted.
        let unresolved = self.everything || self.unresolved.contains(name);
        let count = count + usize::from(unresolved);
        if self.expanded + count > MAX_EXPANDED {
            return Expansion::Lost;
        }
        self.expanded += count;
        let Some(noted) = self.names.get(name) else {
            return Expansion::Nothing;
        };
        let strings = noted.strings.iter().map(|text| Arg::Known(text.clone()));
        let folders = noted
            .folders
            .iter()
            .filter_map(|folder| under(folder, code));
        let mut paths: Vec<Arg> = strings.chain(folders).collect();
        if unresolved {
            paths.push(Arg::Unknown(shorten(code)));
        }
        Expansion::Paths(paths)
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
/// process (`-1`) or the first (`1`), so it comes back as code the reader
/// does not follow.
fn kill(literal: &str) -> Act {
    match pid(literal) {
        Some(pid) => Act::Program(vec![
            Arg::Known("kill".to_string()),
            Arg::Known("--".to_string()),
            Arg::Known(pid),
        ]),
        None => Act::Unread(shorten(literal)),
    }
}

/// The value of a quoted-style mode argument (`open`'s `'w'`, `fs.openSync`'s
/// flags): whether it writes. `None` mode is the default, which reads.
fn writes(mode: Option<&str>) -> bool {
    mode.is_some_and(|mode| mode.contains(['w', 'a', 'x', '+']))
}

/// Whether a module specifier is a `data:` URL, whose code runs where it is
/// written: as the URL parser reads it, leading control characters and
/// spaces and any tab or newline are dropped, and the scheme has no case.
fn data_url(specifier: &str) -> bool {
    let cleaned: String = specifier
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .take(5)
        .collect();
    cleaned.eq_ignore_ascii_case("data:")
}

/// Where a module a specifier names is loaded from, when it is not the
/// workspace's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Foreign {
    /// From the network (`https:`, `http:`) or a registry that downloads it
    /// (`jsr:`, `npm:`).
    Downloaded,
    /// From a file outside the workspace: an absolute path, a `file:` URL, or
    /// one that goes up from where the code runs (`../x.js`).
    Outside,
}

/// Where the module `specifier` is loaded from, when it is not a file of the
/// workspace's own (a relative `./x.js`) or a package it installed (`fs`,
/// `node:fs`, `lodash`). As the URL parser reads it, leading control
/// characters and spaces and any tab or newline are dropped and the scheme has
/// no case.
fn foreign_module(specifier: &str) -> Option<Foreign> {
    let cleaned: String = specifier
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let lower = cleaned.to_ascii_lowercase();
    if ["http:", "https:", "jsr:", "npm:"]
        .iter()
        .any(|scheme| lower.starts_with(scheme))
    {
        return Some(Foreign::Downloaded);
    }
    let drive = {
        let mut chars = cleaned.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':')
    };
    (lower.starts_with("file:")
        || cleaned.starts_with(['/', '\\', '~'])
        || cleaned == ".."
        || cleaned.starts_with("../")
        || cleaned.starts_with("..\\")
        || drive)
        .then_some(Foreign::Outside)
}

/// Whether the module `specifier` is a `data:` URL, whose code runs where it
/// is written, so no one reads it elsewhere. As the URL parser reads it,
/// leading control characters and spaces and any tab or newline are dropped,
/// and the scheme has no case.
pub fn is_data_url(specifier: &str) -> bool {
    data_url(specifier)
}

/// Whether the module `specifier` is loaded from outside the workspace: from
/// the network (`https:`, `http:`) or a registry that downloads it (`jsr:`,
/// `npm:`), or from a file that is not the workspace's own (an absolute path,
/// one in the home directory, a `file:` URL, one that goes up from where the
/// code runs). A relative `./x.js` and an installed package (`fs`,
/// `node:fs`, `lodash`) are not. The reader finds code that loads one as an
/// [`Act::Downloaded`] or an [`Act::Loads`]; this is the same answer for a
/// specifier a caller meets outside the code, such as a `--import` option.
pub fn is_foreign_module(specifier: &str) -> bool {
    foreign_module(specifier).is_some()
}

/// What loading the module `specifier` does when it is not the workspace's
/// own: downloaded and run, or a file outside it.
pub(crate) fn loads(specifier: &str, code: &str) -> Option<Act> {
    Some(match foreign_module(specifier)? {
        Foreign::Downloaded => Act::Downloaded(shorten(code)),
        Foreign::Outside => Act::Loads(shorten(code)),
    })
}
