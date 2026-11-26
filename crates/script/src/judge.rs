//! What the reader found in the code, judged: each act against core's path
//! model, with the shell guard's rule names and reasons for the same act.
//! The reader says what the code does; nothing here knows a language.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashSet;

use milo_guards_code::{self as reader, Act, Arg, Language, Understanding};
use milo_guards_core::spelling::glob;
use milo_guards_core::{Flavour, Paths, Place, Resolver, Sensitivity, Spelling};

use crate::{Finding, Rule, MAX_LEN};

/// How deep code may run code (`exec("…")` inside `exec("…")`).
pub(crate) const MAX_DEPTH: usize = reader::MAX_DEPTH;

/// The most code read for one piece of code, nested code read again
/// included, in bytes: a few times the longest code, which plain code never
/// nears. Code a name holds may be run many times over, and each run is
/// read, so this bounds the work whatever the code does.
pub(crate) const MAX_NESTED_READ: usize = 4 * MAX_LEN;

/// The most places code is judged from: past it, from none known.
pub(crate) const MAX_PLACES: usize = 12;

/// The most folders a move that may have failed is kept as leaving the code
/// in, as the shell guard keeps them for a `cd`: past it, the code may be
/// anywhere, one folder only known when it runs.
pub(crate) const MAX_ELSEWHERE: usize = 8;

/// The longest path a directory and a name are joined into: what the longest
/// systems' own path limit allows. A longer one is a path only known when it
/// runs, never a known one.
pub(crate) const MAX_JOINED: usize = 4096;

/// The most bytes of paths joined to judge one act, from every place and
/// every folder it is judged from: past it, the act is judged from a
/// directory only known when it runs, so the work for an act is bounded
/// however long the directories are.
pub(crate) const MAX_ACT_BYTES: usize = 4 * MAX_JOINED;

/// The characters cmd reads as its own in a line it runs: an operator, a
/// group, an escape, a variable, a quote.
const CMD_SPECIAL: [char; 10] = ['&', '|', '<', '>', '(', ')', '^', '%', '!', '"'];

/// Why code read in part is `unknown`.
const UNREAD_FULLY: &str = "runs code the guard does not read fully";

/// Why code the reader does not follow is `unknown`.
const UNREAD: &str = "runs code the guard does not read";

/// Why a program started with an environment the code sets is `unknown`.
const ENVIRONED: &str = "starts a program with an environment set in the code";

/// Why a read of a file is `unknown`: the path is only known when the code
/// runs, or in part, or cannot be placed.
const PARTIAL: &str = "opens a file whose path is only known when the code runs";

/// Why a read of a path is `unknown` when it goes through more links than
/// any system follows, a link the caller could not read, or past the work
/// one call may spend: as the shell guard says it.
const LOST: &str = "reads a path only known when it runs";

/// Why a path handed to a call the reader does not know is `unknown`.
const HANDED: &str = "gives a path to a call the guard does not read";

/// Why a path that counts from a directory only known when the code runs is
/// `unknown`.
const UNPLACED_READ: &str = "opens a file from a directory only known when the code runs";

/// Why a program started with a word only known when the code runs, or known
/// in part, is `unknown`.
const UNKNOWN_WORD: &str = "runs a program with an argument only known when the code runs";

/// Why a program or a command run from a directory only known when the code
/// runs is `unknown`.
const UNPLACED_RUN: &str = "runs from a directory only known when the code runs";

/// Why a program the guard cannot write as a line for the machine's shell is
/// `unknown`.
const UNWRITTEN: &str = "starts a program the guard cannot write as a command line";

/// Why a program the code may give input to is `unknown`.
const GIVEN_INPUT: &str = "gives a program input the guard does not show";

/// What the reason of a finding judged from a directory the code was in
/// before a move that may have failed ends with, as the shell guard's does.
const MOVED_OFF: &str = " if a cd before it failed or did not run";

/// What a delete beyond the workspace may do instead.
const DELETE_INSIDE: &str = "delete inside the workspace, or ask the user";

/// What code that runs code it downloads may do instead.
const DOWNLOAD_FIRST: &str = "download the code to a file and read it first";

/// How a word only known when the code runs is written in a POSIX command
/// line of a [`Rule::RunProgram`] finding.
const UNKNOWN_POSIX: &str = "\"$UNKNOWN\"";

/// What the names of the files a move or a link lands are, when one is the
/// contents of a folder (`.`): read with the folder.
const CONTENTS: &str = "\u{0}contents";

/// The words a POSIX shell reads as its own in a command's place, which a
/// program's name must not be written as.
const POSIX_RESERVED: [&str; 22] = [
    "!", "{", "}", "[[", "]]", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for",
    "function", "if", "in", "select", "then", "time", "until", "while",
];

/// What judging a piece of code came to, with the counts the guard's own
/// tests hold the work to.
#[derive(Debug, Default)]
#[cfg_attr(
    not(feature = "testing"),
    allow(dead_code, reason = "only the guard's own tests read the counts")
)]
pub(crate) struct Outcome {
    /// Every finding, in the order the code makes them, each once.
    pub(crate) findings: Vec<Finding>,
    /// How many times an act was judged, from each place and each folder a
    /// move that may have failed left the code in.
    pub(crate) judged: usize,
    /// How many moves the places the code is judged from were built of, in
    /// all: what the list of places costs.
    pub(crate) place_moves: usize,
    /// How many bytes of paths were joined, in all.
    pub(crate) joined_bytes: usize,
    /// What the readings of the code did, within the one budget they share.
    #[cfg(feature = "testing")]
    pub(crate) reader: Option<milo_guards_code::testing::Work>,
}

/// Judge `code`.
#[cfg(feature = "testing")]
pub(crate) fn judge(language: Language, code: &str, paths: &Paths) -> Outcome {
    judge_within(language, code, paths, reader::Budget::new(code.len())).0
}

/// Judge `code` within `budget`, and give the budget back: the code judged
/// again on other paths (the paths as spelled) is read from what the budget
/// kept, and draws from the same work.
pub(crate) fn judge_within(
    language: Language,
    code: &str,
    paths: &Paths,
    budget: reader::Budget,
) -> (Outcome, reader::Budget) {
    if code.len() > MAX_LEN {
        let outcome = Outcome {
            findings: vec![finding(Rule::Unreadable, "is too long to read", None)],
            ..Outcome::default()
        };
        return (outcome, budget);
    }
    let mut judge = Judge::within(paths, budget);
    let parses = judge.budget.parses(language, code);
    // Code the reader stops on, past the work its grammar may do for it, is
    // not code that does not parse: it is not read at all, so nothing is
    // found in it, and it is not read again.
    let stopped = !parses && judge.budget.is_spent();
    if stopped {
        judge.add(Rule::Unreadable, "takes too long to read", shown(code));
    } else if !parses {
        judge.add(Rule::Unreadable, "does not parse", shown(code));
    }
    // Python honours a coding declaration when it reads code from a file or
    // its input, which may decode it to other text than the reader sees.
    if language == Language::Python && reader::declares_other_encoding(code) {
        judge.add(Rule::Unknown, UNREAD, shown(code));
    }
    if !stopped {
        judge.apply(language, code, 0, false, !parses);
        // Code the guard did not read whole is `unknown`, unless a finding
        // of its own already asks (a delete, a key, something it does not
        // read). A program is not such a finding: what the program does is
        // the shell guard's to say, and code that starts one is never read
        // whole.
        let asks = judge.findings.iter().any(|f| f.rule != Rule::RunProgram);
        if !asks && !judge.read_whole(language, code) {
            judge.add(Rule::Unknown, UNREAD_FULLY, shown(code));
        }
        // Code the reader stopped on further in (the code it runs, read
        // again at each depth) is not read in full either.
        if judge.budget.is_spent() && !judge.findings.iter().any(|f| f.rule == Rule::Unreadable) {
            judge.add(Rule::Unreadable, "takes too long to read", shown(code));
        }
    }
    let mut seen = HashSet::new();
    let findings = std::mem::take(&mut judge.findings)
        .into_iter()
        .filter(|found| seen.insert(found.clone()))
        .collect();
    let outcome = Outcome {
        findings,
        judged: judge.judged,
        place_moves: judge.place_moves,
        joined_bytes: judge.joined_bytes.get(),
        #[cfg(feature = "testing")]
        reader: Some(milo_guards_code::testing::spent(&judge.budget)),
    };
    (outcome, judge.budget)
}

/// How a command line starts when the code runs it from where it is.
enum Moved {
    /// From where the code started: as it is.
    Here,
    /// From another directory: with this move in front.
    By(String),
    /// From a directory the machine's shell cannot be told to move to.
    Unwritten,
}

/// A directory the code is in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Dir {
    /// Where it starts: the working directory of the `Paths`.
    Start,
    /// A directory it moved to, as the code spells it: absolute, in the home
    /// directory, or from where it started.
    At(String),
    /// A directory only known when it runs.
    Unknown,
}

/// Where the code is: its directory, and the directories a move that may
/// have failed left it in (a `chdir` raises an error, which the code may
/// catch and go on), as the shell guard keeps them for a `cd`: at most
/// [`MAX_ELSEWHERE`], and past that the code is `adrift`, in a folder only
/// known when it runs.
#[derive(Debug, Clone)]
struct Here {
    dir: Dir,
    stayed: Vec<Dir>,
    adrift: bool,
}

struct Judge {
    /// The work the reader may do for the code: every reading of it, and of
    /// the code inside it, draws from the one budget, so nesting does not
    /// multiply the work.
    budget: reader::Budget,
    resolver: Resolver,
    flavour: Flavour,
    here: Here,
    findings: Vec<Finding>,
    /// The bytes of nested code read so far (see [`MAX_NESTED_READ`]).
    nested: usize,
    /// What the write of the act being judged found where the code is, from
    /// each place it is judged from: a write is a redirect to the shell
    /// guard, and what a redirect finds from one place the code may be in is
    /// what it finds from a folder a move that may have failed left it in.
    written: Vec<Finding>,
    /// The bytes of paths joined for the act being judged (see
    /// [`MAX_ACT_BYTES`]), and in all.
    act_bytes: Cell<usize>,
    joined_bytes: Cell<usize>,
    /// Whether the code hands a shell a list of words, which Windows joins
    /// into the line (see `gives_shell_a_list`), on a Windows machine.
    listed_shell: bool,
    judged: usize,
    place_moves: usize,
}

fn finding(rule: Rule, reason: impl Into<String>, target: Option<String>) -> Finding {
    Finding {
        rule,
        reason: reason.into(),
        target,
        instead: None,
    }
}

/// A piece of code short enough to show in a prompt: its first line, cut.
/// `None` for code with nothing on its first line.
fn shown(code: &str) -> Option<String> {
    let line = code.lines().next().unwrap_or_default().trim();
    let mut short: String = line.chars().take(60).collect();
    if short.len() < line.len() {
        short.push('…');
    }
    (!short.is_empty()).then_some(short)
}

impl Judge {
    #[cfg(test)]
    fn new(paths: &Paths, len: usize) -> Self {
        Self::within(paths, reader::Budget::new(len))
    }

    fn within(paths: &Paths, budget: reader::Budget) -> Self {
        let resolver = Resolver::new(paths);
        let flavour = resolver.flavour();
        Self {
            budget,
            resolver,
            flavour,
            here: Here {
                dir: Dir::Start,
                stayed: Vec::new(),
                adrift: false,
            },
            findings: Vec::new(),
            nested: 0,
            written: Vec::new(),
            act_bytes: Cell::new(0),
            joined_bytes: Cell::new(0),
            listed_shell: false,
            judged: 0,
            place_moves: 0,
        }
    }

    fn add(&mut self, rule: Rule, reason: impl Into<String>, target: Option<String>) {
        self.findings.push(finding(rule, reason, target));
    }

    fn add_about(&mut self, rule: Rule, reason: impl Into<String>, arg: &Arg) {
        self.add(rule, reason, Some(arg.text().to_string()));
    }

    fn windows(&self) -> bool {
        self.flavour == Flavour::Windows
    }

    /// Whether `code` is read whole: understood, and for Python, which looks
    /// in the folder it runs in first for what it imports, run from the
    /// workspace's own folder.
    fn read_whole(&self, language: Language, code: &str) -> bool {
        match self.budget.understand(language, code) {
            Understanding::NotUnderstood => false,
            Understanding::Understood { imports: false } => true,
            Understanding::Understood { imports: true } => matches!(
                self.resolver.place(Spelling::Plain("."), self.flavour),
                Place::Inside | Place::Workspace { exact: true }
            ),
        }
    }

    /// Whether `text`, a path as the code spells it, does not count from
    /// where the code is: absolute, a drive's, a share's, or in a home
    /// directory.
    fn rooted(&self, text: &str) -> bool {
        if text.starts_with('~') || text.starts_with(self.flavour.separators()) {
            return true;
        }
        let mut chars = text.chars();
        self.windows()
            && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.next() == Some(':')
    }

    /// `text` as a path from where the code starts, from the directory `dir`
    /// it is in. `None` when it counts from a directory only known when it
    /// runs, when it is longer than [`MAX_JOINED`], and once the act being
    /// judged has joined [`MAX_ACT_BYTES`]: a path past those is one only
    /// known when it runs.
    fn joined_from(&self, dir: &Dir, text: &str) -> Option<String> {
        let joined = if self.rooted(text) {
            text.to_string()
        } else {
            match dir {
                Dir::Start => text.to_string(),
                Dir::At(dir) => format!("{}/{text}", dir.trim_end_matches(['/', '\\'])),
                Dir::Unknown => return None,
            }
        };
        let spent = self.act_bytes.get() + joined.len();
        if joined.len() > MAX_JOINED || spent > MAX_ACT_BYTES {
            return None;
        }
        self.act_bytes.set(spent);
        self.joined_bytes
            .set(self.joined_bytes.get() + joined.len());
        Some(joined)
    }

    fn joined(&self, text: &str) -> Option<String> {
        self.joined_from(&self.here.dir, text)
    }

    /// The text of a path the code gives whole, from where the code starts.
    fn known(&self, arg: &Arg) -> Option<String> {
        self.joined(arg.known()?)
    }

    /// A path's text as the resolver reads it: on Windows, the NT prefix
    /// `\??\` is the object namespace a file API opens the rest in, as
    /// `\\?\` is (`\??\C:\x` is `C:\x`, `\??\PhysicalDrive0` a disk,
    /// `\??\UNC\…` a share), which the resolver places.
    fn normal<'t>(&self, text: &'t str) -> Cow<'t, str> {
        if self.windows() {
            if let Some(rest) = text
                .strip_prefix("\\??\\")
                .or_else(|| text.strip_prefix("/??/"))
            {
                return Cow::Owned(format!("\\\\?\\{rest}"));
            }
        }
        Cow::Borrowed(text)
    }

    /// A path's spelling as the resolver takes it, for a text already read
    /// as the resolver reads it ([`Self::normal`]): `~` and `~/…` are the
    /// home directory, as a shell reads them and as the reader gives them.
    /// `None` for another user's home directory (`~alice`), which the
    /// spelling does not place.
    fn spelling<'t>(&self, text: &'t str) -> Option<Spelling<'t>> {
        match text.strip_prefix('~') {
            Some(rest) if rest.is_empty() || rest.starts_with(self.flavour.separators()) => {
                Some(Spelling::Home(rest))
            }
            Some(_) => None,
            None => Some(Spelling::Plain(text)),
        }
    }

    fn place_of(&self, text: &str, into: bool) -> Place {
        let text = self.normal(text);
        let Some(spelling) = self.spelling(&text) else {
            return Place::Unknown;
        };
        if into {
            self.resolver.place_into(spelling, self.flavour, false)
        } else {
            self.resolver.place(spelling, self.flavour)
        }
    }

    /// Where `arg` lands to what acts on the name itself (a delete, a
    /// move): a path that ends at a link the caller named is the link, not
    /// what it points to, unless a trailing separator goes through it.
    fn place_name(&self, arg: &Arg) -> Place {
        let Some(text) = self.known(arg) else {
            return Place::Unknown;
        };
        if text.ends_with(['/', '\\']) {
            return self.place_of(&text, false);
        }
        let text = self.normal(&text);
        match self.spelling(&text) {
            Some(spelling) => self.resolver.place_name(spelling, self.flavour, false),
            None => Place::Unknown,
        }
    }

    /// Where `arg` lands: written into (`into`), or touched as an item.
    fn place(&self, arg: &Arg, into: bool) -> Place {
        match self.known(arg) {
            Some(text) => self.place_of(&text, into),
            None => Place::Unknown,
        }
    }

    /// `dir` after a move to `target`: a directory spelled longer than
    /// [`MAX_JOINED`] is one only known when it runs.
    fn moved(&self, dir: &Dir, target: &Arg) -> Dir {
        let moved = match target.known() {
            Some(text) if self.rooted(text) => text.to_string(),
            Some(text) => match dir {
                Dir::Start => text.to_string(),
                Dir::At(dir) => format!("{}/{text}", dir.trim_end_matches(['/', '\\'])),
                Dir::Unknown => return Dir::Unknown,
            },
            None => return Dir::Unknown,
        };
        if moved.len() > MAX_JOINED {
            Dir::Unknown
        } else {
            Dir::At(moved)
        }
    }

    /// The code moves to `target`. The move may fail (a `chdir` raises an
    /// error the code may catch) and leave it where it was, or in any folder
    /// an earlier such move left it in, as the shell guard keeps them for a
    /// `cd`: each once and not the one it moved to, at most
    /// [`MAX_ELSEWHERE`], and past that, and from then on, anywhere. (A move
    /// that only goes up does not fail to the shell guard; in code it never
    /// comes here, since a `..` makes the code anywhere already: see
    /// [`Self::places`].)
    fn cd(&mut self, target: &Arg) {
        let dir = self.moved(&self.here.dir, target);
        let mut folders: Vec<Dir> = self
            .here
            .stayed
            .iter()
            .map(|folder| self.moved(folder, target))
            .collect();
        folders.push(self.here.dir.clone());
        folders.extend(self.here.stayed.iter().cloned());
        let mut stayed: Vec<Dir> = Vec::new();
        for folder in folders {
            if folder != dir && !stayed.contains(&folder) {
                stayed.push(folder);
            }
        }
        let mut adrift = self.here.adrift;
        if adrift || stayed.len() > MAX_ELSEWHERE {
            adrift = true;
            stayed.clear();
        }
        self.here = Here {
            dir,
            stayed,
            adrift,
        };
    }

    /// The folders a move that may have failed left the code in, but the one
    /// it is in, each once; one only known when it runs once there were too
    /// many to keep.
    fn moved_off(&self) -> Vec<Dir> {
        let mut folders: Vec<Dir> = Vec::new();
        for folder in &self.here.stayed {
            if *folder != self.here.dir && !folders.contains(folder) {
                folders.push(folder.clone());
            }
        }
        if self.here.adrift && self.here.dir != Dir::Unknown && !folders.contains(&Dir::Unknown) {
            folders.push(Dir::Unknown);
        }
        folders
    }

    /// Read `code` in `language`, run `depth` levels deep, and judge what it
    /// does. `unplaced` is whether the code starts in a directory only known
    /// when it runs; `broken` that it does not parse, which the reader says
    /// first, and which is already a finding.
    fn apply(
        &mut self,
        language: Language,
        code: &str,
        depth: usize,
        unplaced: bool,
        broken: bool,
    ) {
        if depth > MAX_DEPTH {
            self.add(
                Rule::Unreadable,
                "runs code inside code too deeply to read",
                None,
            );
            return;
        }
        if code.len() > MAX_LEN {
            self.add(Rule::Unreadable, "is too long to read", None);
            return;
        }
        if depth > 0 {
            self.nested += code.len() + 1;
            if self.nested > MAX_NESTED_READ {
                self.add(
                    Rule::Unreadable,
                    "runs too much code inside code to read",
                    None,
                );
                return;
            }
        }
        let reading = self.budget.read(language, code);
        if reading.deep {
            self.add(Rule::Unreadable, "nests too deeply to read", None);
        }
        let mut acts = reading.acts;
        if broken && matches!(acts.first(), Some(Act::Unread(_))) {
            acts.remove(0);
        }
        // Whether this code, at any depth, may hand a shell a list of words,
        // which Windows joins into the line: then none of its programs is
        // one the guard can write as a line there.
        let listed = self.listed_shell;
        self.listed_shell |= self.windows() && self.budget.gives_shell_a_list(language, code);
        let before = self.findings.len();
        // A `chdir` in the code moves its own process; what runs the code
        // stays where it was.
        let outer = self.here.clone();
        let written = std::mem::take(&mut self.written);
        let places = self.places(&acts, depth);
        if places.len() == 1 {
            for act in acts {
                self.written.clear();
                self.act_bytes.set(0);
                self.perform(act, depth, unplaced);
            }
        } else {
            // The code can be in any of these places when it makes an act: a
            // function is defined before the `chdir` and called after it, a
            // loop's second pass follows the first pass's `chdir`, an action
            // registered for later runs when the code ends. So each act is
            // judged from each place, and from nowhere known where that
            // cannot be told.
            for act in acts {
                if matches!(act, Act::Chdir(_)) {
                    continue;
                }
                self.written.clear();
                self.act_bytes.set(0);
                for place in &places {
                    for dir in place {
                        self.cd(dir);
                    }
                    let unplaced = after(unplaced, place);
                    self.perform(act.clone(), depth, unplaced);
                    self.here = outer.clone();
                }
            }
        }
        self.here = outer;
        self.written = written;
        self.listed_shell = listed;
        // A program this code starts may be given input the code writes
        // (`input=`, `stdin`), which no target shows.
        let programs = self.findings[before..]
            .iter()
            .any(|found| found.rule == Rule::RunProgram);
        if programs && self.budget.gives_input(language, code) {
            self.add(Rule::Unknown, GIVEN_INPUT, None);
        }
    }

    /// Whether nested code, run `depth` levels deep, may change the
    /// directory: it holds a `chdir`, at any depth. Code the reader cannot
    /// follow, or that is too long, too deep or too much to read, may.
    fn changes_directory(&mut self, language: Language, code: &str, depth: usize) -> bool {
        self.nested += code.len() + 1;
        if depth > MAX_DEPTH || code.len() > MAX_LEN || self.nested > MAX_NESTED_READ {
            return true;
        }
        let reading = self.budget.read(language, code);
        reading.deep
            || reading.acts.iter().any(|act| match act {
                Act::Chdir(_) | Act::Unread(_) => true,
                Act::Code(language, text) => self.changes_directory(*language, text, depth + 1),
                _ => false,
            })
    }

    /// Where the code may be when it makes an act: each is the moves that
    /// lead there from where it starts. Just the start (one place, no moves)
    /// when the code never changes directory. Else the start, each `chdir`'s
    /// target and the places the `chdir`s lead to one after another as they
    /// are written: a target that is an absolute folder is where the code
    /// is, and one below where it was (`sub`) is another folder below the
    /// start, so those places hold wherever the code can be. When the
    /// targets mix the two, one goes up (`..`) or is only known when it runs,
    /// nested code holds a `chdir` or cannot be read, or there are more
    /// places than [`MAX_PLACES`], the code may be anywhere, and a relative
    /// path is only known when it runs. The count is known before any place
    /// is built, so many `chdir`s cost no more than their number.
    fn places(&mut self, acts: &[Act], depth: usize) -> Vec<Vec<Arg>> {
        let mut targets = Vec::new();
        let mut hidden = false;
        for act in acts {
            match act {
                Act::Chdir(target) => targets.push(target),
                Act::Code(language, text) => {
                    hidden |= self.changes_directory(*language, text, depth + 1);
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
        // The start, each target, and each run of targets from the first.
        let count = 1 + 2 * targets.len() - 1;
        if unknown || (absolute && below) || count > MAX_PLACES {
            self.place_moves += 1;
            return vec![Vec::new(), vec![Arg::Unknown("a directory".to_string())]];
        }
        let mut places = vec![Vec::new()];
        for (at, target) in targets.iter().enumerate() {
            places.push(vec![(*target).clone()]);
            self.place_moves += 1;
            if at > 0 {
                places.push(
                    targets[..=at]
                        .iter()
                        .map(|target| (*target).clone())
                        .collect(),
                );
                self.place_moves += at + 1;
            }
        }
        places
    }

    /// Judge one act.
    ///
    /// `unplaced` is whether the code is in a directory only known when it
    /// runs: a path that counts from there, and a program or a command run
    /// from there, is only known when it runs too.
    fn perform(&mut self, act: Act, depth: usize, unplaced: bool) {
        self.judged += 1;
        match act {
            Act::Remove(_)
            | Act::Write(_)
            | Act::Read(_)
            | Act::ReadTree(_)
            | Act::Opaque(_)
            | Act::Move { .. }
            | Act::Link { .. }
            | Act::Chmod { .. }
            | Act::Chown(_) => self.file_act(&act, unplaced),
            Act::Chdir(path) => self.cd(&path),
            Act::In(dir, acts) => {
                let outer = self.here.clone();
                let unplaced = after(unplaced, std::slice::from_ref(&dir));
                self.cd(&dir);
                for act in acts {
                    self.perform(act, depth, unplaced);
                }
                self.here = outer;
            }
            Act::Script(script) => self.script(&script, unplaced),
            Act::Program(words) => self.program(&words, unplaced),
            Act::Code(language, text) => self.apply(language, &text, depth + 1, unplaced, false),
            Act::Unread(code) => self.add(Rule::Unknown, UNREAD, Some(code)),
            Act::Downloaded(code) => {
                self.findings.push(Finding {
                    rule: Rule::RunDownloaded,
                    reason: "runs code it downloads".to_string(),
                    target: Some(code.clone()),
                    instead: Some(DOWNLOAD_FIRST.to_string()),
                });
                self.add(Rule::Unknown, UNREAD, Some(code));
            }
            Act::Loads(code) => self.add(
                Rule::Unknown,
                "loads code from outside the workspace",
                Some(code),
            ),
            Act::Environment => {}
            Act::Started(acts) => {
                self.add(Rule::Unknown, ENVIRONED, None);
                for act in acts {
                    self.perform(act, depth, unplaced);
                }
            }
        }
    }

    /// An act on files, judged where the code is, and from each folder a
    /// move that may have failed left it in: what that finds beyond what is
    /// found where the code is says so (`… if a cd before it failed or did
    /// not run`), as the shell guard says it for a unit after a `cd`.
    fn file_act(&mut self, act: &Act, unplaced: bool) {
        let before = self.findings.len();
        self.on_files(act, unplaced, true);
        let mut mine: Vec<Finding> = self.findings[before..].to_vec();
        if matches!(act, Act::Write(_)) {
            self.written.append(&mut mine);
            mine.clone_from(&self.written);
        }
        let others = self.moved_off();
        if others.is_empty() {
            return;
        }
        let own = self.findings.len();
        let saved = self.here.clone();
        for folder in others {
            self.judged += 1;
            self.here.dir = folder;
            let from = self.findings.len();
            self.on_files(act, unplaced, false);
            for mut found in self.findings.split_off(from) {
                if mine.contains(&found) {
                    continue;
                }
                found.reason.push_str(MOVED_OFF);
                if !self.findings[own..].contains(&found) {
                    self.findings.push(found);
                }
            }
        }
        self.here = saved;
    }

    /// What an act on files finds where the code is. `doubts` says whether a
    /// read of a path the guard cannot name says so (`unknown`), which is
    /// said once, from where the code is.
    fn on_files(&mut self, act: &Act, unplaced: bool, doubts: bool) {
        match act {
            Act::Remove(path) => self.delete(path),
            Act::Write(path) => self.write(path),
            Act::Read(path) => {
                let doubt = read_doubt(path, unplaced).filter(|_| doubts);
                self.read(path, false, doubt, doubts);
            }
            Act::ReadTree(path) => {
                let doubt = read_doubt(path, unplaced).filter(|_| doubts);
                self.read(path, true, doubt, doubts);
            }
            Act::Opaque(path) => self.read(path, false, doubts.then_some(HANDED), doubts),
            Act::Move { from, to } => {
                self.move_away(from);
                self.lands(from, to);
            }
            Act::Link { target, link } => {
                self.links_to(target);
                self.lands(target, link);
            }
            Act::Chmod { path, mode } => self.chmod(path, mode),
            Act::Chown(path) => self.permissions(path, "changes the owner of"),
            _ => {}
        }
    }

    /// A delete of `path`, as `rm -rf PATH` is judged.
    fn delete(&mut self, path: &Arg) {
        match self.place_name(path) {
            place if place.harmless() => {}
            Place::Disk => self.add_about(Rule::WipeDisk, "deletes a disk", path),
            place => {
                let reason = format!("deletes {}", place.words());
                let instead = beyond_workspace(place).then(|| DELETE_INSIDE.to_string());
                self.findings.push(Finding {
                    rule: Rule::Delete,
                    reason,
                    target: Some(path.text().to_string()),
                    instead,
                });
            }
        }
    }

    /// What a move takes away from where it was: anything beyond the
    /// workspace and its temporary files is lost there.
    fn move_away(&mut self, from: &Arg) {
        match self.place_name(from) {
            place if place.harmless() => {}
            place => self.add_about(Rule::Delete, format!("moves {}", place.words()), from),
        }
    }

    /// A write into the file `path`, as a redirect's is judged.
    fn write(&mut self, path: &Arg) {
        match self.place(path, true) {
            place if place.harmless() => {}
            Place::Workspace { exact: true } | Place::Temp { exact: true } => {}
            Place::Disk => self.add_about(Rule::WipeDisk, "writes over a disk", path),
            Place::Outside => {
                self.add_about(
                    Rule::Overwrite,
                    "writes to a file outside the workspace",
                    path,
                );
            }
            Place::Unknown => {
                self.add_about(
                    Rule::Overwrite,
                    "writes to a file only known when it runs",
                    path,
                );
            }
            place => self.add_about(
                Rule::Overwrite,
                format!("writes to {}", place.words()),
                path,
            ),
        }
    }

    /// What a move or a link of `source` to `destination` writes: the
    /// destination, as a file, and the name the source lands at in it when
    /// it is a folder, which may be a protected path or a file a tool runs
    /// on its own.
    fn lands(&mut self, source: &Arg, destination: &Arg) {
        self.write(destination);
        let Some(text) = destination.known() else {
            return;
        };
        let separators = self.flavour.separators();
        let leaf = match source.known() {
            Some(text) => match text.trim_end_matches(separators).rsplit(separators).next() {
                None | Some("" | "." | ".." | "~") => CONTENTS.to_string(),
                Some(name) => name.to_string(),
            },
            None => "*".to_string(),
        };
        if leaf == CONTENTS {
            return;
        }
        let folder = text.trim_end_matches(separators);
        // A trailing separator, `.` and `..` can only be a folder.
        let folder_for_sure = text.ends_with(separators)
            || matches!(text.rsplit(separators).next(), Some("." | ".."));
        let landing = Arg::Known(format!("{folder}/{leaf}"));
        let target = destination.text().to_string();
        if let Place::Protected(words) = self.place(&landing, true) {
            self.add(
                Rule::Overwrite,
                format!("writes to {words}"),
                Some(target.clone()),
            );
        }
        if folder_for_sure && !glob::has_wildcard(&leaf) {
            let words = self.known(&landing).and_then(|text| {
                let text = self.normal(&text);
                let spelling = self.spelling(&text)?;
                self.resolver.startup(spelling, self.flavour, false)
            });
            if let Some(words) = words {
                self.add(Rule::Overwrite, format!("writes to {words}"), Some(target));
            }
        }
    }

    /// A link to `target`: a later write or delete of the link lands on it.
    fn links_to(&mut self, target: &Arg) {
        let place = self.place(target, false);
        if !place.harmless() && !matches!(place, Place::Workspace { exact: true }) {
            self.add_about(
                Rule::Overwrite,
                format!("links to {}", place.words()),
                target,
            );
        }
    }

    fn chmod(&mut self, path: &Arg, mode: &Arg) {
        let everyone = mode.known().is_some_and(|mode| {
            matches!(mode, "777" | "0777" | "666" | "0666" | "a=rwx" | "o=rwx")
                || mode.split(',').any(|clause| {
                    clause.contains('+')
                        && (clause.starts_with('a') || clause.starts_with('o'))
                        && clause.contains('w')
                })
        });
        if everyone {
            self.add_about(Rule::Permissions, "lets everyone change it", path);
        }
        self.permissions(path, "changes permissions of");
    }

    fn permissions(&mut self, path: &Arg, verb: &str) {
        match self.place(path, false) {
            place if place.harmless() => {}
            Place::Workspace { exact: true } => {}
            place => self.add_about(Rule::Permissions, format!("{verb} {}", place.words()), path),
        }
    }

    /// A read of `path`, a folder read all the way down when `recursive`.
    /// A key it names is `read_secret`; else a path the guard cannot name,
    /// or cannot place, is `unknown` for the `doubt` it carries, or for
    /// [`PARTIAL`] when it cannot be placed (`unplaceable` says whether to
    /// say so).
    fn read(&mut self, path: &Arg, recursive: bool, doubt: Option<&str>, unplaceable: bool) {
        if let Some(words) = self.secret(path) {
            self.add_about(Rule::ReadSecret, format!("reads {words}"), path);
            return;
        }
        if recursive {
            if let Some(words) = self.holder(path) {
                self.add_about(
                    Rule::ReadSecret,
                    format!("reads {words}, and the keys in it"),
                    path,
                );
                return;
            }
        }
        if let Some(doubt) = doubt {
            self.add_about(Rule::Unknown, doubt, path);
        } else if self.lost(path) {
            self.add_about(Rule::Unknown, LOST, path);
        } else if unplaceable && path.known().is_some() && self.place(path, false) == Place::Unknown
        {
            self.add_about(Rule::Unknown, PARTIAL, path);
        }
    }

    /// The words of the key or credential a read of `arg` reads. A path known
    /// only in part reads in the folder it is known to be in.
    fn secret(&self, arg: &Arg) -> Option<&'static str> {
        let text = match arg {
            Arg::Known(text) => text,
            Arg::Below { folder, .. } => folder,
            Arg::Unknown(_) => return None,
        };
        // Python and JavaScript do not expand a `~`: `open('~/x')` opens
        // `./~/x`. The path is read as the home directory's too
        // (`os.path.expanduser` gives the same text), so each is judged.
        self.secret_of(text).or_else(|| {
            text.starts_with('~')
                .then(|| self.secret_of(&format!("./{text}")))
                .flatten()
        })
    }

    /// The words of the key or credential a read of the path `text` reads.
    fn secret_of(&self, text: &str) -> Option<&'static str> {
        // From a directory only known when it runs, a name may be one in the
        // home directory, which that directory may be, or one the caller
        // named, wherever it is.
        if self.here.dir == Dir::Unknown && !self.rooted(text) {
            return self.secret_in_unknown_folder(text);
        }
        // A path past the join bounds is read as from a folder only known
        // when it runs.
        let Some(joined) = self.joined(text) else {
            return if self.rooted(text) {
                None
            } else {
                self.secret_in_unknown_folder(text)
            };
        };
        let joined = self.normal(&joined);
        // Another user's home directory, wherever a system keeps one.
        if let Some(homes) = self.homes(&joined) {
            return homes
                .iter()
                .find_map(|home| self.secret_at(Spelling::Plain(home), home));
        }
        self.secret_at(self.spelling(&joined)?, &joined)
    }

    /// The key or credential a relative `text` names from a folder only known
    /// when it runs: one in the home directory, which that folder may be, or
    /// one the caller named, wherever it is.
    fn secret_in_unknown_folder(&self, text: &str) -> Option<&'static str> {
        let climbs = text
            .split(self.flavour.separators())
            .any(|part| part == "..");
        let home = (!climbs).then(|| self.secret_at(Spelling::Home(text), text));
        home.flatten().or_else(|| {
            self.resolver
                .named_secret_in_unknown_folder(text, self.flavour, false)
        })
    }

    /// `~alice/rest` as the paths it can be: the user's home directory under
    /// the folders systems keep them in (`/home`, `/Users`, `C:\Users`), and
    /// the root user's (`/root`, `/var/root`), as the shell guard reads it.
    /// `None` for a path that is not in another user's home directory.
    fn homes(&self, text: &str) -> Option<Vec<String>> {
        let user = text.strip_prefix('~')?;
        let (name, rest) = user
            .split_once(self.flavour.separators())
            .unwrap_or((user, ""));
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return None;
        }
        let folders = if self.windows() {
            vec![format!(r"C:\Users\{name}")]
        } else {
            let mut folders = vec![format!("/home/{name}"), format!("/Users/{name}")];
            if name == "root" {
                folders.extend(["/root".to_string(), "/var/root".to_string()]);
            }
            folders
        };
        Some(
            folders
                .into_iter()
                .map(|folder| format!("{folder}/{rest}"))
                .collect(),
        )
    }

    /// The words of the key or credential at `spelling` (spelled `text`).
    fn secret_at(&self, spelling: Spelling<'_>, text: &str) -> Option<&'static str> {
        let place = self.resolver.place(spelling, self.flavour);
        match place {
            Place::Sensitive(words, Sensitivity::Secret) => return Some(words),
            Place::Disk => return Some("a disk, and every key on it"),
            // A path the caller named both protected and secret is protected
            // to core; a read of it reads the secret.
            Place::Protected(_) => {
                if let Some(words) = self.resolver.named_secret(spelling, self.flavour) {
                    return Some(words);
                }
            }
            // A Windows name the spelling does not settle (a stream such as
            // `id_rsa::$DATA`, a part that ends in a space or a dot) is read
            // for the file it is a name of.
            Place::Unknown | Place::Outside if self.windows() => {
                if let Some(named) = without_streams(text) {
                    let words = self
                        .spelling(&named)
                        .and_then(|spelling| self.secret_at(spelling, &named));
                    if words.is_some() {
                        return words;
                    }
                }
            }
            _ => {}
        }
        self.resolver
            .picks_secret(spelling, self.flavour, false)
            .or_else(|| {
                // What the kernel serves is not in the workspace, a temporary
                // folder or the home directory.
                if matches!(place, Place::Top(_) | Place::Outside | Place::Null) {
                    self.resolver.kernel(spelling, self.flavour)
                } else {
                    None
                }
            })
    }

    /// The words of the home directory, or a folder that holds it, that a
    /// read of `arg` all the way down reads.
    fn holder(&self, arg: &Arg) -> Option<&'static str> {
        let holds = |place: Place| {
            matches!(
                place,
                Place::Home { .. } | Place::Top("the root of the disk")
            )
            .then(|| place.words())
        };
        // Another user's home directory, wherever a system keeps one.
        if let Some(homes) = self.known(arg).and_then(|text| self.homes(&text)) {
            return homes
                .iter()
                .find_map(|home| holds(self.place_of(home, false)));
        }
        holds(self.place(arg, false)).or_else(|| {
            // A folder that holds a link the caller named holds what the
            // link lands on, for a reader that follows the links it meets.
            let known = self.known(arg)?;
            let text = self.normal(&known).into_owned();
            let spelling = self.spelling(&text)?;
            self.resolver.linked_holder(spelling, self.flavour)
        })
    }

    /// Whether `arg` goes through more links than any system follows, a
    /// link the caller could not read, or past the work one call may spend.
    fn lost(&self, arg: &Arg) -> bool {
        let Some(text) = self.known(arg) else {
            return false;
        };
        let text = self.normal(&text);
        self.spelling(&text)
            .is_some_and(|spelling| self.resolver.lost(spelling, self.flavour))
    }

    /// The move a command line starts with when the code runs it from
    /// another directory than where it started, in the machine's shell:
    /// `cd -- DIR && ` (cmd: `cd /d DIR && `), with a directory only known
    /// when it runs written as a word that is.
    fn moved_line(&self) -> Moved {
        let dir = match &self.here.dir {
            Dir::Start => return Moved::Here,
            Dir::At(dir) => Some(dir.as_str()),
            Dir::Unknown => None,
        };
        if self.windows() {
            match dir {
                // A directory that starts as a switch does is read as one.
                Some(dir) if dir.starts_with(['/', '-']) => Moved::Unwritten,
                // cmd has no word the shell guard reads as a folder only
                // known when it runs, as a POSIX shell's `"$UNKNOWN"` is.
                None => Moved::Unwritten,
                Some(dir) => cmd_word(dir, false).map_or(Moved::Unwritten, |dir| {
                    Moved::By(format!("cd /d {dir} && "))
                }),
            }
        } else {
            Moved::By(match dir {
                Some(dir) => format!("cd -- {} && ", posix_word(dir, false)),
                None => format!("cd -- {UNKNOWN_POSIX} && "),
            })
        }
    }

    /// A finding that the code starts a program, with its command line, or
    /// with none and a second `unknown` that says why.
    fn run(&mut self, reason: &str, line: Option<String>, shown: String) {
        let unwritten = line.is_none();
        self.add(Rule::RunProgram, reason, line);
        if unwritten {
            self.add(Rule::Unknown, UNWRITTEN, Some(shown));
        }
    }

    /// A command line a shell runs: the machine's shell, `sh` on a POSIX
    /// machine and `cmd` on Windows.
    fn script(&mut self, script: &Arg, unplaced: bool) {
        if unplaced {
            self.add_about(Rule::Unknown, UNPLACED_RUN, script);
        }
        let Arg::Known(text) = script else {
            self.add_about(
                Rule::Unknown,
                "runs a script only known when it runs",
                script,
            );
            return;
        };
        // On Windows, a list of words handed to a shell is joined into the
        // line, which the act does not give, and a line that starts with a
        // quote has its quotes taken off by `cmd /c` as cmd's own rules say.
        let unwritten = self.windows() && (self.listed_shell || text.trim_start().starts_with('"'));
        let line = match self.moved_line() {
            _ if unwritten => None,
            Moved::Here => Some(text.clone()),
            Moved::Unwritten => None,
            Moved::By(cd) if self.windows() => {
                (!text.contains(['"', '\n', '\r'])).then(|| format!("{cd}cmd /c \"{text}\""))
            }
            Moved::By(cd) => Some(format!("{cd}sh -c {}", posix_word(text, false))),
        };
        self.run("runs a command in a shell", line, text.clone());
    }

    /// A program and its arguments, run without a shell.
    fn program(&mut self, words: &[Arg], unplaced: bool) {
        let Some(program) = words.first() else {
            return;
        };
        let shown = words.iter().map(Arg::text).collect::<Vec<_>>().join(" ");
        if unplaced {
            self.add(Rule::Unknown, UNPLACED_RUN, Some(shown.clone()));
        }
        if program.known().is_none() {
            self.add_about(
                Rule::Unknown,
                "runs a program only known when it runs",
                program,
            );
            return;
        }
        if let Some(unknown) = words.iter().skip(1).find(|word| word.known().is_none()) {
            self.add_about(Rule::Unknown, UNKNOWN_WORD, unknown);
        }
        let windows = self.windows();
        if windows {
            // On Windows the words are joined into one line as Windows joins
            // them, and a program may hand that line on to cmd (cmd itself, a
            // batch file, a launcher): a target is only words that cmd and
            // the C runtime both read as themselves, bare or in plain double
            // quotes for a space, and none where the code may hand a shell a
            // list.
            let joined: Option<Vec<String>> = words
                .iter()
                .enumerate()
                .map(|(at, arg)| {
                    let text = arg.known()?;
                    if at == 0 && cmd_reads_as_its_own(text) {
                        return None;
                    }
                    windows_joined(text)
                })
                .collect();
            let line = match (self.moved_line(), joined) {
                _ if self.listed_shell => None,
                (Moved::Here, Some(joined)) => Some(joined.join(" ")),
                (Moved::By(cd), Some(joined)) => Some(format!("{cd}{}", joined.join(" "))),
                _ => None,
            };
            self.run("runs a program", line, shown);
            return;
        }
        let spelled: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(at, arg)| match arg {
                Arg::Known(text) => posix_word(text, at == 0),
                Arg::Below { folder, .. } => {
                    format!("{}{UNKNOWN_POSIX}", posix_word(folder, false))
                }
                Arg::Unknown(_) => UNKNOWN_POSIX.to_string(),
            })
            .collect();
        let line = match self.moved_line() {
            Moved::Here => Some(spelled.join(" ")),
            Moved::By(cd) => Some(format!("{cd}{}", spelled.join(" "))),
            Moved::Unwritten => None,
        };
        self.run("runs a program", line, shown);
    }
}

/// Whether cmd reads a program's name as its own, in a command's place: a
/// keyword (`if`, `for`, `rem`), a leading `@`, or a leading `/` or `-`,
/// which it reads as a switch.
fn cmd_reads_as_its_own(name: &str) -> bool {
    name.starts_with(['@', '/', '-'])
        || ["if", "for", "rem"]
            .iter()
            .any(|word| name.eq_ignore_ascii_case(word))
}

/// `text` as Windows joins one word of a list into a command line
/// (`list2cmdline`): as it is, or double-quoted when it holds a space or a
/// tab or is empty. `None` when cmd, which may read the joined line, reads a
/// character of it as its own ([`CMD_SPECIAL`]), when it holds a control
/// character, or when it is quoted and ends in a backslash, which the C
/// runtime reads as escaping the quote.
fn windows_joined(text: &str) -> Option<String> {
    if text.contains(CMD_SPECIAL) || text.chars().any(char::is_control) {
        return None;
    }
    if text.is_empty() {
        return Some("\"\"".to_string());
    }
    if !text.contains([' ', '\t']) {
        return Some(text.to_string());
    }
    (!text.ends_with('\\')).then(|| format!("\"{text}\""))
}

/// The name a Windows path is a name of once its streams and the spaces and
/// dots that end a part are taken off, as Windows takes them off:
/// `id_rsa::$DATA` is `id_rsa`, `.ssh \id_rsa` is `.ssh\id_rsa`. `None`
/// when there is nothing to take off.
fn without_streams(text: &str) -> Option<String> {
    let mut changed = false;
    let parts: Vec<&str> = text
        .split(['/', '\\'])
        .map(|part| {
            let drive = part.len() == 2 && part.ends_with(':');
            let name = if drive {
                part
            } else {
                part.split(':').next().unwrap_or(part)
            };
            let name = if matches!(name, "." | "..") {
                name
            } else {
                name.trim_end_matches([' ', '.'])
            };
            changed |= name.len() != part.len();
            name
        })
        .collect();
    changed.then(|| parts.join("\\"))
}

/// Whether `place` is beyond the workspace: the home directory, a top-level
/// or system folder, a folder holding the workspace, or anywhere else
/// outside it.
fn beyond_workspace(place: Place) -> bool {
    matches!(
        place,
        Place::Outside | Place::Home { .. } | Place::Top(_) | Place::Workspace { exact: false }
    )
}

/// Whether the code is still in a directory only known when it runs after
/// the moves `dirs` from a start that was (`unplaced`) or was not: an
/// absolute folder places it, one below where it was or above it (`..`)
/// keeps it where it was, and one only known when it runs leaves it
/// unplaced.
fn after(unplaced: bool, dirs: &[Arg]) -> bool {
    dirs.iter().fold(unplaced, |state, dir| match dir.known() {
        Some(text) if text.starts_with(['/', '~']) => false,
        Some(_) => state,
        None => true,
    })
}

/// Why a read of `path` is `unknown`, if it is: the path is only known when
/// the code runs, or known in part, or counts from a directory only known
/// when it runs (`unplaced`). A key it names is said as `read_secret`
/// instead.
fn read_doubt(path: &Arg, unplaced: bool) -> Option<&'static str> {
    match path.known() {
        None => Some(PARTIAL),
        Some(text) if unplaced && !text.starts_with(['/', '~']) => Some(UNPLACED_READ),
        Some(_) => None,
    }
}

/// `text` as one word of a POSIX shell line: as it is when every character
/// is one a shell reads as itself or as a pattern (so the shell guard reads
/// a `~`, a wildcard and a brace list in it as it reads them in the code),
/// single-quoted otherwise, and single-quoted when it is a word the shell
/// reads as its own (`{`, `if`) or, as the program (`first`), when it holds
/// a `=`, which makes it an assignment.
fn posix_word(text: &str, first: bool) -> String {
    let plain = !text.is_empty()
        && !text.starts_with('#')
        && !POSIX_RESERVED.contains(&text)
        && (!first || !text.contains('='))
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-~*?[]{},=:@%+^".contains(c));
    if plain {
        text.to_string()
    } else {
        quoted(text)
    }
}

/// `text` single-quoted for a POSIX shell.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// `text` as one word of a cmd line that cmd hands the program as it is: bare
/// when every character is one cmd reads as itself, double-quoted otherwise,
/// and quoted when it is a word cmd reads as its own in a command's place
/// (`if`, `for`, `rem`, a leading `@`). `None` when cmd cannot carry it: a
/// `"`, a `%` (which cmd expands even in quotes), a control character, or a
/// backslash at the end of a quoted word (which the program reads as
/// escaping the quote).
fn cmd_word(text: &str, first: bool) -> Option<String> {
    if text.is_empty() {
        return Some("\"\"".to_string());
    }
    // A program named as a switch is (`/bin/rm`) is read as one by cmd.
    if text.contains(['"', '%'])
        || text.chars().any(char::is_control)
        || (first && text.starts_with(['/', '-']))
    {
        return None;
    }
    let reserved = first
        && (text.starts_with('@')
            || ["if", "for", "rem"]
                .iter()
                .any(|word| text.eq_ignore_ascii_case(word)));
    let plain = !reserved
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "\\/._-:~*?@+[]{}#$'".contains(c));
    if plain {
        Some(text.to_string())
    } else if text.ends_with('\\') {
        None
    } else {
        Some(format!("\"{text}\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posix() -> Paths {
        Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
    }

    #[test]
    fn a_word_is_quoted_where_a_posix_shell_would_split_expand_or_keep_it() {
        for (text, first, spelled) in [
            ("git", true, "git"),
            ("--force", false, "--force"),
            ("~/x", false, "~/x"),
            ("*.log", false, "*.log"),
            ("a b", false, "'a b'"),
            ("it's", false, "'it'\\''s'"),
            ("$HOME", false, "'$HOME'"),
            ("#x", false, "'#x'"),
            ("", false, "''"),
            ("a;b", false, "'a;b'"),
            ("{", true, "'{'"),
            ("}", false, "'}'"),
            ("if", true, "'if'"),
            ("!", true, "'!'"),
            ("A=1", true, "'A=1'"),
            ("A=1", false, "A=1"),
        ] {
            assert_eq!(posix_word(text, first), spelled, "{text:?}");
        }
    }

    #[test]
    fn a_word_is_quoted_for_cmd_or_cannot_be_written() {
        for (text, first, spelled) in [
            ("rm", true, Some("rm")),
            (r"C:\Users\me", false, Some(r"C:\Users\me")),
            ("a b", false, Some("\"a b\"")),
            ("a&b", false, Some("\"a&b\"")),
            ("a,b", false, Some("\"a,b\"")),
            ("if", true, Some("\"if\"")),
            ("if", false, Some("if")),
            ("@x", true, Some("\"@x\"")),
            ("", false, Some("\"\"")),
            ("%PATH%", false, None),
            ("a\"b", false, None),
            ("a b\\", false, None),
            ("a\nb", false, None),
        ] {
            assert_eq!(cmd_word(text, first).as_deref(), spelled, "{text:?}");
        }
    }

    #[test]
    fn a_windows_name_is_read_without_its_streams() {
        assert_eq!(
            without_streams(r"C:\Users\me\.ssh\id_rsa::$DATA").as_deref(),
            Some(r"C:\Users\me\.ssh\id_rsa")
        );
        assert_eq!(
            without_streams(r"C:\Users\me\.ssh \id_rsa").as_deref(),
            Some(r"C:\Users\me\.ssh\id_rsa")
        );
        assert_eq!(without_streams(r"C:\Users\me\x"), None);
    }

    #[test]
    fn code_is_shown_by_its_first_line_cut() {
        assert_eq!(shown("print(1)\nprint(2)").as_deref(), Some("print(1)"));
        assert_eq!(shown(""), None);
        assert_eq!(shown("\nx"), None);
        let long = "x".repeat(100);
        assert_eq!(shown(&long).map(|s| s.chars().count()), Some(61));
    }

    #[test]
    fn the_guard_holds_code_to_the_readers_limits() {
        assert_eq!(MAX_LEN, reader::MAX_LEN);
        assert_eq!(MAX_DEPTH, reader::MAX_DEPTH);
    }

    #[test]
    fn code_run_past_the_depth_is_unreadable() {
        let mut judge = Judge::new(&posix(), MAX_LEN);
        judge.apply(
            Language::Python,
            "import shutil; shutil.rmtree('/home/me')",
            MAX_DEPTH + 1,
            false,
            false,
        );
        assert_eq!(judge.findings.len(), 1, "{:?}", judge.findings);
        assert_eq!(judge.findings[0].rule, Rule::Unreadable);
        assert_eq!(
            judge.findings[0].reason,
            "runs code inside code too deeply to read"
        );
        // At the depth it is read.
        let mut judge = Judge::new(&posix(), MAX_LEN);
        judge.apply(
            Language::Python,
            "import shutil; shutil.rmtree('/home/me')",
            MAX_DEPTH,
            false,
            false,
        );
        assert_eq!(judge.findings[0].rule, Rule::Delete);
    }

    #[test]
    fn nested_code_past_the_budget_is_unreadable() {
        let code = "import shutil; shutil.rmtree('/home/me')";
        let mut judge = Judge::new(&posix(), MAX_LEN);
        judge.nested = MAX_NESTED_READ - code.len();
        judge.apply(Language::Python, code, 1, false, false);
        assert_eq!(judge.findings.len(), 1, "{:?}", judge.findings);
        assert_eq!(
            judge.findings[0].reason,
            "runs too much code inside code to read"
        );
        // Within it, it is read; the code at the top is not counted.
        let mut judge = Judge::new(&posix(), MAX_LEN);
        judge.nested = MAX_NESTED_READ - code.len() - 1;
        judge.apply(Language::Python, code, 1, false, false);
        assert_eq!(judge.findings[0].rule, Rule::Delete);
        let mut judge = Judge::new(&posix(), MAX_LEN);
        judge.nested = MAX_NESTED_READ;
        judge.apply(Language::Python, code, 0, false, false);
        assert_eq!(judge.findings[0].rule, Rule::Delete);
    }
}
