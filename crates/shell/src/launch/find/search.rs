//! What a `find` expression can do with the places below each folder it
//! searches: the repository's `.git` itself, as a folder and as the file or
//! link it is in a linked worktree or a submodule, the entries `.git` holds
//! (`HEAD`, `config`, a pack), and an ordinary entry, one no name or path
//! pattern of the expression picks out. The expression is read as `find`
//! reads it, its tests and actions joined by `-a`, `-o`, `,`, `!` and
//! brackets, and each test is asked of each place: true, false, or not
//! known. An action that may run on `.git` as a folder, or on an ordinary
//! entry, hands on the whole folder searched; one that may run on `.git` as
//! a file, or on an entry inside it, hands on `.git`. A `-prune` sure to run
//! on `.git` as a folder keeps the search out of it, unless the search goes
//! depth first (`-depth`, `-d`, or `-delete`, which turns it on: GNU find
//! then refuses the line, and BSD and macOS find descend into the pruned
//! folder all the same). An expression that cannot be read, or that holds a
//! word that may split into more when it runs, is taken to reach everything.

use std::collections::BTreeMap;

use milo_guards_core::spelling::glob;
use milo_guards_core::Flavour;

use crate::unit::{may_split, Arg};
use crate::Shell;

/// How deep brackets and negations may nest before the expression is not
/// read: it is then taken to reach everything.
const MAX_NESTING: usize = 64;

/// The most bytes of name patterns, and of path patterns, read in one
/// expression, each asked of every name `.git` holds; past it the expression
/// is not read.
const MAX_PATTERN_BYTES: usize = 4096;

/// The most work the tests that depend on the folder searched may take, in
/// the steps [`glob::path_reach_work`] counts: for each distinct folder, each
/// way the search spells its `.git` and each path pattern, the pattern's
/// tokens times the names it is asked of, and [`NODE_WORK`] for each node of
/// the expression, which is walked again for each folder. Past it the
/// expression is not read. It keeps the worst line to tens of milliseconds.
const MAX_PATH_WORK: usize = 1 << 23;

/// The work of walking one node of the expression for one place, in the steps
/// of [`MAX_PATH_WORK`].
const NODE_WORK: usize = 8;

/// A test's answer for one place: true, false, or not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    False,
    Maybe,
    True,
}

impl Tri {
    fn not(self) -> Self {
        match self {
            Self::False => Self::True,
            Self::Maybe => Self::Maybe,
            Self::True => Self::False,
        }
    }

    /// The answer of a test asked of several spellings of one place.
    fn all(answers: impl Iterator<Item = Self>) -> Self {
        let (mut any_true, mut any_false) = (false, false);
        for answer in answers {
            match answer {
                Self::True => any_true = true,
                Self::False => any_false = true,
                Self::Maybe => return Self::Maybe,
            }
        }
        match (any_true, any_false) {
            (true, false) => Self::True,
            (false, true) => Self::False,
            _ => Self::Maybe,
        }
    }
}

/// The places asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// `.git` directly inside the folder searched, as a folder.
    GitFolder,
    /// The same `.git` as a file or a link, as it is in a linked worktree or
    /// a submodule: nothing is below it.
    GitFile,
    /// An entry `.git` holds, at any depth below it.
    Entry,
    /// An ordinary entry: a name and a path that no name or path pattern
    /// matches, unless the pattern matches every one.
    Other,
}

/// Every place, in the order of a [`Node::Fixed`]'s answers.
const PLACES: usize = 4;

impl Place {
    fn index(self) -> usize {
        match self {
            Self::GitFolder => 0,
            Self::GitFile => 1,
            Self::Entry => 2,
            Self::Other => 3,
        }
    }
}

/// One part of the expression.
#[derive(Debug)]
enum Node {
    /// A test whose answer does not depend on the folder searched, for each
    /// place in the order of [`Place::index`].
    Fixed([Tri; PLACES]),
    /// `-path` and its kin: the pattern as written, the pattern as `find`'s
    /// matching reads it (`None` when it is not read), and whether it
    /// compares without case.
    Path {
        raw: Option<String>,
        read: Option<String>,
        fold: bool,
    },
    /// An action that hands on or deletes what it is run on, and its answer.
    HandOn(Tri),
    /// `-prune`.
    Prune,
    Not(usize),
    All(Vec<usize>),
    Any(Vec<usize>),
    Each(Vec<usize>),
}

/// What one walk of the expression found.
#[derive(Debug, Default)]
struct Walk {
    /// An action that hands on may run.
    hands_on: bool,
    /// A `-prune` is sure to run.
    prunes: bool,
}

/// What a search does with the places below one folder it searches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// It may act on `.git` as a folder, or on an ordinary entry: the folder
    /// is taken whole.
    Whole,
    /// It acts on files inside the folder, and on `.git` (as a file, or on
    /// its entries) when `git` is set.
    Inside { git: bool },
}

/// A `find` expression, read.
#[derive(Debug)]
pub(super) struct Search {
    nodes: Vec<Node>,
    root: Option<usize>,
    /// It could not be read, or holds no test of a name or a path: every
    /// folder searched is taken whole.
    whole: bool,
    /// It goes depth first, so a `-prune` keeps nothing out.
    depth_first: bool,
    /// It has an action that hands on; without one `find` prints what the
    /// whole expression is true for.
    acts: bool,
    /// Its path patterns, as `find`'s matching reads them.
    paths: Vec<String>,
}

impl Search {
    /// Reads `expression`, the arguments of `find` after the folders it
    /// searches.
    pub(super) fn read(expression: &[Arg]) -> Self {
        let mut parser = Parser {
            args: expression,
            at: 0,
            nodes: Vec::new(),
            nesting: 0,
            depth_first: false,
            acts: false,
            filters: false,
            name_bytes: 0,
            path_bytes: 0,
            paths: Vec::new(),
        };
        let root = if expression.is_empty() {
            Ok(None)
        } else {
            parser.comma().map(Some)
        };
        // A word that may split when it runs may be any number of tests,
        // actions and operators, a `;` that ends an `-exec` among them.
        let split = expression.iter().any(|arg| may_split(arg, Shell::Posix));
        let read = root.is_ok() && parser.at == expression.len() && !split;
        Self {
            whole: !read || !parser.filters,
            root: root.ok().flatten(),
            depth_first: parser.depth_first,
            acts: parser.acts,
            paths: parser.paths,
            nodes: parser.nodes,
        }
    }

    /// What the search does below each of `starts`.
    pub(super) fn reach_all(&self, starts: &[Arg]) -> Vec<Reach> {
        if self.whole {
            return vec![Reach::Whole; starts.len()];
        }
        // Without a path test, read or not, every folder gets the same
        // answer.
        if !self
            .nodes
            .iter()
            .any(|node| matches!(node, Node::Path { .. }))
        {
            return vec![self.reach(None); starts.len()];
        }
        // Each distinct folder is read once, and the work of all of them is
        // counted before any is.
        let mut folders: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for start in starts.iter().filter_map(Arg::known) {
            folders.entry(start).or_insert_with(|| git_spellings(start));
        }
        let walks = self
            .nodes
            .len()
            .saturating_mul(PLACES)
            .saturating_mul(NODE_WORK);
        let mut work = walks;
        for spellings in folders.values() {
            work = work.saturating_add(walks);
            for spelling in spellings {
                for pattern in &self.paths {
                    work = work.saturating_add(glob::path_reach_work(pattern, spelling));
                }
            }
        }
        if work > MAX_PATH_WORK {
            return vec![Reach::Whole; starts.len()];
        }
        let reached: BTreeMap<&str, Reach> = folders
            .iter()
            .map(|(start, spellings)| (*start, self.reach(Some(spellings))))
            .collect();
        let unknown = self.reach(None);
        starts
            .iter()
            .map(|start| {
                start
                    .known()
                    .and_then(|text| reached.get(text).copied())
                    .unwrap_or(unknown)
            })
            .collect()
    }

    /// What the search does below a folder whose `.git` is spelled in each
    /// of `git` (`None` when the folder is only known when it runs, or no
    /// test asks).
    fn reach(&self, git: Option<&[String]>) -> Reach {
        let folder = self.walk(Place::GitFolder, git);
        if folder.hands_on || self.walk(Place::Other, git).hands_on {
            return Reach::Whole;
        }
        let file = self.walk(Place::GitFile, git).hands_on;
        if folder.prunes && !self.depth_first {
            return Reach::Inside { git: file };
        }
        Reach::Inside {
            git: file || self.walk(Place::Entry, git).hands_on,
        }
    }

    /// Walks the expression for `place`, below a folder whose `.git` is
    /// spelled in each of `git`.
    fn walk(&self, place: Place, git: Option<&[String]>) -> Walk {
        let mut walk = Walk::default();
        let Some(root) = self.root else {
            walk.hands_on = true;
            return walk;
        };
        let answer = self.eval(root, place, git, true, &mut walk);
        if !self.acts && answer != Tri::False {
            walk.hands_on = true;
        }
        walk
    }

    /// The answer of the node `at` for `place`, noting in `walk` what it may
    /// run; `sure` says the node is sure to be reached.
    fn eval(
        &self,
        at: usize,
        place: Place,
        git: Option<&[String]>,
        sure: bool,
        walk: &mut Walk,
    ) -> Tri {
        match &self.nodes[at] {
            Node::Fixed(answers) => answers[place.index()],
            Node::Path { raw, read, fold } => match (git, raw, read) {
                (Some(git), Some(raw), Some(read)) => path_answer(place, raw, read, *fold, git),
                _ => Tri::Maybe,
            },
            Node::HandOn(answer) => {
                walk.hands_on = true;
                *answer
            }
            Node::Prune => {
                walk.prunes |= sure && place == Place::GitFolder;
                Tri::True
            }
            Node::Not(inner) => self.eval(*inner, place, git, sure, walk).not(),
            Node::All(parts) => {
                let mut answer = Tri::True;
                for part in parts {
                    let got = self.eval(*part, place, git, sure && answer == Tri::True, walk);
                    answer = match (answer, got) {
                        (_, Tri::False) => Tri::False,
                        (Tri::True, Tri::True) => Tri::True,
                        _ => Tri::Maybe,
                    };
                    if answer == Tri::False {
                        break;
                    }
                }
                answer
            }
            Node::Any(parts) => {
                let mut answer = Tri::False;
                for part in parts {
                    let got = self.eval(*part, place, git, sure && answer == Tri::False, walk);
                    answer = match (answer, got) {
                        (_, Tri::True) => Tri::True,
                        (Tri::False, Tri::False) => Tri::False,
                        _ => Tri::Maybe,
                    };
                    if answer == Tri::True {
                        break;
                    }
                }
                answer
            }
            Node::Each(parts) => {
                let mut answer = Tri::True;
                for part in parts {
                    answer = self.eval(*part, place, git, sure, walk);
                }
                answer
            }
        }
    }
}

/// The ways a search of `start` spells the path of `.git` inside it: GNU
/// find drops the trailing `/` of a folder (`./` gives `./.git`), and BSD
/// and macOS find keep it (`.//.git`).
fn git_spellings(start: &str) -> Vec<String> {
    let trimmed = start.trim_end_matches('/');
    let mut spellings = vec![format!("{trimmed}/.git")];
    if start.ends_with('/') {
        for spelling in [format!("{start}/.git"), format!("{start}.git")] {
            if !spellings.contains(&spelling) {
                spellings.push(spelling);
            }
        }
    }
    spellings
}

/// The path of the `.git` folder inside `start`.
pub(super) fn git_inside(start: &str) -> String {
    format!("{}/.git", start.trim_end_matches('/'))
}

/// The answer of a `-path` test for `place`, below a folder whose `.git` is
/// spelled in each of `git`.
fn path_answer(place: Place, raw: &str, read: &str, fold: bool, git: &[String]) -> Tri {
    match place {
        Place::GitFolder | Place::GitFile => {
            Tri::all(git.iter().map(|path| matching(raw, read, path, fold)))
        }
        Place::Entry => {
            // `PREFIX*` takes every path below `.git` when `PREFIX` matches
            // the path of `.git`, or of `.git` and a `/`.
            let every = exact(raw)
                && raw.strip_suffix('*').is_some_and(|head| {
                    git.iter().all(|path| {
                        matches(head, path, fold) || matches(head, &format!("{path}/"), fold)
                    })
                });
            if every {
                Tri::True
            } else if git
                .iter()
                .any(|path| glob::path_can_reach_git_entry(read, path, fold))
            {
                Tri::Maybe
            } else {
                Tri::False
            }
        }
        Place::Other => {
            if matches_every(raw) {
                return Tri::True;
            }
            // `PREFIX*` takes every path below the folder when `PREFIX`
            // matches the folder, or the folder and a `/` (`./*`, `.*`).
            let head = raw.trim_end_matches('*');
            if !exact(raw) || head.len() == raw.len() {
                return Tri::False;
            }
            Tri::all(git.iter().map(|path| {
                let folder = path.strip_suffix(".git").unwrap_or(path);
                let every = matches(head, folder, fold)
                    || matches(head, folder.trim_end_matches('/'), fold);
                if every {
                    Tri::True
                } else {
                    Tri::False
                }
            }))
        }
    }
}

/// Whether a pattern read exactly matches every name, and every path: it is
/// made of `*`, with at most one `?` among them.
fn matches_every(raw: &str) -> bool {
    !raw.is_empty() && raw.chars().all(|c| matches!(c, '*' | '?')) && raw.matches('?').count() <= 1
}

/// Whether a pattern is read exactly: it holds no bracket and no backslash,
/// which are read only as widely as needed for the answer never to be wrongly
/// `false`.
fn exact(raw: &str) -> bool {
    !raw.contains(['[', '\\'])
}

/// Whether `read` matches `subject` as `find` matches a name or a path: a
/// wildcard matches a leading dot, and with `fold` case does not count.
fn matches(read: &str, subject: &str, fold: bool) -> bool {
    if fold {
        glob::matches_ignoring_case(read, subject, Flavour::Posix, true)
    } else {
        glob::matches(read, subject, Flavour::Posix, true)
    }
}

/// The answer of a pattern for one name or path: sure when it is read
/// exactly.
fn matching(raw: &str, read: &str, subject: &str, fold: bool) -> Tri {
    if !matches(read, subject, fold) {
        Tri::False
    } else if exact(raw) {
        Tri::True
    } else {
        Tri::Maybe
    }
}

/// A pattern as `find`'s matching (`fnmatch`) reads it, where a backslash
/// makes the next character itself: `\*` is a star, `\H` is `H`. A backslash
/// before a backslash is read as any character, wider than it is. `None` for
/// a pattern with a backslash and a bracket, where the backslash escapes
/// inside the bracket too: it is not read.
fn fnmatch(text: &str) -> Option<String> {
    if !text.contains('\\') {
        return Some(text.to_string());
    }
    if text.contains('[') {
        return None;
    }
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(next @ ('*' | '?')) => {
                out.push('[');
                out.push(next);
                out.push(']');
            }
            Some('\\') => out.push('?'),
            Some(next) => out.push(next),
            None => out.push('\\'),
        }
    }
    Some(out)
}

/// Reads a `find` expression into [`Node`]s.
struct Parser<'a> {
    args: &'a [Arg],
    at: usize,
    nodes: Vec<Node>,
    nesting: usize,
    depth_first: bool,
    acts: bool,
    /// A test of a name or a path was read.
    filters: bool,
    name_bytes: usize,
    path_bytes: usize,
    /// The path patterns read, as `find`'s matching reads them.
    paths: Vec<String>,
}

/// The expression could not be read.
#[derive(Debug)]
struct Unread;

/// Tests and options beside the name, path and type tests whose next
/// argument is their value.
const VALUED: [&str; 27] = [
    "-newer",
    "-mtime",
    "-mmin",
    "-atime",
    "-amin",
    "-ctime",
    "-cmin",
    "-size",
    "-perm",
    "-user",
    "-group",
    "-links",
    "-samefile",
    "-inum",
    "-uid",
    "-gid",
    "-fstype",
    "-used",
    "-context",
    "-regex",
    "-iregex",
    "-xtype",
    "-anewer",
    "-cnewer",
    "-files0-from",
    "-Bmin",
    "-Btime",
];

/// Options, which are always true, and the ones of them that take a value.
const OPTIONS: [&str; 11] = [
    "-xdev",
    "-mount",
    "-follow",
    "-noleaf",
    "-daystart",
    "-warn",
    "-nowarn",
    "-ignore_readdir_race",
    "-noignore_readdir_race",
    "-x",
    "-true",
];

/// Options that take a value, and are always true.
const VALUED_OPTIONS: [&str; 3] = ["-maxdepth", "-mindepth", "-regextype"];

/// Tests that take no value and hand nothing on, beside the ones read on
/// their own.
const TESTS: [&str; 12] = [
    "-empty",
    "-readable",
    "-writable",
    "-executable",
    "-nouser",
    "-nogroup",
    "-quit",
    "-acl",
    "-xattr",
    "-sparse",
    "-s",
    "-E",
];

impl Parser<'_> {
    fn push(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn peek(&self) -> Option<&str> {
        self.args.get(self.at).and_then(Arg::known)
    }

    /// The next argument, as the value of the test before it.
    fn value(&mut self) -> Result<&Arg, Unread> {
        let value = self.args.get(self.at).ok_or(Unread)?;
        self.at += 1;
        Ok(value)
    }

    /// Parts joined by `,`.
    fn comma(&mut self) -> Result<usize, Unread> {
        let mut parts = vec![self.or()?];
        while self.peek() == Some(",") {
            self.at += 1;
            parts.push(self.or()?);
        }
        Ok(if parts.len() == 1 {
            parts[0]
        } else {
            self.push(Node::Each(parts))
        })
    }

    /// Parts joined by `-o`.
    fn or(&mut self) -> Result<usize, Unread> {
        let mut parts = vec![self.and()?];
        while matches!(self.peek(), Some("-o" | "-or")) {
            self.at += 1;
            parts.push(self.and()?);
        }
        Ok(if parts.len() == 1 {
            parts[0]
        } else {
            self.push(Node::Any(parts))
        })
    }

    /// Parts joined by `-a`, or set side by side.
    fn and(&mut self) -> Result<usize, Unread> {
        let mut parts = vec![self.unary()?];
        loop {
            match self.peek() {
                Some("-a" | "-and") => {
                    self.at += 1;
                    parts.push(self.unary()?);
                }
                Some("-o" | "-or" | "," | ")") => break,
                _ if self.at >= self.args.len() => break,
                _ => parts.push(self.unary()?),
            }
        }
        Ok(if parts.len() == 1 {
            parts[0]
        } else {
            self.push(Node::All(parts))
        })
    }

    /// A primary, a bracket, or either after any number of `!`.
    fn unary(&mut self) -> Result<usize, Unread> {
        let mut negations = 0_usize;
        while matches!(self.peek(), Some("!" | "-not")) {
            self.at += 1;
            negations += 1;
        }
        let inner = if self.peek() == Some("(") {
            self.at += 1;
            self.nesting += 1;
            if self.nesting > MAX_NESTING {
                return Err(Unread);
            }
            let inner = self.comma()?;
            self.nesting -= 1;
            if self.peek() != Some(")") {
                return Err(Unread);
            }
            self.at += 1;
            inner
        } else {
            self.primary()?
        };
        Ok(if negations % 2 == 1 {
            self.push(Node::Not(inner))
        } else {
            inner
        })
    }

    /// A test, an action or an option.
    fn primary(&mut self) -> Result<usize, Unread> {
        let text = self.peek().ok_or(Unread)?.to_string();
        self.at += 1;
        let node = match text.as_str() {
            "-name" | "-iname" | "-lname" | "-ilname" => {
                self.filters = true;
                let fold = text.starts_with("-i");
                match self.value()?.known().map(str::to_string) {
                    Some(raw) => {
                        self.name_bytes += raw.len();
                        if self.name_bytes > MAX_PATTERN_BYTES {
                            return Err(Unread);
                        }
                        name_test(&raw, fold)
                    }
                    None => Node::Fixed([Tri::Maybe; PLACES]),
                }
            }
            "-path" | "-ipath" | "-wholename" | "-iwholename" => {
                self.filters = true;
                let fold = text.starts_with("-i");
                let raw = self.value()?.known().map(str::to_string);
                self.path_bytes += raw.as_ref().map_or(1, String::len).max(1);
                if self.path_bytes > MAX_PATTERN_BYTES {
                    return Err(Unread);
                }
                let read = raw.as_deref().and_then(fnmatch);
                if let Some(read) = &read {
                    self.paths.push(read.clone());
                }
                Node::Path { raw, read, fold }
            }
            "-type" => match self.value()?.known() {
                Some(kinds) => type_test(kinds),
                None => Node::Fixed([Tri::Maybe; PLACES]),
            },
            "-false" => Node::Fixed([Tri::False; PLACES]),
            "-depth" | "-d" => {
                self.depth_first = true;
                Node::Fixed([Tri::True; PLACES])
            }
            "-delete" => {
                self.depth_first = true;
                self.acts = true;
                Node::HandOn(Tri::Maybe)
            }
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                while let Some(word) = self.args.get(self.at) {
                    self.at += 1;
                    if matches!(word.known(), Some(";" | "+")) {
                        break;
                    }
                }
                self.acts = true;
                Node::HandOn(Tri::Maybe)
            }
            "-print" | "-print0" | "-ls" => {
                self.acts = true;
                Node::HandOn(Tri::True)
            }
            "-printf" | "-fprint" | "-fprint0" | "-fls" => {
                self.value()?;
                self.acts = true;
                Node::HandOn(Tri::True)
            }
            "-fprintf" => {
                self.value()?;
                self.value()?;
                self.acts = true;
                Node::HandOn(Tri::True)
            }
            "-prune" => Node::Prune,
            text if OPTIONS.contains(&text) => Node::Fixed([Tri::True; PLACES]),
            text if VALUED_OPTIONS.contains(&text) => {
                self.value()?;
                Node::Fixed([Tri::True; PLACES])
            }
            text if VALUED.contains(&text) || text.starts_with("-newer") => {
                self.value()?;
                Node::Fixed([Tri::Maybe; PLACES])
            }
            text if TESTS.contains(&text) => Node::Fixed([Tri::Maybe; PLACES]),
            // Any other primary may be an action that hands on what it is run
            // on, as NetBSD's `-printx` does; it is not counted as one, so
            // the `-print` `find` adds when there is none is still read.
            text if text.starts_with('-') && text.len() > 1 => Node::HandOn(Tri::Maybe),
            _ => return Err(Unread),
        };
        Ok(self.push(node))
    }
}

/// A test of a name (`-name`, `-iname`, and `-lname`, `-ilname`, read alike,
/// since a link may be named anything): for `.git`, whether the pattern
/// matches its name; for an entry inside it, whether it can match one of the
/// names `.git` holds.
fn name_test(raw: &str, fold: bool) -> Node {
    let Some(read) = fnmatch(raw) else {
        return Node::Fixed([Tri::Maybe; PLACES]);
    };
    let on_git = matching(raw, &read, ".git", fold);
    let reaches = if fold {
        glob::can_match_git_entry_ignoring_case(&read)
    } else {
        glob::can_match_git_entry(&read, Flavour::Posix)
    };
    let on_entry = if reaches { Tri::Maybe } else { Tri::False };
    let on_other = if matches_every(raw) {
        Tri::True
    } else {
        Tri::False
    };
    Node::Fixed([on_git, on_git, on_entry, on_other])
}

/// A `-type` test of the kinds in `kinds` (GNU find takes a list, `-type
/// f,d`): `.git` is a folder in a repository's own checkout, and a file, or
/// a link, in a linked worktree or a submodule.
fn type_test(kinds: &str) -> Node {
    let on_folder = if kinds.contains('d') {
        Tri::True
    } else {
        Tri::False
    };
    let on_file = match (kinds.contains('f'), kinds.contains('l')) {
        (true, true) => Tri::True,
        (false, false) => Tri::False,
        _ => Tri::Maybe,
    };
    Node::Fixed([on_folder, on_file, Tri::Maybe, Tri::Maybe])
}
