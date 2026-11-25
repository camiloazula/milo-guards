//! What the readers are built from besides the grammars: the argument of a
//! call as the code gives it, the limits, and two helpers that walk a tree.

use crate::scan::Scanned;

/// One value the code hands to a call, as far as the reader knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Its value is in the text: `'target'`, `'~/x'`.
    Known(String),
    /// Only known when the code runs (a name nothing sets, a call's result):
    /// its source text.
    Unknown(String),
    /// A path that starts as the code says and ends in something only known
    /// when it runs: somewhere in a folder (`'/home/me/.ssh/id_' + name` is a
    /// file in `/home/me/.ssh/`). Not a value, but the folder is known, and a
    /// caller judges a read of the path by it.
    Below {
        /// The folder, as the code spells it, with its closing `/`.
        folder: String,
        /// The value as written.
        source: String,
    },
}

impl Arg {
    /// The value, when the code gives it whole.
    pub fn known(&self) -> Option<&str> {
        match self {
            Self::Known(text) => Some(text),
            Self::Unknown(_) | Self::Below { .. } => None,
        }
    }

    /// The value, or the source text of what is only known when the code runs.
    pub fn text(&self) -> &str {
        match self {
            Self::Known(text) | Self::Unknown(text) | Self::Below { source: text, .. } => text,
        }
    }
}

/// How deep code may run code (`exec("…")` inside `exec("…")`) before the
/// reader stops following it.
pub const MAX_DEPTH: usize = 8;

/// How deep a parse tree is walked before the code is too nested to read:
/// walking deeper would risk overflowing the stack. Code whose brackets
/// (and Python's format strings, JavaScript's templates and JSX)
/// nest deeper than this is not read at all, before it is parsed: the
/// parser goes back through its stack, as deep as what is left open, by
/// recursion, and within this depth a reading needs less than half a
/// mebibyte of stack. Real code nests 36 deep at most.
pub const MAX_TREE_DEPTH: usize = 400;

/// The longest code the reader reads: it reads in time that grows with the
/// code, and the strings it works out from names are held to a few times
/// this. Longer code is not read, before it is parsed (the shell guard's
/// limit on a line is the same number).
pub const MAX_LEN: usize = 64 * 1024;

/// The reports of its progress tree-sitter makes (one each 100 steps of its
/// parser) that the parses of a [`Budget`] may make in all: one for each
/// this many bytes it is made for. A count, never a clock, so the answer is
/// the same on every machine.
///
/// Each question asked of the same code is answered from one parse (see
/// [`KEPT`]), but the code `exec` and `eval` run inside it is parsed again,
/// and a line may hold many pieces of code, so this allows some three parses
/// of the densest real code: valid code written to be dense (`x=(a,a,…)`)
/// takes a report for 13 bytes. It is the backstop for a parse that moves
/// on at a cost the counts below do not see, and what bounds a line of many
/// pieces that each meet an error, each stopped where the parser starts to
/// recover from it.
pub(crate) const REPORT_BYTES: usize = 6;

/// The reports any [`Budget`] may make beside [`REPORT_BYTES`] for each
/// byte: enough for short code that meets an error to make the report with
/// the log that sees it.
pub(crate) const REPORT_BASE: usize = 64;

/// The bytes the lexers may be handed for the parses of a [`Budget`], for
/// each byte it is made for, beside [`HANDED_BASE`]; 256 bytes at a time
/// ([`PIECE`]), so what a lexer reads again is counted to within a piece.
/// A byte handed while the log is kept counts as [`LOGGED_WEIGHT`] bytes.
/// Past it the text ends where the lexer is, and the parse is stopped. A
/// lexer can go back over the same text: tree-sitter-python's scanner reads
/// the rest of a run of comment lines in a block again at each line of it,
/// so a run of `n` lines is handed some `4·n²` bytes.
pub(crate) const HANDED_BYTES: usize = 64;

/// The bytes the lexers may be handed for any [`Budget`], beside
/// [`HANDED_BYTES`] for each byte: little enough that a lexer that goes over
/// the same text again is handed it all in about 0.2 s.
pub(crate) const HANDED_BASE: usize = 24 * 1024 * 1024;

/// How many bytes each byte handed to a lexer while the log is kept counts
/// for (see [`HANDED_BYTES`]): the log writes an entry for each character a
/// lexer moves over, which costs some eight times the move itself.
pub(crate) const LOGGED_WEIGHT: usize = 12;

/// The most bytes a grammar is handed at once (more only to end where a
/// character does).
pub(crate) const PIECE: usize = 256;

/// How many drops and merges of the versions of a parse (its log's
/// `condense`) the parses of a [`Budget`] may make beside the code they move
/// through: each counts one, each byte the lexers move on to takes back this
/// many thousandths of one, and past [`TANGLE_BASE`] the parse is stopped (a
/// bound on the drops and merges of every stretch of the code, of this many
/// for each KB and the base). Where the grammar reads the code two ways at
/// once and the two never part, at an error, or the end of the code, each
/// way through the versions it merged is built as a tree of its own, in one
/// step of the parser, which no report sees, in time and memory that grow
/// with the square of the code. Real code reads two ways often (an object that
/// may be a pattern, a parenthesis that may be an arrow's parameters,
/// starred names that may be a target), so this is a loose bound: code
/// generated for exact arithmetic, minified, drops and merges versions 140
/// times for each KB, and comes to 175 past this rate. The costly Python
/// found is refused before it is parsed (`scan::python`), and the costly
/// JavaScript held by the choices it makes ([`MAX_SELECTED`]) or refused
/// before it is parsed (`scan::javascript`).
pub(crate) const TANGLE_RATE: usize = 256;

/// See [`TANGLE_RATE`]: real code comes to at most 175 (JavaScript; Python
/// at most 31).
pub(crate) const TANGLE_BASE: usize = 384;

/// How many times one parse may choose between the trees of two ways a
/// step went back through, as its log says (`select_…`), before the parse
/// is stopped; and [`SELECTED_IN_ALL`] for a [`Budget`]. A reduce that goes
/// back through versions merged before builds a tree for each way through
/// them and keeps one: the work of each step grows with the ways, which no
/// count of steps sees (in steps that each cost more than the last). Real
/// code chooses so at most 44 times in a file
/// (most never); Python that calls a function with a starred argument at
/// the start of a statement (`print(*a)`) more than some 500 times, after a
/// kilobyte or two of other code, is stopped by it.
pub(crate) const MAX_SELECTED: usize = 512;

/// See [`MAX_SELECTED`].
pub(crate) const SELECTED_IN_ALL: usize = 2 * MAX_SELECTED;

/// How many reports of its progress one parse may make before it keeps the
/// log, which makes a parse some four times slower: a parse is first run
/// without it, for as many reports as this, and stops at the first report
/// that says it is in error; code it reads to its end in them is read at the
/// grammar's own speed. Any other is read again from its start with the log,
/// which sees an error the moment the parser starts to recover from it, and
/// two ways of reading the code that never part. Without the log these
/// reports are what such code can cost: some milliseconds.
pub(crate) const MAX_QUIET: usize = 32;

/// How many reports the parses of a [`Budget`] may make without the log in
/// all (see [`MAX_QUIET`]): past them each parse keeps the log from its
/// start. Code read in many pieces, each short enough to be read to its end
/// without the log, would otherwise cost what no count sees once for each
/// piece, and a line holds a hundred of them.
pub(crate) const QUIET_IN_ALL: usize = 2 * MAX_QUIET;

/// How many of the trees its parses built a [`Budget`] keeps, the last
/// ones, to give again for the same code: a caller asks each question of a
/// piece of code in turn (`read`, then `understand`), and each would parse
/// it again.
const KEPT: usize = 4;

/// The units of the reader's own work, walking the tree and naming what
/// it finds, its readings within a [`Budget`] may spend, for each byte it
/// is made for, beside [`WALK_BASE`]: one for each node a walk visits and
/// each name worked out. Past it the reading stops where it is and the
/// code is not read. Without it a name worked out again from each of
/// thousands of calls in a chain (`x()()()…`) cost 1.6 s at the length
/// limit.
pub(crate) const WALK_BYTES: usize = 16;

/// See [`WALK_BYTES`].
pub(crate) const WALK_BASE: usize = 64 * 1024;

/// What the readings within a [`Budget`] have done so far, against what
/// they may do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Spent {
    /// The reports of its progress the parser made.
    pub(crate) reports: usize,
    /// The reports the parses made without the log.
    pub(crate) quiet: usize,
    /// The drops and merges of versions left over the code moved through
    /// (see [`TANGLE_RATE`]), in thousandths, and the most they came to, in
    /// whole drops.
    pub(crate) level: usize,
    pub(crate) tangled: usize,
    /// The choices between the trees of two ways (see [`MAX_SELECTED`]).
    pub(crate) selected: usize,
    /// The bytes the lexers were handed, each handed with the log on
    /// counted [`LOGGED_WEIGHT`] times.
    pub(crate) handed: usize,
    /// The units of the reader's own work.
    pub(crate) walked: usize,
    /// The parses that met an error, and were stopped there.
    pub(crate) errors: usize,
    /// The most a scan of the code before its parse found its openers
    /// nested, and its marks of a costly shape (see `scan::Scanned`).
    pub(crate) depth: usize,
    pub(crate) marks: usize,
    /// Whether a reading went past a limit and was stopped: every reading
    /// after it within the same budget is stopped before it starts.
    pub(crate) stopped: bool,
}

/// The work the reader may do for code, or for a line that holds code: one
/// budget for every reading a caller makes of it, so that reading the same
/// code again, or the code inside it, draws from the same work and does not
/// multiply it.
///
/// [`crate::read`] and the reader's other functions make one for the code
/// they are given. A caller that asks several questions of a piece of code
/// (`read`, then `understand`), reads several pieces of one line, or the
/// code inside code, makes one for the whole ([`Budget::new`] with its
/// length) and asks each question through it ([`Budget::read`] and the
/// others): the budget keeps the last few trees its parses built, so a
/// question asked again of the same code is answered from its tree, with no
/// parse, where the functions parse it again each time. The work is counted
/// as the grammars go and never by a clock, so the answer is the same on
/// every machine: past it a reading is stopped and the code is not read
/// ([`crate::Act::Unread`], not understood, not taken to parse, and may give
/// input and hand a shell a list), and so is every reading after it within
/// the same budget.
///
/// A budget is [`Send`], and not [`Sync`]: one thread asks its questions at
/// a time. Its [`Debug`] shows what it has spent, never the code it keeps.
pub struct Budget {
    reports: usize,
    handed: usize,
    walk: usize,
    spent: std::cell::Cell<Spent>,
    kept: std::cell::RefCell<Vec<Kept>>,
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget")
            .field("spent", &self.spent.get())
            .field("kept", &self.kept.borrow().len())
            .finish_non_exhaustive()
    }
}

/// What a [`Budget`] keeps of a parse (see [`KEPT`]): the tree, or that the
/// parse met an error.
struct Kept {
    language: tree_sitter::Language,
    code: Box<str>,
    tree: Option<tree_sitter::Tree>,
}

impl Budget {
    /// The work the reader may do for code, or a line, of `len` bytes: the
    /// length of the code, or of the line that holds the code asked about.
    /// A length past [`MAX_LEN`], the longest code the reader reads, is
    /// taken as [`MAX_LEN`] (so `Budget::new(usize::MAX)` is the most any
    /// budget allows).
    #[must_use]
    pub fn new(len: usize) -> Self {
        let len = len.min(MAX_LEN);
        Self {
            reports: len / REPORT_BYTES + REPORT_BASE,
            handed: len * HANDED_BYTES + HANDED_BASE,
            walk: len * WALK_BYTES + WALK_BASE,
            spent: std::cell::Cell::default(),
            kept: std::cell::RefCell::default(),
        }
    }

    /// Whether a reading within it was stopped: every reading after it is
    /// stopped before it starts.
    #[must_use]
    pub fn is_spent(&self) -> bool {
        self.spent.get().stopped
    }

    /// What the readings have done so far.
    pub(crate) fn spent(&self) -> Spent {
        self.spent.get()
    }

    /// Note a parse that met an error without being run (see
    /// `scan::python`).
    pub(crate) fn met_error(&self) {
        let mut spent = self.spent.get();
        spent.errors = spent.errors.saturating_add(1);
        self.spent.set(spent);
    }

    /// Stop the readings within it: the code is not read, and no reading
    /// after it starts.
    pub(crate) fn stop(&self) {
        let mut spent = self.spent.get();
        spent.stopped = true;
        self.spent.set(spent);
    }

    /// Note what a scan of code before its parse found.
    fn scanned(&self, scanned: Scanned) {
        let mut spent = self.spent.get();
        spent.depth = spent.depth.max(scanned.depth);
        spent.marks = spent.marks.max(scanned.marks);
        self.spent.set(spent);
    }

    /// Spend `units` of the reader's own work: `false`, and the budget
    /// spent, when that is more than it may do.
    ///
    /// A parse stopped within the budget stops every later parse, not the
    /// walk of what was parsed, so the acts beside a piece of code inside
    /// the code that is not read are still found.
    pub(crate) fn walk(&self, units: usize) -> bool {
        let mut spent = self.spent.get();
        spent.walked = spent.walked.saturating_add(units);
        let within = spent.walked <= self.walk;
        spent.stopped |= !within;
        self.spent.set(spent);
        within
    }
}

/// What one parse gave.
pub(crate) enum Parsed {
    /// The tree, with no error in it.
    Tree(tree_sitter::Tree),
    /// The grammar met an error in the code: the parse was stopped where the
    /// parser started to recover from it, or its tree holds one. The code is
    /// not read through the error, and does not parse.
    Error,
    /// The parse went past its [`Budget`], or an earlier one of the same
    /// budget did: the code is not read, and is not taken for code that does
    /// not parse (which raises before it runs a thing).
    Stopped,
    /// The grammar gave nothing back.
    Failed,
}

/// Why a scan of code before its parse refuses it (see `scan`).
pub(crate) enum Refusal {
    /// The language refuses it: it is code with an error.
    Error,
    /// The parse would cost more than any count of it sees: it is not read.
    Stopped,
}

/// Parse `code` with `language`, within what is left of `budget`: what the
/// budget kept for the same code, or first without the log, then, unless
/// that read it to its end or met an error, again from its start with the
/// log (see [`MAX_QUIET`]).
///
/// Code longer than [`MAX_LEN`] is not read, and nor is code `scan`
/// refuses: it is not parsed, and is code with an error or code not read,
/// as it says.
pub(crate) fn parse(
    budget: &Budget,
    language: &tree_sitter::Language,
    code: &str,
    scan: impl Fn(&str) -> (Scanned, Option<Refusal>),
) -> Parsed {
    if budget.spent.get().stopped {
        return Parsed::Stopped;
    }
    let kept = budget
        .kept
        .borrow()
        .iter()
        .find(|kept| kept.language == *language && *kept.code == *code)
        .map(|kept| kept.tree.clone());
    if let Some(tree) = kept {
        return tree.map_or(Parsed::Error, Parsed::Tree);
    }
    if code.len() > MAX_LEN {
        budget.stop();
        return Parsed::Stopped;
    }
    let (scanned, refusal) = scan(code);
    budget.scanned(scanned);
    let parsed = match refusal {
        Some(Refusal::Error) => {
            budget.met_error();
            Parsed::Error
        }
        Some(Refusal::Stopped) => {
            budget.stop();
            return Parsed::Stopped;
        }
        None => parse_anew(budget, language, code),
    };
    let tree = match &parsed {
        Parsed::Tree(tree) => Some(tree.clone()),
        Parsed::Error => None,
        Parsed::Stopped | Parsed::Failed => return parsed,
    };
    let mut kept = budget.kept.borrow_mut();
    if kept.len() >= KEPT {
        kept.remove(0);
    }
    kept.push(Kept {
        language: language.clone(),
        code: code.into(),
        tree,
    });
    drop(kept);
    parsed
}

/// Parse `code` with `language` (see [`parse`]), keeping nothing.
fn parse_anew(budget: &Budget, language: &tree_sitter::Language, code: &str) -> Parsed {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(language).is_err() {
        return Parsed::Failed;
    }
    // Short code may make as few reports without the log as it may make in
    // all, so it costs no more than it would with it; and the budget's
    // reports without the log may be spent.
    let quiet = MAX_QUIET
        .min(code.len() / REPORT_BYTES)
        .min(QUIET_IN_ALL.saturating_sub(budget.spent.get().quiet));
    if quiet > 0 {
        // Without a tree, the run was cut short, or the grammar gave
        // nothing back: either is read again.
        match parse_once(&mut parser, budget, code, Some(quiet)) {
            Parsed::Failed => {}
            done => return done,
        }
        // Read again from the start, not from where the quiet run stopped.
        parser.reset();
    }
    parse_once(&mut parser, budget, code, None)
}

/// What the log of one parse has said so far.
#[derive(Default)]
struct Logged {
    /// Whether the parser started to recover from an error, and whether a
    /// version read the code to its end.
    erred: bool,
    accepted: bool,
    /// The drops and merges left over the code moved through, in
    /// thousandths (see [`TANGLE_RATE`]), the most they came to, and how
    /// far into the code the lexers were when they were last counted.
    level: usize,
    most_level: usize,
    counted_at: usize,
    /// How far the lexers have read: the text handed so far.
    read_to: std::rc::Rc<std::cell::Cell<usize>>,
    /// The choices between the trees of two ways (see [`MAX_SELECTED`]).
    selected: usize,
}

impl Logged {
    /// Read one entry of the log of the parser (not of the lexer).
    fn parse_entry(&mut self, message: &str) {
        if message.starts_with("resume version") {
            // tree-sitter writes this when the best version of the parse has
            // met an error (one alone may meet one, and is dropped, where
            // the grammar reads the code two ways): it is about to recover,
            // and every recovery starts here. Once a version has read the
            // code to its end, another that recovers there loses to it.
            self.erred |= !self.accepted;
        } else if message == "accept" {
            self.accepted = true;
        } else if message == "condense" {
            let at = self.read_to.get();
            let moved = at.saturating_sub(self.counted_at);
            self.counted_at = self.counted_at.max(at);
            self.level = self
                .level
                .saturating_sub(moved.saturating_mul(TANGLE_RATE))
                .saturating_add(1024);
            self.most_level = self.most_level.max(self.level);
        } else if message.starts_with("select_") {
            self.selected = self.selected.saturating_add(1);
        }
    }
}

/// Run `parser` over `code` once, within what is left of `budget`: without
/// the log for at most `quiet` reports, stopping at an error, or with it.
/// [`Parsed::Stopped`] when it went past the budget, which is then spent;
/// [`Parsed::Error`] when it met an error, which spends nothing more;
/// [`Parsed::Failed`] when the run gave no tree, a run without the log cut
/// short included.
fn parse_once(
    parser: &mut tree_sitter::Parser,
    budget: &Budget,
    code: &str,
    quiet: Option<usize>,
) -> Parsed {
    use std::cell::{Cell, RefCell};
    use std::ops::ControlFlow;
    use std::rc::Rc;
    let mut spent = budget.spent.get();
    let read_to = Rc::new(Cell::new(0_usize));
    let logged = Rc::new(RefCell::new(Logged {
        erred: false,
        accepted: false,
        level: spent.level,
        most_level: spent.level,
        counted_at: 0,
        read_to: Rc::clone(&read_to),
        selected: 0,
    }));
    if quiet.is_none() {
        let logged = Rc::clone(&logged);
        parser.set_logger(Some(Box::new(move |kind, message: &str| {
            if kind == tree_sitter::LogType::Parse {
                logged.borrow_mut().parse_entry(message);
            }
        })));
    }
    let weight = if quiet.is_none() { LOGGED_WEIGHT } else { 1 };
    let bytes = code.as_bytes();
    let handed = Cell::new(spent.handed);
    let over_handed = || handed.get() > budget.handed;
    let selected = spent.selected;
    let over_logged = || {
        let log = logged.borrow();
        log.level > TANGLE_BASE * 1024
            || log.selected > MAX_SELECTED
            || selected.saturating_add(log.selected) > SELECTED_IN_ALL
    };
    let erred = || logged.borrow().erred;
    let mut read = |at: usize, _: tree_sitter::Point| -> &[u8] {
        // Past the budget the text ends here, so a lexer that reads on
        // stops at once, not at the next report.
        if over_handed() {
            handed.set(handed.get().saturating_add(1));
            return &[];
        }
        let stop = (at.saturating_add(PIECE)..=bytes.len())
            .find(|stop| code.is_char_boundary(*stop))
            .unwrap_or(bytes.len());
        let piece = bytes.get(at..stop).unwrap_or_default();
        read_to.set(read_to.get().max(stop));
        handed.set(
            handed
                .get()
                .saturating_add(piece.len().max(1).saturating_mul(weight)),
        );
        piece
    };
    let reports = Cell::new(spent.reports);
    let steps = Cell::new(0_usize);
    let past = Cell::new(false);
    let in_error = Cell::new(false);
    let mut progress = |state: &tree_sitter::ParseState| {
        reports.set(reports.get().saturating_add(1));
        steps.set(steps.get().saturating_add(1));
        if reports.get() > budget.reports || over_handed() || over_logged() {
            past.set(true);
            return ControlFlow::Break(());
        }
        // The flag is on once a recovery left every version in error, which
        // the log sees earlier, as the recovery starts.
        if state.has_error() || erred() {
            in_error.set(true);
            return ControlFlow::Break(());
        }
        // A run without the log stops past its reports.
        if quiet.is_some_and(|quiet| steps.get() > quiet) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };
    let options = tree_sitter::ParseOptions::new().progress_callback(&mut progress);
    let tree = parser.parse_with_options(&mut read, None, Some(options));
    if quiet.is_none() {
        parser.set_logger(None);
    }
    let log = logged.borrow();
    spent.level = log.level;
    spent.tangled = spent.tangled.max(log.most_level.div_ceil(1024));
    spent.selected = spent.selected.saturating_add(log.selected);
    drop(log);
    spent.reports = reports.get();
    spent.handed = handed.get();
    if quiet.is_some() {
        spent.quiet = spent.quiet.saturating_add(steps.get());
    }
    // A text cut short by the bytes handed may still give a tree, of less
    // than the code.
    spent.stopped = past.get() || over_handed() || over_logged();
    let tree = match tree {
        _ if spent.stopped => None,
        Some(tree) if tree.root_node().has_error() => {
            in_error.set(true);
            None
        }
        tree => tree,
    };
    if in_error.get() && !spent.stopped {
        spent.errors = spent.errors.saturating_add(1);
    }
    budget.spent.set(spent);
    match tree {
        _ if spent.stopped => Parsed::Stopped,
        _ if in_error.get() => Parsed::Error,
        Some(tree) => Parsed::Tree(tree),
        None => Parsed::Failed,
    }
}

/// Where each chain of assignments among `found` ends (`a = b = 'x'` sets
/// `a` to `'x'` too), by the id of each assignment of the kind `kind`: the
/// value after the last assignment of the chain, or that assignment when it
/// has no value. Found once for each chain, from its end, so a chain of
/// thousands (`x = a = a = …`) is not walked again from each assignment in
/// it, which took seconds at the length limit. `found` is in the order the
/// tree is walked, each node before the ones inside it.
pub(crate) fn chain_ends<'t>(
    found: &[tree_sitter::Node<'t>],
    kind: &str,
) -> std::collections::HashMap<usize, tree_sitter::Node<'t>> {
    let mut ends = std::collections::HashMap::new();
    for node in found.iter().rev().filter(|node| node.kind() == kind) {
        let end = match node.child_by_field_name("right") {
            Some(right) if right.kind() == kind => chain_end(right, kind, &ends),
            Some(right) => right,
            None => *node,
        };
        ends.insert(node.id(), end);
    }
    ends
}

/// The end of the chain of assignments of the kind `kind` that starts at
/// `value` (see [`chain_ends`]); `value` itself when it is no assignment.
pub(crate) fn chain_end<'t>(
    value: tree_sitter::Node<'t>,
    kind: &str,
    ends: &std::collections::HashMap<usize, tree_sitter::Node<'t>>,
) -> tree_sitter::Node<'t> {
    let mut value = value;
    while value.kind() == kind {
        if let Some(end) = ends.get(&value.id()) {
            return *end;
        }
        let Some(next) = value.child_by_field_name("right") else {
            break;
        };
        value = next;
    }
    value
}

/// Visit every node under `root`, without recursion, so a deep tree cannot
/// overflow the stack, within what is left of `budget`.
pub(crate) fn for_each_node<'tree>(
    budget: &Budget,
    root: tree_sitter::Node<'tree>,
    mut visit: impl FnMut(tree_sitter::Node<'tree>),
) {
    let mut cursor = root.walk();
    loop {
        // Each node visited is a unit of the reader's own work.
        if !budget.walk(1) {
            return;
        }
        visit(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// The source text of `node`.
pub(crate) fn text<'s>(node: &tree_sitter::Node<'_>, source: &'s str) -> &'s str {
    source.get(node.byte_range()).unwrap_or_default()
}
