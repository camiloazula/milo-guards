//! What only the reader's own tests read, behind the `testing` feature: its
//! tests turn it on (the crate's dev-dependency on itself). It is not part
//! of the API and not for callers: it is hidden from the docs, and may
//! change or go without notice. Nothing here changes what the reader does
//! or answers; it reads counts the reader keeps anyway.

use crate::{Language, Reading, Understanding};

/// One report of progress the parses of a budget may make for each this
/// many bytes it is made for, before they are stopped and the code is not
/// read.
pub const REPORT_BYTES: usize = crate::unit::REPORT_BYTES;

/// The reports any budget may make beside [`REPORT_BYTES`] for each byte.
pub const REPORT_BASE: usize = crate::unit::REPORT_BASE;

/// How many bytes the lexers may be handed for a budget, for each byte it
/// is made for, before the parse is stopped.
pub const HANDED_BYTES: usize = crate::unit::HANDED_BYTES;

/// The bytes the lexers may be handed for any budget, beside
/// [`HANDED_BYTES`] for each byte.
pub const HANDED_BASE: usize = crate::unit::HANDED_BASE;

/// What a byte handed with the log on counts for.
pub const LOGGED_WEIGHT: usize = crate::unit::LOGGED_WEIGHT;

/// How many reports one parse may make before it keeps the log: a parse is
/// first run without it.
pub const MAX_QUIET: usize = crate::unit::MAX_QUIET;

/// The reports the parses of a budget may make without the log in all.
pub const QUIET_IN_ALL: usize = crate::unit::QUIET_IN_ALL;

/// What each byte the lexers move on to takes back of the drops and merges
/// of versions counted, in thousandths of one.
pub const TANGLE_RATE: usize = crate::unit::TANGLE_RATE;

/// The drops and merges of versions left over the code moved through past
/// which a parse is stopped.
pub const TANGLE_BASE: usize = crate::unit::TANGLE_BASE;

/// The stars where Python allows none that code may hold before it is not
/// parsed.
pub const MAX_STARS_AFTER_OPERATORS: usize = crate::scan::MAX_STARS_AFTER_OPERATORS;

/// The `await`s before a `/` JavaScript may hold before it is not read.
pub const MAX_AWAITED_SLASHES: usize = crate::scan::MAX_AWAITED_SLASHES;

/// The spaces a grammar passes over, other than ASCII ones, that code may
/// hold outside its strings and comments before it is not read.
pub const MAX_ODD_SPACES: usize = crate::scan::MAX_ODD_SPACES;

/// What the scan of `code` in `language` before its parse finds: how deep
/// its openers nest (counted up to one past the reader's `MAX_TREE_DEPTH`),
/// its marks of a costly shape (in Python the stars where Python allows
/// none, in JavaScript the `await`s before a `/`), the spaces other than
/// ASCII ones outside its strings and comments, and, in Python, its
/// backticks there, each counted up to one past its bound.
#[must_use]
pub fn scan(language: Language, code: &str) -> (usize, usize, usize, usize) {
    let scanned = scanned(language, code);
    (scanned.depth, scanned.marks, scanned.odd, scanned.backticks)
}

/// The depth and the marks the scan of `code` in `language` counts on its
/// bytes alone (in Python the stars after an operator, in JavaScript the
/// `await`s before a `/`), each counted up to one past its bound.
#[must_use]
pub fn raw(language: Language, code: &str) -> (usize, usize) {
    let scanned = scanned(language, code);
    (scanned.raw_depth, scanned.raw_marks)
}

/// The stars after an operator Python may hold, counted on its bytes alone,
/// before it is not read.
pub const MAX_RAW_STARS: usize = crate::scan::MAX_RAW_STARS;

fn scanned(language: Language, code: &str) -> crate::scan::Scanned {
    match language {
        Language::Python => crate::scan::python(code),
        Language::JavaScript => crate::scan::javascript(code),
    }
}

/// How many times one parse may choose between the trees of two ways.
pub const MAX_SELECTED: usize = crate::unit::MAX_SELECTED;

/// How many times the parses of a budget may in all.
pub const SELECTED_IN_ALL: usize = crate::unit::SELECTED_IN_ALL;

/// The units of the reader's own work a budget allows, for each byte,
/// beside [`WALK_BASE`].
pub const WALK_BYTES: usize = crate::unit::WALK_BYTES;

/// See [`WALK_BYTES`].
pub const WALK_BASE: usize = crate::unit::WALK_BASE;

/// The most bytes a grammar is handed at once (more only to end where a
/// character does): a parse sees that it is past [`HANDED_BYTES`] only
/// after the piece that took it there.
pub const PIECE: usize = crate::unit::PIECE;

/// What the readings within one budget did. It depends on the code only, so it is
/// the same on every machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Work {
    /// The reports of its progress tree-sitter made (one each 100 steps of
    /// its parser), for every parse within the budget.
    pub reports: usize,
    /// The reports the parses made without the log, before each was read
    /// again with it.
    pub quiet: usize,
    /// The most the drops and merges of versions left over the code moved
    /// through came to.
    pub tangled: usize,
    /// The choices between the trees of two ways, in all.
    pub selected: usize,
    /// The units of the reader's own work.
    pub walked: usize,
    /// The bytes the lexers were handed, again or for the first time, each
    /// handed with the log on counted [`LOGGED_WEIGHT`] times.
    pub handed: usize,
    /// The parses that met an error and were stopped there.
    pub errors: usize,
    /// The most the scans of the code before its parses found its openers
    /// nested, and their marks of a costly shape (see [`scan`]).
    pub depth: usize,
    pub marks: usize,
    /// Whether a parse went past a limit and was stopped.
    pub stopped: bool,
}

impl From<crate::unit::Spent> for Work {
    fn from(spent: crate::unit::Spent) -> Self {
        Self {
            reports: spent.reports,
            quiet: spent.quiet,
            tangled: spent.tangled,
            selected: spent.selected,
            walked: spent.walked,
            handed: spent.handed,
            errors: spent.errors,
            depth: spent.depth,
            marks: spent.marks,
            stopped: spent.stopped,
        }
    }
}

/// Read `code` as [`crate::read`] does, and say what its parses did.
#[must_use]
pub fn read(language: Language, code: &str) -> (Reading, Work) {
    let (reading, spent) = crate::read_counted(language, code);
    (reading, spent.into())
}

/// Ask of `code` what [`crate::understand`] does, and say what its parse
/// did.
#[must_use]
pub fn understand(language: Language, code: &str) -> (Understanding, Work) {
    let (understood, spent) = crate::understand_counted(language, code);
    (understood, spent.into())
}

/// Ask of `code` what [`crate::parses`] does, and say what its parse did.
#[must_use]
pub fn parses(language: Language, code: &str) -> (bool, Work) {
    let (answer, spent) = crate::parses_counted(language, code);
    (answer, spent.into())
}

/// Ask of `code` what [`crate::gives_input`] does, and say what its parse
/// did.
#[must_use]
pub fn gives_input(language: Language, code: &str) -> (bool, Work) {
    let (answer, spent) = crate::gives_input_counted(language, code);
    (answer, spent.into())
}

/// Ask of `code` what [`crate::gives_shell_a_list`] does, and say what its
/// parse did.
#[must_use]
pub fn gives_shell_a_list(language: Language, code: &str) -> (bool, Work) {
    let (answer, spent) = crate::gives_shell_a_list_counted(language, code);
    (answer, spent.into())
}

/// Whether the reader stops on `code`: its parse (as [`crate::parses`]
/// makes it) spends the budget made for it, and what it did.
#[must_use]
pub fn stops(language: Language, code: &str) -> (bool, Work) {
    let budget = crate::Budget::new(code.len());
    let _ = budget.parses(language, code);
    (budget.is_spent(), budget.spent().into())
}

/// What the readings within `budget` have done so far.
#[must_use]
pub fn spent(budget: &crate::Budget) -> Work {
    budget.spent().into()
}
