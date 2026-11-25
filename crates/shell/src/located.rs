//! Where in the caller's line each finding is: what [`locate`](crate::locate)
//! reads, kept by the walk of the line only when it is asked for, and how a
//! finding's range is worked out from it.
//!
//! The walk reads several texts: the line, each as its grammar is handed it
//! after the guard prepared it (backslash-newlines joined, PowerShell's
//! spaces, quotes and dashes written in ASCII, a number's letters in lower
//! case, a word that is a variable and a path put in quotes, a line break put
//! at the end of a cmd line), and each script and piece of code the line
//! runs. A [`Map`] says where each byte of such a text is in the caller's
//! line, exactly where it is the same byte there and only as a whole where it
//! is not. Each word the walk reads for a program, an argument or a
//! redirect's file is kept as a [`Spot`], and each unit keeps the spots of
//! its program and its arguments ([`Words`]). A rule that makes a finding
//! about an argument it was handed tells [`crate::detect`] which argument
//! by where it is in memory ([`Ident`]); the finding's range is that
//! argument's word. A finding with no such word is placed at the part of
//! the line it was found in ([`Here`]): its command, or the word that holds
//! the script or code it was found in. No word is ever found by what it
//! reads as.
//!
//! None of it is kept when no range is asked for ([`Split::placing`] is
//! `None`): `classify`, `effect` and `explain` read the line as before, and a
//! finding never depends on it, so `locate` gives `classify`'s findings.

use std::ops::Range;
use std::rc::Rc;

use crate::unit::{Arg, Split};
use crate::{Finding, Reading};

/// How a range of a text the guard read lands in the caller's line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fit {
    /// Byte for byte: the line holds the same bytes there.
    Exact,
    /// Its two ends land where they are, but some byte between is not the
    /// line's (a non-ASCII space written as an ASCII one).
    Ends,
    /// An end fell inside a part of the text that is not the line's byte
    /// for byte (a script decoded, an escape read), and the range was
    /// widened to the whole of that part.
    Wide,
}

/// A run of a text that lands in one run of the line.
#[derive(Debug, Clone, Copy)]
struct Piece {
    /// Where the run is in the text.
    from: usize,
    to: usize,
    /// Where it lands in the line.
    start: usize,
    end: usize,
    /// Whether each byte of it is the same byte of the line (and the two
    /// runs are as long); otherwise only the run as a whole lands there.
    exact: bool,
    /// For a run that is not exact, whether it is what the line writes
    /// there spelled again (a character for a character, a quote put in),
    /// so a word that ends at it ends where the line's does; not for a text
    /// placed as a whole at the part that holds it, where no word of it
    /// ends where it does in the line.
    respelled: bool,
}

/// The most bytes an edit may make, and replace, to be a spelling again of
/// what it replaces (see [`Piece::respelled`]): one character.
const RESPELLED: usize = 4;

/// Where each byte of a text the guard reads is in the caller's line.
///
/// The pieces are in order, none is empty, and together they cover the text
/// from its start to its end. Bytes the guard took out of the line (a
/// backslash-newline) are the gap between two pieces; bytes it put in (a
/// quote) are a piece that lands on no byte.
#[derive(Debug, Clone)]
pub(crate) struct Map {
    pieces: Vec<Piece>,
    /// The part of the line the whole text lands in: what an empty text,
    /// which has no piece, is placed at.
    all: Range<usize>,
}

/// A change the guard made to a text before its grammar read it: `old`, in
/// the text before, became `new`, in the text after. Edits are in order and
/// apart.
#[derive(Debug, Clone)]
pub(crate) struct Edit {
    pub(crate) old: Range<usize>,
    pub(crate) new: Range<usize>,
}

/// `edits`, when they are what made `new` of `old`: what they leave is the
/// same bytes in both. Otherwise one edit of the whole text, which places it
/// as a whole: a range is never placed by edits that do not hold.
pub(crate) fn verified(old: &str, new: &str, edits: Vec<Edit>) -> Vec<Edit> {
    let (mut at_new, mut at_old) = (0, 0);
    let mut holds = true;
    for edit in edits.iter().chain(std::iter::once(&Edit {
        old: old.len()..old.len(),
        new: new.len()..new.len(),
    })) {
        let kept_new = new.as_bytes().get(at_new..edit.new.start);
        let kept_old = old.as_bytes().get(at_old..edit.old.start);
        if kept_new.is_none() || kept_new != kept_old {
            holds = false;
            break;
        }
        at_new = edit.new.end;
        at_old = edit.old.end;
    }
    if holds {
        edits
    } else {
        vec![Edit {
            old: 0..old.len(),
            new: 0..new.len(),
        }]
    }
}

impl Map {
    /// A text of `len` bytes that is the line's bytes from `at` on.
    pub(crate) fn exact(len: usize, at: usize) -> Self {
        let pieces = if len == 0 {
            Vec::new()
        } else {
            vec![Piece {
                from: 0,
                to: len,
                start: at,
                end: at + len,
                exact: true,
                respelled: false,
            }]
        };
        Self {
            pieces,
            all: at..at + len,
        }
    }

    /// A text of `len` bytes that lands in `range` of the line only as a
    /// whole: a script decoded, joined from several words or read from a
    /// word with escapes in it.
    pub(crate) fn whole(len: usize, range: Range<usize>) -> Self {
        let pieces = if len == 0 {
            Vec::new()
        } else {
            vec![Piece {
                from: 0,
                to: len,
                start: range.start,
                end: range.end,
                exact: false,
                respelled: false,
            }]
        };
        Self { pieces, all: range }
    }

    /// The text `len` bytes long that starts `at` bytes into this one, as
    /// this one places it.
    pub(crate) fn slice(&self, at: usize, len: usize) -> Self {
        let end = at + len;
        let (all, _) = self.locate(at, end);
        let mut pieces = Vec::new();
        for piece in self.overlapping(at..end) {
            let from = piece.from.max(at);
            let to = piece.to.min(end);
            if from >= to {
                continue;
            }
            pieces.push(if piece.exact {
                Piece {
                    from: from - at,
                    to: to - at,
                    start: piece.start + (from - piece.from),
                    end: piece.start + (to - piece.from),
                    ..*piece
                }
            } else {
                Piece {
                    from: from - at,
                    to: to - at,
                    // Part of a run spelled again is no spelling of it.
                    respelled: piece.respelled && from == piece.from && to == piece.to,
                    ..*piece
                }
            });
        }
        Self { pieces, all }
    }

    /// The text `edits` make of this one, `len` bytes long: what is left as
    /// it was is placed as it was, and what an edit made is placed where the
    /// part it replaced is, as a whole.
    pub(crate) fn edited(&self, edits: &[Edit], len: usize) -> Self {
        let mut pieces = Vec::new();
        // Where the text after and the text before are, between the edits.
        let (mut new, mut old) = (0, 0);
        for edit in edits {
            // Edits out of order, or that do not line up with the text, are
            // not the guard's: the text is placed as a whole.
            if edit.new.start < new
                || edit.old.start < old
                || edit.new.start - new != edit.old.start - old
                || edit.new.end < edit.new.start
                || edit.old.end < edit.old.start
            {
                return Self::whole(len, self.all.clone());
            }
            self.kept(&mut pieces, new..edit.new.start, old);
            if edit.new.end > edit.new.start {
                let (range, fit) = self.locate(edit.old.start, edit.old.end);
                pieces.push(Piece {
                    from: edit.new.start,
                    to: edit.new.end,
                    start: range.start,
                    end: range.end,
                    exact: false,
                    respelled: fit != Fit::Wide
                        && edit.new.len() <= RESPELLED
                        && edit.old.len() <= RESPELLED,
                });
            }
            new = edit.new.end;
            old = edit.old.end;
        }
        if len < new {
            return Self::whole(len, self.all.clone());
        }
        self.kept(&mut pieces, new..len, old);
        Self {
            pieces,
            all: self.all.clone(),
        }
    }

    /// Add to `pieces` the run `new` of an edited text, kept as it was from
    /// `old` on in this one.
    fn kept(&self, pieces: &mut Vec<Piece>, new: Range<usize>, old: usize) {
        if new.is_empty() {
            return;
        }
        let shift = |at: usize| at + new.start - old;
        let end = old + new.len();
        for piece in self.overlapping(old..end) {
            let from = piece.from.max(old);
            let to = piece.to.min(end);
            if from >= to {
                continue;
            }
            pieces.push(if piece.exact {
                Piece {
                    from: shift(from),
                    to: shift(to),
                    start: piece.start + (from - piece.from),
                    end: piece.start + (to - piece.from),
                    ..*piece
                }
            } else {
                Piece {
                    from: shift(from),
                    to: shift(to),
                    respelled: piece.respelled && from == piece.from && to == piece.to,
                    ..*piece
                }
            });
        }
    }

    /// The pieces that overlap `range` of the text, found by halving: the
    /// pieces are in order and apart, so a slice or an edit costs the
    /// pieces it keeps, not every piece of the text.
    fn overlapping(&self, range: Range<usize>) -> &[Piece] {
        let first = self.pieces.partition_point(|piece| piece.to <= range.start);
        let last = self.pieces.partition_point(|piece| piece.from < range.end);
        self.pieces.get(first..last.max(first)).unwrap_or_default()
    }

    /// Where the line goes on after `to` of the text when the guard took
    /// bytes out of it there: the start of the piece that starts at `to`,
    /// when a gap is before it.
    fn past_cut(&self, to: usize) -> Option<usize> {
        let at = self.pieces.partition_point(|piece| piece.from < to);
        let before = at
            .checked_sub(1)
            .and_then(|before| self.pieces.get(before))?;
        // The text goes on at the next piece, or, at its end, where the
        // line it is placed in ends.
        let next = match self.pieces.get(at) {
            Some(next) if next.from == to => next.start,
            Some(_) => return None,
            None if before.to == to => self.all.end,
            None => return None,
        };
        (next > before.end).then_some(next)
    }

    /// [`Self::locate`], with the steps it takes added to `work`: one, and
    /// one for each piece between the two ends, which it looks over.
    pub(crate) fn locate_counted(
        &self,
        (from, to): (usize, usize),
        work: &mut usize,
    ) -> (Range<usize>, Fit) {
        let (low, high) = (from.min(to), to.max(from));
        let first = self.pieces.partition_point(|piece| piece.to <= low);
        let last = self.pieces.partition_point(|piece| piece.to < high);
        *work += 1 + last.saturating_sub(first);
        self.locate(from, to)
    }

    /// Where `from..to` of the text is in the line, and how it fits there.
    pub(crate) fn locate(&self, from: usize, to: usize) -> (Range<usize>, Fit) {
        let (from, to) = (from.min(to), to.max(from));
        let (Some(first), Some(last)) = (self.pieces.first(), self.pieces.last()) else {
            return (self.all.clone(), Fit::Wide);
        };
        let mut fit = Fit::Exact;
        // The piece the start is in: the first that ends after it.
        let at = self.pieces.partition_point(|piece| piece.to <= from);
        let start = match self.pieces.get(at) {
            None => last.end,
            Some(piece) if piece.exact => piece.start + (from - piece.from),
            Some(piece) => {
                if from > piece.from || !piece.respelled {
                    fit = Fit::Wide;
                }
                piece.start
            }
        };
        // The piece the end is in: the first that reaches it.
        let till = self.pieces.partition_point(|piece| piece.to < to);
        let end = if to == 0 || to <= first.from {
            first.start
        } else {
            match self.pieces.get(till) {
                None => last.end,
                Some(piece) if piece.exact => piece.start + (to - piece.from),
                Some(piece) => {
                    if to < piece.to || !piece.respelled {
                        fit = Fit::Wide;
                    }
                    piece.end
                }
            }
        };
        if fit == Fit::Exact {
            // Byte for byte only when every piece between is, and each
            // goes on where the one before ended; its ends land where they
            // are only when every piece between is the line's, spelled again
            // or not.
            let pieces = self
                .pieces
                .get(at.min(self.pieces.len() - 1)..=till.min(self.pieces.len() - 1))
                .unwrap_or_default();
            if pieces.iter().any(|piece| !piece.exact && !piece.respelled) {
                fit = Fit::Wide;
            } else if !(pieces.iter().all(|piece| piece.exact)
                && pieces.windows(2).all(|pair| pair[0].end == pair[1].start))
            {
                fit = Fit::Ends;
            }
        }
        (start.min(end)..end.max(start), fit)
    }
}

/// The edits that made `new` of `old` when each character of one is the
/// character of the other at the same place (PowerShell's spaces, quotes and
/// dashes written in ASCII, a number's letters in lower case): one edit for
/// each run of characters that differ. Texts of different counts of
/// characters are one edit of the whole.
pub(crate) fn diffed(old: &str, new: &str) -> Vec<Edit> {
    let mut edits: Vec<Edit> = Vec::new();
    let mut olds = old.char_indices();
    let mut news = new.char_indices();
    loop {
        match (olds.next(), news.next()) {
            (Some((at_old, a)), Some((at_new, b))) => {
                if a == b {
                    continue;
                }
                let old_end = at_old + a.len_utf8();
                let new_end = at_new + b.len_utf8();
                match edits.last_mut() {
                    Some(last) if last.old.end == at_old && last.new.end == at_new => {
                        last.old.end = old_end;
                        last.new.end = new_end;
                    }
                    _ => edits.push(Edit {
                        old: at_old..old_end,
                        new: at_new..new_end,
                    }),
                }
            }
            (None, None) => return edits,
            _ => {
                return vec![Edit {
                    old: 0..old.len(),
                    new: 0..new.len(),
                }]
            }
        }
    }
}

/// A word the walk read for a program, an argument or a redirect's file.
#[derive(Debug, Clone)]
pub(crate) struct Spot {
    /// Where the word is in the line: the word as written, or, when the text
    /// it is in is placed only as a whole there, the part that holds it.
    pub(crate) range: Range<usize>,
    /// Whether `range` is the word as written, so reading it as the guard
    /// does gives `reading`: its two ends land where they are, it is one
    /// word (not a word that holds several the guard read apart), and its
    /// text was read in full by its grammar.
    pub(crate) whole: bool,
    /// Where `reading` starts in the line when the word's value is its own
    /// bytes there (a plain word, or one in quotes with no escape in it),
    /// byte for byte; a script read from it then lands byte for byte too.
    pub(crate) value: Option<usize>,
    /// What the guard read the word as: its value, or its source text when
    /// that is only known when it runs (see [`Arg::text`]).
    pub(crate) reading: String,
}

/// The words a unit was read from, by their place in [`Placing::spots`]:
/// its program's, and each argument's, in step with [`Unit::args`]
/// (`crate::unit::Unit`). The walk that reads a command sets them; taking a
/// wrapper off keeps the words of what is left (see
/// [`crate::launch`]'s `inner`). Any other change to the arguments leaves
/// them out of step, or the argument no longer reads as its word, and then
/// the word is not taken for it (see [`Words::of`]).
#[derive(Debug, Clone, Default)]
pub(crate) struct Words {
    pub(crate) program: Option<usize>,
    pub(crate) args: Vec<Option<usize>>,
}

/// [`Words`], on a unit. It takes no part in what the unit is (see
/// [`Placed`]).
#[derive(Debug, Clone, Default)]
pub(crate) struct Worded(pub(crate) Option<Rc<Words>>);

impl PartialEq for Worded {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Worded {
    /// The words of what is left of a unit when its first `start` arguments
    /// come off and the one at `start` is the program: the unit a wrapper
    /// runs.
    pub(crate) fn after(&self, start: usize) -> Self {
        Self(self.0.as_deref().map(|words| {
            Rc::new(Words {
                program: words.args.get(start).copied().flatten(),
                args: words.args.get(start + 1..).unwrap_or_default().to_vec(),
            })
        }))
    }
}

impl Worded {
    /// One more argument at the end, with no word of its own.
    pub(crate) fn push(&mut self, word: Option<usize>) {
        if let Some(words) = self.0.as_mut() {
            Rc::make_mut(words).args.push(word);
        }
    }

    /// The words of a unit read from `program` and `args`.
    pub(crate) fn new(program: Option<usize>, args: Vec<Option<usize>>) -> Self {
        Self(Some(Rc::new(Words { program, args })))
    }
}

impl Words {
    /// The spot of the argument at `at` of a unit whose arguments are
    /// `args`, when the unit's words are in step with them and the word
    /// still reads as the argument.
    fn of(&self, args: &[Arg], at: usize, spots: &[Spot]) -> Option<usize> {
        if self.args.len() != args.len() {
            return None;
        }
        let spot = (*self.args.get(at)?)?;
        (spots.get(spot)?.reading == args.get(at)?.text()).then_some(spot)
    }
}

/// What a part of the line a unit, a redirect or a finding was read in is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The line itself, no command of it.
    Line,
    /// A command, or the text of a script that holds it.
    Part,
}

/// The part of the line something was read in.
#[derive(Debug, Clone)]
pub(crate) struct Here {
    pub(crate) range: Range<usize>,
    pub(crate) kind: Kind,
    /// For a finding of the split, where its target is when the target is a
    /// part of the text being read (`Some(text)` of the source a grammar
    /// read), by where it is in memory: the range, and whether it is the
    /// line's bytes there.
    pub(crate) at: Option<(Range<usize>, bool)>,
}

/// Where a unit or a redirect was read, when the line is read for its
/// ranges. It takes no part in what the unit is: two units the same but for
/// where they are written are the same, so the walk, which compares units,
/// reads the line the same way whether or not it keeps them.
#[derive(Debug, Clone, Default)]
pub(crate) struct Placed(pub(crate) Option<Rc<Here>>);

impl PartialEq for Placed {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// A text the walk is reading, and where it is in the line.
#[derive(Debug)]
struct Text {
    /// Where its bytes are in memory, to tell a part of it handed back as a
    /// script of its own (cmd's `set X=1 && del y`) or as a finding's
    /// target: an address compared, never read.
    at: usize,
    len: usize,
    map: Map,
    /// Whether its grammar could not read it in full: where a word of it
    /// ends is then the grammar's guess, so none is taken for the word as
    /// written.
    broken: bool,
}

/// Which arguments of the unit that runs it a script or a piece of code was
/// made of, as the launcher that made it says (see `crate::launch`): one
/// argument, from where in its value the script starts (the whole value, or
/// what follows `--eval=`), or a run of arguments joined by a space
/// (`eval rm -rf ~`). Told by where the arguments are in memory, never by
/// what they read as. It takes no part in what a launch is.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Source(Option<Cut>);

#[derive(Debug, Clone, Copy)]
enum Cut {
    Arg { at: usize, offset: usize },
    Join { first: usize, count: usize },
}

impl PartialEq for Source {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// Where `arg` is in memory.
fn address(arg: &Arg) -> usize {
    std::ptr::from_ref(arg) as usize
}

impl Source {
    /// A script made of no argument it can be told by.
    pub(crate) const NONE: Self = Self(None);

    /// The script is the value of `arg`, an argument of the unit.
    pub(crate) fn arg(arg: &Arg) -> Self {
        Self(Some(Cut::Arg {
            at: address(arg),
            offset: 0,
        }))
    }

    /// The script is `part`, a part of the value of `arg` (what follows
    /// `--eval=`), by where it is in memory; none when it is not one.
    pub(crate) fn part(arg: &Arg, part: &str) -> Self {
        let Some(value) = arg.known() else {
            return Self::NONE;
        };
        let offset = (part.as_ptr() as usize).checked_sub(value.as_ptr() as usize);
        match offset.filter(|offset| offset + part.len() <= value.len()) {
            Some(offset) => Self(Some(Cut::Arg {
                at: address(arg),
                offset,
            })),
            None => Self::NONE,
        }
    }

    /// The script is `args`, arguments of the unit, joined by a space.
    pub(crate) fn joined(args: &[Arg]) -> Self {
        match args.first() {
            Some(first) => Self(Some(Cut::Join {
                first: address(first),
                count: args.len(),
            })),
            None => Self::NONE,
        }
    }

    /// Where in `args` the argument at `at` in memory is.
    fn index(at: usize, args: &[Arg]) -> Option<usize> {
        let start = address(args.first()?);
        let offset = at.checked_sub(start)?;
        let size = size_of::<Arg>();
        (offset.is_multiple_of(size) && offset / size < args.len()).then_some(offset / size)
    }
}

/// Where the script or code about to be read comes from (see
/// [`Split::launch`]): a part of one word, from where in its value it
/// starts, or the words of arguments joined by a space.
#[derive(Debug)]
enum From {
    /// The word, and where in its value the script starts.
    At(usize, usize),
    /// Each argument's text, and its word.
    Join(Vec<(String, Option<usize>)>),
}

/// [`From`], for the texts begun at `level` (the count of texts being read
/// when it was set): a script the script reads is not from its words.
#[derive(Debug)]
struct Launcher {
    level: usize,
    from: From,
}

/// What the walk keeps for the ranges of a line's findings.
#[derive(Debug, Default)]
pub(crate) struct Placing {
    /// The length of the caller's line.
    line: usize,
    texts: Vec<Text>,
    /// The parts being read, the innermost last.
    heres: Vec<Here>,
    pub(crate) spots: Vec<Spot>,
    /// In step with [`Split::findings`]: where each was found.
    pub(crate) findings: Vec<Rc<Here>>,
    /// In step with [`Split::unread`].
    pub(crate) unread: Vec<Rc<Here>>,
    launcher: Option<Launcher>,
    /// Each run of units that holds a redirect, and the part of the line
    /// the redirect is read in (see [`Split::hold_redirect`]).
    holds: Vec<(Range<usize>, Range<usize>)>,
    /// The work done to place the line, in steps: spots kept, pieces of
    /// maps made, arguments read for where a script comes from. What
    /// `tests/robust.rs` holds to a bound.
    pub(crate) work: usize,
}

impl Placing {
    pub(crate) fn new(line: usize) -> Self {
        Self {
            line,
            ..Self::default()
        }
    }

    /// A fresh one for the same line, for a read of it again.
    pub(crate) fn again(&self) -> Self {
        Self {
            line: self.line,
            work: self.work,
            ..Self::default()
        }
    }

    /// The part being read now: the line, when nothing is.
    fn here(&self) -> Here {
        match self.heres.last() {
            Some(here) => Here {
                range: here.range.clone(),
                kind: here.kind,
                at: None,
            },
            None => Here {
                range: 0..self.line,
                kind: Kind::Line,
                at: None,
            },
        }
    }

    fn map(&self) -> Option<&Map> {
        self.texts.last().map(|text| &text.map)
    }

    /// Where `text`, handed to a grammar, is: a part of the text being read
    /// (by where it is in memory), what the unit that runs it gives it (see
    /// [`Self::launched`]), or else the whole of the part being read.
    fn map_of(&mut self, text: &str) -> Map {
        let len = text.len();
        let Some(top) = self.texts.last() else {
            return Map::exact(len, 0);
        };
        let at = text.as_ptr() as usize;
        if top.len > 0 && at >= top.at && at + len <= top.at + top.len {
            let map = top.map.slice(at - top.at, len);
            self.work += 1 + map.pieces.len();
            return map;
        }
        if let Some(map) = self.launched(text) {
            return map;
        }
        Map::whole(len, self.here().range)
    }

    /// The map of `text`, a script or code the unit being launched hands
    /// on, from the words its launcher says it was made of (see [`From`]):
    /// the part of the word, byte for byte when the word's value is its own
    /// bytes and the text is that part of it, else the word as a whole; or
    /// each joined word as a whole, and each space between at what is
    /// between them. `None` when no launcher said.
    fn launched(&mut self, text: &str) -> Option<Map> {
        let level = self.texts.len();
        let launcher = self
            .launcher
            .as_ref()
            .filter(|launcher| launcher.level == level)?;
        let len = text.len();
        let spots = &self.spots;
        // A script that is one argument joined to none is that argument's
        // value.
        let from = match &launcher.from {
            From::Join(words) if words.len() == 1 => words[0].1.map(|at| (at, 0)),
            From::At(at, offset) => Some((*at, *offset)),
            From::Join(_) => None,
        };
        let (map, work) = match (from, &launcher.from) {
            (Some((at, offset)), _) => {
                let spot = spots.get(at)?;
                let same = spot.reading.get(offset..offset + len) == Some(text);
                let map = match spot.value {
                    Some(value) if spot.whole && same => Map::exact(len, value + offset),
                    _ => Map::whole(len, spot.range.clone()),
                };
                // The bytes compared, as many as the script's.
                (map, 1 + len)
            }
            (None, From::At(..)) => return None,
            (None, From::Join(words)) => {
                let held: Option<Vec<&Spot>> =
                    words.iter().map(|(_, at)| spots.get((*at)?)).collect();
                let held = held?;
                let map = if is_joined(words, text) {
                    Map::joined(words, &held)
                } else {
                    let start = held.first().map_or(0, |spot| spot.range.start);
                    let end = held.last().map_or(0, |spot| spot.range.end);
                    Map::whole(len, start..end)
                };
                // The words looked over, and the script's bytes compared.
                (map, 2 * words.len() + len)
            }
        };
        self.work += work;
        Some(map)
    }
}

/// Whether `text` is `words` joined by a space.
fn is_joined(words: &[(String, Option<usize>)], text: &str) -> bool {
    let mut rest = text;
    for (at, (word, _)) in words.iter().enumerate() {
        if at > 0 {
            match rest.strip_prefix(' ') {
                Some(after) => rest = after,
                None => return false,
            }
        }
        match rest.strip_prefix(word.as_str()) {
            Some(after) => rest = after,
            None => return false,
        }
    }
    rest.is_empty()
}

impl Map {
    /// A text that is `words` joined by a space, each placed as a whole at
    /// its word of `spots`, and each space at what is between the two.
    fn joined(words: &[(String, Option<usize>)], spots: &[&Spot]) -> Self {
        let mut pieces = Vec::new();
        let mut from = 0;
        for (at, ((word, _), spot)) in words.iter().zip(spots).enumerate() {
            let range = &spot.range;
            if at > 0 {
                let before = spots[at - 1].range.end;
                pieces.push(Piece {
                    from,
                    to: from + 1,
                    start: before.min(range.start),
                    end: range.start.max(before),
                    exact: false,
                    respelled: false,
                });
                from += 1;
            }
            if !word.is_empty() {
                pieces.push(Piece {
                    from,
                    to: from + word.len(),
                    start: range.start,
                    end: range.end,
                    exact: false,
                    respelled: false,
                });
            }
            from += word.len();
        }
        let all = spots.first().map_or(0, |spot| spot.range.start)
            ..spots.last().map_or(0, |spot| spot.range.end);
        Self { pieces, all }
    }
}

impl Split {
    /// Begin reading the text a grammar is handed, which the guard made
    /// from `text` in `steps`: each the text it made and the edits that
    /// made it of the one before. The last is what the grammar reads.
    #[inline(never)]
    pub(crate) fn begin_text(&mut self, text: &str, steps: &[(&str, Vec<Edit>)]) {
        let Some(placing) = self.placing.as_deref_mut() else {
            return;
        };
        let nested = !placing.texts.is_empty();
        // What a text the grammar did not read in full hands on is not read
        // in full either.
        let broken = placing.texts.last().is_some_and(|text| text.broken);
        let outer = placing.here();
        let mut map = placing.map_of(text);
        let mut prepared = text;
        for (made, edits) in steps {
            if !edits.is_empty() || made.len() != prepared.len() {
                map = map.edited(edits, made.len());
                placing.work += 1 + edits.len() + map.pieces.len();
            }
            prepared = made;
        }
        placing.work += 1;
        let (mut range, _) = map.locate_counted((0, prepared.len()), &mut placing.work);
        // An empty script is placed where what runs it is; the line itself
        // is the whole line, whatever the guard cut off it.
        if range.is_empty() || !nested {
            range = if nested { outer.range } else { 0..placing.line };
        }
        placing.texts.push(Text {
            at: prepared.as_ptr() as usize,
            len: prepared.len(),
            map,
            broken,
        });
        placing.heres.push(Here {
            range,
            kind: if nested { Kind::Part } else { Kind::Line },
            at: None,
        });
    }

    /// Say whether the grammar read the text being read in full (see
    /// [`Text::broken`]).
    #[inline(never)]
    pub(crate) fn text_read(&mut self, in_full: bool) {
        if let Some(text) = self
            .placing
            .as_deref_mut()
            .and_then(|placing| placing.texts.last_mut())
        {
            text.broken |= !in_full;
        }
    }

    /// The text [`Self::begin_text`] began is read.
    #[inline(never)]
    pub(crate) fn end_text(&mut self) {
        if let Some(placing) = self.placing.as_deref_mut() {
            placing.texts.pop();
            placing.heres.pop();
        }
    }

    /// Begin reading a command at `range` of the text being read: what is
    /// found in it until [`Self::leave_command`] is placed there.
    #[inline(never)]
    pub(crate) fn enter_command(&mut self, range: Range<usize>) {
        let Some(placing) = self.placing.as_deref_mut() else {
            return;
        };
        let Some(text) = placing.texts.last() else {
            return;
        };
        let (mut range, _) = text
            .map
            .locate_counted((range.start, range.end), &mut placing.work);
        // A command the grammar reads as missing (a node of no width) is
        // placed where the walk is.
        if range.is_empty() {
            range = placing.here().range;
        }
        placing.heres.push(Here {
            range,
            kind: Kind::Part,
            at: None,
        });
    }

    /// The command [`Self::enter_command`] began is read.
    #[inline(never)]
    pub(crate) fn leave_command(&mut self) {
        if let Some(placing) = self.placing.as_deref_mut() {
            if placing.heres.len() > placing.texts.len() {
                placing.heres.pop();
            }
        }
    }

    /// Say that the script or code about to be read is what `source` says
    /// of the arguments of the unit at `unit` of the split (see
    /// [`Placing::launched`]), until [`Self::launch_done`].
    #[inline(never)]
    pub(crate) fn launch(&mut self, unit: usize, source: Source) {
        let (Some(placing), Some(unit), Some(cut)) =
            (self.placing.as_deref_mut(), self.units.get(unit), source.0)
        else {
            if let Some(placing) = self.placing.as_deref_mut() {
                placing.launcher = None;
            }
            return;
        };
        let words = unit.words.0.as_deref();
        let spot = |at: usize| words.and_then(|words| words.of(&unit.args, at, &placing.spots));
        let from = match cut {
            Cut::Arg { at, offset } => Source::index(at, &unit.args)
                .and_then(spot)
                .map(|spot| From::At(spot, offset)),
            Cut::Join { first, count } => Source::index(first, &unit.args).map(|first| {
                let end = (first + count).min(unit.args.len());
                From::Join(
                    (first..end)
                        .map(|at| (unit.args[at].text().to_string(), spot(at)))
                        .collect(),
                )
            }),
        };
        placing.work += 1 + match &from {
            Some(From::Join(words)) => words.len(),
            _ => 0,
        };
        placing.launcher = from.map(|from| Launcher {
            level: placing.texts.len(),
            from,
        });
    }

    /// Say that the script about to be read is the part of the argument at
    /// `at` of the unit at `unit`, from `offset` on (see
    /// [`Placing::launched`]).
    #[inline(never)]
    pub(crate) fn launch_at(&mut self, unit: usize, at: usize, offset: usize) {
        let (Some(placing), Some(unit)) = (self.placing.as_deref_mut(), self.units.get(unit))
        else {
            return;
        };
        let spot = unit
            .words
            .0
            .as_deref()
            .and_then(|words| words.of(&unit.args, at, &placing.spots));
        placing.work += 1;
        placing.launcher = spot.map(|spot| Launcher {
            level: placing.texts.len(),
            from: From::At(spot, offset),
        });
    }

    /// The script or code [`Self::launch`] named is read.
    #[inline(never)]
    pub(crate) fn launch_done(&mut self) {
        if let Some(placing) = self.placing.as_deref_mut() {
            placing.launcher = None;
        }
    }

    /// Begin reading inline code the unit being launched hands its
    /// interpreter: what the code does is placed at the word that holds it
    /// (see [`Placing::launched`]), or at the command.
    #[inline(never)]
    #[cfg_attr(
        not(feature = "inline"),
        allow(dead_code, reason = "only the reader of inline code reads code")
    )]
    pub(crate) fn enter_code(&mut self) {
        let Some(placing) = self.placing.as_deref_mut() else {
            return;
        };
        let here = code_here(placing);
        placing.heres.push(here);
        // Counted as a text, so `leave_command` does not take it off; it
        // holds no text of the line a grammar reads, and a script the code
        // runs is placed at the code's word as a whole.
        placing.texts.push(Text {
            at: 0,
            len: 0,
            map: Map::whole(0, 0..0),
            broken: true,
        });
    }

    /// The code [`Self::enter_code`] began is read.
    #[inline(never)]
    #[cfg_attr(
        not(feature = "inline"),
        allow(dead_code, reason = "only the reader of inline code reads code")
    )]
    pub(crate) fn leave_code(&mut self) {
        self.end_text();
    }

    /// Keep the word at `range` of the text being read, written `written`
    /// there, which the guard read as `arg`; its place in the spots. `whole`
    /// says the word is that one argument, not one of several it holds.
    #[inline(never)]
    pub(crate) fn spot(
        &mut self,
        range: Range<usize>,
        arg: &Arg,
        written: &str,
        whole: bool,
    ) -> Option<usize> {
        let placing = self.placing.as_deref_mut()?;
        let text = placing.texts.last()?;
        let (map, broken) = (&text.map, text.broken);
        let work = &mut placing.work;
        let (line, fit) = map.locate_counted((range.start, range.end), work);
        // A word the grammar reads as missing is not one the line writes,
        // nor is what a pipeline hands on (`$_`, `<input>`).
        if line.is_empty() || matches!(arg, Arg::Input) {
            return None;
        }
        let reading = arg.text();
        // A word read as nothing is no word that reads as its target. A word
        // only known when it runs reads as its source text, which is the
        // line's only when each byte of it is the line's.
        let known = matches!(arg, Arg::Known(_));
        let whole = whole
            && !broken
            && !reading.is_empty()
            && (fit == Fit::Exact || known && fit == Fit::Ends);
        // The value is the word's own bytes, or the bytes inside its quotes.
        let offset = if !matches!(arg, Arg::Known(_)) || written == reading {
            (written == reading).then_some(0)
        } else {
            let quote = written.chars().next().filter(|c| matches!(c, '\'' | '"'));
            let inner = quote
                .filter(|quote| written.len() >= 2 && written.ends_with(*quote))
                .and_then(|_| written.get(1..written.len() - 1));
            (inner == Some(reading)).then_some(1)
        };
        let value = offset.and_then(|offset| {
            let from = range.start + offset;
            let (value, fit) = map.locate_counted((from, from + reading.len()), work);
            (fit == Fit::Exact).then_some(value.start)
        });
        placing.spots.push(Spot {
            range: line,
            whole,
            value,
            reading: reading.to_string(),
        });
        Some(placing.spots.len() - 1)
    }

    /// Stretch the end of the spot at `at`, a word that ended at `to` of the
    /// text being read, over what the guard took out of the line right
    /// after it (zsh's `(D)` glob qualifier): the word as written holds it.
    #[inline(never)]
    pub(crate) fn spot_past_cut(&mut self, at: Option<usize>, to: usize) {
        let Some(placing) = self.placing.as_deref_mut() else {
            return;
        };
        let past = placing.map().and_then(|map| map.past_cut(to));
        if let (Some(past), Some(spot)) = (past, at.and_then(|at| placing.spots.get_mut(at))) {
            spot.range.end = spot.range.end.max(past);
        }
    }

    /// Where the walk is now, for a unit, a redirect or a finding read
    /// here.
    #[inline(never)]
    pub(crate) fn placed_here(&self) -> Placed {
        Placed(
            self.placing
                .as_deref()
                .map(|placing| Rc::new(placing.here())),
        )
    }

    /// The units at `units` take their input or their output from a
    /// redirect read now: each is placed so that it holds the redirect, as a
    /// command holds its own (`true && nc h 1 < f`: the `nc` is in
    /// `nc h 1 < f`). Kept as the run and the part, and laid over the units
    /// once, when the line is placed (see [`held`]).
    #[inline(never)]
    pub(crate) fn hold_redirect(&mut self, units: Range<usize>) {
        let Some(placing) = self.placing.as_deref_mut() else {
            return;
        };
        if units.is_empty() {
            return;
        }
        let here = placing.here().range;
        // The redirects of one command hold the same units at the same part:
        // `{ a; b; } >f >g` is held once.
        if placing.holds.last() != Some(&(units.clone(), here.clone())) {
            placing.holds.push((units, here));
        }
        placing.work += 1;
    }

    /// Note where the finding about to be added to [`Self::findings`] was
    /// found, and where its target is when the target is a part of the
    /// text being read.
    #[inline(never)]
    pub(crate) fn place_finding(&mut self, target: Option<&str>) {
        let len = self.findings.len();
        let Some(placing) = self.placing.as_deref_mut() else {
            return;
        };
        let mut here = placing.here();
        if let (Some(target), Some(text)) = (target, placing.texts.last()) {
            let at = target.as_ptr() as usize;
            if text.len > 0
                && !target.is_empty()
                && at >= text.at
                && at + target.len() <= text.at + text.len
            {
                let from = at - text.at;
                let (range, fit) = text
                    .map
                    .locate_counted((from, from + target.len()), &mut placing.work);
                here.at = Some((range, fit == Fit::Exact && !text.broken));
            }
        }
        // A finding added another way is placed at the whole line.
        if placing.findings.len() < len {
            let line = Rc::new(Here {
                range: 0..placing.line,
                kind: Kind::Line,
                at: None,
            });
            placing.findings.resize(len, line);
        }
        placing.findings.truncate(len);
        placing.findings.push(Rc::new(here));
    }

    /// Note where the finding about to be added to [`Self::unread`] was
    /// found: at the word that holds the code.
    #[inline(never)]
    pub(crate) fn place_unread(&mut self) {
        let len = self.unread.len();
        if let Some(placing) = self.placing.as_deref_mut() {
            let here = Rc::new(code_here(placing));
            placing.unread.truncate(len);
            placing.unread.resize(len + 1, here);
        }
    }
}

/// The part of the line `code` is read in: the word of the unit being
/// launched that holds it, as its launcher said (see [`Placing::launched`]),
/// or else the part being read.
fn code_here(placing: &mut Placing) -> Here {
    let here = placing.here();
    let level = placing.texts.len();
    let found = match placing
        .launcher
        .as_ref()
        .filter(|launcher| launcher.level == level)
        .map(|launcher| &launcher.from)
    {
        Some(From::At(at, _)) => placing.spots.get(*at).map(|spot| spot.range.clone()),
        Some(From::Join(words)) => {
            let ranges: Option<Vec<Range<usize>>> = words
                .iter()
                .map(|(_, at)| Some(placing.spots.get((*at)?)?.range.clone()))
                .collect();
            ranges.and_then(|ranges| Some(ranges.first()?.start..ranges.last()?.end))
        }
        None => None,
    };
    placing.work += 1;
    match found {
        Some(range) => Here {
            range,
            kind: Kind::Part,
            at: None,
        },
        None => here,
    }
}

/// An argument of the split, by its place: the program or an argument of
/// a unit, or the file of a redirect. [`crate::detect`] tells which one a
/// rule was handed by where it is in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owned {
    Arg {
        unit: usize,
        at: usize,
    },
    Program(usize),
    Write(usize),
    Read(usize),
    /// A file redirected onto units, by its place in `Split::redirects`.
    Redirect(usize),
}

/// What the rule that made a finding judged, when it was a word of the
/// line: the argument it was handed, or the one it was judging by what it
/// expands to (`{/etc,/usr}`, a pattern, a variable's values) when the
/// target is one of those values, which the argument's word holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ident {
    Is(Owned),
    Holds(Owned),
    /// The finding is about what the unit at this place in `Split::units`
    /// does and what the unit it was found in does together (a secret one
    /// reads and the other sends): it holds both.
    Spans(usize),
}

/// Where a finding of the line came from, for its range when no word of it
/// is what it judged: the step of [`crate::detect`] that found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// What splitting found, by its place in [`Split::findings`].
    Line(usize),
    /// What the unit at this place in [`Split::units`] found.
    Unit(usize),
    /// What the read through `<` at this place in [`Split::reads`] found.
    Read(usize),
    /// What the write at this place in [`Split::writes`] found.
    Write(usize),
    /// Inline code not read whole, at this place in [`Split::unread`].
    Unread(usize),
    /// Inline Python that imports, at this place in [`Split::importing`].
    Importing(usize),
    /// What a unit's step said of the whole line.
    Whole,
}

/// What part of the line a [`Located`](crate::Located) range covers.
///
/// `#[non_exhaustive]`: a finer kind may be added, so a caller's `match`
/// needs a fallback arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Covers {
    /// The finding's target as the line writes it: the very word the rule
    /// judged (an operand, a flag, a program, a redirect's file), with its
    /// quotes, escapes, tilde, braces or variable, so reading that word as
    /// the guard reads one word gives the target; or the part of the line,
    /// as written, the guard handed on as the target.
    Target,
    /// A part of the line that holds what the finding is about, where no
    /// word of it is known to be what the rule judged: the word that holds
    /// a nested script whose words are not the line's bytes one for one,
    /// the word of inline code, or the command the finding was found in. A
    /// finding with no target and one whose target has no word of its own
    /// are both `Part`.
    Part,
    /// The whole line: the finding is about no one part of it (it cannot
    /// be read, it is too long, or it is empty).
    Line,
}

/// The range of `finding`, whose rule judged `ident` when it judged a word
/// of the line, and which was found at `here`, and what it covers.
fn resolve(
    line: &str,
    reading: &Reading,
    placing: &Placing,
    finding: &Finding,
    ident: Option<Ident>,
    (here, held): (Option<&Here>, &[Option<Range<usize>>]),
) -> (Range<usize>, Covers) {
    let split = &reading.split;
    let spots = &placing.spots;
    let target = finding.target.as_deref();
    // The word the rule judged, while it is in step with what it read.
    let (owned, is) = match ident {
        Some(Ident::Is(owned)) => (Some(owned), true),
        Some(Ident::Holds(owned)) => (Some(owned), false),
        Some(Ident::Spans(other)) => {
            if let (Some(other), Some(here)) = (unit_here(split, held, other), here) {
                let range =
                    other.range.start.min(here.range.start)..other.range.end.max(here.range.end);
                return (range, Covers::Part);
            }
            (None, false)
        }
        None => (None, false),
    };
    let spot = owned.and_then(|owned| {
        let (spot, text) = match owned {
            Owned::Arg { unit, at } => {
                let unit = split.units.get(unit)?;
                return unit.words.0.as_deref()?.of(&unit.args, at, spots);
            }
            Owned::Program(unit) => {
                let unit = split.units.get(unit)?;
                (unit.words.0.as_deref()?.program?, unit.program.text())
            }
            Owned::Write(at) => {
                let write = split.writes.get(at)?;
                (write.spot?, write.target.text())
            }
            Owned::Read(at) => {
                let read = split.reads.get(at)?;
                (read.spot?, read.target.text())
            }
            Owned::Redirect(at) => {
                let redirect = split.redirects.get(at)?;
                (redirect.spot?, redirect.target.text())
            }
        };
        (spots.get(spot)?.reading == text).then_some(spot)
    });
    if let (Some(spot), Some(target)) = (spot.and_then(|at| spots.get(at)), target) {
        // The word itself, when it is the target as written; else the word
        // that holds it.
        let covers = if is && spot.whole && spot.reading == target {
            Covers::Target
        } else {
            Covers::Part
        };
        return (spot.range.clone(), covers);
    }
    let Some(here) = here else {
        return (0..line.len(), Covers::Line);
    };
    if let (Some((range, whole)), Some(_)) = (&here.at, target) {
        let covers = if *whole { Covers::Target } else { Covers::Part };
        return (range.clone(), covers);
    }
    match here.kind {
        Kind::Line => (0..line.len(), Covers::Line),
        Kind::Part => (here.range.clone(), Covers::Part),
    }
}

/// Each finding of `reading`, with its range in `line`.
pub(crate) fn locate(line: &str, reading: &Reading) -> Vec<crate::Located> {
    counted(line, reading).0
}

/// [`locate`], and the steps it and the walk took (see [`Placing::work`]),
/// which `tests/robust.rs` holds to a bound through the `testing` feature.
pub(crate) fn counted(line: &str, reading: &Reading) -> (Vec<crate::Located>, usize) {
    let found = &reading.judged.found;
    let Some(placing) = reading.split.placing.as_deref() else {
        let whole = found
            .iter()
            .map(|finding| crate::Located {
                finding: finding.clone(),
                range: 0..line.len(),
                covers: Covers::Line,
            })
            .collect();
        return (whole, 0);
    };
    let split = &reading.split;
    let origins = &reading.judged.origins;
    let idents = &reading.judged.idents;
    let (held, swept) = held(split.units.len(), &placing.holds);
    let located = found
        .iter()
        .enumerate()
        .map(|(at, finding)| {
            let unit;
            let here: Option<&Here> = match origins.get(at).copied() {
                Some(Origin::Line(at)) => placing.findings.get(at).map(Rc::as_ref),
                Some(Origin::Unit(at)) => {
                    unit = unit_here(split, &held, at);
                    unit.as_ref()
                }
                Some(Origin::Read(at)) => {
                    split.reads.get(at).and_then(|read| read.place.0.as_deref())
                }
                Some(Origin::Write(at)) => split
                    .writes
                    .get(at)
                    .and_then(|write| write.place.0.as_deref()),
                Some(Origin::Unread(at)) => placing.unread.get(at).map(Rc::as_ref),
                Some(Origin::Importing(at)) => split
                    .importing
                    .get(at)
                    .and_then(|code| code.place.0.as_deref()),
                Some(Origin::Whole) | None => None,
            };
            let ident = idents.get(finding).copied().flatten();
            let (range, covers) = resolve(line, reading, placing, finding, ident, (here, &held));
            crate::Located {
                finding: finding.clone(),
                range: within_line(line, range),
                covers,
            }
        })
        .collect();
    (located, placing.work + swept + found.len())
}

/// Where the unit at `at` is: its own place, and the redirects it holds
/// (see [`held`]).
fn unit_here(split: &Split, held: &[Option<Range<usize>>], at: usize) -> Option<Here> {
    let place = split.units.get(at)?.place.0.as_deref()?;
    Some(match held.get(at).cloned().flatten() {
        Some(redirect) => Here {
            range: place.range.start.min(redirect.start)..place.range.end.max(redirect.end),
            kind: Kind::Part,
            at: None,
        },
        None => Here {
            range: place.range.clone(),
            kind: place.kind,
            at: place.at.clone(),
        },
    })
}

/// For each of the `units` of the split, the part of the line that holds
/// every redirect it holds (see [`Split::hold_redirect`]), and the steps
/// that took: one sweep over the units, with the runs that hold each kept
/// by where their parts start and end, so a unit inside a thousand groups
/// costs no more than one.
fn held(
    units: usize,
    holds: &[(Range<usize>, Range<usize>)],
) -> (Vec<Option<Range<usize>>>, usize) {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    if holds.is_empty() {
        return (Vec::new(), 0);
    }
    let mut order: Vec<&(Range<usize>, Range<usize>)> = holds.iter().collect();
    order.sort_by_key(|(run, _)| run.start);
    let mut starts = BinaryHeap::new();
    let mut ends = BinaryHeap::new();
    let mut next = order.iter().peekable();
    let mut held = Vec::with_capacity(units);
    for unit in 0..units {
        while let Some((run, here)) = next.next_if(|(run, _)| run.start <= unit) {
            starts.push(Reverse((here.start, run.end)));
            ends.push((here.end, run.end));
        }
        while starts.peek().is_some_and(|Reverse((_, end))| *end <= unit) {
            starts.pop();
        }
        while ends.peek().is_some_and(|(_, end)| *end <= unit) {
            ends.pop();
        }
        held.push(match (starts.peek(), ends.peek()) {
            (Some(Reverse((start, _))), Some((end, _))) => Some(*start..*end),
            _ => None,
        });
    }
    let sorted = holds
        .len()
        .checked_ilog2()
        .map_or(0, |log| log as usize + 1);
    (held, units + holds.len() * (4 + sorted))
}

/// `range` held inside `line` and on its character boundaries, wider where
/// it is not: a range the walk works out is on them, and this keeps a
/// slip from ever making a caller's slice panic.
fn within_line(line: &str, range: Range<usize>) -> Range<usize> {
    let mut start = range.start.min(line.len());
    let mut end = range.end.clamp(start, line.len());
    while !line.is_char_boundary(start) {
        start -= 1;
    }
    while !line.is_char_boundary(end) {
        end += 1;
    }
    start..end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_places_kept_bytes_exactly_and_edited_ones_whole() {
        // `r\<newline>m -rf ~`, joined into `rm -rf ~`.
        let line = Map::exact(10, 0);
        let joined = line.edited(
            &[Edit {
                old: 1..3,
                new: 1..1,
            }],
            8,
        );
        assert_eq!(joined.locate(0, 2), (0..4, Fit::Ends));
        assert_eq!(joined.locate(3, 6), (5..8, Fit::Exact));
        assert_eq!(joined.locate(7, 8), (9..10, Fit::Exact));
        // A two-byte space written as one.
        let spaced = Map::exact(4, 0).edited(
            &[Edit {
                old: 1..3,
                new: 1..2,
            }],
            3,
        );
        assert_eq!(spaced.locate(0, 3), (0..4, Fit::Ends));
        assert_eq!(spaced.locate(2, 3), (3..4, Fit::Exact));
        // A quote put in front of a word.
        let quoted = Map::exact(2, 0).edited(
            &[
                Edit {
                    old: 0..0,
                    new: 0..1,
                },
                Edit {
                    old: 2..2,
                    new: 3..4,
                },
            ],
            4,
        );
        assert_eq!(quoted.locate(0, 4), (0..2, Fit::Ends));
        assert_eq!(quoted.locate(1, 3), (0..2, Fit::Exact));
    }

    #[test]
    fn a_text_placed_whole_widens_every_range_in_it() {
        let whole = Map::whole(8, 4..20);
        assert_eq!(whole.locate(2, 3), (4..20, Fit::Wide));
        // Even the whole text: no word of it ends where it does in the line.
        assert_eq!(whole.locate(0, 8), (4..20, Fit::Wide));
        assert_eq!(Map::whole(0, 4..20).locate(0, 0), (4..20, Fit::Wide));
        let inner = Map::exact(10, 5).slice(2, 4);
        assert_eq!(inner.locate(0, 4), (7..11, Fit::Exact));
    }

    #[test]
    fn words_joined_are_each_placed_as_a_whole_at_their_word() {
        // `eval rm '~'`: `rm ~`, the `~` from the word `'~'` at 8..11.
        let words = [("rm".to_string(), None), ("~".to_string(), None)];
        let spot = |range: Range<usize>, reading: &str| Spot {
            range,
            whole: true,
            value: None,
            reading: reading.to_string(),
        };
        let (rm, home) = (spot(5..7, "rm"), spot(8..11, "~"));
        let joined = Map::joined(&words, &[&rm, &home]);
        assert_eq!(joined.locate(3, 4), (8..11, Fit::Wide));
        assert_eq!(joined.locate(0, 2), (5..7, Fit::Wide));
        assert_eq!(joined.locate(0, 4), (5..11, Fit::Wide));
    }

    #[test]
    fn each_unit_holds_every_redirect_of_the_runs_it_is_in() {
        // Units 0..4; a group of 1..3 at 10..20, one of 1..2 inside it at
        // 12..15, and a run 2..4 that crosses the first at 18..30.
        let holds = [(1..2, 12..15), (1..3, 10..20), (2..4, 18..30)];
        let (held, work) = held(5, &holds);
        assert_eq!(held, [None, Some(10..20), Some(10..30), Some(18..30), None]);
        assert!(work >= 5 + holds.len());
        assert_eq!(super::held(3, &[]), (Vec::new(), 0));
    }

    #[test]
    fn a_text_is_words_joined_only_when_each_is_where_a_space_puts_it() {
        let words = [("rm -rf".to_string(), None), ("~".to_string(), None)];
        assert!(is_joined(&words, "rm -rf ~"));
        assert!(!is_joined(&words, "rm -rf  ~"));
        assert!(!is_joined(&words, "rm -rf ~ x"));
        assert!(!is_joined(&words, "rm -rf"));
    }

    #[test]
    fn a_script_cut_from_an_argument_is_told_by_where_it_is_in_memory() {
        let args = [
            Arg::Known("--eval=rm".to_string()),
            Arg::Known("rm".to_string()),
        ];
        let Some(value) = args[0].known() else {
            unreachable!("a known argument");
        };
        let Source(Some(Cut::Arg { at, offset })) = Source::part(&args[0], &value[7..]) else {
            unreachable!("a part of the argument");
        };
        assert_eq!((Source::index(at, &args), offset), (Some(0), 7));
        // The same text elsewhere is no part of it.
        assert!(Source::part(&args[0], "rm").0.is_none());
        let Source(Some(Cut::Arg { at, .. })) = Source::arg(&args[1]) else {
            unreachable!("an argument");
        };
        assert_eq!(Source::index(at, &args), Some(1));
        assert_eq!(Source::index(at, &args[..1]), None);
        assert!(Source::joined(&[]).0.is_none());
    }

    #[test]
    fn edits_that_do_not_line_up_place_the_text_whole() {
        let map = Map::exact(4, 0).edited(
            &[Edit {
                old: 2..3,
                new: 1..1,
            }],
            3,
        );
        assert_eq!(map.locate(0, 1), (0..4, Fit::Wide));
    }

    #[test]
    fn a_range_is_held_to_the_line_and_its_characters() {
        let line = "é x";
        assert_eq!(within_line(line, 1..2), 0..2);
        assert_eq!(within_line(line, 3..99), 3..4);
        assert_eq!(within_line(line, 9..99), 4..4);
    }

    #[test]
    fn words_out_of_step_with_the_arguments_are_no_word_of_them() {
        let spot = |reading: &str| Spot {
            range: 0..1,
            whole: true,
            value: None,
            reading: reading.to_string(),
        };
        let spots = [spot("a"), spot("b")];
        let words = Words {
            program: None,
            args: vec![Some(0), Some(1)],
        };
        let args = [Arg::Known("a".to_string()), Arg::Known("b".to_string())];
        assert_eq!(words.of(&args, 1, &spots), Some(1));
        // An argument read again another way, or one taken off.
        let changed = [Arg::Known("a".to_string()), Arg::Known("c".to_string())];
        assert_eq!(words.of(&changed, 1, &spots), None);
        assert_eq!(words.of(&args[..1], 0, &spots), None);
    }
}
