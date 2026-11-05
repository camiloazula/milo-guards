//! What only the shell guard's own tests read, behind the `testing` feature:
//! its tests turn it on (the crate's dev-dependency on itself). It is not
//! part of the API and not for callers: it is hidden from the docs, and may
//! change or go without notice. Nothing here changes what the guard does or
//! answers; it reads counts the guard keeps anyway.

use crate::{assessed, Assessment, Paths, Reading, Shell};

/// How many times the bytes of text the grammars parse for a line their
/// lexers may be handed, beside [`MAX_LEXED_BASE`], before the line is
/// stopped and unreadable ("takes too long to read").
pub const MAX_LEXED: usize = crate::unit::MAX_LEXED;

/// The bytes the grammars' lexers may be handed for any line, beside
/// [`MAX_LEXED`] times its text.
pub const MAX_LEXED_BASE: usize = crate::unit::MAX_LEXED_BASE;

/// The most bytes a grammar is handed at once (more only to end where a
/// character does): a parse sees that it is past [`MAX_LEXED`] only after
/// the piece that took it there.
pub const LEXED_PIECE: usize = crate::unit::LEXED_PIECE;

/// What the grammars read for a line, and what the guard answered for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lexed {
    /// The bytes the grammars' lexers were handed for the line, again or
    /// for the first time: the count [`MAX_LEXED`] holds a line to. It
    /// depends on the line, the shell and the paths only, so it is the same
    /// number on every machine.
    pub handed: usize,
    /// The bytes of text the grammars parsed for the line: the line, and
    /// the scripts and inline code in it.
    pub parsed: usize,
    /// What [`crate::classify`] answers for the line, from the same read.
    pub answer: Assessment,
}

/// Read `line` as [`crate::classify`] does, and say what its grammars'
/// lexers were handed for it (in the line's last read: a line read again,
/// as a PowerShell line that makes a drive is, counts afresh each time).
#[must_use]
pub fn lexed(line: &str, shell: Shell, paths: &Paths) -> Lexed {
    let reading = Reading::new(line, shell, paths, false);
    let (handed, parsed) = reading.split.lexed();
    Lexed {
        handed,
        parsed,
        answer: assessed(reading.judged.found),
    }
}
