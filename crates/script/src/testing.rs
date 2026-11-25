//! What only the script guard's own tests read, behind the `testing`
//! feature: its tests turn it on (the crate's dev-dependency on itself). It
//! is not part of the API and not for callers: it is hidden from the docs,
//! and may change or go without notice. Nothing here changes what the guard
//! does or answers; it reads counts the guard keeps anyway.

use crate::{assessed, Assessment, Language, Paths};

/// The most places code is judged from.
pub const MAX_PLACES: usize = crate::judge::MAX_PLACES;

/// The most bytes of paths joined to judge one act.
pub const MAX_ACT_BYTES: usize = crate::judge::MAX_ACT_BYTES;

/// The longest path a directory and a name are joined into.
pub const MAX_JOINED: usize = crate::judge::MAX_JOINED;

/// What judging a piece of code cost, and what the guard answered for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Work {
    /// How many times an act was judged: from each place the code may be
    /// in, and from each folder a move that may have failed left it in.
    pub judged: usize,
    /// How many moves the places the code is judged from were built of, in
    /// all.
    pub place_moves: usize,
    /// How many bytes of paths were joined, in all: at most
    /// [`MAX_ACT_BYTES`] for each act.
    pub joined_bytes: usize,
    /// What [`crate::judge`] answers for the code, from the same judging.
    pub answer: Assessment,
}

/// Judge `code` as [`crate::judge`] does, and say what it cost.
pub fn work(language: Language, code: &str, paths: &Paths) -> Work {
    let outcome = crate::judge::judge(language, code, paths);
    Work {
        judged: outcome.judged,
        place_moves: outcome.place_moves,
        joined_bytes: outcome.joined_bytes,
        answer: assessed(outcome.findings),
    }
}
