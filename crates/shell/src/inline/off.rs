//! The shell guard without the reader of inline code (the `inline` feature
//! off): the interpreter's line is found as it always is, and none of its
//! code is read, so every inline line is `unknown`, as code that is not read
//! whole is.

use super::Code;
use crate::unit::{Arg, Split};

/// The languages the guard finds code in by the interpreter's name; none is
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    Python,
    JavaScript,
}

/// Code given with a flag is not read: the line is `unknown`, unless it has
/// a finding of its own.
pub(crate) fn apply_all(split: &mut Split, _language: Language, code: &Code, _depth: usize) {
    split.unread_code(code.pieces.first().map_or("", Arg::text));
}

/// Code an interpreter takes from its input is not read either.
pub(crate) fn apply_input(split: &mut Split, _language: Language, code: &str, _depth: usize) {
    split.unread_code(code);
}

/// Nothing tells a `data:` URL that runs where it is written from any other
/// module, so every module an option loads counts as one that is not read:
/// the line is `unknown`, as node loading code from a `data:` URL is.
pub(crate) fn is_data_url(_specifier: &str) -> bool {
    true
}

/// Nothing tells a module the workspace owns from one outside it, or one
/// downloaded, so every module an option or a `PYTHONPATH` names counts as
/// outside it: the line is `unknown`.
pub(crate) fn is_foreign_module(_specifier: &str) -> bool {
    true
}
