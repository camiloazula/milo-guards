//! Inline reads of keys: code that reads a key is a read of it
//! (`read_secret`), as the shell command that reads the same file is; so is
//! a read of a path that starts in a folder of keys. A delete or a write to a
//! path the reader cannot work out is judged as `rm -rf "$DIR"` is: a place
//! unknown. A read fails closed the same way: code that opens a file whose
//! path the guard does not fully know (a call or a name it does not follow,
//! the command line, a loop or a listing, a `%` or `format` of a part that is
//! not a literal, a name bound another way than to a string, a spread in a
//! join, a call it has no row for) is `unknown`, unless the part it does know
//! already lies in a place that holds a key. A key handed to a started
//! program is read as the program reads it. Only code the reader fully
//! understands is safe.
//!
//! The lines and their answers are in `tests/cases/inline_secrets.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_secrets");
}
