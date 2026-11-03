//! Where the relative paths of inline code land: `bun --cwd` moves the code
//! first, `os.chdir` and the other ways Python changes directory (`fchdir`,
//! `contextlib.chdir`, a directory handle) move what comes after, a `chdir`
//! is not where the code sits (a function, a loop, a handler), a `chdir` in
//! nested code is read rather than searched for, and a relative read after a
//! `chdir` the reader cannot place is unknown.
//!
//! The lines and their answers are in `tests/cases/inline_cwd.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_cwd");
}
