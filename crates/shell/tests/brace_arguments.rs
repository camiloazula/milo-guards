//! A brace list or a sequence among a program's arguments is read as the
//! words the shell spells it out into, before the program's options are
//! read, for every program: a shell or an interpreter, a launcher, a wrapper
//! and every other. A part only known when the line runs, and a list that
//! makes too many words, is a word only known then.
//!
//! The lines and their answers are in `tests/cases/brace_arguments.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("brace_arguments");
}
