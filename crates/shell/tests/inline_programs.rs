//! Inline code that starts a program: the options of the call (`cwd`,
//! `executable`, `shell`), Python library calls that run code, every call of
//! `execa` and `cross-spawn`, a spread in the call, members of a function that
//! starts a program, `os.kill` and `process.kill` of a literal id, the
//! members of `child_process` that run what the reader does not read,
//! `asyncio.subprocess`, a string handed to a timer, the words a program is
//! started with in either quoting, and an environment given to a started
//! program.
//!
//! The lines and their answers are in `tests/cases/inline_programs.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_programs");
}
