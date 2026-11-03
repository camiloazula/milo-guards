//! How code reaches an interpreter: every code flag of node and bun, the
//! operands of `deno eval`, Python 2's `exec`, code an interpreter reads from
//! its input (a here-document, `-i`, `repl`, a debugger), flags that only
//! print a version or help, perl, ruby, php and lua options that take the
//! print flag as their value, runners and bun options in front of the code,
//! hashbang lines, Python coding declarations and carriage returns, `data:`
//! URLs and `NODE_OPTIONS`, and code handed to an interpreter under cmd and
//! PowerShell.
//!
//! The lines and their answers are in `tests/cases/inline_interpreters.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_interpreters");
}
