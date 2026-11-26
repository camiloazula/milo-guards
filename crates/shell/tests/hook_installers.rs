//! A program that installs a git hook (`pre-commit install`, `lefthook
//! install`, `simple-git-hooks`), sets `core.hooksPath` (`husky`) or
//! rewrites a hook manager's config (`pre-commit autoupdate`) is judged as
//! the write it makes is, in the same rule and words, through every package
//! runner; running the hooks is not.
//!
//! The lines and their answers are in `tests/cases/hook_installers.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("hook_installers");
}
