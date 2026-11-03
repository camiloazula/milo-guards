//! The shell guard without the reader of inline code: the `inline` feature
//! off. The line is still found (`python3 -c CODE`, `node -e CODE`, a
//! here-document fed to an interpreter), but none of the code is read, so
//! every such line is `unknown`, whatever the code is, and neither grammar is
//! built.
//!
//! This test is only compiled without the feature, which `--all-features`
//! never is; `just no-inline` runs it:
//!
//! ```text
//! cargo test -p milo-guards-shell --no-default-features --test inline_off
//! ```
//!
//! The lines and their answers are in `tests/cases/inline_off.cases`.

#![cfg(not(feature = "inline"))]

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_off");
}
