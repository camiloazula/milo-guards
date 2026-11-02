//! In PowerShell the grammar reads `>`, `>>`, `2>` to `6>`, `*>` and their
//! doubled forms as redirect operators, but not `1>`, `7>`, or a `>` glued to
//! its word (`x>f`): those come out as words. They are redirects all the
//! same, so each writes its file, and a word that might be one and cannot be
//! told apart makes the line unknown.
//!
//! The lines and their answers are in `tests/cases/powershell_redirects.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("powershell_redirects");
}
