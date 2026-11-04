//! Programs that write a file the line names, beyond the redirects, copies
//! and cmdlets other files hold: each destination is judged where it lands,
//! so one beyond the workspace, in a startup place or protected is
//! `overwrite`, and one inside the workspace stays safe.
//!
//! The lines and their answers are in `tests/cases/writers.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("writers");
}
