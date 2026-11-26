//! A path is read by the rules of the system the shell given is for, never
//! by those of the host the guard runs on: its last name and extension, and
//! the order and the set of the paths `effect_paths` lists, so an answer is
//! the same on every host (see `common::path_disagreement`, which holds
//! every case of every file to a list ordered by its text, read so).
//!
//! The lines and their answers are in `tests/cases/any_host.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("any_host");
}
