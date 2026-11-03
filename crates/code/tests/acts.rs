//! What reading code finds: the acts, in the order the code makes them, with
//! the paths they name. The cases, each code and the acts it must give, are
//! in `tests/cases/acts.cases`.

mod common;

#[test]
fn reading_code_finds_its_acts_in_order() {
    common::cases::check("acts");
}
