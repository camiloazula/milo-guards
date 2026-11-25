//! The directory the code moves to is where the paths after it are read
//! from. The cases are in `tests/cases/directories.cases`.

mod common;

#[test]
fn paths_are_read_from_where_the_code_moved() {
    common::cases::check("directories");
}
