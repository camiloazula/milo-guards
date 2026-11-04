//! `Resolver::holds_protected`: the protected path a program can reach when
//! it changes files below a folder that the line does not name (a search, a
//! patch, an archive, a recursive copy): one the folder is, is under or
//! holds, whatever else the folder is. The cases are in
//! `tests/cases/holds_protected.cases`.

mod common;

#[test]
fn a_folder_holds_the_protected_paths_below_it() {
    common::cases::check("holds_protected");
}
