//! A delete or a move of a path beyond the workspace, the workspace itself,
//! a sensitive file or a path only known when the code runs. The cases are
//! in `tests/cases/delete.cases`.

mod common;

#[test]
fn a_delete_beyond_the_workspace_is_delete() {
    common::cases::check("delete");
}
