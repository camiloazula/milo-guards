//! A write beyond the workspace, to a sensitive file, to a file a tool
//! runs on its own, or over a disk. The cases are in
//! `tests/cases/overwrite.cases`.

mod common;

#[test]
fn a_write_beyond_the_workspace_is_overwrite() {
    common::cases::check("overwrite");
}
