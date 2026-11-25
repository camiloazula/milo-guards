//! A change of permissions or owner beyond the workspace. The cases are in
//! `tests/cases/permissions.cases`.

mod common;

#[test]
fn a_change_of_permissions_beyond_the_workspace_is_permissions() {
    common::cases::check("permissions");
}
