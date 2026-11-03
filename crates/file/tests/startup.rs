//! Files a tool runs on its own (`.vscode/tasks.json`, `.envrc`, `.husky/*`,
//! `.github/workflows/*`...): a write to one, at any depth in a workspace
//! folder and however it is spelled, is `write_sensitive`; a read is safe;
//! and the files that only run when someone asks (`Makefile`, `justfile`,
//! `package.json`) stay safe. Every spelling a review could try is a case in
//! `tests/cases/startup.cases`.

mod common;

#[test]
fn a_file_a_tool_runs_on_its_own_is_found_however_it_is_spelled() {
    common::cases::check("startup");
}
