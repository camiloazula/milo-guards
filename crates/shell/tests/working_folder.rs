//! The folder a wrapper or a runner starts its command in, by an option of
//! its own (`env -C`, `pnpm -C`, `uv --directory`, `Start-Process
//! -WorkingDirectory`, cmd's `start /d`): the command's relative paths are
//! judged from there, and the rest of the line from where it was.
//!
//! The lines and their answers are in `tests/cases/working_folder.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("working_folder");
}
