//! How PowerShell hands words to a native program, and what the program
//! gets: a `` `u{…} `` that makes a space PowerShell splits on (in a script,
//! or in one handed on through `cmd /c` or `bash -c`) and the same escape in
//! a path, which is still the place it names; the character a backtick names
//! in an expandable string; each argument of `Write-Output` sent as a line;
//! and a value piped into a client, which says what it is.
//!
//! The lines and their answers are in `tests/cases/powershell_arguments.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("powershell_arguments");
}
