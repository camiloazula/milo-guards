//! Reads and writes judged against a Windows machine's paths: every
//! spelling Windows reads as one name must be judged as that name. The cases
//! are in `tests/cases/windows.cases`.

mod common;

#[test]
fn a_path_on_a_windows_machine_gets_its_answer() {
    common::cases::check("windows");
}
