//! Code judged on a Mac's and a Windows machine's paths. The cases are in
//! `tests/cases/machines.cases`.

mod common;

#[test]
fn code_is_judged_on_the_machine_the_paths_describe() {
    common::cases::check("machines");
}
