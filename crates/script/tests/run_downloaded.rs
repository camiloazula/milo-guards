//! Code that runs code it downloads. The cases are in
//! `tests/cases/run_downloaded.cases`.

mod common;

#[test]
fn code_that_runs_code_it_downloads_is_run_downloaded() {
    common::cases::check("run_downloaded");
}
