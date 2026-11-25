//! Code read whole that does nothing risky is safe. The cases are in
//! `tests/cases/safe.cases`.

mod common;

#[test]
fn code_read_whole_that_does_nothing_risky_is_safe() {
    common::cases::check("safe");
}
