//! Code that does not parse is unreadable. The cases are in
//! `tests/cases/unreadable.cases`; code too long or too deep is in
//! `tests/robust.rs`.

mod common;

#[test]
fn code_that_does_not_parse_is_unreadable() {
    common::cases::check("unreadable");
}
