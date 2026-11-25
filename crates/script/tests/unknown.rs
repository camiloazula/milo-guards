//! Code the reader does not follow or does not understand whole is never
//! safe. The cases are in `tests/cases/unknown.cases`.

mod common;

#[test]
fn code_not_read_whole_is_unknown() {
    common::cases::check("unknown");
}
