//! What the caller gates with: a write to it breaks `write_protected` with
//! the caller's words, wherever it sits and however it is spelled, and a read
//! of it is safe. The cases are in `tests/cases/protected.cases`.

mod common;

#[test]
fn a_protected_path_is_the_callers_whatever_it_is_spelled() {
    common::cases::check("protected");
}
