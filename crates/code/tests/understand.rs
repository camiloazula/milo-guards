//! Which code is understood: the strict, fail-closed subset. Anything outside
//! it is not understood, and the cases of each language, in
//! `tests/cases/understand.cases`, hold one for every way out of it.

mod common;

#[test]
fn only_code_in_the_subset_is_understood() {
    common::cases::check("understand");
}
