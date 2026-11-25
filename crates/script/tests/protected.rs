//! The paths the caller protects and the secrets it names, in the caller's
//! words. The cases are in `tests/cases/protected.cases`.

mod common;

#[test]
fn protected_paths_and_named_secrets_are_judged_in_the_callers_words() {
    common::cases::check("protected");
}
