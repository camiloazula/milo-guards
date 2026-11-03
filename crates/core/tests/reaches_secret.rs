//! What reading a folder or a pattern can reach below it: a secret that
//! `place` does not say, since it names only the path itself. A folder read
//! whole (`deep`) holds whatever is below it; a pattern picks what its parts
//! match, by the shell's own rules for hidden names. The cases are in
//! `tests/cases/reaches_secret.cases`.

mod common;

#[test]
fn a_folder_or_a_pattern_reaches_the_secrets_below_it() {
    common::cases::check("reaches_secret");
}
