//! A read of a key or a credential. The cases are in
//! `tests/cases/read_secret.cases`.

mod common;

#[test]
fn a_read_of_a_key_is_read_secret() {
    common::cases::check("read_secret");
}
