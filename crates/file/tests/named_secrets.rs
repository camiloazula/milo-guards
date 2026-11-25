//! The secrets a caller names (`Paths::secrets`): a read of one breaks
//! `read_secret` in the caller's words, inside the workspace too, however it
//! is spelled, and a write to one `write_sensitive`; a path also protected
//! keeps `write_protected` for a write. The cases are in
//! `tests/cases/named_secrets.cases`.

mod common;

#[test]
fn a_read_of_a_named_secret_is_a_read_of_a_key() {
    common::cases::check("named_secrets");
}
