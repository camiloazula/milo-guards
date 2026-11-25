//! The secrets a caller names (`Paths::secrets`), in every shell: a read of
//! one is `read_secret` and sending one `send_secret`, in the caller's words,
//! inside the workspace too, however it is spelled and through a wildcard
//! that can pick it; `effect` reads it as beyond the workspace. A path also
//! protected keeps its protected finding for a write or a delete. The cases
//! are in `tests/cases/named_secrets.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("named_secrets");
}
