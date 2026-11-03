//! The spellings a reviewer tries, each a permanent case: whatever the URL
//! parser reads as the host is the host, and a spelling a client could read
//! differently is unreadable. A fix must never silently reopen one. The
//! cases are in `tests/cases/spellings.cases`.

mod common;

#[test]
fn every_case() {
    common::cases::check("spellings");
}
