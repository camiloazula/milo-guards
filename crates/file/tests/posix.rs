//! Reads and writes judged against a POSIX machine's paths, and a Mac's. The
//! cases are in `tests/cases/posix.cases`; what stays here is made in a loop.

mod common;

use common::{posix, safe};
use milo_guards_file::{judge, Access, Rule};

#[test]
fn a_path_on_a_posix_machine_or_a_mac_gets_its_answer() {
    common::cases::check("posix");
}

#[test]
fn a_path_longer_than_the_limit_is_unreadable() {
    let at_the_limit = "a".repeat(milo_guards_file::MAX_PATH_LEN);
    safe(Access::Read, &posix(), &[&at_the_limit]);
    safe(Access::Write, &posix(), &[&at_the_limit]);
    for long in [
        "a".repeat(milo_guards_file::MAX_PATH_LEN + 1),
        "a/".repeat(milo_guards_file::MAX_PATH_LEN / 2 + 1),
        "../".repeat(5_000) + "etc/shadow",
    ] {
        for access in [Access::Read, Access::Write] {
            let assessment = judge(access, &long, &posix());
            assert_eq!(assessment.findings().len(), 1);
            assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
            // The finding does not carry a path that long.
            assert_eq!(assessment.findings()[0].target, None);
        }
    }
}
