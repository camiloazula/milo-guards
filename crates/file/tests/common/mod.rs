//! What the tests share: the directories paths are judged against, a check
//! that names every row that came out wrong at once, and (in [`cases`]) the
//! runner of the case files in `tests/cases`.

#![allow(dead_code, unreachable_pub, unused_imports)]

pub mod cases;

use milo_guards_core::testing;
pub use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_file::{judge, Access, Paths, Rule};

/// Every `safe` path is safe for `access`, and every `risky` path breaks
/// its rule; the rows that do not are named together.
pub fn check(access: Access, paths: &Paths, safe: &[&str], risky: &[(&str, Rule)]) {
    testing::check(safe, risky, |path| judge(access, path, paths));
}

/// Every path is safe for `access`.
pub fn safe(access: Access, paths: &Paths, rows: &[&str]) {
    check(access, paths, rows, &[]);
}
