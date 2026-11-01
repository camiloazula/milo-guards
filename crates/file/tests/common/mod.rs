//! What the tables share: the directories paths are judged against, and a
//! check that names every row that came out wrong at once.

#![allow(dead_code, unreachable_pub, unused_imports)]

use milo_guards_core::testing;
pub use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_file::{judge, Access, Paths, Rule};

/// Every `safe` path is safe for `access`, and every `risky` path breaks
/// its rule; the rows that do not are named together.
pub fn check(access: Access, paths: &Paths, safe: &[&str], risky: &[(&str, Rule)]) {
    testing::check(safe, risky, |path| judge(access, path, paths));
}

/// The rules `path` breaks for `access`, in order.
pub fn rules(access: Access, paths: &Paths, path: &str) -> Vec<Rule> {
    testing::rules(path, |path| judge(access, path, paths))
}

/// Every path is safe for `access`.
pub fn safe(access: Access, paths: &Paths, rows: &[&str]) {
    check(access, paths, rows, &[]);
}

/// Every path breaks its rule for `access`.
pub fn risky(access: Access, paths: &Paths, rows: &[(&str, Rule)]) {
    check(access, paths, &[], rows);
}

/// Every path breaks exactly the rules listed, in order, for `access`.
pub fn exactly(access: Access, paths: &Paths, rows: &[(&str, &[Rule])]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(path, expected)| {
            let got = rules(access, paths, path);
            (got != *expected).then(|| format!("{path}: expected {expected:?}, got {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
