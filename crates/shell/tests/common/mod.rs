//! What the tables share: the directories commands run with, and a check
//! that names every row that came out wrong at once.

#![allow(dead_code, unreachable_pub, unused_imports)]

use milo_guards_core::testing;
pub use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_shell::{classify, Paths, Rule, Shell};

/// The rules a line breaks, in order.
pub fn rules(command: &str, shell: Shell, paths: &Paths) -> Vec<Rule> {
    testing::rules(command, |line| classify(line, shell, paths))
}

/// Every `safe` line is safe and every `risky` line breaks its rule; the
/// rows that do not are named together.
pub fn check(shell: Shell, paths: &Paths, safe: &[&str], risky: &[(&str, Rule)]) {
    testing::check(safe, risky, |line| classify(line, shell, paths));
}
