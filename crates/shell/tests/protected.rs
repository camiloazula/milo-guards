//! Paths the caller protects, in every shell. A protected path is its own
//! whatever the line does to it: a delete, a write or a permission change of
//! it is a finding, a read is not. It wins over the workspace it is in, a
//! folder that holds one cannot go whole, a copy, move or link into its
//! folder by its name replaces it, names compare without case, and only a
//! protected folder has something below its name.
//!
//! The lines and their answers, and the sets of protected paths they are
//! judged with, are in `tests/cases/protected.cases`; here is a finding that
//! is not the first of its rule.

mod common;

use common::{classify, posix};
use milo_guards_shell::{Protected, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("protected");
}

/// A permission change of a protected folder says so in the caller's words,
/// beside the finding of the mode itself.
#[test]
fn a_permission_change_of_a_protected_folder_says_so() {
    let paths =
        posix().with_protected([Protected::folder("/home/me/.agent", "the agent's settings")]);
    let line = "chmod 777 ~/.agent/rules";
    let assessment = classify(line, Shell::Posix, &paths);
    assert!(
        assessment
            .findings()
            .iter()
            .any(|finding| finding.rule == Rule::Permissions
                && finding.reason == "changes permissions of the agent's settings"),
        "{line}: {:?}",
        assessment.findings()
    );
}
