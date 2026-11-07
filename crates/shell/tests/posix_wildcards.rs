//! Which names a POSIX wildcard matches. A wildcard skips a dot name unless
//! the pattern starts with a dot, so `*git` is not `.git`; a line can turn
//! hidden names on (`dotglob`, `globdots`, a non-empty `GLOBIGNORE`, set by
//! an assignment, an expansion such as `${GLOBIGNORE:=x}` or arithmetic), and
//! zsh's `(D)` glob qualifier does it for one pattern. With `extendedglob`
//! on in the line, a word with zsh's `#`, `^` or `~` is judged as written and
//! as zsh reads it. A qualifier or an extended glob the guard does not read
//! stays unreadable; POSIX classes and collating elements in a bracket are
//! read as each shell reads them. A listing piped into a delete is judged as
//! the delete of its pattern, and a pattern in a temporary folder picks
//! temporary files.
//!
//! The lines and their answers are in `tests/cases/posix_wildcards.cases`;
//! the time a long run of class openers takes, and a write into a long
//! pattern, is in `tests/timing.rs`.

mod common;

use common::lines::long_pattern_copy;
use common::posix;
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("posix_wildcards");
}

/// A write into a long pattern of folders is judged by its last part: a
/// plain name stays the agent's own, and a file a tool runs on its own is
/// planted wherever the pattern lands.
#[test]
fn a_write_into_a_long_pattern_is_judged_by_where_it_lands() {
    for size in [16 * 1024, 60 * 1024] {
        for part in ["a*/", "**/"] {
            let line = long_pattern_copy(size, part, "x");
            assert!(
                classify(&line, Shell::Posix, &posix()).is_safe(),
                "{part} {size}"
            );
            let line = long_pattern_copy(size, part, ".envrc");
            let found = classify(&line, Shell::Posix, &posix());
            assert!(
                found
                    .findings()
                    .iter()
                    .any(|finding| finding.rule == Rule::Overwrite),
                "{part} {size}: {found:?}"
            );
        }
    }
}
