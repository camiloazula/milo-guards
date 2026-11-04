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
//! the time a long run of class openers takes is in `tests/timing.rs`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("posix_wildcards");
}
