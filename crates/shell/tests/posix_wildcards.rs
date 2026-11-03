//! Which names a POSIX wildcard matches. A wildcard skips a dot name unless
//! the pattern starts with a dot, so `*git` is not `.git`; a line can turn
//! hidden names on (`dotglob`, `globdots`, a non-empty `GLOBIGNORE`, set by
//! an assignment, an expansion such as `${GLOBIGNORE:=x}` or arithmetic), and
//! zsh's `(D)` glob qualifier does it for one pattern. A qualifier or an
//! extended glob the guard does not read stays unreadable; POSIX classes and
//! collating elements in a bracket are read as each shell reads them. A
//! listing piped into a delete is judged as the delete of its pattern, and a
//! pattern in a temporary folder picks temporary files.
//!
//! The lines and their answers are in `tests/cases/posix_wildcards.cases`;
//! here is the time a long run of class openers takes.

mod common;

use std::time::Duration;

use common::{posix, took};
use milo_guards_shell::Shell;

#[test]
fn every_case_holds() {
    common::cases::check("posix_wildcards");
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_long_run_of_posix_class_openers_in_a_word_is_read_in_a_bound() {
    // A bracket whose only `]`s close `[:a:]`-style elements has no end, and
    // each `[` after it must not scan to the end of the word again: a run of
    // them read in minutes before.
    let runs = [
        "[[:a:]".repeat(10_600),
        "[[.x.]".repeat(10_600),
        "[[=x=]".repeat(10_600),
        "[[:alpha:]".repeat(6_300),
        "[[::]".repeat(12_700),
    ];
    for run in runs {
        // `mv` takes a part of the run (the work per word is high in the
        // debug build); the others take the whole of it.
        let short = &run[..12_000];
        for line in [
            format!("mv {short} x"),
            format!("rm -rf {run}"),
            format!("rm -rf **/{run}(D)"),
            format!("shopt -s dotglob; rm -rf **/{run}"),
        ] {
            assert!(line.len() <= 64 * 1024, "{}", line.len());
            let elapsed = took(&line, Shell::Posix, &posix());
            // The read is linear: well under two seconds in the debug build.
            // The quadratic one took ten seconds for the `mv` line alone in
            // a release build, and minutes at the full length.
            assert!(
                elapsed < Duration::from_secs(6),
                "took {elapsed:?} for a line of {} bytes: {}",
                line.len(),
                &line[..line.len().min(40)]
            );
        }
    }
}
