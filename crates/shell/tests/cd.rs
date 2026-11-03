//! Where a `cd`, `pushd` or cmd `cd` leaves the line, so the line that
//! follows is judged from there.
//!
//! `pushd` takes its own options before the folder, as `cd` does: `-n` (the
//! stack changes and the shell stays), `-L` and `-P`. None of them is the
//! folder, and an option the guard does not know makes the folder only known
//! when it runs.
//!
//! cmd's `cd` without `/d` sets another drive's working directory and does
//! not leave the drive the line is on, so a later relative path is judged
//! against where the line really is. A path on a drive's own working
//! directory (`D:x`) is unknown, and a `cd` with more than one word goes to
//! the words joined as written.
//!
//! The lines and their answers are in `tests/cases/cd.cases`; here are the
//! paths a line after `pushd` lists.

mod common;

use common::{exact, lists, posix};
use milo_guards_shell::{effect_paths, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("cd");
}

#[test]
fn the_line_after_pushd_is_read_from_where_pushd_leaves_it() {
    let src = "/home/me/work/repo/src";
    lists(
        Shell::Posix,
        &posix(),
        &[
            // `-n` does not move the line.
            (
                "pushd -n ~/.ssh && cat id_rsa",
                vec![exact("/home/me/work/repo/id_rsa")],
            ),
            (
                "pushd -n -P /etc && cat shadow",
                vec![exact("/home/me/work/repo/shadow")],
            ),
            (
                "pushd -nP ~/.ssh && cat src/a.rs",
                vec![exact("/home/me/work/repo/src/a.rs")],
            ),
            ("pushd -n ~/.ssh", vec![]),
            // `-P`, `-L` and `--` move it to the folder written.
            (
                "pushd -P ~/.ssh && cat id_rsa",
                vec![exact("/home/me/.ssh"), exact("/home/me/.ssh/id_rsa")],
            ),
            (
                "pushd -L /etc && cat shadow",
                vec![exact("/etc"), exact("/etc/shadow")],
            ),
            (
                "pushd -P src && cat a.rs",
                vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
            ),
            (
                "pushd -P src && cat ../../x",
                vec![exact(src), exact("/home/me/work/repo/src/../../x")],
            ),
            (
                "pushd -PL src && cat a.rs",
                vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
            ),
            (
                "pushd -- src && cat a.rs",
                vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
            ),
            (
                "pushd -- -P && cat a",
                vec![
                    exact("/home/me/work/repo/-P"),
                    exact("/home/me/work/repo/-P/a"),
                ],
            ),
        ],
    );
}

#[test]
fn no_option_of_pushd_is_listed_as_a_path() {
    let paths = posix();
    for line in [
        "pushd -P src && ls",
        "pushd -L src && ls",
        "pushd -n -P src && ls",
        "pushd -n src && ls",
        "pushd -n",
        "pushd -nL",
        "pushd -- src && ls",
    ] {
        let list = effect_paths(line, Shell::Posix, &paths).unwrap();
        for read in &list {
            let name = read.path.file_name().unwrap_or_default().to_string_lossy();
            assert!(!name.starts_with('-'), "{line}: {list:?}");
        }
    }
}
