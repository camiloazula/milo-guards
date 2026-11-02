//! cmd's `cd` without `/d` sets another drive's working directory and does
//! not leave the drive the line is on, so a later relative path is judged
//! against where the line really is. A path on a drive's own working
//! directory (`D:x`) is unknown, and a `cd` with more than one word goes to
//! the words joined as written.

mod common;

use common::check;
use milo_guards_shell::{Paths, Rule, Shell};

/// A machine whose working directory is on `C:` and whose workspaces are on
/// `C:` and `D:`.
fn two_drives() -> Paths {
    Paths::new(
        r"C:\Users\me\repo",
        r"C:\Users\me",
        [r"C:\Users\me\repo", r"D:\ws"],
    )
}

fn deletes(lines: &[&'static str]) -> Vec<(&'static str, Rule)> {
    lines.iter().map(|line| (*line, Rule::Delete)).collect()
}

#[test]
fn a_cd_to_another_drive_without_d_leaves_the_line_where_it_was() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &deletes(&[
            r"cd D:\ws\a\b\c & rd /s /q ..\..",
            r"chdir D:\ws\a\b\c & rd /s /q ..\..",
            r"cd d:\ws\a\b\c & rd /s /q ..\..",
            r"cd D:\ws\a & rd /s /q ..\..\..\Users",
            // It stays on the first drive, so the folder is judged there.
            r"cd /d D:\ws\a & cd C:\x & rd /s /q ..\..",
            r"cd D:\ws\a & cd C:\x & rd /s /q ..\..",
        ]),
    );
}

#[test]
fn a_cd_with_d_or_on_the_same_drive_moves_the_line() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            r"cd /d D:\ws\a & rd /s /q b",
            r"cd /D D:\ws\a & rd /s /q b",
            r"chdir /d D:\ws\a & rd /s /q b",
            r"cd /d D:\ws\a & cd D:\ws\a\b & rd /s /q c",
            r"cd C:\Users\me\repo\a & rd /s /q b",
            r"cd c:\Users\me\repo\a & rd /s /q b",
            r"cd sub & del *.obj",
            r"cd sub\deep & rd /s /q build",
            r"pushd D:\ws\a & rd /s /q b",
            r"D: & cd D:\ws\a & rd /s /q b",
        ],
        &deletes(&[
            r"cd /d D:\ws\a & rd /s /q ..\..",
            r"cd /d D:\ws\a & rd /s /q ..\..\..",
            r"cd C:\Users\me\repo\sub & rd /s /q ..\..",
            r"cd /d D:\ws\a & cd D:\ws\a\b & rd /s /q ..\..",
            r"pushd D:\ws\a\b\c & rd /s /q ..\..\..\..",
        ]),
    );
}

#[test]
fn a_move_to_another_drive_that_may_not_run_is_only_a_guess() {
    // Each really deletes under `C:\Windows`: the move to `D:` does not run
    // (a branch that is not taken, a pipe stage, `start`) or fails, so the
    // `cd C:\Windows` that follows really moves the line.
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &deletes(&[
            r"ver || cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"dir q && cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"if exist q (cd /d D:\ws\a) & cd C:\Windows & rd /s /q System32",
            r"(if exist q cd /d D:\ws\a) & cd C:\Windows & rd /s /q System32",
            r"ver | cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"start cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"ver || pushd D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"ver || D: & cd D:\ws\a & cd C:\Windows & rd /s /q System32",
            r"cd /d D:\ws\nonexist & cd C:\Windows & rd /s /q System32",
            r"pushd D:\ws\a & cd C:\Windows & del /q System32\x.dll",
            r"cd /d D:\ws\a & cd C:\Users\me\repo\x & rd /s /q b",
        ]),
    );
}

#[test]
fn a_cd_that_may_have_changed_the_drive_leaves_the_place_unknown() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &deletes(&[
            // `/d` that is not first, or glued to the path: whether cmd reads
            // it is not known.
            r"cd D:\ws\a /d & rd /s /q b",
            r"cd /dD:\ws\a & rd /s /q b",
            // The drive the line is on is not known after `popd`, a path
            // only known when it runs, or a program only known when it runs.
            r"popd & cd D:\ws\a & rd /s /q b",
            r"cd %X% & cd D:\ws\a & rd /s /q b",
            r"%X% & cd D:\ws\a & rd /s /q b",
        ]),
    );
    // A working directory on no drive: the drive the line is on is not known.
    check(
        Shell::Cmd,
        &Paths::new(r"\\host\share\repo", r"C:\Users\me", [r"D:\ws"]),
        &[],
        &deletes(&[r"cd D:\ws\a & rd /s /q b"]),
    );
}

#[test]
fn a_cd_to_a_drive_alone_without_d_shows_its_folder_and_moves_nothing() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[r"cd D: & del *.obj", r"cd C: & del *.obj"],
        &deletes(&[r"cd /d D: & del *.obj"]),
    );
}

#[test]
fn a_drive_relative_path_is_unknown_in_cmd() {
    // On the drive the line is on, and on another one.
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &deletes(&[
            "del C:x",
            "rd /s /q C:x",
            "del C:*.obj",
            r"del C:..\x",
            "del C:",
            "del D:x",
            "rd /s /q D:b",
            r"del D:..\x",
            "del D:",
            r"cd sub & del C:x",
            r"cd D:\ws\a & del D:x",
            r"cd D:\ws\a & rd /s /q D:b",
            r"cd D:\ws\a && rd /s /q D:b",
            r"cd D:\ws\a & rd /s /q D:b",
            r"(cd D:\ws\a) & rd /s /q D:b",
            r"(cd D:\ws\a & rd /s /q D:b)",
            r"cd D:\ws\a && echo ok & rd /s /q D:b",
            r"dir x & cd D:\ws\a & rd /s /q D:b",
        ]),
    );
    // A write is as unknown as a delete.
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            ("echo hi >> C:x", Rule::Overwrite),
            ("echo hi > D:x", Rule::Overwrite),
        ],
    );
    // The working directory is on `D:`.
    check(
        Shell::Cmd,
        &Paths::new(r"D:\work\repo", r"D:\Users\me", [r"D:\work\repo"]),
        &["del *.obj"],
        &deletes(&["del D:*.obj", "del D:x", "rd /s /q C:x"]),
    );
    // What the guard reads from the line's own folder when it matters is
    // still judged as it lands: a key is a key.
    check(
        Shell::Cmd,
        &Paths::new(r"C:\Users\me", r"C:\Users\me", [r"C:\Users\me\repo"]),
        &[],
        &[
            (r"type C:..\..\.ssh\config", Rule::ReadSecret),
            (r"type C:..\..\.ssh\id_rsa", Rule::ReadSecret),
        ],
    );
}

#[test]
fn a_cd_with_more_than_one_word_goes_to_the_words_joined_as_written() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            "cd My Folder & del *.obj",
            "chdir My Folder & del *.obj",
            "pushd My Folder & del *.obj",
            "cd /d My Folder & del *.obj",
            "cd My  Folder   & del *.obj",
            "cd a b c & del *.obj",
            r"cd My Folder\sub & del x",
            // The spaces are part of the name, so `..` goes up from it.
            r"cd x y\.. & del z",
            r"cd x %USERPROFILE%\.. & del z",
        ],
        &deletes(&[
            r"cd x y\..\..\.. & del z",
            r"cd /d x y\..\..\.. & del z",
            r"pushd x y\..\..\.. & del z",
            r"cd x y\..\.. & del z",
            // A word only known when it runs, or a later `/d`, leaves the
            // folder unknown.
            "cd x %X% & del z",
            "cd %X% y & del z",
            "cd My Folder %X% & del *.obj",
            "cd My /d Folder & del z",
        ]),
    );
}
