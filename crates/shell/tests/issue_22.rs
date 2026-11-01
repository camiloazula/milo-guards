//! cmd's `cd` without `/d` sets another drive's working directory and does
//! not leave the drive the line is on, so a later relative path is judged
//! against where the line really is.

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

#[test]
fn a_cd_to_another_drive_without_d_leaves_the_line_where_it_was() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            (r"cd D:\ws\a\b\c & rd /s /q ..\..", Rule::Delete),
            (r"chdir D:\ws\a\b\c & rd /s /q ..\..", Rule::Delete),
            (r"cd d:\ws\a\b\c & rd /s /q ..\..", Rule::Delete),
            (r"cd D:\ws\a & rd /s /q ..\..\..\Users", Rule::Delete),
            // It stays on the first drive, so the folder is judged there.
            (r"cd /d D:\ws\a & cd C:\x & rd /s /q ..\..", Rule::Delete),
            (r"cd D:\ws\a & cd C:\x & rd /s /q ..\..", Rule::Delete),
        ],
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
            r"cd /d D:\ws\a & cd C:\Users\me\repo\x & rd /s /q b",
            r"cd /d D:\ws\a & cd D:\ws\a\b & rd /s /q c",
            r"cd C:\Users\me\repo\a & rd /s /q b",
            r"cd c:\Users\me\repo\a & rd /s /q b",
            r"cd sub & del *.obj",
            r"cd sub\deep & rd /s /q build",
            r"pushd D:\ws\a & rd /s /q b",
            r"D: & cd D:\ws\a & rd /s /q b",
        ],
        &[
            (r"cd /d D:\ws\a & rd /s /q ..\..", Rule::Delete),
            (r"cd /d D:\ws\a & rd /s /q ..\..\..", Rule::Delete),
            (r"cd C:\Users\me\repo\sub & rd /s /q ..\..", Rule::Delete),
            (
                r"cd /d D:\ws\a & cd D:\ws\a\b & rd /s /q ..\..",
                Rule::Delete,
            ),
            (r"pushd D:\ws\a\b\c & rd /s /q ..\..\..\..", Rule::Delete),
        ],
    );
}

#[test]
fn a_cd_that_may_or_may_not_move_leaves_the_line_somewhere_unknown() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            // `/d` that is not first: whether cmd reads it is not known.
            (r"cd D:\ws\a /d & rd /s /q b", Rule::Delete),
            // The drive the line is on is not known after `popd`.
            (r"popd & cd D:\ws\a & rd /s /q b", Rule::Delete),
        ],
    );
    // A working directory on no drive: the drive the line is on is not known.
    check(
        Shell::Cmd,
        &Paths::new(r"\\host\share\repo", r"C:\Users\me", [r"D:\ws"]),
        &[],
        &[(r"cd D:\ws\a & rd /s /q b", Rule::Delete)],
    );
}
