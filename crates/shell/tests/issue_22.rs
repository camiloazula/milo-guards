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
            // After a `cd /d` to another drive the line is only guessed to
            // be on `D:` (the `cd /d` may not have run), so `cd C:` is not
            // known to leave it, and the folder is not judged on `C:`.
            (
                r"cd /d D:\ws\a & cd C:\Users\me\repo\x & rd /s /q b",
                Rule::Delete,
            ),
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

#[test]
fn a_pushd_to_a_network_path_puts_the_line_on_a_drive_it_does_not_name() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[r"pushd D:\ws\a & rd /s /q b"],
        &[
            (
                r"pushd \\host\share & cd C:\Users\me\repo & rd /s /q build",
                Rule::Delete,
            ),
            (
                r"pushd \\host\share\x & cd C:\Users\me\repo\a & rd /s /q b",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_move_to_another_drive_that_may_not_run_is_only_a_guess() {
    // Each really deletes under `C:\Windows`: the move to `D:` does not run
    // (a branch that is not taken, a pipe stage, `start`) or fails, so the
    // `cd C:\Windows` that follows really moves the line.
    let risky: Vec<_> = [
        r"ver || cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
        r"dir q && cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
        r"if exist q (cd /d D:\ws\a) & cd C:\Windows & rd /s /q System32",
        r"if exist q (cd /d D:\ws\a) else (ver) & cd C:\Windows & rd /s /q System32",
        r"(if exist q cd /d D:\ws\a) & cd C:\Windows & rd /s /q System32",
        r"ver | cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
        r"cd /d D:\ws\a | ver & cd C:\Windows & rd /s /q System32",
        r"start cd /d D:\ws\a & cd C:\Windows & rd /s /q System32",
        r"ver || pushd D:\ws\a & cd C:\Windows & rd /s /q System32",
        r"ver || D: & cd D:\ws\a & cd C:\Windows & rd /s /q System32",
        r"cd /d D:\ws\nonexist & cd C:\Windows & rd /s /q System32",
        r"pushd D:\ws\a & cd C:\Windows & del /q System32\x.dll",
        r"ver || cd /d D:\ws\a & cd C:\Windows & del /s /q *.dll",
    ]
    .into_iter()
    .map(|line| (line, Rule::Delete))
    .collect();
    check(Shell::Cmd, &two_drives(), &[], &risky);
}

#[test]
fn a_move_to_the_drive_the_line_is_on_keeps_the_drive_certain() {
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            // None of these can change the drive, so the later `cd D:` is
            // still known to leave the line where it was: the folder is
            // judged on `C:`. Were the drive only a guess, it would not be.
            r"cd /d C:\Users\me\repo\a & cd D:\ws\a & rd /s /q b",
            r"pushd C:\Users\me\repo\a & cd D:\ws\a & rd /s /q b",
        ],
        &[
            (
                r"cd /d C:\Users\me\repo\a & cd D:\ws\a & rd /s /q ..\..",
                Rule::Delete,
            ),
            (
                r"pushd C:\Users\me\repo\a & cd D:\ws\a & rd /s /q ..\..",
                Rule::Delete,
            ),
            // `C:` alone moves to the drive's own folder, which is not
            // known, so this is risky whether the drive is sure or not.
            (r"C: & cd D:\ws\a & rd /s /q ..\..\..\Users", Rule::Delete),
        ],
    );
}

/// The line starts on `D:`; home is on `C:`.
fn home_elsewhere() -> Paths {
    Paths::new(r"D:\ws\repo", r"C:\Users\me", [r"D:\ws\repo"])
}

#[test]
fn a_cd_to_a_place_under_home_goes_to_the_drive_home_is_on() {
    // `%TEMP%` and the like are under home, on `C:`: without `/d` the line
    // stays on `D:`, and the folder is judged there.
    let risky: Vec<_> = [
        r"cd .. & cd %TEMP% & rd /s /q repo",
        r"cd \ & cd %TEMP% & rd /s /q ws",
        r"cd .. & cd %TMP% & rd /s /q repo",
        r"cd .. & cd %LOCALAPPDATA%\Temp & rd /s /q repo",
        r"cd .. & cd %USERPROFILE%\AppData\Local\Temp & rd /s /q repo",
        r"cd .. & cd %APPDATA%\..\Local\Temp & rd /s /q repo",
        r"cd .. & chdir %TEMP% & rd /s /q repo",
        // The drive is only a guess after `cd /d`, so it is not known.
        r"cd /d D:\ws\a & cd %TEMP% & rd /s /q b",
    ]
    .into_iter()
    .map(|line| (line, Rule::Delete))
    .collect();
    check(Shell::Cmd, &home_elsewhere(), &[], &risky);
    // Home on no drive: whether `cd` leaves the line cannot be told.
    check(
        Shell::Cmd,
        &Paths::new(r"D:\ws\repo", r"\\host\share\me", [r"D:\ws\repo"]),
        &[],
        &[(r"cd .. & cd %TEMP% & rd /s /q repo", Rule::Delete)],
    );
    // `pushd` and `cd /d` move onto home's drive, so a later `cd D:` leaves
    // the line there.
    check(
        Shell::Cmd,
        &home_elsewhere(),
        &[],
        &[
            (
                r"pushd %TEMP% & cd D:\ws\repo & rd /s /q ..\..\..",
                Rule::Delete,
            ),
            (
                r"cd /d %TEMP% & cd D:\ws\repo & rd /s /q ..\..\..",
                Rule::Delete,
            ),
        ],
    );
    // On home's own drive it is a plain move.
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            r"cd %TEMP% & rd /s /q x",
            r"cd %USERPROFILE%\AppData\Local\Temp & rd /s /q x",
        ],
        &[],
    );
}

#[test]
fn a_cd_to_a_network_path_leaves_the_line_where_it_was() {
    // cmd refuses a network path as a working directory, so each of these
    // really deletes `C:\Windows\System32`.
    let paths = Paths::new(
        r"C:\Users\me\repo",
        r"C:\Users\me",
        [r"C:\Users\me\repo", r"\\host\share\ws"],
    );
    let risky: Vec<_> = [
        r"cd C:\Windows & cd \\host\share\ws & rd /s /q System32",
        r"cd C:\Windows & chdir \\host\share\ws & rd /s /q System32",
        r"cd C:\Windows & cd /d \\host\share\ws & rd /s /q System32",
        r"cd C:\Windows & cd //host/share/ws & rd /s /q System32",
        r"cd C:\Windows & cd\\host\share\ws & rd /s /q System32",
        // The drive is only a guess here.
        r"cd /d D:\ws\a & cd \\host\share\ws & cd C:\Windows & rd /s /q System32",
    ]
    .into_iter()
    .map(|line| (line, Rule::Delete))
    .collect();
    check(Shell::Cmd, &paths, &[], &risky);
}

#[test]
fn a_powershell_move_to_a_drive_puts_a_later_cmd_on_that_drive() {
    check(
        Shell::PowerShell,
        &two_drives(),
        &[
            r#"Set-Location D:\ws\a; cmd /c "cd D:\ws\a & rd /s /q b""#,
            r#"cd D:\ws\a; cmd /c "cd D:\ws\a & rd /s /q b""#,
            r#"Push-Location D:\ws\a; cmd /c "cd D:\ws\a & rd /s /q b""#,
            r#"Set-Location C:\Users\me\repo\sub; cmd /c "cd C:\Users\me\repo\a & del *.obj""#,
            // A relative move keeps the drive.
            r#"Set-Location sub; cmd /c "cd C:\Users\me\repo\a & del *.obj""#,
        ],
        &[
            // Onto `D:` is a guess, so a `cd C:` is not known to leave it.
            (
                r#"Set-Location D:\ws\a; cmd /c "cd C:\Windows & rd /s /q System32""#,
                Rule::Delete,
            ),
            // A provider path or an unknown one says nothing about the drive.
            (
                r#"Set-Location Env:; cmd /c "cd D:\ws\a & rd /s /q b""#,
                Rule::Delete,
            ),
            (
                r#"Set-Location $x; cmd /c "cd D:\ws\a & rd /s /q b""#,
                Rule::Delete,
            ),
            (
                r#"Set-Location \\host\share; cmd /c "cd D:\ws\a & rd /s /q b""#,
                Rule::Delete,
            ),
        ],
    );
}
