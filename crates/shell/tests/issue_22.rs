//! cmd's `cd` without `/d` sets another drive's working directory and does
//! not leave the drive the line is on, so a later relative path is judged
//! against where the line really is.

mod common;

use common::{check, posix, windows};
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
fn a_cd_to_a_network_path_may_leave_the_line_where_it_was() {
    // cmd may refuse a network path as a working directory, and then each of
    // these deletes `C:\Windows\System32`: where the line is is not known.
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

#[test]
fn a_cd_to_a_device_or_network_path_leaves_the_line_somewhere_unknown() {
    // Nothing shows that cmd refuses `\\?\C:\` or `\\.\C:\` as a working
    // directory, and it may take them, so the folder after one is not known.
    let paths = Paths::new(
        r"C:\Users\me\repo",
        r"C:\Users\me",
        [r"C:\Users\me\repo", r"D:\ws"],
    );
    let risky: Vec<_> = [
        r"cd \\?\C:\Windows & rd /s /q System32",
        r"cd /d \\?\C:\Windows & rd /s /q System32",
        r"chdir \\.\C:\Windows & rd /s /q System32",
        r"cd\\?\C:\Windows & rd /s /q System32",
        r"cd \\.\C:\Windows & rd /s /q System32",
        r"cd //?/C:/Windows & rd /s /q System32",
        r"cd //host/outside & rd /s /q build",
        r"chdir //host/outside & rd /s /q build",
        r"cd /d //host/outside & rd /s /q build",
    ]
    .into_iter()
    .map(|line| (line, Rule::Delete))
    .collect();
    check(Shell::Cmd, &paths, &[], &risky);
}

#[test]
fn a_drive_from_a_system_folder_variable_is_only_a_guess() {
    // Windows may be on `D:`: the `C:` in `%SystemRoot%` is not a drive the
    // line named, so a `cd` to it neither leaves the line where it was nor
    // makes the drive certain.
    let risky: Vec<_> = [
        r"cd %SystemRoot% & rd /s /q System32",
        r"cd %windir%\System32 & del /q *.dll",
        r"cd %SystemDrive%\ & rd /s /q Windows",
        r"cd %ProgramFiles% & rd /s /q x",
        r"cd %ProgramFiles(x86)% & rd /s /q x",
        r"cd %ProgramData% & rd /s /q x",
        r"chdir %SystemRoot% & rd /s /q System32",
        r"cd /d %SystemRoot% & rd /s /q System32",
        r"pushd %SystemRoot% & rd /s /q System32",
    ]
    .into_iter()
    .map(|line| (line, Rule::Delete))
    .collect();
    check(Shell::Cmd, &home_elsewhere(), &[], &risky);
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            // The move to `%SystemRoot%` may land on another drive, where
            // the `cd C:` that follows does not leave it.
            (
                r"cd /d %SystemRoot% & cd C:\Users\me\repo & rd /s /q b",
                Rule::Delete,
            ),
            (
                r"pushd %SystemRoot% & cd C:\Users\me\repo & rd /s /q b",
                Rule::Delete,
            ),
            (
                r"cd %SystemRoot% & cd D:\ws\a & rd /s /q ..\..",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::PowerShell,
        &two_drives(),
        &[],
        &[(
            r#"Set-Location $env:SystemRoot; cmd /c "cd D:\ws\a & rd /s /q b""#,
            Rule::Delete,
        )],
    );
}

#[test]
fn a_tilde_typed_in_cmd_is_a_folder_not_home() {
    // cmd never expands `~`: `~\..\..` from `D:\ws\repo` is `D:\ws`, and the
    // line stays on `D:`. Only a variable (`%USERPROFILE%`, `%TEMP%`) puts a
    // path under home.
    let risky: Vec<_> = [
        r"cd ~\..\.. & rd /s /q repo",
        r"cd ~\..\..\x & rd /s /q repo\y",
        r"cd ~ & rd /s /q ..\..",
        r"chdir ~\.. & rd /s /q repo",
    ]
    .into_iter()
    .map(|line| (line, Rule::Delete))
    .collect();
    check(Shell::Cmd, &home_elsewhere(), &[], &risky);
}

/// The line starts on `D:`; home is on `C:`; the workspaces are `D:\ws\repo`
/// and a folder under home.
fn d_repo() -> Paths {
    Paths::new(
        r"D:\ws\repo",
        r"C:\Users\me",
        [r"D:\ws\repo", r"C:\Users\me\repo"],
    )
}

fn deletes(lines: &[&'static str]) -> Vec<(&'static str, Rule)> {
    lines.iter().map(|line| (*line, Rule::Delete)).collect()
}

#[test]
fn a_drive_switch_the_guard_does_not_read_leaves_the_drive_unknown() {
    // `%SystemDrive%` is `C:` on a default install, and a program that is a
    // drive letter and a colon switches to that drive. The switch is read as
    // one to a drive that is not known, so the `cd C:\Windows` after it is
    // not known to leave the line where it was: each really deletes
    // `C:\Windows\System32`.
    let risky = deletes(&[
        r"%SystemDrive% & cd C:\Windows & rd /s /q System32",
        r"%systemdrive% & cd C:\Windows & del /q System32\x.dll",
        r"%SystemDrive%&cd C:\Windows&rd /s /q System32",
        r#""%SystemDrive%" & cd C:\Windows & rd /s /q System32"#,
        r"%SystemDrive% & cd C:\x & rd /s /q y",
        r"%SystemDrive% & cd %USERPROFILE% & rd /s /q Documents",
        r"cd %USERPROFILE% & %SystemDrive% & rd /s /q Documents",
        // The folder is the drive's own, which is not known.
        r"%SystemDrive% & rd /s /q Windows",
        r#""C:" & cd C:\Windows & rd /s /q System32"#,
    ]);
    check(Shell::Cmd, &d_repo(), &[], &risky);
    check(
        Shell::PowerShell,
        &d_repo(),
        &[],
        &deletes(&[
            r#"cmd /c "%SystemDrive% & cd C:\Windows & rd /s /q System32""#,
            r#"cmd /c "%SystemDrive% & rd /s /q Windows""#,
        ]),
    );
    // The line starts on `C:`: `%SystemDrive%` may still be another drive.
    check(
        Shell::Cmd,
        &Paths::new(
            r"C:\Users\me\repo",
            r"C:\Users\me",
            [r"C:\Users\me\repo", r"D:\ws"],
        ),
        &[],
        &deletes(&[r"%SystemDrive% & cd D:\x & rd /s /q y"]),
    );
}

#[test]
fn a_program_cmd_reads_differently_leaves_the_drive_unknown() {
    // cmd ends the name of a command at `;`, `,` and `=`, and drops `^` and
    // `""` from it: each of these is a drive switch or a `cd /d` or a
    // `pushd` the line does not show.
    let risky = deletes(&[
        r"C:;& cd C:\Windows & rd /s /q System32",
        r"C:,& cd C:\Windows & rd /s /q System32",
        r"C:= & cd C:\Windows & rd /s /q System32",
        r"c^d /d C:\ & cd C:\Windows & rd /s /q System32",
        r"p^ushd C:\ & cd C:\Windows & rd /s /q System32",
        r"cd;/d C:\ & cd C:\Windows & rd /s /q System32",
        r"chdir;/d C:\ & cd C:\Windows & rd /s /q System32",
        r"cd=/d C:\ & cd C:\Windows & rd /s /q System32",
        r#"c""d /d C:\ & cd C:\Windows & rd /s /q System32"#,
        // What it moves to is not known either.
        r"c^d /d C:\Windows & rd /s /q System32",
        r"C:; & rd /s /q Windows",
    ]);
    check(Shell::Cmd, &d_repo(), &[], &risky);
}

#[test]
fn a_program_named_the_usual_way_keeps_the_drive() {
    // A quoted path to a program, a variable that names a place, and a
    // program that ends where cmd ends it say nothing about the drive.
    check(
        Shell::Cmd,
        &d_repo(),
        &[
            r#""C:\Program Files\Git\bin\git.exe" status & cd C:\Windows & rd /s /q build"#,
            r"cd C:\Windows & rd /s /q build",
            r"C:\Windows\System32\where.exe git & cd C:\Windows & rd /s /q build",
        ],
        &[],
    );
}

#[test]
fn a_started_program_runs_in_the_folder_start_names() {
    // After `cd` to a folder on another drive without `/d`, that drive's own
    // working directory is the folder `cd` set: `start /d C:` runs in
    // `C:\Windows`, and a folder on `C:` there is under it.
    let risky = deletes(&[
        r"cd C:\Windows & start /d C: cmd /c rd /s /q System32",
        r"cd C:\Windows & start /d C: /b rd /s /q System32",
        r"cd C:\Windows & start /dC: cmd /c rd /s /q System32",
        r"cd C:\Windows & start /d C:. cmd /c rd /s /q System32",
        r"cd C:\Windows & start /d C:System32 cmd /c del /q *.dll",
        r"cd C:\x & start /d C: cmd /c rd /s /q y",
        r"cd %USERPROFILE% & start /d C: cmd /c rd /s /q Documents",
        r#"cd C:\Windows & start "t" /d C: cmd /c rd /s /q System32"#,
        // The folder is only known when it runs.
        r"start /d %X% cmd /c rd /s /q System32",
        r"start /d C:\Windows cmd /c rd /s /q System32",
    ]);
    check(Shell::Cmd, &d_repo(), &[], &risky);
    check(
        Shell::Cmd,
        &Paths::new(
            r"C:\Users\me\repo",
            r"C:\Users\me",
            [r"C:\Users\me\repo", r"D:\ws"],
        ),
        &[],
        &deletes(&[r"cd D:\x & start /d D: cmd /c rd /s /q y"]),
    );
    // A folder that is known is where the program runs: in the workspace,
    // and out of it.
    check(
        Shell::Cmd,
        &d_repo(),
        &[
            r"start /d D:\ws\repo\sub cmd /c rd /s /q build",
            r"start /d sub cmd /c rd /s /q build",
            r#"start /d "C:\Users\me\repo\sub" cmd /c rd /s /q build"#,
            r"start /d C:\Users\me\repo cmd /c rd /s /q build",
            r"start notepad.exe & rd /s /q build",
            r"start /d C:\Windows notepad.exe & rd /s /q build",
        ],
        &deletes(&[r"start /d C:\Windows\System32 cmd /c rd /s /q ..\..\Windows"]),
    );
}

#[test]
fn a_started_powershell_runs_in_the_folder_its_working_directory_names() {
    let risky = deletes(&[
        r#"cd C:\Windows & pwsh -wd C: -c "Remove-Item System32 -Recurse""#,
        r#"cd C:\Windows & pwsh -WorkingDirectory C: -c "Remove-Item System32 -Recurse""#,
        r#"cd C:\Windows & pwsh -wor C: -c "Remove-Item System32 -Recurse""#,
        r#"cd C:\Windows & pwsh -NoProfile -wd C: -c "Remove-Item System32 -Recurse""#,
        r#"pwsh -wd %X% -c "Remove-Item System32 -Recurse""#,
    ]);
    // Windows PowerShell has no `-wd`: `-wd` itself starts the command text,
    // so its first statement is `-wd C: -c ...`, a command that is not found,
    // which runs nothing. The text is not a statement the guard reads, so
    // the line is risky as unreadable, though nothing is deleted.
    check(Shell::Cmd, &d_repo(), &[], &risky);
    check(
        Shell::Cmd,
        &d_repo(),
        &[],
        &[(
            r#"cd C:\Windows & powershell -wd C: -c "Remove-Item System32 -Recurse""#,
            Rule::Unreadable,
        )],
    );
    check(
        Shell::PowerShell,
        &d_repo(),
        &[
            r#"pwsh -wd D:\ws\repo\sub -c "Remove-Item build -Recurse""#,
            r"Start-Process cmd -WorkingDirectory D:\ws\repo\sub -ArgumentList '/c rd /s /q build'",
        ],
        &deletes(&[
            r#"pwsh -wd C:\Windows -c "Remove-Item System32 -Recurse""#,
            r"Start-Process cmd -WorkingDirectory C:\Windows -ArgumentList '/c rd /s /q System32'",
            r"Start-Process cmd -WorkingDirectory $x -ArgumentList '/c rd /s /q build'",
            r"Start-Process cmd -WorkingDirectory C: -ArgumentList '/c rd /s /q System32'",
        ]),
    );
}

/// Windows PowerShell (`powershell`, version 5.1) has no `-WorkingDirectory`:
/// it reads the first parameter it does not know as the start of the command
/// text, so the statements after it run in the line's own folder. Only `pwsh`
/// runs them in the folder it is given.
#[test]
fn windows_powershell_has_no_working_directory_parameter() {
    let risky = deletes(&[
        r#"powershell -wd C:\Users\me\dev\repo\a\b -c "Get-Date; Remove-Item -Recurse ..\..\x""#,
        r#"powershell -WorkingDirectory C:\Users\me\dev\repo\a\b -Command "Get-Date; Remove-Item -Recurse ..\..\x""#,
        r#"powershell.exe -wd C:\Users\me\dev\repo\a\b -c "ls; Remove-Item -Recurse ..\..\x""#,
        r#"powershell -wo C:\Users\me\dev\repo\a\b -c "Get-Date; Remove-Item -Recurse ..\..\x""#,
        r#"powershell -NoProfile -wd C:\Users\me\dev\repo\a\b -c "Get-Date; Remove-Item -Recurse ..\..\x""#,
    ]);
    check(Shell::PowerShell, &windows(), &[], &risky);
    check(Shell::Cmd, &windows(), &[], &risky);
    // `pwsh` runs the statements in the folder it is given.
    let safe = [
        r#"pwsh -wd C:\Users\me\dev\repo\a\b -c "Get-Date; Remove-Item -Recurse ..\..\x""#,
        r#"pwsh -WorkingDirectory C:\Users\me\dev\repo\a\b -Command "Get-Date; Remove-Item -Recurse ..\..\x""#,
    ];
    check(Shell::PowerShell, &windows(), &safe, &[]);
    check(Shell::Cmd, &windows(), &safe, &[]);
}

/// Windows PowerShell starts the command text at `-wd` (the first parameter it
/// does not know), and every argument after it is part of that text, whatever
/// it looks like: a `-File`, `-WindowStyle` or `-Help` after it is text, so a
/// `;` inside a quoted value after it separates statements that run.
#[test]
fn windows_powershell_reads_everything_after_working_directory_as_command_text() {
    let risky = deletes(&[
        r#"powershell -wd -File "x.ps1; Remove-Item -Recurse C:\Windows""#,
        r"powershell -wd -File x.ps1 ; Remove-Item -Recurse C:\Windows",
        r#"powershell -wd /File "x.ps1; Remove-Item -Recurse C:\Windows""#,
        r#"powershell -wd -WindowStyle "x; Remove-Item -Recurse C:\Windows;" -c Get-Date"#,
        r#"powershell -WorkingDirectory -WindowStyle "x; Remove-Item -Recurse C:\Windows;" -c Get-Date"#,
        r#"powershell -wd -ExecutionPolicy "Bypass; Remove-Item -Recurse C:\Windows;" -c Get-Date"#,
        r#"powershell -wd -InputFormat "Text; Remove-Item -Recurse C:\Windows;" -c Get-Date"#,
        r#"powershell -wd -Help "x; Remove-Item -Recurse C:\Windows""#,
        r#"powershell -wd -? "x; Remove-Item -Recurse C:\Windows""#,
    ]);
    check(Shell::Cmd, &windows(), &[], &risky);
    check(Shell::PowerShell, &windows(), &[], &risky);
    check(
        Shell::Posix,
        &posix(),
        &[],
        &deletes(&[
            r#"powershell -wd -File "x.ps1; Remove-Item -Recurse /etc""#,
            r#"powershell -wd -WindowStyle "x; Remove-Item -Recurse /etc;" -c Get-Date"#,
            r#"powershell -wd -Help "x; Remove-Item -Recurse /etc""#,
        ]),
    );
}

/// Windows PowerShell's command text starts with `-wd` itself, so its first
/// statement is `-wd ...`: a command that is not found, which runs nothing and
/// moves nothing. A `Set-Location` after it is an argument of that statement,
/// never run, so the statements after the first `;` run in the line's own
/// folder (`C:\Windows` here), and each of these really deletes
/// `C:\Windows\System32`.
#[test]
fn windows_powershell_does_not_run_the_statement_that_starts_at_working_directory() {
    let moves = [
        "Set-Location",
        "cd",
        "sl",
        "chdir",
        "Push-Location",
        "pushd",
    ];
    let mut risky: Vec<String> = Vec::new();
    for mover in moves {
        risky.push(format!(
            r"cd /d C:\Windows & powershell -wd {mover} C:\Users\me\dev\repo; Remove-Item -Recurse System32"
        ));
    }
    risky.extend(
        [
            r#"cd /d C:\Windows & powershell -wd "Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32""#,
            r"cd /d C:\Windows & powershell -WorkingDirectory cd C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"cd /d C:\Windows & powershell -NoProfile -wd Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"cd /d C:\Windows & powershell /wd Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"cd /d C:\Windows & powershell -wo Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"cd /d C:\Windows & powershell -work Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"cd /d C:\Windows & powershell -WorkingDir Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"cd /d C:\Windows & powershell.exe -wd Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
        ]
        .map(str::to_string),
    );
    let risky: Vec<_> = risky
        .iter()
        .map(|line| (line.as_str(), Rule::Delete))
        .collect();
    check(Shell::Cmd, &windows(), &[], &risky);
    check(Shell::PowerShell, &windows(), &[], &risky);
    // Read from PowerShell, the same text.
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &deletes(&[
            r"Set-Location C:\Windows; powershell -wd 'Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32'",
            r"Set-Location C:\Windows; powershell.exe -wd 'Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32'",
            r"Set-Location C:\Windows; & powershell -wd 'Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32'",
            r"Set-Location C:\Windows; powershell -wd Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
            r"Set-Location C:\Windows; powershell -wo Set-Location C:\Users\me\dev\repo; Remove-Item -Recurse System32",
        ]),
    );
    // Two drives: the folder it names is not moved to either.
    let two = deletes(&[
        r"cd /d C:\Windows & powershell -wd Set-Location D:\ws\repo; Remove-Item -Recurse System32",
        r"cd /d C:\Windows & powershell -wd Set-Location -Path C:\Users\me\repo; Remove-Item -Recurse System32",
        r"cd /d C:\Windows & powershell -wd Set-Location -LiteralPath C:\Users\me\repo; Remove-Item -Recurse System32",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &two);
    check(Shell::PowerShell, &two_drives(), &[], &two);
    // The text starting at `-wd` is not one the guard reads, so it is risky as
    // unreadable and not guessed to be safe.
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            (
                r"powershell -wd Set-Location C:\Windows; Get-Date",
                Rule::Unreadable,
            ),
            (
                r"cd /d C:\Users\me\dev\repo\a & powershell -wd x; Remove-Item -Recurse b",
                Rule::Unreadable,
            ),
        ],
    );
}

/// A path on a drive's own working directory (`C:name`) is under the folder a
/// `cd` without `/d` set on that drive, which is not the folder the line is
/// in: `cd C:\Users\me\.ssh` from `D:` leaves the line where it was and makes
/// `C:id_rsa` the key.
#[test]
fn a_path_on_a_drive_a_cd_set_is_read_under_the_folder_it_set() {
    // The line starts on `D:`, home is on `C:`.
    let z = d_repo();
    let reads: Vec<_> = [
        r"cd C:\Users\me\.ssh & copy C:id_rsa x.txt",
        r"cd C:\Users\me\.ssh & type C:id_rsa",
        r"cd C:\Users\me & copy C:.ssh\id_rsa x.txt",
        r"cd C:\Users\me & type C:.ssh\id_rsa",
        r"cd c:\Users\me\.ssh & type C:id_ed25519",
        r"cd C:\Users\me\.ssh & type C:id_rsa & cd C:\Users\me\repo",
        r"cd C:\Users\me\.ssh & more < C:id_rsa",
        // A later `cd` on the drive moves from the folder it set.
        r"cd C:\Users\me & cd C:.ssh & type C:id_rsa",
        r"cd C:\Users\me & cd C:.ssh & copy C:id_rsa x.txt",
    ]
    .into_iter()
    .map(|line| (line, Rule::ReadSecret))
    .collect();
    check(Shell::Cmd, &z, &[], &reads);
    // A line that starts on `C:` and moves to `D:` with `cd /d`.
    let x = Paths::new(
        r"C:\Users\me\repo",
        r"C:\Users\me",
        [r"C:\Users\me\repo", r"D:\ws"],
    );
    // `cd D:\x` sets `D:`'s folder and the line stays on `C:`, so `y.txt` is
    // in the workspace, and `D:id_rsa` is `D:\x\id_rsa`: a file of that name
    // outside a key folder is not a place the guard calls a key (as
    // `type D:\x\id_rsa` is not), so it reads safe.
    check(
        Shell::Cmd,
        &x,
        &[
            r"cd D:\x & copy D:id_rsa y.txt",
            r"cd D:\x & type D:id_rsa",
            r"type D:\x\id_rsa",
        ],
        &[],
    );
    // A key folder on `D:` is one (home on `D:`).
    check(
        Shell::Cmd,
        &Paths::new(
            r"C:\Users\me\repo",
            r"D:\Users\me",
            [r"C:\Users\me\repo", r"D:\ws"],
        ),
        &[],
        &[
            (
                r"cd D:\Users\me\.ssh & copy D:id_rsa y.txt",
                Rule::ReadSecret,
            ),
            (r"cd D:\Users\me & type D:.ssh\id_rsa", Rule::ReadSecret),
        ],
    );
    check(
        Shell::Cmd,
        &x,
        &[],
        &[
            // On the drive the line is on, from the folder it moved to.
            (r"cd C:\Users\me\.ssh & type C:id_rsa", Rule::ReadSecret),
            (r"cd /d C:\Users\me\.ssh & type C:id_rsa", Rule::ReadSecret),
            (
                r"cd /d C:\Users\me\.ssh & copy C:id_rsa x.txt",
                Rule::ReadSecret,
            ),
        ],
    );
    // A folder that is not a secret, and a name that is not one.
    check(
        Shell::Cmd,
        &z,
        &[
            r"cd C:\Users\me\repo & type C:notes.txt",
            r"cd C:\Users\me\.ssh & type D:notes.txt",
            r"cd C:\Users\me\.ssh & cd C:\Users\me\repo & type C:notes.txt",
            r"cd C:\Users\me\.ssh & copy x.txt y.txt",
        ],
        &[],
    );
    check(
        Shell::Cmd,
        &x,
        &[
            r"cd /d C:\Users\me\repo\a & type C:notes.txt",
            r"cd /d C:\Users\me\repo\a & del C:*.obj",
            r"cd D:\ws & type D:notes.txt",
        ],
        &[],
    );
    // A delete there is judged under the folder too.
    check(
        Shell::Cmd,
        &z,
        &[r"cd C:\Users\me\repo & rd /s /q C:build"],
        &[
            (r"cd C:\Windows & rd /s /q C:System32", Rule::Delete),
            (r"cd C:\Windows & del /q C:System32\x.dll", Rule::Delete),
            (r"cd C:\Windows & del /s /q C:*.dll", Rule::Delete),
        ],
    );
}

#[test]
fn a_cd_that_may_not_run_does_not_set_the_folder_of_another_drive() {
    // The `cd` sits where it may not run (the right side of `||` or `&&`,
    // an `if`, a pipe stage, behind `start`), or the `rd` runs only because
    // it failed: `D:b` is then the folder `D:` already had, which is not
    // known, and not `D:\ws\a\b`.
    let after_or_and = deletes(&[
        r"cd D:\ws\a || rd /s /q D:b",
        r"cd D:\ws\a || echo no & rd /s /q D:b",
        r"dir x || cd D:\ws\a & rd /s /q D:b",
        r"dir x && cd D:\ws\a & rd /s /q D:b",
        r"dir x 2>nul && cd D:\ws\a & rd /s /q D:b",
        r"echo hi || cd D:\ws\a & rd /s /q D:b",
        // If the first `cd` works, `D:` is `D:\Users`.
        r"cd D:\Users || cd D:\ws\a & rd /s /q D:b",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &after_or_and);
    let in_if = deletes(&[
        r"(if exist x cd D:\ws\a) & rd /s /q D:b",
        r"(if 1==2 cd D:\ws\a) & rd /s /q D:b",
        r"(if a==b (cd D:\ws\a)) & rd /s /q D:b",
        r"if exist x (cd D:\ws\a) else (echo no) & rd /s /q D:b",
        r"if exist x (cd D:\ws\a) & rd /s /q D:b",
        r"if exist x (cd D:\ws\a) & del /q D:b.txt",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &in_if);
    // cmd runs each stage of a pipe in a child cmd.
    let in_pipe = deletes(&[
        r"cd D:\ws\a | echo & rd /s /q D:b",
        r"echo | cd D:\ws\a & rd /s /q D:b",
        r"(cd D:\ws\a | echo) & rd /s /q D:b",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &in_pipe);
    // `start` runs it in a new process.
    let behind_start = deletes(&[
        r"start cd D:\ws\a & rd /s /q D:b",
        r"start /b cd D:\ws\a & rd /s /q D:b",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &behind_start);
    // A redirect target is read under the same folder.
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            (
                r"(if exist x cd D:\ws\a) & echo x > D:b.txt",
                Rule::Overwrite,
            ),
            (r"dir x || cd D:\ws\a & echo x > D:b.txt", Rule::Overwrite),
        ],
    );
    // A `cd` that surely runs still sets the folder: on the left of `&&`,
    // after `&`, in a group.
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            r"cd D:\ws\a && rd /s /q D:b",
            r"cd D:\ws\a & rd /s /q D:b",
            r"(cd D:\ws\a) & rd /s /q D:b",
            r"(cd D:\ws\a & rd /s /q D:b)",
            r"cd D:\ws\a && echo ok & rd /s /q D:b",
            r"dir x & cd D:\ws\a & rd /s /q D:b",
        ],
        &[],
    );
}

#[test]
fn a_cd_given_a_variable_may_name_any_drive() {
    // `%X%` may be `D:\elsewhere`, which replaces the folder `D:` has.
    let risky = deletes(&[
        r"cd D:\ws\a & cd %X% & rd /s /q D:b",
        r#"cd D:\ws\a & cd "%X%" & rd /s /q D:b"#,
        r"cd D:\ws\a & cd D:%X% & rd /s /q D:b",
        r"cd D:\ws\a & cd D:\%X% & rd /s /q D:b",
        r"cd D:\ws\a & chdir %X% & rd /s /q D:b",
        r"cd D:\ws\a & cd !X! & rd /s /q D:b",
        r"cd D:\ws\a & cd %X%\b & rd /s /q D:b",
        r"cd D:\ws\a & cd %~dp0 & rd /s /q D:b",
        r"cd D:\ws\a & set /p X= & cd %X% & rd /s /q D:b",
        r"cd D:\ws\a & cd %X% & cd /d C:\x & rd /s /q D:b",
        r"cd D:\ws\a & cd %X% & del D:b.txt",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &risky);
    check(
        Shell::Cmd,
        &two_drives(),
        &[],
        &[
            (r"cd D:\ws\a & cd %X% & echo x > D:b.txt", Rule::Overwrite),
            (r"cd D:\ws\a & cd %X% & copy x D:b.txt", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_call_may_cd_on_any_drive() {
    // A batch file or a label runs in this very process.
    let risky = deletes(&[
        r"cd D:\ws\a & call x.bat & rd /s /q D:b",
        r"cd D:\ws\a & call :lbl & rd /s /q D:b",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &risky);
}

#[test]
fn a_batch_file_run_without_call_may_cd_on_any_drive_too() {
    // A batch file runs in the line's own process whether or not `call`
    // names it, and a name with no extension may find one through PATHEXT.
    let mut risky = deletes(&[
        r"cd D:\ws\a & x.bat & rd /s /q D:b",
        r"cd D:\ws\a & x.cmd & rd /s /q D:b",
        r"cd D:\ws\a & X.BAT & rd /s /q D:b",
        r#"cd D:\ws\a & "x.bat" & rd /s /q D:b"#,
        r"cd D:\ws\a & D:\ws\x.bat & rd /s /q D:b",
        r"cd D:\ws\a & D:x.bat & rd /s /q D:b",
        r"cd D:\ws\a & x.bat arg & rd /s /q D:b",
        r"cd D:\ws\a & x.bat && rd /s /q D:b",
        r"cd D:\ws\a & x & rd /s /q D:b",
        r"cd D:\ws\a & build & rd /s /q D:b",
        r"cd D:\ws\a & npm install & rd /s /q D:b",
        r"cd D:\ws\a & gradlew build & rd /s /q D:b",
        r"cd D:\ws\a & mvn package & rd /s /q D:b",
        r"cd D:\ws\a & %X% & rd /s /q D:b",
        // What it redirects is read first, but what follows it is after.
        r"cd D:\ws\a & x.bat > nul & rd /s /q D:b",
        r"cd D:\ws\a & x.bat < nul & rd /s /q D:b",
        r"(cd D:\ws\a & x.bat & rd /s /q D:b) > out.txt",
        // On the own drive, with `C:x` read as under the folder.
        r"cd a & x.bat & rd /s /q C:Users",
        r"cd a\b & x.bat & rd /s /q C:..",
        r"cd a\b & npm install & rd /s /q C:..",
        // The same from PowerShell, which hands the line to cmd.
        r#"cmd /c "cd D:\ws\a & x.bat & rd /s /q D:b""#,
    ]);
    risky.extend([
        (
            r"cd D:\ws\a & npm install & echo x > D:b.txt",
            Rule::Overwrite,
        ),
        (
            r"cd D:\ws\a & x.bat & copy C:a.txt D:b.txt",
            Rule::Overwrite,
        ),
    ]);
    check(Shell::Cmd, &two_drives(), &[], &risky);
    check(
        Shell::PowerShell,
        &two_drives(),
        &[],
        &[(
            r#"cmd /c "cd D:\ws\a & x.bat & rd /s /q D:b""#,
            Rule::Delete,
        )],
    );
    // A builtin, a drive switch and a program that is not a batch file run
    // nothing in this process that could `cd`: the folder is still known,
    // and a plain relative path was never affected.
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            r"cd sub & npm install & del *.obj",
            r"cd sub & x.bat & del *.obj",
            r"cd D:\ws\a & echo hi & rd /s /q D:b",
            r"cd D:\ws\a & dir & rd /s /q D:b",
            r"cd D:\ws\a & x.exe & rd /s /q D:b",
            r"cd D:\ws\a & D:\ws\x.exe & rd /s /q D:b",
        ],
        &[],
    );
}

#[test]
fn a_path_on_the_own_drive_is_put_under_the_folder_only_when_every_cd_surely_ran() {
    // If the `cd` did not run, `C:..` is `C:\Users\me\repo\..`, which is
    // `C:\Users\me`, home.
    let risky = deletes(&[
        r"dir x || cd C:\Users\me\repo\a\b & rd /s /q C:..",
        r"dir x || cd C:\Users\me\repo\a\b\c & rd /s /q C:..\..",
    ]);
    check(Shell::Cmd, &two_drives(), &[], &risky);
    // When it surely ran, the folder is followed.
    check(
        Shell::Cmd,
        &two_drives(),
        &[
            r"cd C:\Users\me\repo\a & rd /s /q C:b",
            r"cd C:\Users\me\repo\a && rd /s /q C:b",
        ],
        &[(r"cd C:\Users\me\repo\a & rd /s /q C:..\..", Rule::Delete)],
    );
}
