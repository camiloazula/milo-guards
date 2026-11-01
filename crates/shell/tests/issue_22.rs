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
    // Windows PowerShell has no `-wd`: `-wd` itself starts the command text
    // and `C: -c ...` follows it as statements, the line stays in
    // `D:\ws\repo`, and nothing is deleted outside it.
    check(
        Shell::Cmd,
        &d_repo(),
        &[r#"cd C:\Windows & powershell -wd C: -c "Remove-Item System32 -Recurse""#],
        &risky,
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
