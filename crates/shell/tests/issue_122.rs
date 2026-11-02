//! A script the line writes to a file named by position (`Set-Content
//! i.ps1 x`, `'x' | Out-File i.ps1`, `New-Item i.ps1 -Value x`) and then runs
//! is the same script as one written with `-Path` or `-FilePath`: the line
//! writes it, so what it does is not in the line. Where the name the line
//! writes cannot be read for sure (a pattern, an operand that may be a list,
//! a name only known when it runs), a run that may be of that file is not
//! safe either.

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_script_written_to_a_positional_path_and_then_run_is_unknown() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // Reading what was written is not running it.
            "Set-Content notes.txt x; Get-Content notes.txt",
            "Set-Content i.ps1 x; Get-Content i.ps1",
            // Nothing is run, or what is run is not what was written.
            "Set-Content out.txt x",
            "Set-Content i.ps1 x",
            "Set-Content i.ps1 x; .\\j.ps1",
            "Set-Content i.ps1 x; powershell -File j.ps1",
            "Set-Content sub\\i.ps1 x; .\\i.ps1",
            "Set-Content i.ps1 x; .\\sub\\i.ps1",
            "New-Item i.ps1 -Value x",
            "'x' | Out-File i.ps1",
            "New-Item -ItemType Directory build; .\\i.ps1",
            "Copy-Item a.ps1 b.ps1; .\\a.ps1",
            // The value is not a file when it cannot be read.
            "Set-Content notes.txt $x; .\\i.ps1",
        ],
        &[
            // The lines of the issue.
            ("Set-Content i.ps1 x; powershell -File i.ps1", Rule::Unknown),
            ("Set-Content i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Add-Content i.ps1 x; pwsh -File i.ps1", Rule::Unknown),
            ("'x' | Out-File i.ps1; pwsh -File i.ps1", Rule::Unknown),
            ("New-Item i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            // The same lines with the file named, which were already unknown.
            (
                "Set-Content -Path i.ps1 -Value x; powershell -File i.ps1",
                Rule::Unknown,
            ),
            ("New-Item -Path i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            // The aliases.
            ("sc i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("ac i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("ni i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            ("'x' | tee i.ps1; .\\i.ps1", Rule::Unknown),
            ("'x' | Tee-Object i.ps1; .\\i.ps1", Rule::Unknown),
            // Every way the file is run.
            ("Set-Content i.ps1 x; & .\\i.ps1", Rule::Unknown),
            ("Set-Content i.ps1 x; . .\\i.ps1", Rule::Unknown),
            ("Set-Content i.ps1 x; .\\i", Rule::Unknown),
            ("Set-Content i.bat x; .\\i", Rule::Unknown),
            ("Set-Content i.ps1 x; pwsh i.ps1", Rule::Unknown),
            (
                "Set-Content i.ps1 x; Invoke-Command -FilePath i.ps1",
                Rule::Unknown,
            ),
            // However the file is spelled.
            ("Set-Content ./i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content I.PS1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content 'i.ps1' x; .\\i.ps1", Rule::Unknown),
            ("Set-Content \"i.ps1\" x; .\\i.ps1", Rule::Unknown),
            ("Set-Content .\\sub\\i.ps1 x; .\\sub\\i.ps1", Rule::Unknown),
            (
                "Set-Content sub\\i.ps1 x; sub\\..\\sub\\i.ps1",
                Rule::Unknown,
            ),
            ("cd sub; Set-Content i.ps1 x; .\\i.ps1", Rule::Unknown),
            // After parameters, whatever they take.
            ("Set-Content -Value x i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "Set-Content -Encoding utf8 i.ps1 x; .\\i.ps1",
                Rule::Unknown,
            ),
            ("Set-Content -NoNewline i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Force i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Foo i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Foo x i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "Out-File i.ps1 -InputObject x; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' | Out-File -Append i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' | Out-File -Width 80 i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' | Out-File -Encoding utf8 i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            ("Add-Content -Path:i.ps1 x; .\\i.ps1", Rule::Unknown),
            // `New-Item` names its file in the folder.
            ("New-Item -Name i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            (
                "New-Item -Path . -Name i.ps1 -Value x; .\\i.ps1",
                Rule::Unknown,
            ),
            (
                "New-Item -Path sub -Name i.ps1 -Value x; .\\sub\\i.ps1",
                Rule::Unknown,
            ),
            (
                "New-Item sub -Name i.ps1 -Value x; .\\sub\\i.ps1",
                Rule::Unknown,
            ),
            ("New-Item -ItemType File i.ps1; .\\i.ps1", Rule::Unknown),
            // A copy or a move by position writes its destination.
            ("Copy-Item a.ps1 i.ps1; .\\i.ps1", Rule::Unknown),
            ("Move-Item a.ps1 i.ps1; .\\i.ps1", Rule::Unknown),
            ("Copy-Item a.ps1 sub; .\\sub\\a.ps1", Rule::Unknown),
            ("Copy-Item -Path a.ps1 i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "Copy-Item -Destination i.ps1 a.ps1; .\\i.ps1",
                Rule::Unknown,
            ),
        ],
    );
}

/// A list of paths reaches the guard as separate words, so a file after the
/// first may be one of them, and the same word may only be a value.
#[test]
fn every_readable_operand_of_a_write_may_be_the_file() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Set-Content a.ps1,b.ps1 x; .\\c.ps1"],
        &[
            ("Set-Content a.ps1,b.ps1 x; .\\b.ps1", Rule::Unknown),
            (
                "Set-Content -Path a.ps1,b.ps1 -Value x; .\\b.ps1",
                Rule::Unknown,
            ),
            ("Out-File a.ps1,b.ps1; .\\b.ps1", Rule::Unknown),
            ("New-Item a.ps1,b.ps1 -Value x; .\\b.ps1", Rule::Unknown),
            (
                "New-Item -Name a.ps1,b.ps1 -Value x; .\\b.ps1",
                Rule::Unknown,
            ),
            (
                "New-Item -Path sub -Name a.ps1,b.ps1; .\\sub\\b.ps1",
                Rule::Unknown,
            ),
            // The value is read as a file too: it is not told from one.
            ("Set-Content notes.txt x.ps1; .\\x.ps1", Rule::Unknown),
        ],
    );
}

/// A pattern writes every file it matches, in its folder.
#[test]
fn a_pattern_written_to_may_be_the_script_that_is_run() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Content *.txt x; .\\i.ps1",
            "Set-Content *.ps1 x; .\\sub\\i.ps1",
            "Set-Content sub\\*.ps1 x; .\\i.ps1",
            "Set-Content *.ps1 x",
            "Copy-Item src\\* dest\\; .\\build.ps1",
        ],
        &[
            ("Set-Content *.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Path *.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            ("Set-Content i*.ps1 x; .\\I1.PS1", Rule::Unknown),
            ("Set-Content ?.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content sub\\*.ps1 x; .\\sub\\i.ps1", Rule::Unknown),
            ("Set-Content *.ps1 x; pwsh -File i.ps1", Rule::Unknown),
            ("Set-Content *.ps1 x; .\\i", Rule::Unknown),
            ("Copy-Item src\\* dest\\; .\\dest\\x.ps1", Rule::Unknown),
        ],
    );
}

/// A name only known when it runs is written by a line that is not safe, so
/// the line is not judged only by its run.
#[test]
fn a_file_named_when_the_line_runs_is_not_safe_to_write_and_run() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Set-Content $f x; .\\i.ps1", Rule::Overwrite),
            ("Add-Content $f x; .\\i.ps1", Rule::Overwrite),
            ("'x' | Out-File $f; .\\i.ps1", Rule::Overwrite),
            ("'x' | Tee-Object $f; .\\i.ps1", Rule::Overwrite),
            ("New-Item $f -Value x; .\\i.ps1", Rule::Overwrite),
            ("New-Item -Name $n -Value x; .\\i.ps1", Rule::Overwrite),
            (
                "New-Item -Path $d -Name i.ps1 -Value x; .\\i.ps1",
                Rule::Overwrite,
            ),
            ("Copy-Item a.ps1 $f; .\\i.ps1", Rule::Overwrite),
            (
                "Set-Content (Join-Path $d i.ps1) x; .\\i.ps1",
                Rule::Overwrite,
            ),
            ("Set-Content \"$d\\i.ps1\" x; .\\i.ps1", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_script_written_to_a_positional_path_and_run_by_a_posix_shell_is_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "Set-Content x.sh 'x'; bash y.sh",
            "Set-Content x.sh 'x'",
            "echo x | tee x.sh",
            "cp -r src/* dest/; bash build.sh",
            "echo x | tee *.log; bash build.sh",
        ],
        &[
            ("Set-Content x.sh 'x'; bash x.sh", Rule::Unknown),
            ("Set-Content x.sh 'x'; sh ./x.sh", Rule::Unknown),
            ("Add-Content x.sh 'x'; bash x.sh", Rule::Unknown),
            ("echo x | tee x.sh; bash x.sh", Rule::Unknown),
            ("echo x | tee *.sh; bash x.sh", Rule::Unknown),
            ("echo x | tee sub/*.sh; bash sub/x.sh", Rule::Unknown),
            ("cp -r src/* dest/; bash dest/x.sh", Rule::Unknown),
        ],
    );
}
