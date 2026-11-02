//! A script the line writes to a file named by position (`Set-Content
//! i.ps1 x`, `'x' | Out-File i.ps1`, `New-Item i.ps1 -Value x`) and then runs
//! is the same script as one written with `-Path` or `-FilePath`: the line
//! writes it, so what it does is not in the line. Where the name the line
//! writes cannot be read for sure (a pattern, an operand that may be a list),
//! a run that may be of that file is not safe either. A write cmdlet with a
//! name only known when it runs, first or later in a list, writes any file,
//! so any script the line runs is `unknown`; so does a line that writes by
//! more patterns than the guard reads. The work for each run is bounded
//! whatever the line writes.

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

/// A name only known when it runs, after the first in a list or as the
/// value, is a file that cannot be placed: the line writes any file.
#[test]
fn a_later_name_only_known_when_the_line_runs_may_be_the_script_that_is_run() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // Nothing is run, or the name is not of a write cmdlet's file.
            "Set-Content notes.txt,$x y",
            "Set-Content notes.txt $x",
            "Set-Content -Path notes.txt -Value $x",
            "Set-Content -Path notes.txt -Value $x; Get-Content notes.txt",
            "Get-Content notes.txt,$x; .\\i.ps1",
            "Write-Output notes.txt,$x; .\\i.ps1",
            "Set-Content -Path notes.txt -Value $x; Get-Process",
            // The value is named: it is not a file.
            "Set-Content -Path notes.txt -Value $x; .\\i.ps1",
            "Set-Content notes.txt -Value $x; .\\i.ps1",
            "New-Item -Path a.txt -Value $x; .\\i.ps1",
        ],
        &[
            ("Set-Content notes.txt,$x y; .\\i.ps1", Rule::Unknown),
            (
                "Set-Content -Path notes.txt,$x -Value y; .\\i.ps1",
                Rule::Unknown,
            ),
            ("Add-Content a.txt,$x y; .\\i.ps1", Rule::Unknown),
            ("New-Item -Path a.txt,$x -Value y; .\\i.ps1", Rule::Unknown),
            // The value is not told from a name in a list.
            ("Set-Content notes.txt $x; .\\i.ps1", Rule::Unknown),
            ("Set-Content a.txt,b.txt $x; .\\i.ps1", Rule::Unknown),
            ("'x' | Out-File a.txt,$x; .\\i.ps1", Rule::Unknown),
            ("'x' | Tee-Object a.txt,$x; .\\i.ps1", Rule::Unknown),
            ("New-Item a.txt,$x -Value y; .\\i.ps1", Rule::Unknown),
            ("New-Item -Name a.txt,$x; .\\i.ps1", Rule::Unknown),
            // A name of a part: a string or an expression.
            ("Set-Content a.txt,\"$d\\x\" y; .\\i.ps1", Rule::Unknown),
            (
                "Set-Content a.txt,(Join-Path $d x) y; .\\i.ps1",
                Rule::Unknown,
            ),
            // Whatever runs it, and wherever it is.
            (
                "Set-Content notes.txt,$x y; powershell -File j.ps1",
                Rule::Unknown,
            ),
            ("Set-Content notes.txt,$x y; .\\sub\\j.ps1", Rule::Unknown),
            ("Set-Content notes.txt,$x y; .\\j", Rule::Unknown),
            ("Set-Content notes.txt,$x y; pwsh j.ps1", Rule::Unknown),
            ("sc notes.txt,$x y; .\\i.ps1", Rule::Unknown),
            ("ac notes.txt,$x y; .\\i.ps1", Rule::Unknown),
            ("ni a.txt,$x -Value y; .\\i.ps1", Rule::Unknown),
        ],
    );
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[("Set-Content a.txt,$x y; bash b.sh", Rule::Unknown)],
    );
}

/// `New-Item` makes each path with each name; past a few dozen files a line
/// is read as making any file.
#[test]
fn a_new_item_of_very_many_files_makes_any_file() {
    let names = |count: usize| {
        (0..count)
            .map(|number| format!("n{number}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let few = format!("New-Item -Path a -Name {}; .\\i.ps1", names(30));
    let many = format!("New-Item -Path a -Name {}; .\\i.ps1", names(70));
    check(
        Shell::PowerShell,
        &windows(),
        &[&few],
        &[
            (&many, Rule::Unknown),
            ("New-Item -Path a -Name n1,n2; .\\a\\n2", Rule::Unknown),
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

/// The same pattern again is one pattern, a few distinct ones are each read,
/// and a line that writes by more than the guard reads, or by a pattern too
/// long to match cheaply, writes any file.
#[test]
fn a_line_that_writes_by_too_many_patterns_writes_any_file() {
    // Distinct patterns, none of which a `.sh` script's name matches.
    let writes = |count: usize| {
        (0..count)
            .map(|number| format!("echo x > *{number}.log; "))
            .collect::<Vec<_>>()
            .concat()
    };
    let repeated = "echo x > *.log; ".repeat(100);
    let few = format!("{}bash b.sh", writes(8));
    let many = format!("{}bash b.sh", writes(9));
    let many_before = format!("bash b.sh; {}", writes(9));
    let long_name = format!("echo x > *{}; bash b.sh", "a".repeat(64));
    let short_name = format!("echo x > *{}; bash b.sh", "a".repeat(60));
    let long_script = format!("echo x > *.log; bash {}", "a".repeat(300));
    let repeated_run = format!("{repeated}bash b.sh");
    check(
        Shell::Posix,
        &posix(),
        &[
            &repeated_run,
            &few,
            &short_name,
            "echo x > *.log; bash b.sh",
        ],
        &[
            (&many, Rule::Unknown),
            (&many_before, Rule::Unknown),
            (&long_name, Rule::Unknown),
            (&long_script, Rule::Unknown),
            ("echo x > *.log; bash b.log", Rule::Unknown),
        ],
    );
    // The same in PowerShell, whose runs are also read with each extension.
    let writes = |count: usize| {
        (0..count)
            .map(|number| format!("sc *{number}.log x; "))
            .collect::<Vec<_>>()
            .concat()
    };
    let few = format!("{}.\\b", writes(8));
    let many = format!("{}.\\b", writes(9));
    let repeated_run = format!("{}.\\b", "sc *.log x; ".repeat(100));
    check(
        Shell::PowerShell,
        &windows(),
        &[&repeated_run, &few, "sc *.log x; .\\b"],
        &[(&many, Rule::Unknown), ("sc *.b* x; .\\b", Rule::Unknown)],
    );
}

/// Each run on a line costs a bounded amount whatever the line writes, so a
/// long line that writes by patterns and runs scripts is read in time. When
/// each run was matched against every pattern, with each extension, a line of
/// 24 KB took seconds in an optimized build and minutes in a debug one.
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_pattern_writes_and_many_runs_are_read_in_time() {
    // A line of this length, whatever it holds, is read in about a tenth of
    // a second in an optimized build, and a debug build takes ten times
    // that; a write by a pattern costs the guard more than a write by a name
    // whatever the runs are (about 0.1 ms in an optimized build).
    const SIZE: usize = 24 * 1024;
    const LIMIT: std::time::Duration = if cfg!(debug_assertions) {
        std::time::Duration::from_secs(8)
    } else {
        std::time::Duration::from_secs(1)
    };
    let fit = |unit: &str, head: &str, tail: &str| {
        let count = (SIZE - head.len() - tail.len()) / unit.len();
        format!("{head}{}{tail}", unit.repeat(count))
    };
    // A write and a run, each `#` in them the number of the pair: distinct
    // patterns, written out one after another.
    let numbered = |write: &str, run: &str| {
        let mut line = String::new();
        let mut number = 0;
        loop {
            let next = format!("{write}{run}").replace('#', &number.to_string());
            if line.len() + next.len() > SIZE {
                return line;
            }
            line += &next;
            number += 1;
        }
    };
    let star_name = format!("{}b", "a*".repeat(28));
    let lines = [
        (
            Shell::PowerShell,
            "a pattern and a run, repeated",
            fit("sc *a x;.\\b;", "", ""),
        ),
        (
            Shell::PowerShell,
            "a pattern that backtracks",
            fit(
                &format!("sc *a*a*a*a*a*a*a*b x;.\\{};", "a".repeat(40)),
                "",
                "",
            ),
        ),
        (
            Shell::PowerShell,
            "a pattern and a run of a script",
            fit("sc *a x;.\\b.ps1;", "", ""),
        ),
        (
            Shell::PowerShell,
            "distinct patterns, each before a run",
            numbered("sc *a# x;", ".\\b;"),
        ),
        (
            Shell::PowerShell,
            "patterns that backtrack, distinct",
            numbered(
                &format!("sc *{star_name}# x;"),
                ".\\aaaaaaaaaaaaaaaaaaaaaaaa;",
            ),
        ),
        (
            Shell::PowerShell,
            "a name only known when it runs, repeated",
            fit("sc a.txt,$x y;.\\b;", "", ""),
        ),
        (
            Shell::PowerShell,
            "a pattern and a run of a long name",
            format!("sc *a x;.\\{}", "a".repeat(SIZE - 20)),
        ),
        (
            Shell::PowerShell,
            "a long pattern and a run of a long name",
            format!(
                "sc *{} x;.\\{}",
                "a*".repeat(SIZE / 8),
                "a".repeat(SIZE / 2)
            ),
        ),
        (
            Shell::Posix,
            "tee a pattern, repeated",
            fit("tee *a;./b;", "", ""),
        ),
        (
            Shell::Posix,
            "a redirect to a pattern, repeated",
            fit("echo x > *a; bash b;", "", ""),
        ),
        (
            Shell::Posix,
            "distinct patterns, each before a run",
            numbered("echo x > *a#;", " bash b;"),
        ),
    ];
    for (shell, what, line) in &lines {
        assert!(line.len() <= SIZE, "{what}: {}", line.len());
        let paths = if *shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let started = std::time::Instant::now();
        let _ = milo_guards_shell::classify(line, *shell, &paths);
        let took = started.elapsed();
        assert!(took < LIMIT, "{what} in {shell:?}: {took:?}");
    }
}
