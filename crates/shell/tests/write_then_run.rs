//! A script the line writes and then runs is `unknown`: the line writes it,
//! so what it does is not in the line. However it is run (handed to a POSIX
//! shell, run as the program itself by its path, with `powershell -File`,
//! `pwsh -File` or `Invoke-Command -FilePath`, by cmd's look in the working
//! folder before `PATH`), and however it is written (by a redirect, a
//! download, a copy, a write cmdlet's named or positional path). Where the
//! name the line writes cannot be read for sure (a pattern, an operand that
//! may be a list, a name only known when it runs, more patterns than the
//! guard reads), a run that may be of that file is not safe either. The work
//! for each run is bounded whatever the line writes.
//!
//! The lines and their answers are in `tests/cases/write_then_run.cases`;
//! here are the script a finding names, the lines made of many names or
//! patterns, and the timed test.

mod common;

use std::time::Duration;

use common::{check, classify, posix, took, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("write_then_run");
}

/// The finding says the line runs a script it writes, and names the script
/// as the line wrote it.
#[test]
fn the_finding_names_the_script_and_says_why() {
    for (shell, line, script) in [
        (Shell::Posix, "echo 'rm -rf ~' > x.sh; ./x.sh", "./x.sh"),
        (Shell::Posix, "echo hi > x/run; x/run", "x/run"),
        (Shell::Posix, "echo hi > /tmp/x; /tmp/x", "/tmp/x"),
        (Shell::Posix, "echo hi > x.sh; sudo ./x.sh", "./x.sh"),
        (
            Shell::PowerShell,
            "'x' > i.ps1; powershell -File i.ps1",
            "i.ps1",
        ),
        (
            Shell::PowerShell,
            "'x' > i.ps1; pwsh -NoProfile -File .\\i.ps1",
            ".\\i.ps1",
        ),
        (Shell::PowerShell, "'x' > i.ps1; pwsh i.ps1", "i.ps1"),
        (
            Shell::PowerShell,
            "'x' > i.ps1; powershell -File:i.ps1",
            "i.ps1",
        ),
        (
            Shell::PowerShell,
            "'x' > i.ps1; Invoke-Command -FilePath i.ps1",
            "i.ps1",
        ),
        (
            Shell::PowerShell,
            "'x' > i.ps1; & powershell -f i.ps1",
            "i.ps1",
        ),
    ] {
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let assessment = classify(line, shell, &paths);
        assert!(
            assessment.findings().iter().any(|finding| {
                finding.rule == Rule::Unknown
                    && finding.reason == "runs a script the same line writes"
                    && finding.target.as_deref() == Some(script)
            }),
            "{line}: {:?}",
            assessment.findings()
        );
    }
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
        &[(&many, Rule::Unknown)],
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
        &[&repeated_run, &few, &short_name],
        &[
            (&many, Rule::Unknown),
            (&many_before, Rule::Unknown),
            (&long_name, Rule::Unknown),
            (&long_script, Rule::Unknown),
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
        &[&repeated_run, &few],
        &[(&many, Rule::Unknown)],
    );
}

/// Each run on a line costs a bounded amount whatever the line writes, so a
/// long line that writes by patterns and runs scripts is read in time. When
/// each run was matched against every pattern, with each extension, a line of
/// 24 KB took seconds in an optimized build and minutes in a debug one.
#[test]
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
    const LIMIT: Duration = if cfg!(debug_assertions) {
        Duration::from_secs(8)
    } else {
        Duration::from_secs(1)
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
        let elapsed = took(line, *shell, &paths);
        assert!(elapsed < LIMIT, "{what} in {shell:?}: {elapsed:?}");
    }
}
