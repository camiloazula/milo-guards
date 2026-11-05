//! A script the line writes and then runs is `unknown`: the line writes it,
//! so what it does is not in the line. However it is run (handed to a POSIX
//! shell, run as the program itself by its path, with `powershell -File`,
//! `pwsh -File` or `Invoke-Command -FilePath`, by cmd's look in the working
//! folder before `PATH`), and however it is written (by a redirect, a
//! download, a copy, a write cmdlet's named or positional path, a database
//! client's output). Where the name the line writes cannot be read for sure
//! (a pattern, an operand that may be a list, a name only known when it
//! runs, more patterns than the guard reads), a run that may be of that file
//! is not safe either. The work for each run is bounded whatever the line
//! writes.
//!
//! The lines and their answers are in `tests/cases/write_then_run.cases`;
//! here are the script a finding names and the lines made of many names or
//! patterns. The time long lines take is in `tests/timing.rs`.

mod common;

use common::{check, classify, posix, windows};
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
