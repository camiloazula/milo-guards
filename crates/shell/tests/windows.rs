//! PowerShell and cmd lines, judged against a Windows machine's paths: risky
//! PowerShell (`Invoke-Expression` of a download among it), trap and event
//! actions, the aliases and functions a PowerShell line sets, risky cmd, the
//! Windows spellings of a path (case, `/dev`, providers, drive-relative paths,
//! a bare drive, a drive's root, trailing dots and spaces, short names, stream
//! suffixes, long paths, the letters NTFS folds), and scripts run from a place
//! the guard cannot read. Which names a wildcard matches is in
//! `windows_wildcards.rs`, protected paths in `protected.rs`, and the everyday
//! lines that stay safe in the front door's `tests/everyday.rs`.
//!
//! The lines and their answers are in `tests/cases/windows.cases`; the time
//! the shells and interpreters a cmd line starts take is in
//! `tests/timing.rs`.

mod common;

use common::lines::{after, cmd_commands_read_again, names_set_many_times};
use common::windows;
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("windows");
}

#[test]
fn cmd_commands_read_again_are_not_safe() {
    // Each is read again as a statement of its own, holding the rest of the
    // line, and the line still deletes `C:\`. Their time is in
    // `tests/timing.rs`.
    for line in &cmd_commands_read_again() {
        assert!(
            !classify(line, Shell::Cmd, &windows()).is_safe(),
            "{:?}",
            &line[..40]
        );
    }
}

#[test]
fn commands_of_a_name_the_line_sets_many_times_are_unreadable_or_unknown() {
    // Every command may run any of the targets the line sets its name to, so
    // the readings are bounded, and past the bound the line is unreadable.
    // Their time is in `tests/timing.rs`.
    for (head, unit, risky) in &names_set_many_times() {
        if !risky {
            continue;
        }
        let assessment = classify(&after(head, unit, 64 * 1024), Shell::PowerShell, &windows());
        assert!(
            assessment
                .findings()
                .iter()
                .any(|finding| matches!(finding.rule, Rule::Unreadable | Rule::Unknown)),
            "{}… {unit}…: {assessment:?}",
            &head[..20]
        );
    }
}
