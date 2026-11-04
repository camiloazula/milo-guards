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

#[test]
fn every_case_holds() {
    common::cases::check("windows");
}
