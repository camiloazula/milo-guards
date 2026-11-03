//! PowerShell and cmd lines, judged against a Windows machine's paths: risky
//! PowerShell (`Invoke-Expression` of a download among it), trap and event
//! actions, risky cmd, the Windows spellings of a path (case, `/dev`,
//! providers, drive-relative paths, a bare drive, a drive's root, trailing
//! dots and spaces, short names, stream suffixes, long paths, the letters
//! NTFS folds), and scripts run from a place the guard cannot read. Which
//! names a wildcard matches is in `windows_wildcards.rs`, protected paths in
//! `protected.rs`, and the everyday lines that stay safe in the front door's
//! `tests/everyday.rs`.
//!
//! The lines and their answers are in `tests/cases/windows.cases`; this file
//! times the shells and interpreters a cmd line starts.

mod common;

use common::{assert_linear, filled, windows};
use milo_guards_shell::Shell;

#[test]
fn every_case_holds() {
    common::cases::check("windows");
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn shells_and_interpreters_a_cmd_line_starts_are_read_in_linear_time() {
    // Each program's arguments are split again as the C runtime splits
    // them, and each script a shell is handed read in the POSIX grammar; a
    // shell handed an input hands it on to its script.
    let paths = windows();
    for part in [
        "bash -c \"echo \\\"a\\\"; rm -rf x\" & ",
        "uv run bash -c \"echo \\\"a\\\"; rm -rf x\" & ",
        "type x.py | cmd /c python & ",
        "cmd /c bash -c \"echo \\\"a\\\"\" < x & ",
    ] {
        assert_linear(part, Shell::Cmd, &paths, |size| filled(part, size, 0));
    }
    // A PowerShell line hands cmd its words as one command line.
    let part = "cmd /c bash -c \"echo a; rm -rf x\"; ";
    assert_linear(part, Shell::PowerShell, &paths, |size| {
        filled(part, size, 0)
    });
    let part = "\\\"";
    assert_linear("python \\\"\\\"…", Shell::Cmd, &paths, |size| {
        format!("python -c \"{}\"", filled(part, size, 16))
    });
}
