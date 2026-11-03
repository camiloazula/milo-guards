//! Everyday commands stay safe through the front door: what an agent runs all
//! day in a POSIX shell, in PowerShell and in cmd needs no one to ask. The
//! lines are in `tests/cases/everyday.cases`, read by the shell guard's
//! runner, which also holds each to the shell guard's own agreement checks:
//! its `effect`, `explain` and `effect_paths` agree with `classify`.

#![cfg(feature = "shell")]

#[path = "../../shell/tests/common/mod.rs"]
mod common;

use milo_guards::shell;

#[test]
fn everyday_lines_are_safe() {
    common::cases::check("everyday");
}

#[test]
fn everyday_lines_are_safe_through_the_front_door() {
    let cases = common::cases::load("everyday");
    assert!(!cases.is_empty(), "no everyday cases");
    let wrong: Vec<String> = cases
        .iter()
        .filter(|case| case.expect.safe)
        .filter(|case| !shell::classify(&case.line, case.shell, &case.paths).is_safe())
        .map(|case| {
            format!(
                "{}: not safe through the front door: {:?}",
                case.at, case.line
            )
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
