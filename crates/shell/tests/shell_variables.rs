//! Variables a shell runs or expands later. `PS4` and `BASH_ENV` hold text a
//! shell runs later: `$(…)` in `PS4` runs with each `set -x` line, and
//! `BASH_ENV` is expanded and then run as a script by every non-interactive
//! bash, so a `BASH_ENV` file is a script it runs that the line does not
//! show, by anything that may start bash (inline code among them), and `ENV`
//! one an interactive POSIX sh runs. The value is read as bash reads it:
//! prompt escapes decoded, subscripts of the variable, declarations behind
//! `builtin` and `command`, and `$PWD` as the folder the line moved to, which
//! is plain only when the line wrote that folder out. Arithmetic, `${!x}` and
//! `${x@P}` read any variable's value again, and run the code it holds.
//!
//! The lines and their answers are in `tests/cases/shell_variables.cases`;
//! here are the lines made of many assignments or reads, the time they take,
//! and the bounds past which a value is only known when it runs.

mod common;

use std::time::Duration;

use common::{check, posix, took};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("shell_variables");
}

/// `count` words, `before`, a number, `after`.
fn names(before: &str, after: &str, count: usize) -> String {
    use std::fmt::Write;
    (0..count).fold(String::new(), |mut line, at| {
        let _ = write!(line, "{before}{at}{after}");
        line
    })
}

#[test]
fn more_bash_env_files_than_are_read_is_unknown() {
    let many = names("BASH_ENV=e", ".sh; ", 40);
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(&format!("{many}bash -c true"), Rule::Unknown)],
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_line_that_sets_bash_env_or_moves_over_and_over_is_judged_within_a_bound() {
    let distinct = names("BASH_ENV=e", ";", 2500);
    let lines = [
        format!(
            "echo x>e;{}{}",
            "BASH_ENV=e;".repeat(3000),
            "bash;".repeat(6000)
        ),
        format!("{distinct}{}", "bash;".repeat(5000)),
        format!("{}{}", "BASH_ENV=e;".repeat(3000), ":;".repeat(15000)),
        "cd abcdefgh; ".repeat(4000),
        "cd a; ls; ".repeat(5000),
        format!("cd 'd$(x)'; {}", "cd abcdefgh; ".repeat(4000)),
        format!("{}ls", "cd \"$x\"; cd a; ".repeat(3000)),
    ];
    for line in lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &posix());
        assert!(
            took < Duration::from_millis(500),
            "took {took:?} for a line of {} bytes",
            line.len()
        );
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_line_that_reads_values_again_over_and_over_is_judged_within_a_bound() {
    let many = names("v", " ", 6000);
    let chain = (0..2500).fold(String::new(), |mut line, at| {
        use std::fmt::Write;
        let _ = write!(line, "a{at}=a{};", at + 1);
        line
    });
    let lines = [
        // A value that names more variables than are followed.
        format!("x='{many}'; {}", "echo $((x));".repeat(2000)),
        // The same plain value read again and again.
        format!("x=1; {}", "echo $((x));".repeat(5000)),
        // An expression that names many variables the line does not set.
        format!("echo $(({}))", names("v", "+", 9000)),
        // Values that name each other, read again and again.
        format!("{chain}{}", "echo $((a0));".repeat(2000)),
        // Code read again and again, past the budget of nested scripts.
        format!("x='a[$(:)]'; {}", "echo $((x));".repeat(5000)),
        "echo \"${x:-'$(:)'}\"; ".repeat(3000),
        format!("x='$(:)'; {}", "echo \"${x@P}\";".repeat(4000)),
    ];
    for line in lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &posix());
        assert!(
            took < Duration::from_millis(500),
            "took {took:?} for a line of {} bytes",
            line.len()
        );
    }
}

#[test]
fn a_value_past_the_bounds_is_only_known_when_it_runs() {
    let many = names("v", " ", 300);
    let chain = (0..100).fold(String::new(), |mut line, at| {
        use std::fmt::Write;
        let _ = write!(line, "a{at}=a{};", at + 1);
        line
    });
    let distinct = names("x=", ";", 20);
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (&format!("x='{many}'; echo $((x))"), Rule::Unknown),
            (&format!("{chain}echo $((a0))"), Rule::Unknown),
            (&format!("{distinct}echo $((x))"), Rule::Unknown),
        ],
    );
}
