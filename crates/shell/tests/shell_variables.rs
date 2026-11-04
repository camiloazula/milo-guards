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

use common::{assert_linear, check, posix, Maker};
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

/// `count` scaled to a line of `size`: the count a line of 64 KB has.
fn at(count: usize, size: usize) -> usize {
    count * size / (64 * 1024)
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
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_line_that_sets_bash_env_or_moves_over_and_over_is_judged_within_a_bound() {
    // At 64 KB each line holds the counts written here (`at`), at 16 KB a
    // quarter of them: the one must take about four times as long as the
    // other, not sixteen.
    let lines: [(&str, Maker); 7] = [
        ("BASH_ENV=e; … bash; …", &|size| {
            format!(
                "echo x>e;{}{}",
                "BASH_ENV=e;".repeat(at(3000, size)),
                "bash;".repeat(at(6000, size))
            )
        }),
        ("BASH_ENV=e<n>; … bash; …", &|size| {
            format!(
                "{}{}",
                names("BASH_ENV=e", ";", at(2500, size)),
                "bash;".repeat(at(5000, size))
            )
        }),
        ("BASH_ENV=e; … :; …", &|size| {
            format!(
                "{}{}",
                "BASH_ENV=e;".repeat(at(3000, size)),
                ":;".repeat(at(15000, size))
            )
        }),
        ("cd abcdefgh; …", &|size| {
            "cd abcdefgh; ".repeat(at(4000, size))
        }),
        ("cd a; ls; …", &|size| "cd a; ls; ".repeat(at(5000, size))),
        ("cd 'd$(x)'; cd abcdefgh; …", &|size| {
            format!("cd 'd$(x)'; {}", "cd abcdefgh; ".repeat(at(4000, size)))
        }),
        ("cd \"$x\"; cd a; … ls", &|size| {
            format!("{}ls", "cd \"$x\"; cd a; ".repeat(at(3000, size)))
        }),
    ];
    for (what, line) in lines {
        assert_linear(what, Shell::Posix, &posix(), line);
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_line_that_reads_values_again_over_and_over_is_judged_within_a_bound() {
    // At 64 KB each line holds the counts written here (`at`), at 16 KB a
    // quarter of them: the one must take about four times as long as the
    // other, not sixteen.
    let chain = |count: usize| {
        (0..count).fold(String::new(), |mut line, at| {
            use std::fmt::Write;
            let _ = write!(line, "a{at}=a{};", at + 1);
            line
        })
    };
    let lines: [(&str, Maker); 7] = [
        // A value that names more variables than are followed.
        ("x='v0 v1 …'; echo $((x)); …", &|size| {
            format!(
                "x='{}'; {}",
                names("v", " ", at(6000, size)),
                "echo $((x));".repeat(at(2000, size))
            )
        }),
        // The same plain value read again and again.
        ("x=1; echo $((x)); …", &|size| {
            format!("x=1; {}", "echo $((x));".repeat(at(5000, size)))
        }),
        // An expression that names many variables the line does not set.
        ("echo $((v0+v1+…))", &|size| {
            format!("echo $(({}))", names("v", "+", at(9000, size)))
        }),
        // Values that name each other, read again and again.
        ("a0=a1; …; echo $((a0)); …", &|size| {
            format!(
                "{}{}",
                chain(at(2500, size)),
                "echo $((a0));".repeat(at(2000, size))
            )
        }),
        // Code read again and again, past the budget of nested scripts.
        ("x='a[$(:)]'; echo $((x)); …", &|size| {
            format!("x='a[$(:)]'; {}", "echo $((x));".repeat(at(5000, size)))
        }),
        ("echo \"${x:-'$(:)'}\"; …", &|size| {
            "echo \"${x:-'$(:)'}\"; ".repeat(at(3000, size))
        }),
        ("x='$(:)'; echo \"${x@P}\"; …", &|size| {
            format!("x='$(:)'; {}", "echo \"${x@P}\";".repeat(at(4000, size)))
        }),
    ];
    for (what, line) in lines {
        assert_linear(what, Shell::Posix, &posix(), line);
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
