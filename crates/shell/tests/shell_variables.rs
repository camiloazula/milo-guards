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
//! here are the bounds past which a value is only known when it runs. The
//! time the lines made of many assignments or reads take is in
//! `tests/timing.rs`.

mod common;

use common::lines::names;
use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("shell_variables");
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
