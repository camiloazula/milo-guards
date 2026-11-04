//! The text a database client gets, read as the client gets it: what
//! `printf` and `echo` print (their escapes, octal, and what a shell leaves as
//! written), what `cat` passes on, here-documents and templates, every program
//! of a stage and every client after it, SQL that runs SQL it holds, and what
//! a client or its server reads in it (backslashes, the client's variables).
//! A text only known when it runs is `unknown`; a text that says too much is
//! not read. What each client does with a statement is in `drop_data.rs`.
//!
//! The lines and their answers are in `tests/cases/drop_data_input.cases`;
//! here are the stages that say too much and SQL nested in SQL. The time of
//! many clients on one line is in `tests/timing.rs`.

mod common;

use common::lines::{nested_do_strings, too_much_said};
use common::{check, posix};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("drop_data_input");
}

#[test]
fn a_stage_that_says_too_much_is_not_read() {
    // Five printfs of 63 KB each are more than a stage may say: unknown, and
    // not printed in full for each client (the time is in `timing.rs`).
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(&too_much_said(), Rule::Unknown)],
    );
}

#[test]
fn sql_in_sql_is_read_a_few_levels_deep() {
    let mut text = "DROP TABLE t".to_string();
    for _ in 0..5 {
        text = format!("EXEC('{}')", text.replace('\'', "''"));
    }
    let line = format!("sqlcmd -Q \"{text}\"");
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::DropData)]);
    // Deeper than that is not read, and what is not read is unknown.
    let mut text = "DROP TABLE t".to_string();
    for _ in 0..12 {
        text = format!("EXEC('{}')", text.replace('\'', "''"));
    }
    let line = format!("sqlcmd -Q \"{text}\"");
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::Unknown)]);
    // A long chain of nested `DO` strings is read without going deep (and
    // quickly: `timing.rs`).
    assert!(!classify(&nested_do_strings(), Shell::Posix, &posix()).is_safe());
}
