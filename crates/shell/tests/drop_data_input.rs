//! The text a database client gets, read as the client gets it: what
//! `printf` and `echo` print (their escapes, octal, and what a shell leaves as
//! written), what `cat` passes on, here-documents and templates, every program
//! of a stage and every client after it, SQL that runs SQL it holds, and what
//! a client or its server reads in it (backslashes, the client's variables).
//! A text only known when it runs is `unknown`; a text that says too much is
//! not read. What each client does with a statement is in `drop_data.rs`.
//!
//! The lines and their answers are in `tests/cases/drop_data_input.cases`;
//! here are the stages that say too much, the timing of many clients on one
//! line, and SQL nested in SQL.

mod common;

use std::fmt::Write;
use std::time::Duration;

use common::{assert_linear, check, filled, posix, took};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("drop_data_input");
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_stage_that_says_too_much_is_not_read_and_stays_quick() {
    // Five printfs of 63 KB each are more than a stage may say: unknown, and
    // not printed in full for each client.
    let args = "a ".repeat(1000);
    let printf = format!("printf '%s{}' {args}; ", "x".repeat(60));
    let line = format!("{{ {}}} | psql", printf.repeat(5));
    assert!(took(&line, Shell::Posix, &posix()) < Duration::from_millis(500));
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::Unknown)]);
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_clients_on_one_line_are_read_in_linear_time() {
    // Each `redis-cli del` that is given keys asks whether the line lists
    // keys; each client asks for the text fed to it. Neither may walk every
    // unit or every text of the line again.
    for part in ["redis-cli del $x; ", "psql <<< x; "] {
        assert_linear(part, Shell::Posix, &posix(), |size| filled(part, size, 0));
    }
    // Many clients of a stage that backs up to many files.
    assert_linear(
        "a stage of backups to many clients",
        Shell::Posix,
        &posix(),
        |size| {
            let mut said = String::new();
            for at in 0..size / 80 {
                let _ = write!(said, "echo '.backup /home/me/{at}.db'; ");
            }
            let clients = filled("sqlite3 ~/x.db; ", size / 2, 40);
            format!("{{ {said}}} | {{ {clients}}}")
        },
    );
    // The time grew with the clients times the programs feeding them.
    let args = "a ".repeat(1000);
    let printf = format!("printf '%s{}' {args}; ", "x".repeat(60));
    let clients = |count: usize| "psql; ".repeat(count);
    let lines = [
        // Fifteen printfs, each saying 63 KB: more than a stage may say.
        format!("{{ {}}} | {{ {}}}", printf.repeat(15), clients(1000)),
        format!(
            "{{ {}}} | {{ {}}}",
            "printf '%s' a b c; ".repeat(64),
            clients(1800)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(30_000),
            clients(5000)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "sqlite3 ~/x.db; ".repeat(2500)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "redis-cli; ".repeat(4000)
        ),
        // Risky: every client has a finding to give.
        format!(
            "{{ echo 'DROP TABLE t; {}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "psql; ".repeat(5000)
        ),
    ];
    for line in &lines {
        let took = took(line, Shell::Posix, &posix());
        assert!(
            took < Duration::from_millis(500),
            "{} bytes took {took:?}",
            line.len()
        );
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
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
    // A long chain of nested `DO` strings is read without going deep.
    let mut body = "SELECT 1".to_string();
    for level in 0..2_000 {
        body = format!("DO $t{level}$ {body} $t{level}$");
    }
    let line = format!("psql -c '{body}'");
    assert!(took(&line, Shell::Posix, &posix()) < Duration::from_millis(200));
    assert!(!classify(&line, Shell::Posix, &posix()).is_safe());
}
