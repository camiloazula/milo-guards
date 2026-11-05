//! A statement given to a database client that drops, truncates or empties
//! something is `drop_data`; reading, inserting, creating and a statement
//! that picks its rows are safe, one only known when it runs is `unknown`,
//! and one the line does not show (a file, a stage it does not read) is
//! `drop_data`.
//! How the text a client gets is read (fed by `printf`, `echo`, `cat` or a
//! here-document) is in `drop_data_input.rs`; how PowerShell hands words to a
//! client is in `tests/cases/powershell_arguments.cases`.
//!
//! The lines and their answers are in `tests/cases/drop_data.cases`; here are
//! the target a prompt can show, a `printf` made to print far more than the
//! line, and lines too large or too deep to read. Their time is in
//! `tests/timing.rs`.

mod common;

use common::lines::{clients_after_a_big_group, numbered};
use common::{check, posix, rules};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("drop_data");
}

#[test]
fn a_target_a_prompt_can_show() {
    let assessment = classify("psql -c 'DROP TABLE users'", Shell::Posix, &posix());
    let finding = &assessment.findings()[0];
    assert_eq!(finding.rule, Rule::DropData);
    assert_eq!(finding.target.as_deref(), Some("DROP TABLE users"));
}

#[test]
fn a_printf_blown_up_past_the_line_is_unknown() {
    // A format used again for every argument can print far more than the line
    // holds; that is not decoded.
    let format = "x".repeat(1_000);
    let args = "a ".repeat(100);
    let line = format!("printf '{format}%s' {args}| psql");
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::Unknown)]);
    let short = format!("printf '{}%s' {}| psql", "x".repeat(10), "a ".repeat(10));
    check(Shell::Posix, &posix(), &[&short], &[]);
}

#[test]
fn a_group_too_large_to_read_is_unknown() {
    let echoes = "echo a; ".repeat(300);
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(&format!("{{ {echoes}}} | psql"), Rule::Unknown)],
    );
    // Many clients after a big group are not read over and over (the time
    // is in `timing.rs`).
    let line = clients_after_a_big_group();
    assert!(line.len() < 64 * 1024, "{}", line.len());
    let rules = rules(&line, Shell::Posix, &posix());
    assert!(rules.iter().all(|rule| *rule == Rule::Unknown), "{rules:?}");
}

#[test]
fn programs_a_client_runs_past_the_budget_or_a_few_levels_deep_are_unknown() {
    let (shell, paths) = (Shell::Posix, posix());
    // Past the budget the programs are `unknown`.
    let line = numbered(4_000, |i| format!("psql -c '\\! ls {i}'; "));
    let found = rules(&line, shell, &paths);
    assert!(found.contains(&Rule::Unknown), "{found:?}");
    // A program that runs a client that runs a program, and so on, is read
    // a few levels deep, and deeper is `unknown`.
    let mut line = "rm -rf ~".to_string();
    for _ in 0..8 {
        line = format!(
            "sqlite3 x.db \".shell {}\"",
            line.replace('\\', "\\\\").replace('"', "\\\"")
        );
    }
    let found = rules(&line, shell, &paths);
    assert!(found.contains(&Rule::Unknown), "{found:?}");
}
