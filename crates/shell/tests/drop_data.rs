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
//! line, and the timed tests.

mod common;

use common::{assert_linear, check, filled, posix, rules, took};
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
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_group_too_large_to_read_is_unknown_and_quick() {
    let echoes = "echo a; ".repeat(300);
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(&format!("{{ {echoes}}} | psql"), Rule::Unknown)],
    );
    // Many clients after a big group are not read over and over.
    let echoes = "echo a; ".repeat(3_000);
    let clients = "psql; ".repeat(3_000);
    let line = format!("{{ {echoes}}} | {{ {clients}}}");
    assert!(line.len() < 64 * 1024, "{}", line.len());
    let took = took(&line, Shell::Posix, &posix());
    assert!(took < std::time::Duration::from_secs(5), "took {took:?}");
    let rules = rules(&line, Shell::Posix, &posix());
    assert!(rules.iter().all(|rule| *rule == Rule::Unknown), "{rules:?}");
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_where_is_found_for_every_verb_in_one_pass() {
    let (shell, paths) = (Shell::Posix, posix());
    // Each verb that needs a `WHERE` used to look for it to the end of the
    // text, and a verb in an open parenthesis never found the end.
    assert_linear("psql -c DELETE (DELETE (…", shell, &paths, |size| {
        format!("psql -c '{}'", filled("DELETE (", size, 20))
    });
    assert_linear("mysql -e DELETE (DELETE (…", shell, &paths, |size| {
        format!("mysql -e '{}'", filled("DELETE (", size, 20))
    });
    assert_linear("UPDATE (UPDATE (…", shell, &paths, |size| {
        format!("psql -c '{}'", filled("UPDATE (", size, 20))
    });
    // A group whose escapes make the shells read it differently.
    assert_linear("a piped group of escapes", shell, &paths, |size| {
        let part = filled("\\x41\\101 DELETE (", size, 100);
        format!("{{ echo -n '{part}'; echo -n '\\x41\\101 '; echo '\\x41\\101 '; }} | mysql")
    });
    // `THEN DELETE` looked back to a `WHEN` for each one.
    assert_linear("MERGE … THEN DELETE …", shell, &paths, |size| {
        format!("psql -c 'MERGE {}'", filled("THEN DELETE ", size, 20))
    });
    // A `WHERE` after each verb of a nest.
    assert_linear("DELETE (DELETE (… WHERE …", shell, &paths, |size| {
        let opens = filled("DELETE (", size / 2, 10);
        let closes = filled(") WHERE x ", size / 2, 10);
        format!("psql -c '{opens}{closes}'")
    });
}

/// Distinct words `make(i)` made for `i` from 0, joined, up to `size` bytes.
fn numbered(size: usize, make: impl Fn(usize) -> String) -> String {
    let mut text = String::new();
    for i in 0.. {
        let part = make(i);
        if text.len() + part.len() > size {
            break;
        }
        text.push_str(&part);
    }
    text
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_files_and_programs_a_client_names_are_read_in_linear_time() {
    let (shell, paths) = (Shell::Posix, posix());
    // Each program is a line of its own, judged in full: past a few the
    // rest are `unknown`, and so are the files past a few.
    assert_linear("\\! ls 0 \\n \\! ls 1 …", shell, &paths, |size| {
        format!(
            "psql <<'EOF'\n{}EOF",
            numbered(size - 20, |i| format!("\\! ls {i}\n"))
        )
    });
    assert_linear("\\o f0 \\o f1 …", shell, &paths, |size| {
        format!(
            "psql -c '{}'",
            numbered(size - 20, |i| format!("\\o /home/me/f{i} "))
        )
    });
    assert_linear(
        "psql -c '\\! ls 0'; psql -c '\\! ls 1'; …",
        shell,
        &paths,
        |size| numbered(size, |i| format!("psql -c '\\! ls {i}'; ")),
    );
    assert_linear(
        "echo '\\! ls' | { psql; psql; … }",
        shell,
        &paths,
        |size| format!("echo '\\! ls' | {{ {}}}", filled("psql; ", size, 20)),
    );
    assert_linear(
        "sqlite3 x.db '.shell ls 0' '.shell ls 1' …",
        shell,
        &paths,
        |size| {
            format!(
                "sqlite3 x.db {}",
                numbered(size - 20, |i| format!("'.shell ls {i}' "))
            )
        },
    );
    // One program as long as the line.
    assert_linear("psql -c '\\! echo a; echo a; …'", shell, &paths, |size| {
        format!("psql -c '\\! {}'", filled("echo a; ", size, 20))
    });
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
