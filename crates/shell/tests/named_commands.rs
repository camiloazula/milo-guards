//! A program that runs a command the line names in a variable it sets (in
//! front of it, with `env`, `export`, PowerShell's `$env:` or cmd's `set`),
//! or in one of its options, runs that command besides what it does: the
//! command is read as a line of the shell the program hands it to and
//! judged by every rule (`GIT_SSH_COMMAND='…' git fetch`, `PAGER='…' git
//! log`, `ssh -o ProxyCommand='…'`, `git rebase -x '…'`, `fd -x cmd`,
//! `sort --compress-program=prog`). A value only known when it runs is a
//! command only known when it runs.
//!
//! The lines and their answers are in `tests/cases/named_commands.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("named_commands");
}

const TOO_MANY: &str = "runs the command a variable sets too many times to read";

/// Whether the line is unreadable for running a command a variable sets
/// more times, or with more values, than the guard reads.
fn too_many(line: &str) -> bool {
    common::classify(line, milo_guards_shell::Shell::Posix, &common::posix())
        .findings()
        .iter()
        .any(|finding| finding.reason == TOO_MANY)
}

#[test]
fn a_program_is_read_with_at_most_sixty_four_values_of_its_variables() {
    let line = |values: usize| {
        let mut line = (0..values).fold(String::new(), |line, at| {
            line + "PAGER=a" + &at.to_string() + "; "
        });
        line.push_str("git log");
        line
    };
    assert!(!too_many(&line(64)));
    assert!(too_many(&line(65)));
    // The same value given again is one value.
    assert!(!too_many(&format!(
        "{}git log",
        "export PAGER=a; ".repeat(200)
    )));
}

#[test]
fn the_commands_variables_name_share_a_budget_of_readings() {
    // Each reading counts 64 bytes at the least against the longest line.
    let line = |programs: usize| format!("export GIT_PAGER=a; {}", "git log; ".repeat(programs));
    assert!(!too_many(&line(1_000)));
    assert!(too_many(&line(1_100)));
}
