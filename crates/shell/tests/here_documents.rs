//! Here-documents. The shell ends one only at a line that is exactly its
//! delimiter (for `<<-`, after leading tabs); the grammar also ends it at a
//! line only near the delimiter (` PY`, `PY `, `PY #...`, `PY ;...`), and
//! then judges the rest as shell commands while the program reads it as its
//! input, so such a line is Unreadable, not guessed at, in `"$(…)"` as
//! outside it. Bash, sh and zsh join a backslash-newline in an unquoted body
//! before they look for the end line, and the shell runs the `$(…)` and
//! backtick substitutions in such a body. Text before a here-document that
//! only looks like one, or whose quotes and brackets a plain scan misreads,
//! hides nothing that follows.
//!
//! The lines and their answers are in `tests/cases/here_documents.cases`;
//! here are the lines made for each quoted delimiter.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("here_documents");
}

/// A quoted delimiter is read through its closing quote, whatever it holds
/// (`<<'E;F'` is `E;F`): reading it short left the rest of the quote open, and
/// the body then copied everything after it, so a backslash-newline in the
/// lines below was never joined.
#[test]
fn a_quoted_delimiter_with_an_operator_or_space_is_read_whole() {
    let tail = "\nr\\\nm -rf /home/me";
    let rows: Vec<(String, Rule)> = [
        ("'E;F'", "E;F"),
        ("'E O'", "E O"),
        ("\"E O\"", "E O"),
        ("'E)'", "E)"),
        ("'E&F'", "E&F"),
        ("'E>F'", "E>F"),
        ("'E(F'", "E(F"),
        ("'E|F'", "E|F"),
    ]
    .iter()
    .flat_map(|(quoted, word)| {
        [
            format!("echo \"$(cat <<{quoted}\nx\n{word}\n)\"{tail}"),
            format!("echo \"`cat <<{quoted}\nx\n{word}\n`\"{tail}"),
        ]
    })
    .map(|line| (line, Rule::Delete))
    .collect();
    let rows: Vec<(&str, Rule)> = rows
        .iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .collect();
    check(Shell::Posix, &posix(), &[], &rows);
}
