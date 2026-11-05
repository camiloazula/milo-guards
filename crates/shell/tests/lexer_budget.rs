//! The lines a grammar reads in quadratic time below the budget of what its
//! lexer is handed (`MAX_LEXED` in `src/unit.rs`), held to that count, not
//! to the clock. The count is the same number on every machine, so this runs
//! in every build, and it holds the work the guard lets the grammar do
//! whatever the machine: a time bound on such a row measured the machine (on
//! GitHub's runner, about twenty times this one on these rows, against two
//! to four times on rows read in linear time), not the guard.
//!
//! cmd's grammar (tree-sitter-batch 0.11.1) reads on to the end of the line
//! at the start of each statement after a `;` or a `&`, only to return the
//! command word: the `'VBS` branch of its `comment` token can start at any
//! command word, and only a line break ends it. So each statement costs the
//! rest of the line, and the line costs its length squared, until the
//! budget stops it ("takes too long to read"). The guard reads less of such
//! a line only by changing its tree, and so its answers, so it is held to
//! the budget instead: at each size, from a line far below the budget to the
//! length limit, the bytes handed stay within it, the line is stopped only
//! past it, and the answer is pinned.

mod common;

use common::windows;
use milo_guards_shell::testing::{lexed, LEXED_PIECE, MAX_LEXED, MAX_LEXED_BASE};
use milo_guards_shell::{Assessment, Rule, Shell};

/// The sizes, in KB, each row is read at: from a line its lexer reads far
/// below the budget to the length limit.
const SIZES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

/// How far past the budget the bytes handed may go: a parse sees it is past
/// only after the piece that took it there (at most [`LEXED_PIECE`] bytes,
/// and up to three more to end where a character does), and each look the
/// lexer takes after that is counted as a byte until the parse stops. The
/// most measured is 263.
const OVERRUN: usize = 2 * LEXED_PIECE;

/// What the guard says of a line its lexer is handed more than the budget
/// for.
const STOPPED: &str = "takes too long to read";

/// What the guard says of a line the grammar reads with an error in it.
const IN_FULL: &str = "cannot be read in full";

/// The answer to a row at a size: the rules found, in order and each once,
/// and the reason of the first finding.
type Answer = (&'static [Rule], &'static str);

/// A row: what is repeated to fill the line, and the answer at a size in KB.
type Row = (&'static str, fn(usize) -> Answer);

/// `unit` repeated to fill `size` bytes.
fn fit(unit: &str, size: usize) -> String {
    unit.repeat(size / unit.len())
}

/// The rules of `answer`, in order and each once, and the reason of its
/// first finding.
fn read(answer: &Assessment) -> (Vec<Rule>, &str) {
    let Assessment::Risky(found) = answer else {
        return (Vec::new(), "safe");
    };
    let mut rules = Vec::new();
    for finding in found {
        if !rules.contains(&finding.rule) {
            rules.push(finding.rule);
        }
    }
    (rules, found.first().map_or("", |f| f.reason.as_str()))
}

#[test]
fn cmd_statements_after_a_separator_are_held_to_the_budget_of_what_the_lexer_reads() {
    use Rule::{Overwrite, Unreadable};
    // Below the budget the grammar reads each line whole, and ends a
    // statement at each `echo` after a `;` with a line break it says is
    // missing ("cannot be read in full"), keeping the findings beside it.
    // Past it the line is stopped. The chain of `&` is stopped from 4 KB
    // before it is parsed, by the count of the commands it chains.
    let rows: [Row; 3] = [
        ("cd x; echo y > NUL; ", |kb| {
            if kb < 16 {
                (&[Unreadable, Overwrite], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("echo y > NUL; ", |kb| {
            if kb < 16 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("echo y & ", |kb| {
            if kb < 4 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], "chains too many commands to read")
            }
        }),
    ];
    let paths = windows();
    let mut wrong = Vec::new();
    for (unit, answer) in rows {
        for kb in SIZES {
            let line = fit(unit, kb * 1024);
            let read_of = lexed(&line, Shell::Cmd, &paths);
            let what = format!("{unit:?} in cmd at {kb} KB");
            // cmd's grammar is handed the line with a line break after it,
            // or nothing, when the line is stopped before it is parsed.
            if read_of.parsed != 0 && read_of.parsed != line.len() + 1 {
                wrong.push(format!(
                    "{what}: parsed {} bytes of a line of {}",
                    read_of.parsed,
                    line.len()
                ));
            }
            let budget = MAX_LEXED * read_of.parsed + MAX_LEXED_BASE;
            if read_of.handed > budget + OVERRUN {
                wrong.push(format!(
                    "{what}: its lexer was handed {} bytes, past the budget of {budget}",
                    read_of.handed
                ));
            }
            let (rules, reason) = read(&read_of.answer);
            if (read_of.handed > budget) != (reason == STOPPED) {
                wrong.push(format!(
                    "{what}: handed {} bytes against a budget of {budget}, and says {reason:?}",
                    read_of.handed
                ));
            }
            let (want_rules, want_reason) = answer(kb);
            if rules != want_rules || reason != want_reason {
                wrong.push(format!(
                    "{what}: {rules:?} {reason:?}, not {want_rules:?} {want_reason:?}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
