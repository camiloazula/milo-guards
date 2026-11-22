//! The lines cmd's grammar reads in quadratic time below the budget of
//! what its lexer is handed (`MAX_LEXED` in `src/unit.rs`), held to that
//! count, not to the clock. The count is the same number on every machine,
//! so this runs in every build, and it holds the work the guard lets the
//! grammar do whatever the machine: a time bound on such a row measured the
//! machine (on GitHub's runner, about twenty times this one on these rows,
//! against two to four times on rows read in linear time), not the guard.
//!
//! cmd's grammar (tree-sitter-batch 0.11.1) goes back over the rest of the
//! line at each statement or token of these shapes: at the start of each
//! statement after a `;` or a `&` it reads on to the end of the line only to
//! return the command word (the `'VBS` branch of its `comment` token can
//! start at any command word, and only a line break ends it), and `@`,
//! `()`, `(echo) `, `$((1<<2)); echo ` and `for %%i in (a) do ` repeated
//! cost it the same. So the line costs its length squared, until the budget
//! stops it ("takes too long to read"). The guard reads less of such a line
//! only by changing its tree, and so its answers, so it is held to the
//! budget instead: at each size, from a line far below the budget to the
//! length limit, the bytes handed stay within it and within a written
//! ceiling, the line is stopped only past it, and the answer is pinned.
//!
//! PowerShell's grammar (tree-sitter-powershell 0.26.6) has such a shape
//! too, bound by other counts than the budget: `${` left open and nested.
//! Its lexer is handed the nest hundreds of times over, up to the depth
//! past which a nest is refused unread, and a time bound on it failed on
//! the runner the same way. It is held to the exact bytes handed at each
//! depth, which are far below the budget.

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

/// The most bytes a line may be handed, written out rather than read from
/// the budget, so that raising `MAX_LEXED` or `MAX_LEXED_BASE` fails here
/// and needs a measured reason: the budget of today at the length limit (32
/// times a line of 64 KB and its line break, and 4 MiB: 6,291,488 bytes)
/// and [`OVERRUN`]. The most measured is 6,291,610.
const MOST_HANDED: usize = 6_292_000;

/// What the guard says of a line its lexer is handed more than the budget
/// for.
const STOPPED: &str = "takes too long to read";

/// What the guard says of a line the grammar reads with an error in it.
const IN_FULL: &str = "cannot be read in full";

/// What the guard says of a line nested deeper than it reads.
const TOO_DEEP: &str = "nests too deeply to read";

/// The answer to a row at a size: the rules found, in order and each once,
/// and the reason of the first finding.
type Answer = (&'static [Rule], &'static str);

/// A row: what starts the line, what is repeated after it to fill the
/// line, and the answer at a size in KB.
type Row = (&'static str, &'static str, fn(usize) -> Answer);

/// `unit` repeated after `head` to fill `size` bytes.
fn fit(head: &str, unit: &str, size: usize) -> String {
    format!("{head}{}", unit.repeat((size - head.len()) / unit.len()))
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
fn lines_cmd_reads_in_quadratic_time_are_held_to_the_budget_of_what_its_lexer_reads() {
    use Rule::{Overwrite, Unknown, Unreadable};
    // Below the budget the grammar reads each line whole, with an error in
    // it ("cannot be read in full"; after a `;` it ends a statement at each
    // `echo` with a line break it says is missing), keeping the findings
    // beside it. Past it the line is stopped. The chain of `&` is stopped
    // from 4 KB before it is parsed, by the count of the commands it chains.
    let rows: [Row; 8] = [
        ("", "cd x; echo y > NUL; ", |kb| {
            if kb < 16 {
                (&[Unreadable, Overwrite], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("", "echo y > NUL; ", |kb| {
            if kb < 16 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("", "echo y & ", |kb| {
            if kb < 4 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], "chains too many commands to read")
            }
        }),
        ("echo ", "$((1<<2)); echo ", |kb| {
            if kb < 8 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        // Up to 4 KB the grammar reads the body of each `for`, which runs
        // a command it cannot name; at 8 KB that is lost to the error.
        ("", "for %%i in (a) do ", |kb| {
            if kb < 8 {
                (&[Unreadable, Unknown], IN_FULL)
            } else if kb < 16 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("", "@", |kb| {
            if kb < 4 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("", "()", |kb| {
            if kb < 4 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
        ("", "(echo) ", |kb| {
            if kb < 4 {
                (&[Unreadable], IN_FULL)
            } else {
                (&[Unreadable], STOPPED)
            }
        }),
    ];
    let paths = windows();
    let mut wrong = Vec::new();
    for (head, unit, answer) in rows {
        for kb in SIZES {
            let line = fit(head, unit, kb * 1024);
            let read_of = lexed(&line, Shell::Cmd, &paths);
            let what = format!("{head:?} then {unit:?} in cmd at {kb} KB");
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
            if read_of.handed > MOST_HANDED {
                wrong.push(format!(
                    "{what}: its lexer was handed {} bytes, past the written ceiling of {MOST_HANDED}",
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

#[test]
fn a_nest_powershell_is_handed_hundreds_of_times_over_is_held_to_the_bytes_handed() {
    // `${` left open and nested, two bytes a level. Up to 255 deep the
    // grammar reads the line whole, with an error in it, and the bytes its
    // lexer is handed grow with the square of the depth. A parse starts one
    // recovery more than the nest is deep, so from 256 deep the recoveries
    // counted stop it (`MAX_RECOVERIES` in `src/unit.rs`): each level then
    // adds 1,296 bytes, less than a whole parse would be handed. Past 400
    // deep the openers are counted before any grammar is handed a byte
    // (`MAX_TREE_DEPTH`), and the line is refused unread. So the depth and
    // the recoveries bound the work together, at 474 times the line.
    //
    // The row was timed, to 250 ms: 9 ms at 312 deep on the machine it was
    // written on, about 263 ms on GitHub's runner, where rows read in linear
    // time take two to four times as long. The count is the same on every
    // machine, so it is held exactly: a change to either limit, or a grammar
    // that hands more or less, fails here and needs a measured reason.
    //
    // It is the shape that was timed, not the costliest: with a space, a
    // name, a `;` or a `|` after each `${` the lexer is handed more at the
    // same depth, a little over three times as much for the `|`. Those are
    // the most found, not the most there is, and are held too, so that what
    // such a line costs is written down.
    let rows: [(&str, usize, usize, &str); 14] = [
        ("${", 1, 20, IN_FULL),
        ("${", 100, 38_726, IN_FULL),
        ("${", 200, 126_215, IN_FULL),
        ("${", 255, 191_280, IN_FULL),
        ("${", 256, 192_575, STOPPED),
        ("${", 312, 265_151, STOPPED),
        ("${", 400, 379_199, STOPPED),
        ("${", 401, 0, TOO_DEEP),
        ("${", 800, 0, TOO_DEEP),
        ("${ ", 400, 568_829, STOPPED),
        ("${a ", 400, 703_715, STOPPED),
        ("${;", 400, 903_252, STOPPED),
        ("${|", 400, 1_182_355, STOPPED),
        ("${|", 401, 0, TOO_DEEP),
    ];
    let paths = windows();
    let mut wrong = Vec::new();
    for (unit, depth, handed, want_reason) in rows {
        let line = unit.repeat(depth);
        let read_of = lexed(&line, Shell::PowerShell, &paths);
        let what = format!("{unit:?} nested {depth} deep in PowerShell");
        // PowerShell's grammar is handed the line as it is, or nothing,
        // when the line is refused before it is parsed.
        let parsed = if want_reason == TOO_DEEP {
            0
        } else {
            line.len()
        };
        if read_of.parsed != parsed {
            wrong.push(format!(
                "{what}: parsed {} bytes, not {parsed}",
                read_of.parsed
            ));
        }
        if read_of.handed != handed {
            wrong.push(format!(
                "{what}: its lexer was handed {} bytes, not {handed}",
                read_of.handed
            ));
        }
        let (rules, reason) = read(&read_of.answer);
        if rules != [Rule::Unreadable] || reason != want_reason {
            wrong.push(format!(
                "{what}: {rules:?} {reason:?}, not [Unreadable] {want_reason:?}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
