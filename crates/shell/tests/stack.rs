//! The shell guard's judging of a line's inline code at the bounds of the code reader's scan before a parse fit a
//! thread of a small stack. tree-sitter's parser goes back through its
//! stack by recursion as it merges the ways it reads code, and the reader
//! walks the tree it builds by recursion too: within the bounds of the scan,
//! a reading needs less than half a mebibyte (the most measured, 0.45 MiB,
//! a shell line's here-document of Python nested 399 deep), against the
//! 2 MiB a thread Rust or tokio starts is given. `just timing` runs this
//! in an optimized build too, where the thread has 1 MiB.

mod common;

use common::posix;
use milo_guards_shell::{classify, effect, Shell};

/// The code reader's own bounds (`milo_guards_code::MAX_TREE_DEPTH` and
/// `MAX_LEN`), written out so that this builds without the reader too.
const MAX_TREE_DEPTH: usize = 400;
const MAX_LEN: usize = 64 * 1024;

/// The most stack a reading may take: a thread of 1 MiB in an optimized
/// build, as a caller runs it; 2 MiB in a debug build, whose frames are
/// larger (the most measured there 1.26 MiB), and 4 MiB in the instrumented
/// one of `just coverage`.
const STACK: usize = if cfg!(coverage) {
    4 << 20
} else if cfg!(debug_assertions) {
    2 << 20
} else {
    1 << 20
};

/// Code at the bounds of the reader's scan before a parse, each within the
/// length limit, as `(python, code)`: nested just within the depth the scan
/// lets through, by each opener it counts; the `await`s before a `/` and
/// the stars where Python allows none it lets through, nested so; chains
/// no scan counts; and shapes it refuses.
fn at_the_bounds() -> Vec<(bool, String)> {
    let deep = MAX_TREE_DEPTH - 1;
    let fill = |head: &str, unit: &str| {
        let count = (MAX_LEN - 64 - head.len()) / unit.len();
        format!("{head}{}a\n", unit.repeat(count))
    };
    let nested = |open: &str, middle: &str, close: &str, count: usize| {
        format!(
            "x = {}{middle}{}\n",
            open.repeat(count),
            close.repeat(count)
        )
    };
    vec![
        (true, nested("(", "a", ")", deep)),
        (true, nested("{1:", "a", "}", deep)),
        (true, nested("f'{", "a", "}'", deep / 2)),
        (true, "(".repeat(deep - 4) + &"+*a".repeat(4)),
        (true, fill("x = ", "not ")),
        (true, fill("x = ", "a if b else ")),
        (true, fill("", "(")),
        (true, fill("", "+*a")),
        (false, nested("(", "a", ")", deep)),
        (false, nested("`${", "a", "}`", deep / 2)),
        (false, nested("a?", "b", ":c", deep)),
        (false, "(".repeat(deep - 4) + &"(await /".repeat(4)),
        (false, "`${".repeat(deep / 2 - 4) + &"`${await /".repeat(4)),
        (false, fill("x = ", "await ")),
        (false, fill("x = ", "await a=")),
        (false, fill("", "(")),
        (false, fill("", "(await /")),
        (false, fill("", "(a,await /(")),
        (true, "(".repeat(MAX_LEN - 64) + &"+*a".repeat(4)),
        (false, "(".repeat(MAX_LEN - 64) + &"(await /".repeat(4)),
        // Spaces the grammars pass over and the lexers' own comments,
        // where a scan that read them otherwise once read no mark and no
        // depth: a zero-width space between an operator and its star, or
        // an `await` and its `/`, an HTML-like comment holding a backtick,
        // a comment holding a `>` in a JSX tag, and a backtick before a
        // triple quote in Python.
        (true, fill("", "+\u{200b}*a")),
        (true, fill("", "+\x0b*a")),
        (true, fill("x = `\'\'\'`\n", "+*a")),
        (false, fill("<!-- `\n", "(a,await\u{200b}/(")),
        (false, fill("<!-- `\n", "(await\u{200b}/")),
        (false, fill("x = <a /* > */ b/>;\n", "(a,await\u{200b}/(")),
        (false, fill("", "(a,await\u{a0}/(")),
    ]
}

#[test]
#[allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the readings run on a thread with a small stack"
)]
fn here_documents_at_the_bounds_fit_a_small_stack() {
    // Each shape is read on a thread of [`STACK`] bytes: a reading that
    // overflows it aborts the test.
    let shapes = at_the_bounds();
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            for (python, code) in &shapes {
                let python = *python;
                let program = if python { "python3" } else { "node" };
                let line = format!("{program} <<'EOF'\n{code}\nEOF\n");
                let paths = posix();
                let _ = classify(&line, Shell::Posix, &paths);
                let _ = effect(&line, Shell::Posix, &paths);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Lines with brace lists at the bounds of their expansion: lists nested in
/// one word to the most it spells out and past it, a word of as many lists as
/// the length limit allows, and a list in a shell inside shells, each
/// within the length limit.
fn brace_lists_at_the_bounds() -> Vec<String> {
    let mut lines = Vec::new();
    for depth in [1, 12, 13, 200, MAX_TREE_DEPTH, MAX_LEN / 6] {
        lines.push(format!(
            "echo {}x{}",
            "{a,".repeat(depth),
            "}".repeat(depth)
        ));
        lines.push(format!(
            "bash {}x{}",
            "{-c,".repeat(depth),
            "}".repeat(depth)
        ));
    }
    // An escaped blank after a quote, where the grammar cuts a list in two,
    // many times, with the `{` quoted and bare.
    lines.push(format!("echo {}x", "'{'\\ ".repeat(MAX_LEN / 5 - 2)));
    lines.push(format!(
        "echo >/dev/null {}x",
        "'{'\\ ".repeat(MAX_LEN / 5 - 4)
    ));
    lines.push(format!("echo {}x", "{'a'\\ ".repeat(MAX_LEN / 6 - 2)));
    for part in ["{$1", "{\\{", "{\\}", "{\\a"] {
        lines.push(format!("echo {}", part.repeat(MAX_LEN / 4 - 2)));
    }
    lines.push(format!("echo {}", "{a,b}".repeat(MAX_LEN / 5 - 2)));
    lines.push(format!("echo {}", "{1..3}".repeat(MAX_LEN / 6 - 2)));
    lines.push(format!("echo {}", "{a,b} ".repeat(MAX_LEN / 6 - 2)));
    // Each shell reads the next as a string, one level in.
    let mut line = "echo {a,'b c'}".to_string();
    for _ in 0..12 {
        line = format!(
            "sh -c \"{}\"",
            line.replace('\\', "\\\\").replace('"', "\\\"")
        );
        lines.push(line.clone());
    }
    lines
}

#[test]
#[allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the readings run on a thread with a small stack"
)]
fn brace_lists_at_the_bounds_fit_a_small_stack() {
    let lines = brace_lists_at_the_bounds();
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            for line in &lines {
                assert!(line.len() <= MAX_LEN, "{}", line.len());
                let paths = posix();
                let _ = classify(line, Shell::Posix, &paths);
                let _ = effect(line, Shell::Posix, &paths);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the readings run on a thread with a small stack"
)]
fn a_shell_line_with_many_letters_it_does_not_know_nested_deep_fits_a_small_stack() {
    // A cluster of letters a shell's table does not have, and many distinct
    // words after it, nested in substitutions.
    let mut words = String::new();
    for at in 0..12_000 {
        words.push_str(" w");
        words.push_str(&at.to_string());
    }
    let line = format!(
        "{}sh -c -{}{words}{}",
        "echo $(".repeat(100),
        "Z".repeat(12_940),
        ")".repeat(100)
    );
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let paths = posix();
            let _ = classify(&line, Shell::Posix, &paths);
            let _ = effect(&line, Shell::Posix, &paths);
        })
        .unwrap()
        .join()
        .unwrap();
}
