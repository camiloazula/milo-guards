//! The code reader's readings of code at the bounds of the code reader's scan before a parse fit a
//! thread of a small stack. tree-sitter's parser goes back through its
//! stack by recursion as it merges the ways it reads code, and the reader
//! walks the tree it builds by recursion too: within the bounds of the scan,
//! a reading needs less than half a mebibyte (the most measured, 0.45 MiB,
//! a shell line's here-document of Python nested 399 deep), against the
//! 2 MiB a thread Rust or tokio starts is given. `just timing` runs this
//! in an optimized build too, where the thread has 1 MiB.

use milo_guards_code::Language::{JavaScript, Python};
use milo_guards_code::{read, understand, Act, MAX_LEN, MAX_TREE_DEPTH};

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
fn readings_at_the_bounds_fit_a_small_stack() {
    // Each shape is read on a thread of [`STACK`] bytes: a reading that
    // overflows it aborts the test.
    let shapes = at_the_bounds();
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            for (python, code) in &shapes {
                let python = *python;
                let language = if python { Python } else { JavaScript };
                let _ = read(language, code);
                let _ = understand(language, code);
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
fn code_only_one_bound_stops_is_not_read() {
    // Valid code, each with a delete after it, that one bound of the scan
    // alone stops, so that a bound taken away fails here: nested past the
    // depth, five `await`s before a `/`, five spaces only the grammar
    // passes over, five stars where Python allows none, a backtick in
    // Python, and, counted on the bytes alone, 300 stars after an operator
    // and brackets past the depth, all in strings. Read on a thread of [`STACK`] bytes, each is an `Unread`
    // alone.
    let deep = MAX_TREE_DEPTH * 5;
    let awaited: Vec<String> = (0..5).map(|i| format!("await /a{i}/")).collect();
    let shapes: Vec<(bool, String)> = vec![
        (
            false,
            format!(
                "x = {}a{};\nrequire('fs').rmSync('/home/me');\n",
                "(".repeat(deep),
                ")".repeat(deep)
            ),
        ),
        (
            false,
            format!(
                "async function f() {{ return [{}]; }}\nrequire('fs').rmSync('/home/me');\n",
                awaited.join(", ")
            ),
        ),
        (
            false,
            "x = 1 +\u{a0}2;\n".repeat(5) + "require('fs').rmSync('/home/me');\n",
        ),
        (
            true,
            "x = a\n".to_string()
                + &"y = (-*a)\n".repeat(5)
                + "import shutil\nshutil.rmtree('/home/me')\n",
        ),
        (
            true,
            "x = 1 +\u{2060}2\n".repeat(5) + "import shutil\nshutil.rmtree('/home/me')\n",
        ),
        (
            true,
            "s = '- *a*'\n".repeat(300) + "import shutil\nshutil.rmtree('/home/me')\n",
        ),
        (
            true,
            format!(
                "s = '{}'\nimport shutil\nshutil.rmtree('/home/me')\n",
                "(".repeat(MAX_TREE_DEPTH + 1)
            ),
        ),
        (
            false,
            format!(
                "s = '{}';\nrequire('fs').rmSync('/home/me');\n",
                "(".repeat(MAX_TREE_DEPTH + 1)
            ),
        ),
        (
            true,
            "x = `a`\nimport shutil\nshutil.rmtree('/home/me')\n".to_string(),
        ),
    ];
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            for (python, code) in &shapes {
                let language = if *python { Python } else { JavaScript };
                let acts = read(language, code).acts;
                assert!(
                    matches!(acts.as_slice(), [Act::Unread(_)]),
                    "{}: {acts:?}",
                    &code[..code.len().min(60)]
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
