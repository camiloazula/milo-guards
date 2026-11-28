//! The script guard's judging of code at the bounds of the code reader's scan before a parse fit a
//! thread of a small stack. tree-sitter's parser goes back through its
//! stack by recursion as it merges the ways it reads code, and the reader
//! walks the tree it builds by recursion too: within the bounds of the scan,
//! a reading needs less than half a mebibyte (the most measured, 0.45 MiB,
//! a shell line's here-document of Python nested 399 deep), against the
//! 2 MiB a thread Rust or tokio starts is given. `just timing` runs this
//! in an optimized build too, where the thread has 1 MiB.

mod common;

use common::posix;
use milo_guards_code::MAX_TREE_DEPTH;
use milo_guards_script::Language::{JavaScript, Python, Ruby};
use milo_guards_script::{judge, MAX_LEN};

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

/// Ruby at the bounds of the reader's scan before a parse, each within the
/// length limit: nested just within the depth the scan lets through, by
/// each opener it counts (brackets, the blocks of `begin`, `do` and `->`,
/// literals and their `#{…}` fields as deep as the grammar's scanner holds
/// them), heredocs as many as it holds, a path worked out of a chain the
/// reader follows, chains no scan counts, and shapes it refuses.
fn ruby_at_the_bounds() -> Vec<String> {
    let deep = MAX_TREE_DEPTH - 1;
    let fill = |head: &str, unit: &str, tail: &str| {
        let count = (MAX_LEN - 64 - head.len() - tail.len()) / unit.len();
        format!("{head}{}{tail}\n", unit.repeat(count))
    };
    // As many levels as fit the length limit, at most `count`: a block of
    // `begin` and `end` takes ten bytes, so the limit holds fewer than the
    // depth the scan allows.
    let nested = |open: &str, middle: &str, close: &str, count: usize| {
        let fits = (MAX_LEN - 64 - middle.len()) / (open.len() + close.len());
        let count = count.min(fits);
        format!(
            "x = {}{middle}{}\n",
            open.repeat(count),
            close.repeat(count)
        )
    };
    let strings = 64;
    // The brackets of each of eight heredocs' fields: eight of them fit the
    // length limit together.
    let each = deep.min(((MAX_LEN - 256) / 8 - 16) / 2);
    vec![
        nested("(", "a", ")", deep),
        nested("[", "a", "]", deep),
        nested("{a=>", "a", "}", deep),
        nested("begin ", "a", " end", deep),
        nested("a do ", "a", " end", deep),
        nested("-> { ", "a", " }", deep),
        format!(
            "x = {}{}a{}{}\n",
            "\"#{".repeat(strings),
            "(".repeat(deep - 2 * strings),
            ")".repeat(deep - 2 * strings),
            "}\"".repeat(strings)
        ),
        format!(
            "x = [{}]\n{}",
            ["<<A"; 8].join(", "),
            format!("#{{{}a{}}}\nA\n", "(".repeat(each), ")".repeat(each)).repeat(8)
        ),
        format!(
            "File.read({}'a'{})\n",
            "(".repeat(deep - 1),
            ")".repeat(deep - 1)
        ),
        fill("File.read(", "'a' + ", "'a')"),
        fill("File.read(Pathname.new('/a')", " / 'b'", ")"),
        fill("File.read(File.join(", "'a', ", "'a'))"),
        fill("", "p /a/;", "a"),
        fill("x = ", "a ? b : ", "a"),
        fill("", "p ", "a"),
        fill("x = ", "- ", "a"),
        fill("x = ", "not ", "a"),
        fill("x = ", "a.", "a"),
        fill("x = ", "a = ", "a"),
        fill("", "(", "a"),
        fill("", "begin ", "a"),
        "(".repeat(MAX_LEN - 64),
    ]
}

#[test]
#[allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the readings run on a thread with a small stack"
)]
fn judging_at_the_bounds_fits_a_small_stack() {
    // Each shape is read on a thread of [`STACK`] bytes: a reading that
    // overflows it aborts the test.
    let shapes = at_the_bounds();
    let ruby = ruby_at_the_bounds();
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            for (python, code) in &shapes {
                let python = *python;
                let language = if python { Python } else { JavaScript };
                let _ = judge(language, code, &posix());
            }
            for code in ruby.iter().chain(&ruby_crashes()) {
                let _ = judge(Ruby, code, &posix());
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Ruby that took tree-sitter-ruby's scanner to the assertion that aborts the
/// process (a heredoc's word longer than it holds), each past a context the scan
/// before a parse once misread: a `%` literal, `__dir__`, `__END__`,
/// `=begin`, a `/` after a value, a quoted word, and white space or a
/// character Ruby or the grammar reads otherwise (a no-break space, U+3000,
/// a zero-width space, U+FEFF, U+2028, an em space, `\v`, `\f`, `\r`). The
/// raw text alone refuses each.
fn ruby_crashes() -> Vec<String> {
    let word = "A".repeat(300);
    let plain = [
        "y = <<W\nW\n",
        "x%(\")\ny = <<W\nW\n\"\n",
        "%\u{1}\ny = <<W\nW\n\u{1}\n",
        "x = 1 %q\u{1}\ny = <<W\nW\n\u{1}\n",
        "__dir__ <<W\nW\n",
        "x = (\n__END__\n<<W\nW\n)\n",
        "=begin\n=end\u{b}\ny = <<W\nW\n=end\n",
        "@x /2; y = <<W\nW\n#/\n",
        "x = {} /2; y = <<W\nW\n#/\n",
        "y = <<\"W\"\nW\n",
        // Right after a quote or a method's `.`, where Ruby starts no
        // heredoc but the grammar, at an error, may.
        "x = ''<<`W`\n",
        "x = a.<<\"W\"\n",
        "x = \"<<`W`\"\n",
    ];
    let around = [
        "x = 1S<<W\nW\n",
        "y = 1\nS=begin\n=end\n<<W\nW\n",
        "=begin\n=endS\nx = <<W\nW\n=end\n",
        "x = 1 #S\ny = <<W\nW\n",
        "x = yS/2; z = <<W\nW\n#/\n",
        "x = 'S'; z = <<W\nW\n",
        "p :aS?b; z = <<W\nW\n",
        "x = 1\nS__END__\ny = <<W\nW\n",
    ];
    let spaces = [
        "\u{a0}", "\u{3000}", "\u{200b}", "\u{feff}", "\u{2028}", "\u{2003}", "\u{b}", "\u{c}",
        "\r",
    ];
    let mut shapes: Vec<String> = plain
        .iter()
        .map(|shape| shape.replace('W', &word))
        .collect();
    for shape in around {
        for space in spaces {
            shapes.push(shape.replace('S', space).replace('W', &word));
        }
    }
    shapes
}
