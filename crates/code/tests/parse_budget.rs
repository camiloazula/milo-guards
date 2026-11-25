//! The code the reader does not read, or reads only so far, held to a count
//! of the work its readings do within a `Budget` (`REPORT_BYTES`,
//! `HANDED_BYTES` and `LOGGED_WEIGHT`, the drops and merges of versions over
//! the code (`TANGLE_RATE` and `TANGLE_BASE`), the choices between the
//! trees of two ways (`MAX_SELECTED`, `SELECTED_IN_ALL`), `MAX_QUIET` and
//! `QUIET_IN_ALL`, and `WALK_BYTES`, in `src/unit.rs`), to the stars where
//! Python allows none (`MAX_STARS_AFTER_OPERATORS`, in `src/python.rs`), and
//! to the rule that code is not read through an error,
//! never to the clock. The counts depend on the code only, so they are the
//! same on every machine, and this runs in every build.
//!
//! Each shape is read at each size, from a kilobyte to the length limit,
//! and held to the count that stops it, written out here rather than read
//! from the budget, so that a bound made ten times larger, or taken away,
//! fails here: the count is past its bound (it stopped the reading), and
//! the work stayed within a ceiling far below what reading the code to its
//! end costs. The answer is pinned: code whose reading is stopped, or that
//! meets an error, is an `Unread` act alone, and is not understood. The
//! counts hold for the tree-sitter runtime and grammars of `Cargo.lock`:
//! another release may stop elsewhere, and
//! `the_log_is_read_as_tree_sitter_writes_it` fails when the log the counts
//! read changes its words.

mod common;

use common::shown;
use milo_guards_code::testing::{self, Work};
use milo_guards_code::Language::{self, JavaScript, Python};
use milo_guards_code::{Budget, Understanding, MAX_LEN, MAX_TREE_DEPTH};

/// The sizes, in KB, each row is read at.
const SIZES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

/// The shape that keeps tree-sitter-javascript's recovery from an error
/// going round the same tokens with no end.
const ROUND: &str = "c(.c(''.(X%'''\"';c(=";

/// The bounds, as this file holds them (see `src/unit.rs` for each).
const REPORT_BYTES: usize = 6;
const REPORT_BASE: usize = 64;
const MAX_QUIET: usize = 32;
const QUIET_IN_ALL: usize = 64;
const TANGLE_BASE: usize = 384;
const MAX_STARS_AFTER_OPERATORS: usize = 4;
const MAX_AWAITED_SLASHES: usize = 4;
const MAX_SELECTED: usize = 512;
const SELECTED_IN_ALL: usize = 1024;
const HANDED_BYTES: usize = 64;
const HANDED_BASE: usize = 24 * 1024 * 1024;
const LOGGED_WEIGHT: usize = 12;
const WALK_BYTES: usize = 16;
const WALK_BASE: usize = 64 * 1024;

/// How far past a bound a count may go before the reading sees it: the
/// parse looks at its counts at each report (each 100 steps) and each piece
/// of text handed (256 bytes, and three more to end where a character does,
/// counted twelve times with the log on), and the walk at each unit.
const OVER_REPORTS: usize = 1;
const OVER_HANDED: usize = 259 * LOGGED_WEIGHT;
const OVER_TANGLED: usize = 16;
const OVER_SELECTED: usize = 4096;

/// Whether the reading was stopped by the drops and merges of versions over
/// the code, or by the choices between the trees of two ways.
fn held(work: Work) -> bool {
    work.stopped && (work.tangled > TANGLE_BASE || work.selected > MAX_SELECTED)
}

/// `unit` repeated between `head` and `tail` to fill `size` bytes.
fn fit(head: &str, unit: &str, tail: &str, size: usize) -> String {
    let count = (size - head.len() - tail.len()) / unit.len();
    format!("{head}{}{tail}", unit.repeat(count))
}

/// The work of the readings within a budget made for `len` bytes is within
/// every bound.
fn within(len: usize, work: Work, at: &str) {
    let len = len.min(MAX_LEN);
    let bounds = [
        (
            "reports",
            work.reports,
            len / REPORT_BYTES + REPORT_BASE + OVER_REPORTS,
        ),
        ("quiet", work.quiet, QUIET_IN_ALL + OVER_REPORTS),
        ("tangled", work.tangled, TANGLE_BASE + OVER_TANGLED),
        ("selected", work.selected, SELECTED_IN_ALL + OVER_SELECTED),
        (
            "handed",
            work.handed,
            len * HANDED_BYTES + HANDED_BASE + OVER_HANDED,
        ),
        ("walked", work.walked, len * WALK_BYTES + WALK_BASE + len),
    ];
    for (what, count, most) in bounds {
        assert!(count <= most, "{at}: {what} {count}, over {most}: {work:?}");
    }
}

/// Read and ask of `code` in `language`, each within a budget of its own:
/// the work of both is within it, and when `stopped`, each was stopped and
/// the answer is that the code is not read; when not, neither was.
fn check(language: Language, code: &str, stopped: bool, at: &str) -> (Work, Work) {
    assert!(code.len() <= MAX_LEN, "{at}: {} bytes", code.len());
    let (reading, read) = testing::read(language, code);
    let (understood, asked) = testing::understand(language, code);
    within(code.len(), read, at);
    within(code.len(), asked, at);
    assert_eq!(read.stopped, stopped, "{at}: read {read:?}");
    assert_eq!(asked.stopped, stopped, "{at}: understand {asked:?}");
    if stopped {
        assert_eq!(shown(&reading.acts), "unread", "{at}");
        assert_eq!(understood, Understanding::NotUnderstood, "{at}");
    }
    (read, asked)
}

/// `code` meets an error and is not read through it: an `Unread` alone,
/// not understood, not parsed, and may give input and hand a shell a list;
/// it spends nothing past the reports that led to the error, and does not
/// spend the budget.
fn not_read_for_an_error(language: Language, code: &str, at: &str) -> Work {
    assert!(code.len() <= MAX_LEN, "{at}: {} bytes", code.len());
    let budget = Budget::new(code.len());
    let reading = budget.read(language, code);
    let work = testing::spent(&budget);
    within(code.len(), work, at);
    assert!(!work.stopped, "{at}: {work:?}");
    assert_eq!(work.errors, 1, "{at}: {work:?}");
    assert_eq!(shown(&reading.acts), "unread", "{at}");
    assert_eq!(
        budget.understand(language, code),
        Understanding::NotUnderstood,
        "{at}"
    );
    assert!(!budget.parses(language, code), "{at}");
    assert!(budget.gives_input(language, code), "{at}");
    assert!(budget.gives_shell_a_list(language, code), "{at}");
    // The other questions are answered from what the budget kept.
    assert_eq!(testing::spent(&budget), work, "{at}");
    work
}

#[test]
fn the_log_is_read_as_tree_sitter_writes_it() {
    // Each count reads tree-sitter's log by its words. Were they to change,
    // the counts would see nothing: these hold that each still counts what
    // it counts, past the reports a parse makes without the log.
    let before = "x = 1\n".repeat(400);
    // An error after the reports without the log: met as the parser starts
    // to recover from it (`resume version`).
    let erring = format!("{before}if (:\n");
    let work = not_read_for_an_error(Python, &erring, "an error after code");
    assert!(work.quiet > 0 && work.reports > work.quiet, "{work:?}");
    // Versions dropped and merged (`condense`).
    let (_, work) = testing::read(JavaScript, &fit("", "- await [a,a]", "", 8 * 1024));
    assert!(work.tangled > TANGLE_BASE && work.stopped, "{work:?}");
    // A step that goes back through versions merged before, and chooses
    // between the trees of two ways (`select_…`).
    // Stopped by the bound of one parse, well before the bound in all.
    let (_, work) = testing::read(JavaScript, &fit("", "- await ", "", 4 * 1024));
    assert!(work.selected > MAX_SELECTED && work.stopped, "{work:?}");
    assert!(work.selected < SELECTED_IN_ALL, "{work:?}");
    // A literal read two ways builds each element as it goes (`reduce`).
    let literal = format!(
        "{before}const o = {{{}}};\n",
        (0..400)
            .map(|i| format!("[k{i}]: v{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let (reading, work) = testing::read(JavaScript, &literal);
    assert!(!work.stopped && work.errors == 0, "{work:?}");
    assert!(work.tangled > 0 && work.tangled < 256, "{work:?}");
    assert_eq!(shown(&reading.acts), "");
}

#[test]
fn code_with_an_error_is_not_read_through_it() {
    // Every shape the grammars' recovery from an error made costly, or
    // endless, is stopped by the one rule, where the parser starts to
    // recover: tree-sitter-javascript's recovery that goes round the same
    // tokens with no end (alone, after code, in a function),
    // recoveries that wrap an error never closed, versions merged after an
    // error, a short prefix the parser never recovers from before valid
    // code, and a lexer that goes over comments again after an error. Each
    // is an `Unread` alone at every size, after the reports that led to it.
    let js_prefix = "/* ' */a=.c(e t...{{:o+a;,||#,0x]/";
    let py_prefix = "[...if*+(p*{a,a\n# \n~if 1if p%n e None\neval with*";
    let rows: [(Language, &str, &str, &str); 13] = [
        (JavaScript, ROUND, "x", ""),
        (JavaScript, "", "x;\n", ROUND),
        (JavaScript, "function f() {\n", "x;\n", ROUND),
        (JavaScript, "in ", "%c=>; ", ""),
        (Python, "", ")+\"", ""),
        (Python, "", "if/*a", ""),
        (Python, "", "/*a", ""),
        (Python, "", "%*a", ""),
        (Python, &"//".repeat(64), "+ *open ", ""),
        (JavaScript, js_prefix, "x = 1;\n", ""),
        (Python, py_prefix, "x = 1\n", ""),
        (Python, "!=]0x ]", "\n#", ""),
        (JavaScript, "/*xfrom  @catch", "@/*== ", ""),
    ];
    for (language, head, unit, tail) in rows {
        for kb in SIZES {
            if head.len() + unit.len() + tail.len() > kb * 1024 {
                continue;
            }
            let code = fit(head, unit, tail, kb * 1024);
            let at = format!("{language:?} {head:.20?} {unit:?} {tail:.20?}, {kb} KB");
            let work = not_read_for_an_error(language, &code, &at);
            // The valid code before an error costs what it costs to read;
            // one at the start is met within the reports without the log
            // and the first few with it.
            if tail.is_empty() && head.len() < 64 {
                assert!(work.reports <= MAX_QUIET + 8, "{at}: {work:?}");
            }
        }
    }
    // The round with a long name at its end: each round lexes the name
    // again, so at the largest sizes the run without the log is handed its
    // bytes before the parse reaches the log that sees the error. Either way
    // the code is not read.
    for kb in SIZES {
        let code = fit("c(.c(''.(X%'''\"';", "c", "(=", kb * 1024);
        let at = format!("a long name, {kb} KB");
        let (reading, work) = testing::read(JavaScript, &code);
        within(code.len(), work, &at);
        assert_eq!(shown(&reading.acts), "unread", "{at}");
        assert!(
            work.errors == 1 && !work.stopped
                || work.stopped && work.handed > code.len() * HANDED_BYTES + HANDED_BASE,
            "{at}: {work:?}"
        );
    }
}

/// `code` is refused before it is parsed, for its stars where Python
/// allows none: an `Unread` alone, not understood, and no report made.
fn refused(code: &str, at: &str) {
    let (reading, work) = testing::read(Python, code);
    within(code.len(), work, at);
    assert_eq!(shown(&reading.acts), "unread", "{at}");
    assert_eq!(
        (work.reports, work.errors, work.stopped),
        (0, 1, false),
        "{at}: {work:?}"
    );
    let (understood, asked) = testing::understand(Python, code);
    assert_eq!(understood, Understanding::NotUnderstood, "{at}");
    assert_eq!(asked.reports, 0, "{at}: {asked:?}");
    assert!(!milo_guards_code::parses(Python, code), "{at}");
}

#[test]
fn python_with_stars_where_python_allows_none_is_not_parsed() {
    // Python read two ways at once that never part: tree-sitter merges the
    // two at each token, and at an error, or the end of the code, builds
    // each way through them as a tree of its own, in one step no report
    // sees, in time and memory that grow with the square of the code. Every such shape found
    // holds a star where Python allows none, after an operator (`+*a`,
    // `-*a`, `/*a`, `%*a`, `@*a`, `if +*a`), which Python refuses: such code
    // is not parsed, alone, in a list, a call's arguments or a function's
    // body, in lines of four at the top level, after `if`, with a call, a
    // subscript or a pair in each unit, at any
    // size and after 60 KB of other code. Inside `exec` it is code that
    // raises before it runs: the code act it is.
    let rows: [(&str, &str, &str); 24] = [
        ("", "+*a", ""),
        ("", "-*a", ""),
        ("", "/*a", ""),
        ("", "%*a", ""),
        ("", "@*a\n", "def f(): pass\n"),
        ("x = [", "+*a", "]\n"),
        ("f(", "+*a", ")\n"),
        ("def f():\n    ", "+*a", "\n"),
        ("", "+*a+*a+*a+*a\n", ""),
        ("", "-*a-*a-*a-*a\n", ""),
        ("if ", "+*a", ""),
        ("if", "-*a", ""),
        ("while ", "+*a", ""),
        ("with ", "+*a", ""),
        ("", "+*a+*a+*f(a,a)+*a", ""),
        ("", "+*f(a,a)", ""),
        ("", "+*a+*a+*a+*a+*a+*a+*a+*a+*a[a,a]", ""),
        ("", "+*a+*a+*f(*a,*a)+*a", ""),
        ("", "+*a+*a+*f(a=a,b=a)+*a", ""),
        ("", "+*a+*a+*a[a:a,a:a]+*a", ""),
        ("", "-*a-*a-*f(a,a)-*a", ""),
        ("", "(a)+*anot ", ""),
        (&"//".repeat(64), "+ *open ", ""),
        ("", "a == *b\n", ""),
    ];
    let before = "x = 1\n".repeat(10_000);
    for (head, unit, tail) in rows {
        for kb in SIZES {
            if head.len() + unit.len() + tail.len() > kb * 1024 {
                continue;
            }
            let code = fit(head, unit, tail, kb * 1024);
            refused(&code, &format!("{head:.8?} {unit:?} {tail:?}, {kb} KB"));
        }
        let shape = fit(head, unit, tail, 4 * 1024);
        refused(&format!("{before}{shape}"), &format!("{unit:?} after code"));
        // Inside `exec`, a shape of four stars is the code act it is, code
        // that raises before it runs; past the stars counted on the bytes
        // alone, which see into the string, the code around it is not read
        // either.
        let small = fit(head, unit, tail, head.len() + tail.len() + 8 * unit.len());
        let (reading, work) = testing::read(Python, &format!("exec({small:?})\n"));
        assert!(!shown(&reading.acts).contains("unread"), "{unit:?} in exec");
        assert!(work.errors > 0 && !work.stopped, "{unit:?}: {work:?}");
        let (reading, work) = testing::read(Python, &format!("exec({shape:?})\n"));
        assert_eq!(shown(&reading.acts), "unread", "{unit:?} in exec");
        assert!(work.reports == 0, "{unit:?}: {work:?}");
    }
}

#[test]
fn stars_are_counted_only_where_python_allows_none() {
    // A starred expression stands after an opening bracket, a comma, a
    // colon, an assignment, plain or augmented, `in`, `for`, `return`,
    // `yield`, `lambda`, `import` or `except`, or in a string or a comment:
    // none is counted. A string ends where Python ends it: in a raw string a
    // backslash keeps the quote after it, and a format string's field may
    // hold strings of its own.
    let stars = |code: &str| testing::scan(Python, code).1;
    for code in [
        "[*a]",
        "f(*a, **k)",
        "x = *a, b",
        "parts += *'ab',",
        "x <<= *a,",
        "a ** b",
        "print(*a, sep='')",
        "for x in *a, b: pass",
        "return *a, b",
        "yield *a, b",
        "def f(*args: *Ts): pass",
        "x: tuple[*Ts, int]",
        "lambda *a: 0",
        "from m import *",
        "except* ValueError: pass",
        "a = b * c",
        "f(a)*b",
        "s = 'a + *b'",
        "s = \"\"\"\n/* a C comment */\n\"\"\"",
        "# a + *b",
        "def f(a, *, b): pass",
        "case [*rest]: pass",
        r#"QUOTE = r"\"" ; HELP = "- *a* - *b* - *c* - *d* - *e*""#,
        r"p = r'[a-z\']*|\*|/' ; h = '- *a* - *b*'",
        "h = f\"{'{'} - *a* - *b* - *c* - *d* - *e*\"",
        "h = f\"{d[\"k\"]} - *a* - *b* - *c* - *d* - *e*\"",
        "h = f'{a!r:*>10}'",
    ] {
        assert_eq!(stars(code), 0, "{code:?}");
    }
    // After an operator, or a keyword that takes an operand, and in a
    // replacement field of a format string: counted.
    for (code, count) in [
        ("+*a+*a", 2),
        ("a == *b", 1),
        ("x <= *a", 1),
        ("not *a", 1),
        ("@*a", 1),
        ("if +*a", 1),
        ("a * *b", 1),
        ("a ** *b", 1),
        ("f\"{a + *b}\"", 1),
        ("x = -*a", 1),
        (r"q = r'\'' + *a", 1),
    ] {
        assert_eq!(stars(code), count, "{code:?}");
    }
}

#[test]
fn a_few_stars_where_python_allows_none_refuse_the_code() {
    // Past the bound only, after an operator, after a keyword and in a
    // format string's field alike: four such stars are parsed, and five
    // are not.
    for star in ["y = (-*a)\n", "y = (not *a)\n", "y = f'{a + *b}'\n"] {
        let four = "x = a\n".to_string() + &star.repeat(MAX_STARS_AFTER_OPERATORS);
        assert!(testing::read(Python, &four).1.reports > 0, "{star:?}");
        refused(&(four + star), &format!("five of {star:?}"));
    }
}

#[test]
fn real_python_with_stars_in_its_strings_is_read() {
    // Real code whose strings hold what looks like a star after an
    // operator: raw strings that end in an escaped quote (as pygments'
    // lexers write their patterns), a format string's field that holds a
    // string, and a field that holds the string's own quote (Python 3.12).
    // Each is read, and the delete after it found.
    let pattern = r"    (r'([a-z_][a-zA-Z0-9_\']*=?|<<|>>|==|<=|<|>=|>|\+|-|~|\*|/|%|^|&&|&|\||\[\]=?)', Name.Function),";
    let rows = [
        format!(
            "from pygments.token import Name\nTOKENS = [\n{}\n]\n",
            [pattern; 5].join("\n")
        ),
        "QUOTE = r\"\\\"\" ; HELP = \"- *a* - *b* - *c* - *d* - *e*\"\n".to_string(),
        "print(f\"{'{'} - *a* - *b* - *c* - *d* - *e*\")\n".to_string(),
        "d = {\"k\": 1}\nprint(f\"{d[\"k\"]} - *a* - *b* - *c* - *d* - *e*\")\n".to_string(),
    ];
    for row in rows {
        let code = format!("import shutil\n{row}shutil.rmtree('/home/me')\n");
        assert_eq!(testing::scan(Python, &code).1, 0, "{row}");
        let (reading, work) = testing::read(Python, &code);
        assert!(!work.stopped && work.errors == 0, "{row}: {work:?}");
        assert_eq!(shown(&reading.acts), "remove /home/me", "{row}");
    }
}

/// `code` is not parsed, refused as code that does not parse or as code
/// not read: an `Unread` alone, not understood, and no report made.
fn refused_unparsed(language: Language, code: &str, at: &str) -> Work {
    let (reading, work) = testing::read(language, code);
    within(code.len(), work, at);
    assert_eq!(shown(&reading.acts), "unread", "{at}");
    assert_eq!(work.reports, 0, "{at}: {work:?}");
    assert!(work.stopped || work.errors == 1, "{at}: {work:?}");
    let (understood, asked) = testing::understand(language, code);
    assert_eq!(understood, Understanding::NotUnderstood, "{at}");
    assert_eq!(asked.reports, 0, "{at}: {asked:?}");
    work
}

/// `code` is not read, and not parsed: an `Unread` alone, not understood,
/// and no report made.
fn not_parsed(language: Language, code: &str, at: &str) -> Work {
    let (reading, work) = testing::read(language, code);
    within(code.len(), work, at);
    assert_eq!(shown(&reading.acts), "unread", "{at}");
    assert!(work.stopped && work.reports == 0, "{at}: {work:?}");
    let (understood, asked) = testing::understand(language, code);
    assert_eq!(understood, Understanding::NotUnderstood, "{at}");
    // Not parsed either (the strict subset may refuse the code before it
    // asks for a parse).
    assert_eq!(asked.reports, 0, "{at}: {asked:?}");
    work
}

#[test]
fn javascript_with_await_before_a_slash_is_not_read() {
    // tree-sitter-javascript reads an `await` before a `/` both as a name
    // divided and as the keyword before a regular expression; inside a
    // bracket, a template's field or a conditional left open, the two ways
    // merge at each one, and each merge goes back through the whole stack,
    // which grows with the code, in time that grows with its square and
    // recursion as deep as the stack. More than four such `await`s,
    // anywhere in the text, and the
    // code is not read, before it is parsed: alone, after 60 KB of other
    // code and inside `eval`.
    let before = "x = 1;\n".repeat(8_500);
    for opener in ["(", "(a,", "`${", "a?a:", "a?", "a(", "!(", "f(a,", "{a:"] {
        for keyword in ["", "typeof ", "void "] {
            for after in ["/", "/(", "/\t", "/a", "\n/", " /"] {
                let unit = format!("{opener}{keyword}await {after}");
                for kb in [2, 8, 64] {
                    let code = fit("", &unit, "", kb * 1024);
                    let work = not_parsed(JavaScript, &code, &format!("{unit:?}, {kb} KB"));
                    assert!(work.marks > MAX_AWAITED_SLASHES, "{unit:?}: {work:?}");
                }
                let shape = fit("", &unit, "", 4 * 1024);
                not_parsed(JavaScript, &format!("{before}{shape}"), "after code");
                // In `eval`, the code it runs is not read, whatever its
                // escapes hide of it from a scan of the text around it.
                let (reading, work) = testing::read(JavaScript, &format!("eval({shape:?})\n"));
                assert!(shown(&reading.acts).starts_with("unread"), "{unit:?}");
                assert!(work.stopped, "{unit:?} in eval: {work:?}");
            }
        }
    }
    // Past the bound only: four are read, five are not.
    let awaited = |n: usize| {
        let values: Vec<String> = (0..n).map(|i| format!("await /a{i}/")).collect();
        format!(
            "async function f() {{ return [{}]; }}\nrequire('fs').rmSync('/home/me');\n",
            values.join(", ")
        )
    };
    let (reading, work) = testing::read(JavaScript, &awaited(MAX_AWAITED_SLASHES));
    assert_eq!(shown(&reading.acts), "remove /home/me", "{work:?}");
    not_parsed(JavaScript, &awaited(MAX_AWAITED_SLASHES + 1), "five");
}

#[test]
fn code_nested_past_the_walk_s_depth_is_not_read() {
    // The parser goes back through its stack, as deep as the openers left
    // unclosed, by recursion: past the depth the reader walks, code is not
    // read, before it is parsed, by bracket, a format string's field and a
    // template's field alike; within it, it is read.
    let rows: [(Language, &str, &str, &str); 8] = [
        (Python, "(", "a", ")"),
        (Python, "[", "a", "]"),
        (Python, "{1:", "a", "}"),
        (Python, "f'{", "a", "}'"),
        (JavaScript, "(", "a", ")"),
        (JavaScript, "[", "a", "]"),
        (JavaScript, "{a:", "a", "}"),
        (JavaScript, "`${", "a", "}`"),
    ];
    for (language, open, middle, close) in rows {
        let levels = testing::scan(language, open).0;
        let (head, tail) = match language {
            Python => ("x = ", "\nimport shutil\nshutil.rmtree('/home/me')\n"),
            JavaScript => ("x = ", ";\nrequire('fs').rmSync('/home/me');\n"),
        };
        let nested = |depth: usize| {
            let count = depth / levels;
            format!(
                "{head}{}{middle}{}{tail}",
                open.repeat(count),
                close.repeat(count)
            )
        };
        let at = format!("{language:?} {open:?}");
        let code = nested(MAX_TREE_DEPTH);
        let (_, work) = testing::read(language, &code);
        assert!(!work.stopped && work.reports > 0, "{at}: {work:?}");
        assert!(work.depth <= MAX_TREE_DEPTH, "{at}: {work:?}");
        let work = not_parsed(language, &nested(MAX_TREE_DEPTH + levels), &at);
        assert!(work.depth > MAX_TREE_DEPTH, "{at}: {work:?}");
    }
}

#[test]
fn code_past_the_length_limit_is_not_read() {
    // The longest code the reader reads: past it, code is not read, before
    // it is parsed, whatever it is.
    for (language, unit) in [
        (JavaScript, "(await /"),
        (JavaScript, "x = 1;\n"),
        (Python, "x = 1\n"),
    ] {
        let code = fit("", unit, "", 4 * MAX_LEN);
        not_parsed(language, &code, unit);
        let code = fit("", unit, "", MAX_LEN + unit.len());
        not_parsed(language, &code, unit);
    }
}

/// The spaces both grammars pass over that are not ASCII ones.
const ODD_SPACES: [&str; 12] = [
    "\u{200b}", "\u{2060}", "\u{feff}", "\u{a0}", "\x0b", "\u{3000}", "\u{85}", "\u{1680}",
    "\u{2007}", "\u{202f}", "\u{205f}", "\u{2028}",
];

#[test]
fn code_with_spaces_only_its_grammar_passes_over_is_not_read() {
    // A space the grammar passes over where the scan once read a name
    // (`+\u{200b}*a` scanned as `+`, a name and `*`, no star counted, and
    // parsed with its stars; an `await` and a `/` with one between them read
    // as no `await` before a `/`): more than four of them outside the
    // strings and comments, and the code is not read, before it is parsed,
    // whatever the shape; four, and it is parsed.
    for space in ODD_SPACES {
        let rows: [(Language, String); 5] = [
            (Python, format!("+{space}*a")),
            (Python, format!("-{space}*a")),
            (
                Python,
                format!("+{space}*a+{space}*a+{space}*a+{space}*a\n"),
            ),
            (JavaScript, format!("(a,await{space}/(")),
            (JavaScript, format!("(await{space}/")),
        ];
        for (language, unit) in rows {
            for kb in [1, 8, 64] {
                let code = fit("", &unit, "", kb * 1024);
                let work = not_parsed(language, &code, &format!("{unit:?}, {kb} KB"));
                assert!(work.marks > 0 || work.depth > 0, "{unit:?}: {work:?}");
            }
        }
        let tail = |language| match language {
            Python => "import shutil\nshutil.rmtree('/home/me')\n",
            JavaScript => "require('fs').rmSync('/home/me');\n",
        };
        for language in [Python, JavaScript] {
            let line = format!("x = 1 +{space}2\n");
            let four = line.repeat(4) + tail(language);
            // Read, and the delete found where the grammar takes the space
            // for one (tree-sitter-python takes no Unicode space but a few).
            let (reading, work) = testing::read(language, &four);
            assert!(!work.stopped, "{space:?}: {work:?}");
            if work.errors == 0 {
                assert_eq!(shown(&reading.acts), "remove /home/me", "{space:?}");
            }
            not_parsed(language, &(line.repeat(5) + tail(language)), "five");
        }
    }
}

#[test]
fn python_strings_start_where_its_grammar_starts_them() {
    // tree-sitter-python takes any run of `f`, `t`, `r`, `b` and `u`
    // before a quote for a string's prefix, and a backtick for a quote
    // (a backtick before a triple quote is the start of a string to the
    // grammar, as it is to the scan).
    for prefix in ["ff", "fu", "fff", "Ft", "tR", "uF", "rTb"] {
        let unit = format!("{prefix}'{{a + *b}}'\n");
        refused(&fit("", &unit, "", 4 * 1024), &unit);
    }
    for head in ["x = `'''`\n", "x = `\"\"\"`\n", "`a`\n"] {
        refused(&fit(head, "+*a", "", 4 * 1024), head);
        refused(&format!("{head}x = 1\n"), head);
    }
}

#[test]
fn what_hides_from_the_scan_of_the_text_is_counted_on_its_bytes() {
    // A head that the scan of the text reads otherwise than the grammar
    // does hides what comes after it from that scan: a named escape whose
    // braces hold quotes (`f"\N{"""}"`), a format spec that holds a quote
    // (`f"{a:"}"""`), a backslash before a NUL (a line's continuation to
    // tree-sitter-python), a `lambda:` or `:=` in a field; and in
    // JavaScript a BOM, a space or a line before a hashbang, a CR in an
    // HTML-like comment or a regular expression, U+2028 in one, a
    // backslash and a CRLF in a string, and `export` read as a name. Counted on the
    // bytes alone, the stars, the `await`s and the brackets are not read
    // past their bounds, whatever comes before them.
    let python_heads = [
        "x = f\"\\N{\"\"\"}\"\n",
        "x = f\"{a:\"}\"\"\"\n",
        "x = f\"{lambda: 1}\"\n",
        "x = f\"{y:=1}\"\n",
        "",
    ];
    for head in python_heads {
        for unit in ["+*a +*a +*a +*a\n", "+\\\0*a", "(+*a"] {
            for kb in [2, 8] {
                let code = fit(head, unit, "", kb * 1024);
                refused_unparsed(Python, &code, &format!("{head:?} {unit:?}, {kb} KB"));
            }
        }
        let code = format!("{head}{}", "(".repeat(MAX_TREE_DEPTH + 1));
        refused_unparsed(Python, &code, &format!("{head:?} then brackets"));
    }
    let javascript_heads = [
        "\u{feff}#!`\n",
        "\n#!`\n",
        " #!`\n",
        "<!-- a\r`\n",
        "x = 'a\\\r\n`';\n",
        "x = /a\r`/;\n",
        "x = /a\u{2028}`/;\n",
        "x = export <a>\n",
        "",
    ];
    for head in javascript_heads {
        for unit in ["f(...await /", "(a,await /(", "x.await /"] {
            for kb in [2, 48] {
                let code = fit(head, unit, "", kb * 1024);
                let work = not_parsed(JavaScript, &code, &format!("{head:?} {unit:?}, {kb} KB"));
                assert!(
                    work.marks > MAX_AWAITED_SLASHES,
                    "{head:?} {unit:?}: {work:?}"
                );
            }
        }
        let code = format!("{head}{}", "(".repeat(MAX_TREE_DEPTH + 1));
        not_parsed(JavaScript, &code, &format!("{head:?} then brackets"));
    }
    // Real code is within the bounds counted on its bytes: the stars in its
    // strings (`c == '*'`), its brackets in strings and comments.
    let real = "import shutil\nif c == '*' or c in '+-*/':\n    pass\n\"\"\"\n- *a*\n- *b*\n\"\"\"\nshutil.rmtree('/home/me')\n";
    let (reading, work) = testing::read(Python, real);
    assert_eq!(shown(&reading.acts), "remove /home/me", "{work:?}");
}

#[test]
fn javascript_conditionals_on_lines_of_their_own_are_read() {
    // A conditional opens no level the scan counts: 405 lines of them
    // without semicolons, which once counted a level for each, are read.
    let lines: String = (0..405)
        .map(|i| "const vN = flagN ? leftN : rightN\n".replace('N', &i.to_string()))
        .collect();
    let code = lines + "require('fs').rmSync('/home/me')\n";
    let (reading, work) = testing::read(JavaScript, &code);
    assert!(!work.stopped, "{work:?}");
    assert_eq!(shown(&reading.acts), "remove /home/me");
}

/// A literal of `count` elements made by `element`, between `open` and
/// `close`, after `head`, and a delete of `/home/me` after it.
fn literal(
    language: Language,
    open: &str,
    element: &dyn Fn(usize) -> String,
    close: &str,
    count: usize,
) -> String {
    let (head, tail) = match language {
        JavaScript => (
            "const fs = require('fs');\n",
            "\nfs.rmSync('/home/me', {recursive: true});\n",
        ),
        Python => ("import shutil\n", "\nshutil.rmtree('/home/me')\n"),
    };
    let elements: Vec<String> = (0..count).map(element).collect();
    format!("{head}{open}{}{close}{tail}", elements.join(", "))
}

#[test]
fn ways_merged_around_a_list_s_elements_are_stopped() {
    // JavaScript's `await` read as a name between operators, with a list's
    // element every few units (`- await ` sixteen times, then `[a,a]`: 3.8 s
    // for 64 KB, each step costing more than the last as merged ways
    // multiply), which a count that started again at a list's element let
    // through: held at every size by the drops and merges over the code and
    // the choices between the trees of two ways, alone, after 60 KB of other
    // code and inside `eval`.
    let before = "x = 1;\n".repeat(8_500);
    for element in ["[a,a]", "(a,a)", "{a,a}", "f(a,a)", "`${a}${a}`"] {
        for every in [1, 2, 4, 16, 32, 64] {
            for (op, name) in [("- ", "await "), ("+", "await "), ("- ", "\nawait ")] {
                let unit = format!("{}{element}", format!("{op}{name}").repeat(every));
                for kb in [2, 8, 64] {
                    if unit.len() * 2 > kb * 1024 {
                        continue;
                    }
                    let code = fit("", &unit, "", kb * 1024);
                    let at = format!("{op:?}{name:?} {every} times then {element}, {kb} KB");
                    let (_, work) = testing::read(JavaScript, &code);
                    within(code.len(), work, &at);
                    // At the length limit: stopped, or read whole having
                    // chosen between two ways a few times, which costs little.
                    if kb == 64 {
                        assert!(held(work) || work.selected <= 64, "{at}: {work:?}");
                    }
                }
                let shape = fit("", &unit, "", 8 * 1024);
                for code in [format!("{before}{shape}"), format!("eval({shape:?})\n")] {
                    let (_, work) = testing::read(JavaScript, &code);
                    within(code.len(), work, "after code or in eval");
                }
            }
        }
    }
}

#[test]
fn modules_and_enums_compiled_to_javascript_are_read_whole() {
    // What compilers write: TypeScript's enums and esbuild's namespaces, one
    // function after another at the top level, each read two ways for a
    // while (as a call or a parenthesized expression).
    let enum_ = "var EN;\n(function (EN) {\n    EN[EN[\"A\"] = 0] = \"A\";\n    EN[EN[\"B\"] = 1] = \"B\";\n})(EN || (EN = {}));\n";
    let space =
        "var nsN;\n((nsN) => {\n  nsN.a = 1;\n  nsN.f = (x) => x + 1;\n})(nsN || (nsN = {}));\n";
    let enums: String = (0..300)
        .map(|i| enum_.replace('N', &i.to_string()))
        .collect();
    let spaces: String = (0..300)
        .map(|i| space.replace('N', &i.to_string()))
        .collect();
    for (name, body) in [("enums", enums), ("namespaces", spaces)] {
        let code = format!("{body}require('fs').rmSync('/home/me');\n");
        assert!(code.len() <= MAX_LEN, "{name}: {}", code.len());
        let (reading, work) = testing::read(JavaScript, &code);
        within(code.len(), work, name);
        assert!(!work.stopped && work.errors == 0, "{name}: {work:?}");
        assert_eq!(shown(&reading.acts), "remove /home/me", "{name}");
    }
}

#[test]
fn literals_read_two_ways_are_read_whole() {
    // Valid literals the grammar reads two ways at once (an object or array
    // that may be a pattern, starred names that may be a target, a `with`
    // whose items may be a tuple): each element is built as it goes, so the
    // versions merge at no cost, and the literal is read, and the delete
    // after it found, at the size first measured and at the length limit.
    type Element = fn(usize) -> String;
    let rows: [(Language, &str, Element, &str, usize); 12] = [
        (
            JavaScript,
            "const h = {",
            |i| format!("[KEY_{i}]: handler{i}"),
            "};",
            130,
        ),
        (
            JavaScript,
            "const rows = [",
            |i| format!("{{id: ID_{i}}}"),
            "];",
            520,
        ),
        (
            JavaScript,
            "const p = [",
            |i| format!("[a{i}, b{i}]"),
            "];",
            520,
        ),
        (
            JavaScript,
            "const o = {",
            |i| format!("k{i}: [a, b]"),
            "};",
            520,
        ),
        (
            JavaScript,
            "module.exports = {",
            |i| format!("name{i}: lib{i}.fn"),
            "};",
            520,
        ),
        (
            JavaScript,
            "let a0; (",
            |i| format!("a{i} = {i}"),
            ");",
            260,
        ),
        (
            JavaScript,
            "export default {",
            |i| format!("n{i}"),
            "};",
            520,
        ),
        (Python, "print(", |i| format!("*part{i}"), ")", 175),
        (Python, "x = [", |i| format!("*a{i}"), "]", 260),
        (
            Python,
            "with (",
            |i| format!("open(f{i}) as g{i}"),
            "):\n    pass",
            260,
        ),
        (Python, "x = [", |i| format!("(a{i}, b{i})"), "]", 520),
        (Python, "d = {", |i| format!("'k{i}': [a, b]"), "}", 520),
    ];
    for (language, open, element, close, count) in rows {
        let at_limit = (1..=MAX_LEN / 64)
            .map(|n| n * 64)
            .take_while(|&n| literal(language, open, &element, close, n).len() <= MAX_LEN)
            .last()
            .unwrap_or(count);
        for count in [count, at_limit] {
            let code = literal(language, open, &element, close, count);
            let at = format!("{language:?} {open:?} {count} elements");
            let (reading, work) = testing::read(language, &code);
            within(code.len(), work, &at);
            assert!(!work.stopped && work.errors == 0, "{at}: {work:?}");
            assert!(work.tangled < 256, "{at}: {work:?}");
            assert!(shown(&reading.acts).contains("remove /home/me"), "{at}");
        }
    }
}

#[test]
fn pieces_each_within_the_bounds_of_a_parse_are_held_together() {
    // Code a parse reads to its end within its own bounds, at a cost the
    // bounds of one parse let through, read in piece after piece of one
    // line: the budget carries the drops and merges left over from each
    // parse to the next, and adds up the choices between the trees of two
    // ways, and stops the pieces after the first few, whatever their number.
    let rows: [(&str, &str, usize, usize); 2] = [
        ("", "- await [a,a]", 4 * 1024, 3),
        ("", "- await - await [a,a]", 8 * 1024, 4),
    ];
    for (head, unit, size, most) in rows {
        let code = fit(head, unit, "", size);
        let at = format!("{unit:?} in pieces of {size} bytes");
        let budget = Budget::new(MAX_LEN);
        let mut readings = 0;
        let mut acts = String::new();
        while !budget.is_spent() && readings < 64 {
            let piece = format!("{code}{readings}");
            acts = shown(&budget.read(JavaScript, &piece).acts);
            readings += 1;
            let work = testing::spent(&budget);
            assert!(work.quiet <= QUIET_IN_ALL + 1, "{at}: {work:?}");
        }
        let work = testing::spent(&budget);
        within(MAX_LEN, work, &at);
        assert!(work.stopped, "{at}: {work:?}");
        assert!(acts.contains("unread"), "{at}: {acts}");
        assert!(readings <= most, "{at}: {readings} readings, {work:?}");
        // Each piece alone is read to its end.
        assert!(!testing::read(JavaScript, &code).1.stopped, "{at}");
        assert!(held(work), "{at}: {work:?}");
    }
}

#[test]
fn pieces_that_each_meet_an_error_are_held_to_the_reports() {
    // Code that meets an error spends nothing past the reports that led to
    // it, and does not spend the budget: a line of many such pieces is held
    // to the reports of the line.
    let budget = Budget::new(MAX_LEN);
    let mut readings = 0;
    while !budget.is_spent() && readings < 2_000 {
        let piece = format!("{}{readings}", fit("", "x;\n", ROUND, 3 * 1024));
        assert!(shown(&budget.read(JavaScript, &piece).acts).contains("unread"));
        readings += 1;
    }
    let work = testing::spent(&budget);
    within(MAX_LEN, work, "pieces in error");
    assert!(work.stopped, "{work:?}");
    assert!(
        work.reports > MAX_LEN / REPORT_BYTES + REPORT_BASE,
        "{work:?}"
    );
    assert!(
        work.errors + 1 >= readings && readings > 2,
        "{readings}: {work:?}"
    );
}

/// Python of `before` KB of statements, then a function whose body holds a
/// run of `lines` comment lines of `width` characters each.
fn comments_in_a_block(before: usize, width: usize, lines: usize) -> String {
    let mut code = "x = 1\n".repeat(before * 1024 / 6);
    code.push_str("import shutil\nshutil.rmtree('/home/me')\ndef f():\n    x = 1\n");
    let line = format!("    #{}\n", "c".repeat(width - 6));
    code.push_str(&line.repeat(lines));
    code.push_str("    y = 2\n");
    code
}

#[test]
fn a_run_of_comment_lines_in_a_block_is_read_up_to_the_bytes_handed() {
    // tree-sitter-python's scanner reads the rest of a run of comment lines
    // in a block again at each line of it: a run of `n` lines is handed some
    // `4·n²` bytes. At the start of the code, read without the log, a run of
    // 2,569 short lines is read; after code longer than the reports without
    // the log, read with it, each byte handed counts twelve times, and a run
    // is read up to some 730 short lines, 330 of 40 characters and 235 of
    // 78; past them it is stopped by the bytes handed. Each row gives the
    // longest run read, which the next line stops, as measured.
    let rows: [(usize, usize, usize); 7] = [
        (0, 8, 2_569),
        (0, 40, 1_184),
        (4, 8, 728),
        (4, 40, 327),
        (4, 78, 235),
        (20, 8, 737),
        (50, 8, 755),
    ];
    for (before, width, read) in rows {
        let at = format!("{read} lines of {width} after {before} KB");
        let code = comments_in_a_block(before, width, read);
        let (reading, work) = testing::read(Python, &code);
        within(code.len(), work, &at);
        assert!(!work.stopped, "{at}: {work:?}");
        assert_eq!(shown(&reading.acts), "remove /home/me", "{at}");
        let code = comments_in_a_block(before, width, read + 1);
        let (reading, work) = testing::read(Python, &code);
        within(code.len(), work, &at);
        assert!(work.stopped, "{at}: {work:?}");
        assert!(
            work.handed > code.len() * HANDED_BYTES + HANDED_BASE,
            "{at}: {work:?}"
        );
        assert_eq!(shown(&reading.acts), "unread", "{at}");
    }
}

#[test]
fn the_reader_s_own_work_is_held_to_its_units() {
    // A chain of calls or of members that names the same thing again from
    // each link, past the depth the walk reads: each link costs the walk the
    // depth again. Past the units the reading stops where it is.
    let rows: [(Language, &str, &str, &str); 5] = [
        (JavaScript, "x", "()", ""),
        (JavaScript, "x", "``", ""),
        (JavaScript, "x", ".a()", ""),
        (Python, "x", "()", ""),
        (Python, "x", " = a", ""),
    ];
    for (language, head, unit, tail) in rows {
        let code = fit(head, unit, tail, MAX_LEN);
        let at = format!("{language:?} {head}{unit}…");
        let (reading, work) = testing::read(language, &code);
        within(code.len(), work, &at);
        assert!(work.stopped, "{at}: {work:?}");
        assert!(
            work.walked > code.len() * WALK_BYTES + WALK_BASE,
            "{at}: {work:?}"
        );
        assert!(shown(&reading.acts).contains("unread"), "{at}");
        assert_eq!(
            milo_guards_code::understand(language, &code),
            Understanding::NotUnderstood,
            "{at}"
        );
    }
}

#[test]
fn every_reading_within_one_budget_draws_from_it() {
    // A caller that reads several pieces of one line through one budget:
    // once a reading is stopped, every one after it is too, before it
    // starts, so reading again, or the code inside code, adds no work.
    let budget = Budget::new(1024);
    assert!(!budget.is_spent());
    let _ = budget.read(JavaScript, &fit("", "- await [a,a]", "", 8 * 1024));
    let spent = testing::spent(&budget);
    assert!(budget.is_spent(), "{spent:?}");
    assert_eq!(
        shown(&budget.read(JavaScript, "console.log(1)").acts),
        "unread"
    );
    assert_eq!(
        budget.understand(JavaScript, "console.log(1)"),
        Understanding::NotUnderstood
    );
    assert_eq!(
        budget.understand_python2("print 1"),
        Understanding::NotUnderstood
    );
    assert!(!budget.parses(JavaScript, "console.log(1)"));
    assert!(budget.gives_input(JavaScript, "console.log(1)"));
    assert!(budget.gives_shell_a_list(JavaScript, "console.log(1)"));
    let after = testing::spent(&budget);
    assert_eq!((after.reports, after.handed), (spent.reports, spent.handed));
    // The code `eval` runs, nested four deep, is read within the budget of
    // the code: nesting does not multiply the work.
    let mut nested = fit("", "- await [a,a]", "", 30_000);
    for _ in 0..4 {
        nested = format!("eval({nested:?})");
    }
    let (reading, work) = testing::read(JavaScript, &nested);
    within(nested.len(), work, "nested four deep");
    assert!(work.stopped, "{work:?}");
    assert!(shown(&reading.acts).contains("unread"));
}

/// The first `budget`, made for `len` bytes and spent on a chain of calls of
/// `links` links, after which asking `ask` runs out of the units of the
/// walk inside it: the walk of the chain leaves the budget not spent, and
/// the question spends it.
fn spent_inside(
    language: Language,
    len: usize,
    ask: &dyn Fn(&Budget) -> bool,
) -> Option<(Budget, bool)> {
    for links in (1..4_000).step_by(7) {
        let budget = Budget::new(len);
        let chain = format!("x{}", "()".repeat(links));
        let _ = budget.read(language, &chain);
        if budget.is_spent() {
            return None;
        }
        let answer = ask(&budget);
        if budget.is_spent() {
            return Some((budget, answer));
        }
    }
    None
}

#[test]
fn a_question_whose_walk_runs_out_answers_the_cautious_way() {
    // Within a budget left short by an earlier reading, a question whose own
    // walk runs out of units part of the way gives the answer of code not
    // read: not understood, may give input, may hand a shell a list; though
    // what it would have found is at the end, past where the walk stopped.
    let js = format!(
        "{}require('fs').rmSync('/home/me/x'); spawnSync('a', ['b'], opts); p.stdin.write(x)",
        "f(a, b);\n".repeat(600)
    );
    let py = format!(
        "{}import os\nos.remove('/home/me/x')\nsubprocess.run(['a'], shell=True)\nsubprocess.run(['a'], input=b'x')\n",
        "f(a, b)\n".repeat(600)
    );
    type Question<'q> = &'q dyn Fn(&Budget, &str) -> bool;
    let questions: [(Language, &str, Question<'_>); 6] = [
        (JavaScript, "understand", &|b, c| {
            b.understand(JavaScript, c) == Understanding::NotUnderstood
        }),
        (JavaScript, "gives_input", &|b, c| {
            b.gives_input(JavaScript, c)
        }),
        (JavaScript, "gives_shell_a_list", &|b, c| {
            b.gives_shell_a_list(JavaScript, c)
        }),
        (Python, "understand", &|b, c| {
            b.understand(Python, c) == Understanding::NotUnderstood
        }),
        (Python, "understand_python2", &|b, c| {
            b.understand_python2(c) == Understanding::NotUnderstood
        }),
        (Python, "gives_shell_a_list", &|b, c| {
            b.gives_shell_a_list(Python, c)
        }),
    ];
    for (language, name, question) in questions {
        let code = if language == JavaScript { &js } else { &py };
        // Without the earlier reading, the code is read to its end: not
        // understood, and it gives input and hands a shell a list, by the
        // acts at its end only.
        let whole = Budget::new(code.len());
        assert!(question(&whole, code), "{language:?} {name}, whole");
        assert!(!whole.is_spent(), "{language:?} {name}");
        // With it, the walk runs out first: the same answer, and the budget
        // spent.
        let ran_out = spent_inside(language, code.len(), &|budget| question(budget, code));
        let (budget, answer) =
            ran_out.unwrap_or_else(|| panic!("{language:?} {name}: never ran out inside"));
        assert!(answer, "{language:?} {name}: {:?}", testing::spent(&budget));
    }
    // Python's input, by the same walk.
    let ran_out = spent_inside(Python, py.len(), &|budget| budget.gives_input(Python, &py));
    assert!(
        ran_out.is_some_and(|(_, answer)| answer),
        "Python gives_input"
    );
}

#[test]
fn literal_code_whose_parse_is_stopped_is_not_read() {
    // The code `exec` and `eval` run is parsed within the same budget: a
    // stopped parse there is code not read, never code that does not parse
    // (which raises before it runs a thing), and the walk of the code
    // around it goes on, so what is beside it is found.
    let stopped = fit("", "- await [a,a]", "", 8 * 1024);
    let code = format!("const m = require('fs');\neval({stopped:?});\nm.rmSync('/home/me');\n");
    let (reading, work) = testing::read(JavaScript, &code);
    within(code.len(), work, "exec of a stopped parse");
    assert!(work.stopped, "{work:?}");
    let acts = shown(&reading.acts);
    assert!(acts.starts_with("unread"), "{acts}");
    assert!(acts.ends_with("remove /home/me"), "{acts}");
    // Literal code with an error raises before it runs: it is code run, and
    // what is beside it is read; the budget is not spent.
    let code = "import shutil\nexec('if (:')\nshutil.rmtree('/home/me')\n";
    let (reading, work) = testing::read(Python, code);
    assert!(!work.stopped && work.errors == 1, "{work:?}");
    assert_eq!(shown(&reading.acts), "python if (:, remove /home/me");
}

#[test]
fn short_code_is_read_whole() {
    // Code of a few lines is read with the few reports it allows, and with
    // the log on only when it needs more than the reports without it.
    for (language, code) in [
        (Python, "import os\nos.remove('/tmp/x')\n"),
        (JavaScript, "require('fs').rmSync('/tmp/x')"),
        (Python, "x = 1"),
        (JavaScript, ""),
    ] {
        let (_, work) = check(language, code, false, code);
        assert!(work.reports <= MAX_QUIET, "{code:?}: {work:?}");
    }
}

#[test]
fn dense_code_at_the_length_limit_is_read_whole() {
    // Valid code written to be dense, at the length limit: within every
    // count, and read whole.
    let rows: [(Language, &str, &str, &str); 4] = [
        (Python, "x = (", "a,", ")\n"),
        (Python, "", "a\n", ""),
        (JavaScript, "x = [", "a,", "];\n"),
        (JavaScript, "", "a;\n", ""),
    ];
    for (language, head, unit, tail) in rows {
        let code = fit(head, unit, tail, MAX_LEN);
        let at = format!("{language:?} {unit:?}");
        let (read, asked) = check(language, &code, false, &at);
        for work in [read, asked] {
            assert!(work.tangled <= 16, "{at}: {work:?}");
            assert_eq!(work.errors, 0, "{at}: {work:?}");
        }
    }
}

#[test]
fn code_nested_as_deep_as_the_walk_reads_is_not_stopped() {
    // Brackets nested as deep as the walk reads: read whole (the walk then
    // says it is too deep), not stopped by any count.
    for (language, open, close) in [(Python, "(", ")"), (JavaScript, "[", "]")] {
        let code = format!("x = {}1{}\n", open.repeat(390), close.repeat(390));
        let at = format!("{language:?} {open}");
        let _ = check(language, &code, false, &at);
    }
}

#[test]
fn a_chain_of_assignments_is_read_in_work_that_grows_with_it() {
    // `x = a = a = …`: the chain is followed to its end once for the chain,
    // not again from each assignment; past some hundred links the walk's
    // units stop it.
    for (kb, stopped) in [(1, false), (4, true), (64, true)] {
        let code = fit("x", " = a", "", kb * 1024);
        let at = format!("{kb} KB of assignments");
        let (_, work) = testing::read(Python, &code);
        within(code.len(), work, &at);
        assert_eq!(work.stopped, stopped, "{at}: {work:?}");
    }
}

#[test]
fn the_other_questions_of_stopped_code_are_held_to_the_budget() {
    // `parses`, `gives_input` and `gives_shell_a_list` make the same parse:
    // the code is not said to parse, may give input and hand a shell a
    // list, and each is held to the budget.
    for kb in [4, 32] {
        let code = fit("", "- await [a,a]", "", kb * 1024 * 2);
        let at = format!("{kb} KB");
        let (parses, work) = testing::parses(JavaScript, &code);
        assert!(!parses && work.stopped, "{at}: {work:?}");
        within(code.len(), work, &at);
        let (input, work) = testing::gives_input(JavaScript, &code);
        assert!(input && work.stopped, "{at}: {work:?}");
        let (list, work) = testing::gives_shell_a_list(JavaScript, &code);
        assert!(list && work.stopped, "{at}: {work:?}");
        assert!(testing::stops(JavaScript, &code).0, "{at}");
    }
}

#[test]
fn the_same_code_asked_again_is_parsed_once() {
    // Each question asked of the same code within one budget is answered
    // from what its first parse gave: the reports, and the bytes handed,
    // are those of one parse, for the last four pieces asked about, in
    // their own language.
    let pieces: Vec<(Language, String)> = (0..4)
        .map(|piece| {
            if piece % 2 == 0 {
                (
                    Python,
                    "import os\nos.remove('/tmp/x')\n".repeat(200 + piece),
                )
            } else {
                (
                    JavaScript,
                    "require('fs').rmSync('/tmp/x');\n".repeat(200 + piece),
                )
            }
        })
        .collect();
    let budget = Budget::new(MAX_LEN);
    let readings: Vec<String> = pieces
        .iter()
        .map(|(language, code)| shown(&budget.read(*language, code).acts))
        .collect();
    let once = testing::spent(&budget);
    for ((language, code), reading) in pieces.iter().zip(&readings) {
        let _ = budget.understand(*language, code);
        assert!(budget.parses(*language, code));
        let _ = budget.gives_input(*language, code);
        let _ = budget.gives_shell_a_list(*language, code);
        assert_eq!(&shown(&budget.read(*language, code).acts), reading);
    }
    let after = testing::spent(&budget);
    assert_eq!(
        (after.reports, after.handed),
        (once.reports, once.handed),
        "{after:?}"
    );
    // What was kept is kept for its language: Python's `def` is no
    // JavaScript.
    let budget = Budget::new(MAX_LEN);
    assert!(budget.parses(Python, "def f(): pass"));
    assert!(!budget.parses(JavaScript, "def f(): pass"));
    // Code that met an error is kept as such.
    let budget = Budget::new(MAX_LEN);
    assert!(!budget.parses(JavaScript, "if ("));
    let once = testing::spent(&budget);
    assert_eq!(shown(&budget.read(JavaScript, "if (").acts), "unread");
    assert_eq!(testing::spent(&budget), once);
}

#[test]
fn a_budget_shows_what_it_spent_and_never_the_code() {
    let budget = Budget::new(usize::MAX);
    let code = "require('fs').rmSync('/home/secret-name')";
    let _ = budget.read(JavaScript, code);
    let shown = format!("{budget:?}");
    assert!(!shown.contains("secret-name"), "{shown}");
    assert!(shown.contains("kept: 1"), "{shown}");
    // A length past the limit is the limit.
    let most = Budget::new(MAX_LEN);
    let _ = most.read(JavaScript, code);
    assert_eq!(testing::spent(&most), testing::spent(&budget));
}
