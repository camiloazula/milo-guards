//! Inline code: Python, JavaScript and Ruby given with `-c`, `-e`, `eval` or a
//! here-document are read, and what they delete, write and run is judged
//! like the same shell command: a finding names the path and why, a path is
//! read as the shell reads it, code that starts code is read to a limit, and
//! long code is read in linear time.
//!
//! The lines and their answers are in `tests/cases/inline.cases`; here are
//! the path a finding names, the code nested past the limit, and long code
//! whose parse the reader stops. The time long code takes is in
//! `tests/timing.rs`.

mod common;

use common::inline::nest;
use common::lines::{long_code, long_ruby_code};
use common::{posix, rules};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("inline");
}

#[test]
fn a_finding_names_the_path_and_why() {
    let paths = posix();
    let judge = |line: &str| classify(line, Shell::Posix, &paths).findings().to_vec();

    let home = judge("python3 -c \"import shutil,os; shutil.rmtree(os.path.expanduser('~'))\"");
    assert_eq!(home.len(), 1, "{home:?}");
    assert_eq!(home[0].rule, Rule::Delete);
    assert_eq!(home[0].reason, "deletes your home directory");
    assert_eq!(home[0].target.as_deref(), Some("~"));

    let here = judge("python3 - <<'PY'\nimport shutil\nshutil.rmtree('/home/me')\nPY");
    assert_eq!(here.len(), 1, "{here:?}");
    assert_eq!(here[0].reason, "deletes your home directory");
    assert_eq!(here[0].target.as_deref(), Some("/home/me"));

    let unknown = judge("python3 -c \"exec(input())\"");
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0].rule, Rule::Unknown);
    assert_eq!(unknown[0].reason, "runs code the guard does not read");
    assert_eq!(unknown[0].target.as_deref(), Some("exec(input())"));
}

#[test]
fn code_that_starts_code_is_read_to_a_limit() {
    let paths = posix();
    // Python that runs `python3 -c` that runs Python, each inside the last.
    let mut line = "rm -rf /tmp/x".to_string();
    for level in 1..=12 {
        line = nest(&line);
        let found = rules(&line, Shell::Posix, &paths);
        if level <= 3 {
            // Read through, so not unreadable; the `import os` of each level
            // is not read whole by the strict gate, so it is unknown.
            assert!(
                found.iter().all(|rule| *rule == Rule::Unknown),
                "level {level} is read: {found:?}"
            );
        }
    }
    let found = rules(&line, Shell::Posix, &paths);
    assert!(
        found.contains(&Rule::Unreadable),
        "nested past the limit: {found:?}"
    );

    let deep = format!(
        "python3 -c \"import os; os.remove({}1{})\"",
        "(".repeat(2000),
        ")".repeat(2000)
    );
    let found = rules(&deep, Shell::Posix, &paths);
    assert!(!found.is_empty(), "too deep to read must be risky");

    let deep = format!(
        "node -e \"require('fs').rmSync({}1{})\"",
        "(".repeat(2000),
        ")".repeat(2000)
    );
    let found = rules(&deep, Shell::Posix, &paths);
    assert!(!found.is_empty(), "too deep to read must be risky");
}

#[test]
fn long_inline_code_is_read_unless_it_nests_too_deep() {
    let (rows, chain) = long_code();
    for line in rows {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        // What nests too deeply to read is not safe, and the rest is read.
        // The body of a quoted here-document is a literal to the shell, so
        // the shell's count of open parentheses does not see it: the reader
        // of the code does, and calls nested past what it reads are code it
        // does not read.
        let assessment = classify(&line, Shell::Posix, &posix());
        let deep = assessment
            .findings()
            .iter()
            .any(|finding| finding.rule == Rule::Unreadable);
        assert_eq!(deep, line.contains(&chain), "{:?}", &line[..20]);
        if line.contains(&"f(".repeat(500)) {
            assert!(!assessment.is_safe(), "{:?}", &line[..20]);
        }
    }
}

#[test]
fn code_whose_parse_the_reader_stops_is_unknown() {
    // Code the reader does not read (it meets an error, or its reading is
    // stopped, as the reader's `tests/parse_budget.rs` holds), up to the
    // reader's length limit, given with `-c` or `-e`, on its input or in a
    // here-document: a finding that the guard does not read it, never safe,
    // and an effect that is unknown, never reads only. tree-sitter-javascript's
    // recovery goes round the last few tokens of the first with no end, and
    // wraps the error the second starts with again at each of its tokens;
    // the third, Python, starts with an error and goes over comments after
    // it; each is stopped where the recovery starts.
    let paths = posix();
    let round = "c(.c(''.(X%'''\"';c(=";
    // Each within the reader's length limit, 3 KiB; longer code is not read
    // for its length, and gets the same answer.
    let javascript = format!("{}{round}", "x;\n".repeat(1_000));
    let python = format!("!=]0x ]{}", "\n#".repeat(1_400));
    let wrapped = format!("in {}", "%c=>; ".repeat(500));
    // Ruby that meets an error: an opener the code never closes, after a
    // run of statements.
    let ruby = format!("{}x = (\n", "x\n".repeat(1_400));
    for (interpreter, code) in [
        ("node", &javascript),
        ("node", &wrapped),
        ("python3", &python),
        ("ruby", &ruby),
    ] {
        let flag = if interpreter == "python3" { "-c" } else { "-e" };
        // The code as one double-quoted word of the line.
        let word = format!("\"{}\"", code.replace('\\', "\\\\").replace('"', "\\\""));
        for line in [
            format!("{interpreter} {flag} {word}"),
            format!("printf %s {word} | {interpreter}"),
            format!("{interpreter} <<'END'\n{code}\nEND"),
        ] {
            let at = format!("{:?}", &line[..line.len().min(30)]);
            assert!(line.len() <= 64 * 1024, "{at}: {}", line.len());
            let assessment = classify(&line, Shell::Posix, &paths);
            assert!(
                assessment
                    .findings()
                    .iter()
                    .any(|finding| finding.rule == Rule::Unknown
                        && finding.reason == "runs code the guard does not read"),
                "{at}: {assessment:?}"
            );
            assert_eq!(
                milo_guards_shell::effect(&line, Shell::Posix, &paths),
                milo_guards_shell::Effect::Unknown,
                "{at}"
            );
        }
    }
}

#[test]
fn long_inline_ruby_is_never_safe_unless_it_is_read() {
    // Ruby up to the reader's length limit, in the shapes of the code above
    // and the ones the grammar reads two ways: every line gets an answer,
    // and the unread ones are not safe.
    let paths = posix();
    for line in long_ruby_code() {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let assessment = classify(&line, Shell::Posix, &paths);
        let found = rules(&line, Shell::Posix, &paths);
        if line.contains(&"f(".repeat(500)) {
            assert!(!assessment.is_safe(), "{:?}: {found:?}", &line[..20]);
        }
    }
}

#[test]
fn code_longer_than_the_readers_limit_is_unknown() {
    // The reader reads code of at most 3 KiB (`MAX_LEN`, a deliberate
    // limit); a line may be longer (64 KiB), and the inline code in it that
    // is not read for its length is `unknown`, in each language, however it
    // is given. Code of the same shape within the limit is read, and safe.
    const MAX_LEN: usize = 3 * 1024;
    let paths = posix();
    let code = |interpreter: &str, filler: usize| match interpreter {
        "python3" => format!("x = '{}'\nprint(x)", "a".repeat(filler)),
        "node" => format!("let x = '{}'; console.log(x)", "a".repeat(filler)),
        _ => format!("x = '{}'\nputs x", "a".repeat(filler)),
    };
    for interpreter in ["python3", "node", "ruby"] {
        let flag = if interpreter == "python3" { "-c" } else { "-e" };
        for (filler, read) in [(2_000, true), (3_100, false), (20_000, false)] {
            let code = code(interpreter, filler);
            assert_eq!(code.len() <= MAX_LEN, read, "{interpreter}");
            for (whole, line) in [
                (true, format!("{interpreter} {flag} \"{code}\"")),
                (false, format!("{interpreter} <<'END'\n{code}\nEND")),
            ] {
                let found = format!("{interpreter} {filler}: {:?}", &line[..line.len().min(30)]);
                let assessment = classify(&line, Shell::Posix, &paths);
                let unread = assessment.findings().iter().any(|finding| {
                    finding.rule == Rule::Unknown
                        && finding.reason == "runs code the guard does not read"
                });
                assert_eq!(unread, !read, "{found}: {assessment:?}");
                // A line is safe only for code written whole on it, and read.
                if read && whole {
                    assert!(assessment.is_safe(), "{found}: {assessment:?}");
                }
            }
        }
    }
}

// The reader's work is counted only where the guard reads inline code.
#[cfg(feature = "inline")]
#[test]
fn every_reading_of_a_line_s_code_draws_from_one_budget() {
    // The reader reads the code of a line, and the code `eval` and `exec`
    // run inside it, within one budget made for the line: code nested four
    // deep costs what the line's length allows, not four times it. Each row
    // is a shape the reader stops on (an error after which a lexer goes over
    // the same comments again, the round, a chain of calls named again from
    // each link) and one it reads whole, nested in `eval` or `exec` from
    // none to four deep, given as a here-document: its work is held to the
    // budget of the line, written out (see the reader's
    // `tests/parse_budget.rs`), and the answer is never safe.
    use milo_guards_shell::testing::lexed;
    let paths = posix();
    let rows: [(&str, &str, String); 5] = [
        (
            "node",
            "eval",
            format!("/*xfrom  @catch{}", "@/*== ".repeat(250)),
        ),
        ("python3", "exec", format!("!=]0x ]{}", "\n#".repeat(700))),
        ("node", "eval", format!("x{}", "()".repeat(700))),
        (
            "node",
            "eval",
            format!("x;\n{}c(.c(''.(X%'''\"';c(=", "x;\n".repeat(450)),
        ),
        ("python3", "exec", "print(1); x = [1, 2, 3]\n".repeat(60)),
    ];
    for (interpreter, runs, code) in rows {
        let mut code = code;
        for depth in 0..=4 {
            let line = format!("{interpreter} - <<'END'\n{code}\nEND");
            let at = format!(
                "{interpreter} {depth} deep: {:?}",
                &code[..code.len().min(30)]
            );
            if line.len() > 64 * 1024 {
                break;
            }
            let read = lexed(&line, Shell::Posix, &paths);
            assert!(!read.answer.is_safe(), "{at}");
            let work = read.reader.unwrap_or_else(|| panic!("{at}: nothing read"));
            let len = line.len();
            // The bounds of a budget for the line, as the reader's own tests
            // write them, and what a count may go past one before it is seen.
            let bounds = [
                ("reports", work.reports, len / 6 + 64 + 1),
                ("quiet", work.quiet, 64 + 1),
                ("tangled", work.tangled, 384 + 16),
                ("selected", work.selected, 1024 + 4096),
                ("handed", work.handed, len * 64 + (24 << 20) + 259 * 12),
                ("walked", work.walked, len * 16 + (64 << 10) + len),
            ];
            for (what, count, most) in bounds {
                assert!(count <= most, "{at}: {what} {count}, over {most}");
            }
            code = format!("{runs}({code:?})");
        }
    }
}

// The reader's work is counted only where the guard reads inline code.
#[cfg(feature = "inline")]
#[test]
fn pieces_of_a_line_each_read_whole_are_held_together() {
    // Python each piece of which tree-sitter reads two ways at once (versions
    // merged at each token, built at the end way by way), given in piece
    // after piece of one line: each piece has
    // stars where Python allows none, and is refused before it is parsed;
    // pieces that each meet an error are each
    // stopped where the recovery starts. Every piece is code the guard does
    // not read, and the line is held to its reports.
    use milo_guards_shell::testing::lexed;
    let paths = posix();
    let rows = [
        ("+*a".repeat(256), 80, false),
        ("if/*a".repeat(512), 24, false),
        ("+*a".repeat(170), 110, false),
        // Lines of four at the top level, and `if` then `-*a`: Python with
        // stars where Python
        // allows none, refused before each is parsed.
        ("+*a+*a+*a+*a\n".repeat(60), 70, false),
        (format!("if{}", "-*a".repeat(260)), 70, false),
    ];
    for (code, pieces, stopped) in rows {
        let line = (0..pieces)
            .map(|piece| format!("python3 -c '{code}#{piece}'"))
            .collect::<Vec<_>>()
            .join(" ; ");
        let at = format!("{pieces} pieces of {:?}", &code[..6]);
        assert!(line.len() <= 64 * 1024, "{at}: {} bytes", line.len());
        let read = lexed(&line, Shell::Posix, &paths);
        assert!(!read.answer.is_safe(), "{at}");
        let work = read.reader.unwrap_or_else(|| panic!("{at}: nothing read"));
        assert_eq!(work.stopped, stopped, "{at}: {work:?}");
        if !stopped {
            assert_eq!(work.errors, pieces, "{at}: {work:?}");
        }
        // The bounds in all of a budget, as the reader's own tests write
        // them, and what a count may go past one before it is seen.
        let bounds = [
            ("quiet", work.quiet, 64 + 1),
            ("tangled", work.tangled, 384 + 16),
            ("selected", work.selected, 1024 + 4096),
            ("reports", work.reports, line.len() / 6 + 64 + 1),
        ];
        for (what, count, most) in bounds {
            assert!(count <= most, "{at}: {what} {count}, over {most}");
        }
    }
}
