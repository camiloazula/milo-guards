//! The format of the case files every guard's tests read: what a line holds,
//! that a text holds any command line exactly, and every line it refuses,
//! named by its file and line. Then the runner of the path model's own case
//! files in `tests/cases`: what a case says, every case it refuses and every
//! wrong answer it names by file and line, that each case file is checked by
//! the test file of its name, and that no case repeats another across files.
//! `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-core --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self as runner, Case};
use format::{decode, encode, parse, read, Record, Word};
use milo_guards_core::{Flavour, Protected};

use common::cases::format;

fn bare(word: &str) -> Word {
    Word::Bare(word.to_string())
}

fn field(name: &str, value: &str) -> Word {
    Word::Field(name.to_string(), value.to_string())
}

/// The one record of a one-line file.
fn one(line: &str) -> Record {
    let records = parse("t.cases", line);
    assert!(
        matches!(&records, Ok(records) if records.len() == 1),
        "{records:?}"
    );
    records.unwrap_or_default().remove(0)
}

/// What `source` is refused for; empty when it is read, which fails the
/// test's own check of what it holds.
fn refused(source: &str) -> String {
    parse("t.cases", source)
        .err()
        .unwrap_or_default()
        .join("\n")
}

#[test]
fn a_line_is_words_then_the_text_after_the_bar() {
    let record = one("posix finds=delete reason=\"deletes a file\" | rm -rf x | cat");
    assert_eq!(record.at, "t.cases:1");
    assert_eq!(
        record.words,
        [
            bare("posix"),
            field("finds", "delete"),
            field("reason", "deletes a file")
        ]
    );
    assert_eq!(record.text.as_deref(), Some("rm -rf x | cat"));
    // Words may be spaced to line up; a declaration has no text.
    let record = one("paths  home   cwd=/home/me home=C:\\\\Users\\\\me");
    assert_eq!(
        record.words,
        [
            bare("paths"),
            bare("home"),
            field("cwd", "/home/me"),
            field("home", "C:\\Users\\me")
        ]
    );
    assert_eq!(record.text, None);
    // A bar with nothing after it is the empty line.
    assert_eq!(one("posix safe |").text.as_deref(), Some(""));
}

#[test]
fn blank_lines_and_comments_are_skipped_and_lines_are_counted() {
    let records = parse(
        "t.cases",
        "# a comment\n\nposix safe | ls\n#posix safe | rm\nposix safe | pwd\n",
    )
    .expect("read");
    let at: Vec<&str> = records.iter().map(|record| record.at.as_str()).collect();
    assert_eq!(at, ["t.cases:3", "t.cases:5"]);
}

#[test]
fn a_text_holds_any_line_exactly() {
    let rows = [
        (r"cat < a\tb", "cat < a\tb"),
        (r"cd sub <<EOF\nx\nEOF", "cd sub <<EOF\nx\nEOF"),
        (r"echo hi\r\nrm -rf ~", "echo hi\r\nrm -rf ~"),
        (r"del ..\\x.txt", "del ..\\x.txt"),
        (r"\\\\host\\share", "\\\\host\\share"),
        (r#"echo "it's" '$HOME'"#, "echo \"it's\" '$HOME'"),
        (r"\sls\s", " ls "),
        (r"\s\s", "  "),
        (r"ls  -la", "ls  -la"),
        ("cat ~/José/日本/🦀", "cat ~/José/日本/🦀"),
        (r"rm\u{a0}-rf\u{2028}~\u{0}", "rm\u{a0}-rf\u{2028}~\u{0}"),
        (r"echo |", "echo |"),
        (r"# not a comment", "# not a comment"),
        (r"x=1 | y", "x=1 | y"),
    ];
    for (written, held) in rows {
        let record = one(&format!("posix safe | {written}"));
        assert_eq!(record.text.as_deref(), Some(held), "{written}");
        assert_eq!(encode(held), written, "{held:?}");
    }
}

#[test]
fn encode_and_decode_give_back_any_text() {
    let texts = [
        "",
        " ",
        "\\",
        "\\n",
        "\\s",
        "a\u{7f}b\u{1b}[0m",
        "\u{feff}x\u{200b}",
        "trailing\t",
        " lead",
        "tab\tin\rthe\nmiddle",
        "\"quoted\" 'single'",
    ];
    for text in texts {
        let written = encode(text);
        assert_eq!(decode(&written, false).as_deref(), Ok(text), "{written}");
        let record = one(format!("posix safe | {written}").trim_end_matches(' '));
        assert_eq!(record.text.as_deref(), Some(text), "{written}");
    }
}

#[test]
fn a_quoted_value_holds_spaces_bars_and_quotes() {
    let record = one(r#"posix reason="writes to \"a b\" | c\\d" | x"#);
    assert_eq!(record.words[1], field("reason", "writes to \"a b\" | c\\d"));
    assert_eq!(record.text.as_deref(), Some("x"));
}

#[test]
fn a_raw_control_character_is_refused() {
    assert!(refused("posix safe | a\tb").contains("t.cases:1: a raw \\t"));
    assert!(refused("posix safe | ls\r\n").contains("t.cases:1: a raw \\r"));
    assert!(refused("posix safe | a\u{1b}b").contains("t.cases:1: a raw \\u{1b}"));
}

#[test]
fn a_space_at_either_end_is_refused() {
    assert!(refused("posix safe | ls ").contains("t.cases:1: a space at the end"));
    assert!(refused(" posix safe | ls").contains("t.cases:1: a space at the start of the line"));
    assert!(refused("posix safe |  ls").contains("t.cases:1: a space at the start of the text"));
    assert!(refused("posix safe | ").contains("t.cases:1: a space at the end"));
    assert!(refused("# a comment \n").contains("t.cases:1: a space at the end"));
}

#[test]
fn an_unknown_or_unfinished_escape_is_refused() {
    assert!(refused(r"cmd safe | del ..\x.txt").contains(r"t.cases:1: an unknown escape `\x`"));
    assert!(refused(r#"posix safe | echo \""#).contains(r#"an unknown escape `\"`"#));
    assert!(refused(r"posix safe | ls \").contains("a backslash at the end"));
    assert!(refused(r"posix safe | \u{110000}").contains("is not a character"));
    assert!(refused(r"posix safe | \u{}").contains("one to six digits"));
    assert!(refused(r"posix safe | \u41").contains("one to six digits"));
    assert!(refused(r"paths x cwd=C:\Users").contains("an unknown escape `\\U`"));
}

#[test]
fn a_malformed_word_is_refused() {
    assert!(refused(r#"posix reason="open | x"#).contains("no closing quote"));
    assert!(refused(r#"posix reason="a"b | x"#).contains("a space must follow the quoted value"));
    assert!(refused(r#"posix reason=a"b | x"#).contains("must be quoted"));
    assert!(refused(r#"posix "safe" | x"#).contains("a malformed word"));
    assert!(refused("posix =x | ls").contains("a malformed field name"));
    assert!(refused("posix safe |ls").contains("a malformed word `|ls`"));
}

#[test]
fn every_refused_line_is_named_at_once() {
    let why = refused("posix safe | a\\q\nposix safe | ok\nposix safe | b \n");
    assert!(why.contains("t.cases:1:"), "{why}");
    assert!(!why.contains("t.cases:2:"), "{why}");
    assert!(why.contains("t.cases:3:"), "{why}");
}

#[test]
fn a_missing_file_is_refused() {
    let why = read("no_such_cases").expect_err("refused").join("\n");
    assert!(
        why.contains("tests/cases/no_such_cases.cases: no case file"),
        "{why}"
    );
}

#[test]
fn a_repeated_key_is_named_with_the_first() {
    let items = [
        ("t.cases:1".to_string(), "a"),
        ("t.cases:2".to_string(), "b"),
        ("t.cases:3".to_string(), "a"),
    ];
    assert_eq!(
        format::repeated(items),
        ["t.cases:3: repeats the case at t.cases:1"]
    );
}

/// The path model's cases of `source`, which must be read.
fn cases_of(source: &str) -> Vec<Case> {
    let cases = runner::parse("t.cases", source);
    assert!(cases.is_ok(), "refused: {cases:?}");
    cases.unwrap_or_default()
}

/// Why the path model's runner refuses `source`; empty when it is read.
fn refused_case(source: &str) -> String {
    runner::parse("t.cases", source)
        .err()
        .unwrap_or_default()
        .join("\n")
}

#[test]
fn a_case_says_its_flavour_paths_spelling_questions_and_path() {
    let cases = cases_of(concat!(
        "# A comment.\n",
        "posix place=inside | src/main.rs\n",
        "windows place=\"secret:your SSH keys\" absolute=C:\\\\Users\\\\me\\\\.ssh | ..\\\\..\\\\.ssh\n",
        "posix@macos home hidden picks=none startup=none |\n",
        "posix@posix deep reaches=yes | /\n",
        "windows network=yes | \\\\\\\\server\\\\share\n",
    ));
    assert_eq!(cases.len(), 5);
    let at: Vec<&str> = cases.iter().map(|case| case.at.as_str()).collect();
    assert_eq!(
        at,
        [
            "t.cases:2",
            "t.cases:3",
            "t.cases:4",
            "t.cases:5",
            "t.cases:6"
        ]
    );
    // A POSIX path is judged on `posix` and a Windows one on `windows`,
    // unless the case names its paths.
    let homes: Vec<String> = cases
        .iter()
        .map(|case| case.paths.home.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        homes,
        [
            "/home/me",
            r"C:\Users\me",
            "/Users/me",
            "/home/me",
            r"C:\Users\me"
        ]
    );
    assert_eq!(cases[1].flavour, Flavour::Windows);
    assert_eq!(cases[1].path, r"..\..\.ssh");
    assert_eq!(
        cases[1].expect.get("absolute").map(String::as_str),
        Some(r"C:\Users\me\.ssh")
    );
    assert_eq!(
        cases[1].expect.get("place").map(String::as_str),
        Some("secret:your SSH keys")
    );
    assert!(cases[2].home && cases[2].hidden && !cases[2].deep);
    assert_eq!(cases[2].path, "");
    assert_eq!(cases[2].expect.len(), 2);
    assert!(cases[3].deep && !cases[3].home);
    assert_eq!(cases[4].path, r"\\server\share");
}

#[test]
fn a_paths_declaration_names_the_paths_a_case_is_judged_on() {
    let cases = cases_of(concat!(
        "paths home cwd=/home/me home=/home/me workspace=/home/me\n",
        "paths agent base=posix workspace=/home/me/other folder=/home/me/.agent words=\"the agent's settings\" file=/home/me/x.yaml words=\"the agent's rules\"\n",
        "posix@home place=inside | x\n",
        "posix@agent place=inside | x\n",
    ));
    let home = &cases[0].paths;
    assert_eq!(
        (home.cwd.to_str(), home.home.to_str()),
        (Some("/home/me"), Some("/home/me"))
    );
    assert_eq!(home.workspaces, [std::path::PathBuf::from("/home/me")]);
    let agent = &cases[1].paths;
    assert_eq!(agent.cwd, runner::posix().cwd);
    assert_eq!(
        agent.workspaces,
        [
            std::path::PathBuf::from("/home/me/work/repo"),
            std::path::PathBuf::from("/home/me/other")
        ]
    );
    assert_eq!(
        agent.protected,
        [
            Protected::folder("/home/me/.agent", "the agent's settings"),
            Protected::file("/home/me/x.yaml", "the agent's rules"),
        ]
    );
}

#[test]
fn a_malformed_case_is_refused() {
    for (source, why) in [
        (
            "posix place=inside x\n",
            "t.cases:1: a case with no `| PATH`",
        ),
        ("| x\n", "t.cases:1: a case starts with its flavour"),
        ("posix | x\n", "t.cases:1: a case with no answer"),
        ("posix home | x\n", "a case with no answer"),
        ("posix place=inside place=outside | x\n", "`place` twice"),
        ("posix home home place=inside | x\n", "`home` twice"),
        ("posix place | x\n", "`place` takes a value"),
        (
            "posix hidden=yes picks=none | x\n",
            "`hidden` takes no value",
        ),
        ("posix hidden place=inside | x\n", "`hidden` takes one of"),
        ("posix deep startup=none | x\n", "`deep` takes `reaches`"),
        ("posix home network=no | x\n", "`network` reads the text"),
        (
            "posix place=inside | x\\q\n",
            "t.cases:1: an unknown escape `\\q`",
        ),
        ("posix place=inside | x \n", "t.cases:1: a space at the end"),
        ("paths\n", "`paths` takes a name first"),
        (
            "paths posix base=posix\n",
            "the paths `posix` are already named",
        ),
        ("paths x cwd=/a\n", "takes `base`, or `cwd` and `home`"),
        (
            "paths x base=posix words=w\n",
            "`words` must follow its `folder` or `file`",
        ),
        (
            "paths x base=posix folder=/a\n",
            "each `folder` and `file` takes its `words`",
        ),
        ("paths x base=posix extra\n", "an unknown word"),
    ] {
        let got = refused_case(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_flavour_field_word_answer_or_paths_is_refused() {
    for (source, why) in [
        ("cmd place=inside | x\n", "an unknown flavour `cmd`"),
        ("posix colour=red | x\n", "an unknown field `colour`"),
        ("posix sure place=inside | x\n", "an unknown word `sure`"),
        (
            "posix place=inner | x\n",
            "`inner` is no answer `place` gives",
        ),
        (
            "posix place=secret | x\n",
            "`secret` is no answer `place` gives",
        ),
        (
            "posix place=secret: | x\n",
            "`secret:` is no answer `place` gives",
        ),
        (
            "posix into=keys:x | x\n",
            "`keys:x` is no answer `into` gives",
        ),
        (
            "posix reaches=maybe | x\n",
            "`maybe` is no answer `reaches` gives",
        ),
        (
            "posix network=true | x\n",
            "`true` is no answer `network` gives",
        ),
        ("posix@mars place=inside | x\n", "no paths named `mars`"),
        ("paths x base=mars\n", "no paths named `mars`"),
        (
            "paths x base=posix colour=red\n",
            "an unknown field `colour`",
        ),
    ] {
        let got = refused_case(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn a_repeated_case_is_refused() {
    let got = refused_case("posix place=inside | x\nposix git=none | x\nposix place=inside | x\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    // The same paths, named or by default, and the same answer in another
    // order are the same case.
    let got = refused_case("posix@posix place=inside | x\nposix place=inside | x\n");
    assert!(
        got.contains("t.cases:2: repeats the case at t.cases:1"),
        "{got}"
    );
    let got = refused_case("posix git=none place=inside | x\nposix place=inside git=none | x\n");
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    let got = refused_case(
        "paths same base=posix\nposix@same place=inside | x\nposix place=inside | x\n",
    );
    assert!(got.contains("t.cases:3: repeats"), "{got}");
    // Other paths, another flavour, spelling or answer, or another path is not.
    cases_of(concat!(
        "posix place=inside | x\n",
        "posix@macos place=inside | x\n",
        "windows@posix place=inside | x\n",
        "posix home place=inside | x\n",
        "posix place=outside | x\n",
        "posix place=inside | x\\s\n",
    ));
}

#[test]
#[should_panic(expected = "tests/cases/no_such_behaviour.cases: no case file")]
fn a_missing_case_file_fails_its_test() {
    runner::check("no_such_behaviour");
}

#[test]
fn a_wrong_case_is_named_by_its_file_and_line() {
    let cases = cases_of(concat!(
        "posix place=inside | src/main.rs\n",
        "posix place=outside | src/main.rs\n",
        "posix place=\"secret:your SSH keys\" git=none | /home/me/.ssh/id_rsa\n",
        "posix kernel=none | /dev/mem\n",
        "windows absolute=C:\\\\x | D:x\n",
        "posix@macos home reaches=no | /.ssh\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(runner::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    assert!(wrong[2].is_empty(), "{:?}", wrong[2]);
    for (index, missed) in [
        (
            1,
            "expected place=\"outside\": \"src/main.rs\"\n    got \"inside\"",
        ),
        (
            3,
            "expected kernel=\"none\": \"/dev/mem\"\n    got \"a device file\"",
        ),
        (
            4,
            "expected absolute=\"C:\\\\x\": \"D:x\"\n    got \"none\"",
        ),
        (5, "expected reaches=\"no\": \"/.ssh\"\n    got \"yes\""),
    ] {
        let at = format!("t.cases:{}: ", index + 1);
        let got = wrong[index].join("\n");
        assert!(
            got.starts_with(&at) && got.contains(missed),
            "{index}: {got}"
        );
    }
}

#[test]
fn every_case_file_is_checked_by_the_test_file_of_its_name() {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let names = format::names();
    assert!(!names.is_empty(), "no case files in tests/cases");
    let unchecked: Vec<String> = names
        .iter()
        .filter(|name| {
            let call = format!("common::cases::check(\"{name}\")");
            std::fs::read_to_string(tests.join(format!("{name}.rs")))
                .map_or(true, |source| !source.contains(&call))
        })
        .map(|name| format!("tests/cases/{name}.cases: tests/{name}.rs does not call `common::cases::check(\"{name}\")`"))
        .collect();
    assert!(unchecked.is_empty(), "{}", unchecked.join("\n"));
}

#[test]
fn no_case_repeats_another_across_files() {
    let all: Vec<Case> = format::names()
        .iter()
        .flat_map(|name| runner::load(name))
        .collect();
    let repeats = format::repeated(all.iter().map(|case| (case.at.clone(), runner::key(case))));
    assert!(repeats.is_empty(), "{}", repeats.join("\n"));
}

/// Every case of every case file, one to a line: where it is, the flavour,
/// the paths, the answer and the path as Rust writes a string, tab
/// separated.
#[test]
#[ignore = "prints every case: run it by name with --ignored --nocapture"]
fn dump() {
    for name in format::names() {
        for case in runner::load(&name) {
            println!("{}", runner::dumped(&case));
        }
    }
}
