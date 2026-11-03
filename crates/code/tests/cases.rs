//! The runner of the case files in `tests/cases`: what a case says, every
//! case it refuses and every wrong answer it names by file and line, that
//! each case file is checked by the test file of its name, and that no case
//! repeats another across files. `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-code --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self, format, parse, Case, What};

/// The cases of `source`, which must be read.
fn read(source: &str) -> Vec<Case> {
    let cases = parse("t.cases", source);
    assert!(cases.is_ok(), "refused: {cases:?}");
    cases.unwrap_or_default()
}

/// Why `source` is refused; empty when it is read, which fails the test's
/// own check of what it holds.
fn refused(source: &str) -> String {
    parse("t.cases", source)
        .err()
        .unwrap_or_default()
        .join("\n")
}

#[test]
fn a_case_says_what_it_reads_its_answer_and_its_code() {
    let cases = read(concat!(
        "# A comment.\n",
        "python acts=\"remove x\" understand=no | import os\\nos.remove('x')\n",
        "javascript acts=\"\" understand=yes | console.log(1)\n",
        "python2 understand=importing | import sys\n",
        "module data_url=no foreign=yes | ../x.js\n",
        "python other_encoding=no |\n",
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
    let what: Vec<What> = cases.iter().map(|case| case.what).collect();
    assert_eq!(
        what,
        [
            What::Python,
            What::JavaScript,
            What::Python2,
            What::Module,
            What::Python
        ]
    );
    assert_eq!(cases[0].code, "import os\nos.remove('x')");
    assert_eq!(
        cases[0].expect.get("acts").map(String::as_str),
        Some("remove x")
    );
    assert_eq!(cases[1].expect.get("acts").map(String::as_str), Some(""));
    assert_eq!(cases[3].expect.len(), 2);
    assert_eq!(cases[4].code, "");
}

#[test]
fn a_malformed_case_is_refused() {
    for (source, why) in [
        (
            "python understand=no\n",
            "t.cases:1: a case with no `| CODE`",
        ),
        ("| x\n", "t.cases:1: a case starts with what it reads"),
        ("acts=\"\" | x\n", "a case starts with what it reads"),
        ("python | x\n", "t.cases:1: a case with no answer"),
        (
            "python understand=no understand=yes | x\n",
            "`understand` twice",
        ),
        (
            "python understand=maybe | x\n",
            "`maybe` is no answer `understand` gives",
        ),
        (
            "module foreign=true | x\n",
            "`true` is no answer `foreign` gives",
        ),
        (
            "python understand=no | x\\q\n",
            "t.cases:1: an unknown escape `\\q`",
        ),
        (
            "python understand=no | x \n",
            "t.cases:1: a space at the end",
        ),
        ("python understand=no | a\tb\n", "t.cases:1: a raw \\t"),
        (
            "python understand=no |  x\n",
            "a space at the start of the text",
        ),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_kind_field_or_word_is_refused() {
    for (source, why) in [
        ("ruby understand=no | x\n", "an unknown kind of code `ruby`"),
        (
            "python colour=red | x\n",
            "an unknown field `colour` for `python`",
        ),
        ("python safe | x\n", "an unknown word `safe`"),
        (
            "python foreign=no | x\n",
            "an unknown field `foreign` for `python`",
        ),
        (
            "javascript other_encoding=no | x\n",
            "an unknown field `other_encoding` for `javascript`",
        ),
        (
            "python2 acts=\"\" | x\n",
            "an unknown field `acts` for `python2`",
        ),
        (
            "module acts=\"\" | x\n",
            "an unknown field `acts` for `module`",
        ),
        ("paths x base=posix\n", "a case with no `| CODE`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn a_repeated_case_is_refused() {
    let got = refused("python understand=no | x\npython acts=\"\" | x\npython understand=no | x\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    // The same answer in another order is the same case.
    let got = refused("python acts=\"\" understand=no | x\npython understand=no acts=\"\" | x\n");
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    // Another kind of code, another answer or other code is not.
    read(concat!(
        "python understand=no | x\n",
        "javascript understand=no | x\n",
        "python2 understand=no | x\n",
        "python understand=yes | x\n",
        "python understand=no | x\\s\n",
    ));
}

#[test]
#[should_panic(expected = "tests/cases/no_such_behaviour.cases: no case file")]
fn a_missing_file_is_refused() {
    cases::check("no_such_behaviour");
}

#[test]
fn a_wrong_case_is_named_by_its_file_and_line() {
    let cases = read(concat!(
        "python acts=\"remove x\" | import os\\nos.remove('x')\n",
        "python acts=\"\" | import os\\nos.remove('x')\n",
        "javascript understand=no | console.log(1)\n",
        "python2 understand=importing | import time\n",
        "python other_encoding=yes | print(1)\n",
        "module data_url=no foreign=yes | data:x\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(cases::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    for (index, missed) in [
        (
            1,
            "expected acts=\"\": \"import os\\nos.remove('x')\"\n    got \"remove x\"",
        ),
        (
            2,
            "expected understand=\"no\": \"console.log(1)\"\n    got \"yes\"",
        ),
        (
            3,
            "expected understand=\"importing\": \"import time\"\n    got \"no\"",
        ),
        (
            4,
            "expected other_encoding=\"yes\": \"print(1)\"\n    got \"no\"",
        ),
        (5, "expected data_url=\"no\": \"data:x\"\n    got \"yes\""),
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
        .flat_map(|name| cases::load(name))
        .collect();
    let repeats = format::repeated(all.iter().map(|case| (case.at.clone(), cases::key(case))));
    assert!(repeats.is_empty(), "{}", repeats.join("\n"));
}

/// Every case of every case file, one to a line: where it is, what it reads,
/// the answer and the code as Rust writes a string, tab separated.
#[test]
#[ignore = "prints every case: run it by name with --ignored --nocapture"]
fn dump() {
    for name in format::names() {
        for case in cases::load(&name) {
            println!("{}", cases::dumped(&case));
        }
    }
}
