//! The runner of the case files in `tests/cases`: what a case says, every
//! case it refuses and every wrong answer it names by file and line, that
//! each case file is checked by the test file of its name, and that no case
//! repeats another across files. `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-secrets --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self, format, parse, Case, Expect};
use milo_guards_secrets::Rule;

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
fn a_case_says_its_answer_and_text() {
    let cases = read(concat!(
        "# A comment.\n",
        "safe | password: String,\n",
        "finds=email,phone/public_ip | x\n",
        "rules=generic_secret first=generic_secret lacks=email | password=x\n",
        "finds=generic_secret reason=\"holds a password or secret\" target=\"… (9 chars)\" | x\n",
        "span=\"a\\\"b\" covers=\"a\\\\b\" | \\sa\\tb\n",
        "safe |\n",
    ));
    assert_eq!(cases.len(), 6);
    let at: Vec<&str> = cases.iter().map(|case| case.at.as_str()).collect();
    assert_eq!(
        at,
        [
            "t.cases:2",
            "t.cases:3",
            "t.cases:4",
            "t.cases:5",
            "t.cases:6",
            "t.cases:7"
        ]
    );
    assert_eq!(
        cases[0].expect,
        Expect {
            safe: true,
            ..Expect::default()
        }
    );
    assert_eq!(
        cases[1].expect.finds,
        [vec![Rule::Email], vec![Rule::Phone, Rule::PublicIp]]
    );
    assert_eq!(
        cases[2].expect,
        Expect {
            rules: Some(vec![Rule::GenericSecret]),
            first: Some(Rule::GenericSecret),
            lacks: vec![Rule::Email],
            ..Expect::default()
        }
    );
    assert_eq!(
        cases[3].expect.reason.as_deref(),
        Some("holds a password or secret")
    );
    assert_eq!(cases[3].expect.target.as_deref(), Some("… (9 chars)"));
    assert_eq!(cases[4].expect.span.as_deref(), Some("a\"b"));
    assert_eq!(cases[4].expect.covers.as_deref(), Some(r"a\b"));
    assert_eq!(cases[4].text, " a\tb");
    assert_eq!(cases[5].text, "");
}

#[test]
fn a_malformed_line_is_refused() {
    for (source, why) in [
        ("safe x\n", "t.cases:1: a case with no `| TEXT`"),
        ("| x\n", "t.cases:1: a case with no answer"),
        ("safe finds=email | x\n", "`safe` takes no other field"),
        ("safe span=x | x\n", "`safe` takes no other field"),
        ("safe lacks=email | x\n", "`safe` takes no other field"),
        ("safe safe | x\n", "`safe` twice"),
        ("finds=email finds=phone | x\n", "`finds` twice"),
        ("finds | x\n", "`finds` takes a value"),
        ("span | x\n", "`span` takes a value"),
        ("covers= | x\n", "`covers` takes a part of the text"),
        ("safe=yes | x\n", "`safe` takes no value"),
        ("finds=email, | x\n", "an empty item"),
        (
            "finds=email,phone reason=x | x\n",
            "`reason` takes `first`, or `finds` of one rule",
        ),
        (
            "rules=email target=x | x\n",
            "`target` takes `first`, or `finds` of one rule",
        ),
        ("safe | x\\q\n", "t.cases:1: an unknown escape `\\q`"),
        ("safe | x \n", "t.cases:1: a space at the end"),
        ("safe | a\tb\n", "t.cases:1: a raw \\t"),
        ("safe |  x\n", "t.cases:1: a space at the start of the text"),
        ("paths x base=posix\n", "t.cases:1: a case with no `| TEXT`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_field_word_or_rule_is_refused() {
    for (source, why) in [
        (
            "safe colour=red | x\n",
            "t.cases:1: an unknown field `colour`",
        ),
        ("sure | x\n", "t.cases:1: an unknown word `sure`"),
        ("finds=password | x\n", "an unknown rule `password`"),
        ("finds=email/Email | x\n", "an unknown rule `Email`"),
        ("rules=email,wipe | x\n", "an unknown rule `wipe`"),
        ("effect=changes | x\n", "an unknown field `effect`"),
        ("posix safe | x\n", "an unknown word `posix`"),
        ("@posix safe | x\n", "an unknown word `@posix`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn a_repeated_case_is_refused() {
    let got = refused("safe | x\nfinds=email | a@acme.io\nsafe | x\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    // The same answer in another order is the same case.
    let got =
        refused("first=email span=a@acme.io | a@acme.io\nspan=a@acme.io first=email | a@acme.io\n");
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    // Another answer or another text is not.
    read(concat!("safe | x\n", "lacks=email | x\n", "safe | x\\s\n",));
}

#[test]
#[should_panic(expected = "tests/cases/no_such_behaviour.cases: no case file")]
fn a_missing_file_is_refused() {
    cases::check("no_such_behaviour");
}

#[test]
fn a_wrong_case_is_named_by_its_file_and_line() {
    let cases = read(concat!(
        "safe | password: String,\n",
        "safe | password=fakePass0word1\n",
        "finds=email | password: String,\n",
        "finds=email/generic_secret | password=fakePass0word1\n",
        "rules=email | password=fakePass0word1\n",
        "first=email | password=fakePass0word1\n",
        "lacks=generic_secret | password=fakePass0word1\n",
        "finds=generic_secret reason=\"holds a key\" | password=fakePass0word1\n",
        "first=generic_secret target=\"fake…\" | password=fakePass0word1\n",
        "span=\"fakePass\" | password=fakePass0word1\n",
        "covers=\"password\" | password=fakePass0word1\n",
        "covers=\"absent\" | password=fakePass0word1\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(cases::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    assert!(wrong[3].is_empty(), "{:?}", wrong[3]);
    for (index, missed) in [
        (1, "expected safe: \"password=fakePass0word1\""),
        (2, "expected finds [Email]: \"password: String,\""),
        (4, "expected rules [Email]"),
        (5, "expected first Email"),
        (6, "expected lacks GenericSecret"),
        (7, "expected reason \"holds a key\""),
        (8, "expected target \"fake…\""),
        (9, "expected span \"fakePass\""),
        (10, "expected covers \"password\""),
        (11, "expected covers \"absent\""),
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

/// Every case of every case file, one to a line: where it is, the answer and
/// the text as Rust writes a string, tab separated.
#[test]
#[ignore = "prints every case: run it by name with --ignored --nocapture"]
fn dump() {
    for name in format::names() {
        for case in cases::load(&name) {
            println!("{}", cases::dumped(&case));
        }
    }
}
