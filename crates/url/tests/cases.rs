//! The runner of the case files in `tests/cases`: what a case says, every
//! case it refuses and every wrong answer it names by file and line, that
//! each case file is checked by the test file of its name, and that no case
//! repeats another across files. `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-url --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self, format, parse, Case, Expect};
use milo_guards_url::{Protected, Rule};

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
fn a_case_says_its_paths_answer_and_url() {
    let cases = read(concat!(
        "# A comment.\n",
        "safe | https://example.com/\n",
        "@windows finds=local_file,scheme/unreadable | file:///C:\\\\x\n",
        "rules=credentials,local_address first=credentials lacks=metadata | http://me:pw@127.0.0.1/\n",
        "finds=local_address reason=\"fetches your own machine\" target=\"127.0.0.1\" | http://2130706433/\n",
        "@macos finds=unreadable | \\sa\\tb\n",
        "finds=unreadable |\n",
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
    // A URL is judged on `posix` unless the case names its paths.
    let homes: Vec<String> = cases
        .iter()
        .map(|case| case.paths.home.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        homes,
        [
            "/home/me",
            r"C:\Users\me",
            "/home/me",
            "/home/me",
            "/Users/me",
            "/home/me"
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
        [vec![Rule::LocalFile], vec![Rule::Scheme, Rule::Unreadable]]
    );
    assert_eq!(cases[1].url, r"file:///C:\x");
    assert_eq!(
        cases[2].expect,
        Expect {
            rules: Some(vec![Rule::Credentials, Rule::LocalAddress]),
            first: Some(Rule::Credentials),
            lacks: vec![Rule::Metadata],
            ..Expect::default()
        }
    );
    assert_eq!(
        cases[3].expect.reason.as_deref(),
        Some("fetches your own machine")
    );
    assert_eq!(cases[3].expect.target.as_deref(), Some("127.0.0.1"));
    assert_eq!(cases[4].url, " a\tb");
    assert_eq!(cases[5].url, "");
}

#[test]
fn a_paths_declaration_names_the_paths_a_case_is_judged_on() {
    let cases = read(concat!(
        "paths home cwd=/home/me home=/home/me workspace=/home/me\n",
        "paths agent base=posix folder=/home/me/.agent words=\"the agent's settings\" file=/home/me/x.yaml words=\"the agent's rules\"\n",
        "@home safe | https://example.com/\n",
        "@agent safe | https://example.com/\n",
    ));
    let home = &cases[0].paths;
    assert_eq!(
        (home.cwd.to_str(), home.home.to_str()),
        (Some("/home/me"), Some("/home/me"))
    );
    assert_eq!(home.workspaces, [std::path::PathBuf::from("/home/me")]);
    let agent = &cases[1].paths;
    assert_eq!(agent.cwd, common::posix().cwd);
    assert_eq!(
        agent.protected,
        [
            Protected::folder("/home/me/.agent", "the agent's settings"),
            Protected::file("/home/me/x.yaml", "the agent's rules"),
        ]
    );
}

#[test]
fn a_malformed_line_is_refused() {
    for (source, why) in [
        ("safe x\n", "t.cases:1: a case with no `| URL`"),
        ("| x\n", "t.cases:1: a case with no answer"),
        ("@posix | x\n", "t.cases:1: a case with no answer"),
        (
            "safe finds=scheme | x\n",
            "`safe` takes no other rule field",
        ),
        (
            "safe lacks=scheme | x\n",
            "`safe` takes no other rule field",
        ),
        ("safe safe | x\n", "`safe` twice"),
        ("finds=scheme finds=metadata | x\n", "`finds` twice"),
        ("finds | x\n", "`finds` takes a value"),
        ("target | x\n", "`target` takes a value"),
        ("safe=yes | x\n", "`safe` takes no value"),
        ("finds=scheme, | x\n", "an empty item"),
        (
            "finds=scheme,metadata reason=x | x\n",
            "`reason` takes `first`, or `finds` of one rule",
        ),
        ("reason=x | x\n", "`reason` takes `first`"),
        (
            "rules=scheme target=x | x\n",
            "`target` takes `first`, or `finds` of one rule",
        ),
        (
            "safe @windows | x\n",
            "the paths `@windows` must come first",
        ),
        ("safe | x\\q\n", "t.cases:1: an unknown escape `\\q`"),
        ("safe | x \n", "t.cases:1: a space at the end"),
        ("safe | a\tb\n", "t.cases:1: a raw \\t"),
        ("safe |  x\n", "t.cases:1: a space at the start of the text"),
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
        ("paths x base=posix | x\n", "an unknown word `paths`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_field_word_rule_or_paths_is_refused() {
    for (source, why) in [
        (
            "safe colour=red | x\n",
            "t.cases:1: an unknown field `colour`",
        ),
        ("sure | x\n", "t.cases:1: an unknown word `sure`"),
        ("finds=local | x\n", "an unknown rule `local`"),
        (
            "finds=scheme/LocalAddress | x\n",
            "an unknown rule `LocalAddress`",
        ),
        ("rules=scheme,wipe | x\n", "an unknown rule `wipe`"),
        ("effect=changes | x\n", "an unknown field `effect`"),
        ("posix safe | x\n", "an unknown word `posix`"),
        ("@mars safe | x\n", "no paths named `mars`"),
        ("paths x base=mars\n", "no paths named `mars`"),
        (
            "paths x base=posix colour=red\n",
            "an unknown field `colour`",
        ),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn a_repeated_case_is_refused() {
    let got = refused("safe | x\nfinds=scheme | ftp://x/\nsafe | x\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    // The same paths, named or by default, and the same answer in another
    // order are the same case.
    let got = refused("@posix safe | x\nsafe | x\n");
    assert!(
        got.contains("t.cases:2: repeats the case at t.cases:1"),
        "{got}"
    );
    let got =
        refused("first=scheme finds=scheme | ftp://x/\nfinds=scheme first=scheme | ftp://x/\n");
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    let got = refused("paths same base=posix\n@same safe | x\nsafe | x\n");
    assert!(got.contains("t.cases:3: repeats"), "{got}");
    // Other paths, another answer or another URL is not.
    read(concat!(
        "safe | x\n",
        "@macos safe | x\n",
        "lacks=scheme | x\n",
        "safe | x\\s\n",
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
        "safe | https://example.com/\n",
        "safe | http://127.0.0.1/\n",
        "finds=scheme | https://example.com/\n",
        "finds=credentials/scheme | http://me:pw@127.0.0.1/\n",
        "rules=local_address,credentials | http://me:pw@127.0.0.1/\n",
        "first=local_address | http://me:pw@127.0.0.1/\n",
        "lacks=credentials | http://me:pw@127.0.0.1/\n",
        "finds=local_address reason=\"fetches a key\" | http://127.0.0.1/\n",
        "first=local_address target=\"localhost\" | http://127.0.0.1/\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(cases::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    assert!(wrong[3].is_empty(), "{:?}", wrong[3]);
    for (index, missed) in [
        (1, "expected safe: \"http://127.0.0.1/\""),
        (2, "expected finds [Scheme]: \"https://example.com/\""),
        (4, "expected rules [LocalAddress, Credentials]"),
        (5, "expected first LocalAddress"),
        (6, "expected lacks Credentials"),
        (7, "expected reason \"fetches a key\""),
        (8, "expected target \"localhost\""),
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

/// Every case of every case file, one to a line: where it is, the paths,
/// the answer and the URL as Rust writes a string, tab separated.
#[test]
#[ignore = "prints every case: run it by name with --ignored --nocapture"]
fn dump() {
    for name in format::names() {
        for case in cases::load(&name) {
            println!("{}", cases::dumped(&case));
        }
    }
}
