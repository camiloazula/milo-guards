//! The runner of the case files in `tests/cases`: what a case says, every
//! case it refuses and every wrong answer it names by file and line, that
//! each case file is checked by the test file of its name, and that no case
//! repeats another across files. `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-file --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self, format, parse, Case, Expect};
use milo_guards_file::{Access, Protected, Rule};

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
fn a_case_says_its_access_paths_answer_and_path() {
    let cases = read(concat!(
        "# A comment.\n",
        "read safe | src/main.rs\n",
        "write@windows finds=write_outside,network_share/unreadable | \\\\\\\\srv\\\\x\n",
        "write rules=write_sensitive first=write_sensitive lacks=write_outside | ~/.zshrc\n",
        "read finds=read_secret reason=\"reads your SSH keys\" | ~/.ssh/id_rsa\n",
        "read@macos finds=unreadable | \\sa\\tb\n",
        "read finds=unreadable |\n",
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
    let accesses: Vec<Access> = cases.iter().map(|case| case.access).collect();
    assert_eq!(
        accesses,
        [
            Access::Read,
            Access::Write,
            Access::Write,
            Access::Read,
            Access::Read,
            Access::Read
        ]
    );
    // A path is judged on `posix` unless the case names its paths.
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
        [
            vec![Rule::WriteOutside],
            vec![Rule::NetworkShare, Rule::Unreadable]
        ]
    );
    assert_eq!(cases[1].path, r"\\srv\x");
    assert_eq!(
        cases[2].expect,
        Expect {
            rules: Some(vec![Rule::WriteSensitive]),
            first: Some(Rule::WriteSensitive),
            lacks: vec![Rule::WriteOutside],
            ..Expect::default()
        }
    );
    assert_eq!(
        cases[3].expect.reason.as_deref(),
        Some("reads your SSH keys")
    );
    assert_eq!(cases[4].path, " a\tb");
    assert_eq!(cases[5].path, "");
}

#[test]
fn a_paths_declaration_names_the_paths_a_case_is_judged_on() {
    let cases = read(concat!(
        "paths home cwd=/home/me home=/home/me workspace=/home/me\n",
        "paths two cwd=D:\\\\work home=C:\\\\Users\\\\me workspace=D:\\\\work workspace=C:\\\\Users\\\\me\\\\dev\\\\repo\n",
        "paths none cwd=/srv/app home=/home/me\n",
        "paths agent base=posix folder=/home/me/.agent words=\"the agent's settings\" file=/home/me/work/repo/x.yaml words=\"the agent's rules\"\n",
        "read@home safe | x\n",
        "read@two safe | x\n",
        "read@none safe | x\n",
        "read@agent safe | x\n",
    ));
    let home = &cases[0].paths;
    assert_eq!(
        (home.cwd.to_str(), home.home.to_str()),
        (Some("/home/me"), Some("/home/me"))
    );
    assert_eq!(home.workspaces, [std::path::PathBuf::from("/home/me")]);
    let two = &cases[1].paths;
    assert_eq!(two.cwd.to_str(), Some(r"D:\work"));
    assert_eq!(
        two.workspaces,
        [r"D:\work", r"C:\Users\me\dev\repo"].map(std::path::PathBuf::from)
    );
    assert!(cases[2].paths.workspaces.is_empty());
    let agent = &cases[3].paths;
    assert_eq!(agent.cwd, common::posix().cwd);
    assert_eq!(
        agent.protected,
        [
            Protected::folder("/home/me/.agent", "the agent's settings"),
            Protected::file("/home/me/work/repo/x.yaml", "the agent's rules"),
        ]
    );
}

#[test]
fn a_malformed_line_is_refused() {
    for (source, why) in [
        ("read safe x\n", "t.cases:1: a case with no `| PATH`"),
        ("read | x\n", "t.cases:1: a case with no answer"),
        ("| x\n", "t.cases:1: a case starts with its access"),
        ("safe=1 | x\n", "t.cases:1: a case starts with its access"),
        (
            "write safe finds=write_outside | x\n",
            "`safe` takes no other rule field",
        ),
        (
            "write safe lacks=write_outside | x\n",
            "`safe` takes no other rule field",
        ),
        ("read safe safe | x\n", "`safe` twice"),
        (
            "write finds=write_outside finds=network_share | x\n",
            "`finds` twice",
        ),
        ("write finds | x\n", "`finds` takes a value"),
        ("read safe=yes | x\n", "`safe` takes no value"),
        ("write finds=write_outside, | x\n", "an empty item"),
        (
            "write finds=write_outside,network_share reason=x | x\n",
            "`reason` takes `first`, or `finds` of one rule",
        ),
        ("write reason=x | x\n", "`reason` takes `first`"),
        ("read safe | x\\q\n", "t.cases:1: an unknown escape `\\q`"),
        ("read safe | x \n", "t.cases:1: a space at the end"),
        ("read safe | a\tb\n", "t.cases:1: a raw \\t"),
        (
            "read safe |  x\n",
            "t.cases:1: a space at the start of the text",
        ),
        ("paths\n", "`paths` takes a name first"),
        (
            "paths posix base=posix\n",
            "the paths `posix` are already named",
        ),
        ("paths x cwd=/a\n", "takes `base`, or `cwd` and `home`"),
        (
            "paths x base=posix cwd=/a home=/b\n",
            "takes `base`, or `cwd` and `home`",
        ),
        (
            "paths x base=posix words=w\n",
            "`words` must follow its `folder` or `file`",
        ),
        (
            "paths x base=posix folder=/a\n",
            "each `folder` and `file` takes its `words`",
        ),
        ("paths x base=posix extra\n", "an unknown word"),
        ("paths x base=posix | x\n", "an unknown access `paths`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_field_word_rule_access_or_paths_is_refused() {
    for (source, why) in [
        (
            "read safe colour=red | x\n",
            "t.cases:1: an unknown field `colour`",
        ),
        ("read sure | x\n", "t.cases:1: an unknown word `sure`"),
        (
            "read finds=read_secrets | x\n",
            "an unknown rule `read_secrets`",
        ),
        (
            "read finds=read_secret/ReadSecret | x\n",
            "an unknown rule `ReadSecret`",
        ),
        (
            "write rules=write_outside,wipe | x\n",
            "an unknown rule `wipe`",
        ),
        ("read effect=changes | x\n", "an unknown field `effect`"),
        ("open safe | x\n", "an unknown access `open`"),
        ("posix safe | x\n", "an unknown access `posix`"),
        ("read@mars safe | x\n", "no paths named `mars`"),
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
    let got = refused("read safe | x\nwrite finds=write_outside | /x\nread safe | x\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    // The same paths, named or by default, and the same answer in another
    // order are the same case.
    let got = refused("read@posix safe | x\nread safe | x\n");
    assert!(
        got.contains("t.cases:2: repeats the case at t.cases:1"),
        "{got}"
    );
    let got = refused(
        "write first=write_outside finds=write_outside | /x\nwrite finds=write_outside first=write_outside | /x\n",
    );
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    let got = refused("paths same base=posix\nread@same safe | x\nread safe | x\n");
    assert!(got.contains("t.cases:3: repeats"), "{got}");
    // Another access, other paths, another answer or another path is not.
    read(concat!(
        "read safe | x\n",
        "write safe | x\n",
        "read@macos safe | x\n",
        "read lacks=read_secret | x\n",
        "read safe | x\\s\n",
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
        "read safe | src/x\n",
        "read safe | ~/.ssh/id_rsa\n",
        "read finds=read_secret | src/x\n",
        "write@windows finds=write_outside/network_share | \\\\\\\\srv\\\\share\\\\x\n",
        "write@windows rules=network_share,write_outside | \\\\\\\\srv\\\\share\\\\x\n",
        "write@windows first=network_share | \\\\\\\\srv\\\\share\\\\x\n",
        "write@windows lacks=network_share | \\\\\\\\srv\\\\share\\\\x\n",
        "read finds=read_secret reason=\"reads a key\" | ~/.ssh/id_rsa\n",
        "read first=read_secret reason=\"reads a key\" | ~/.ssh/id_rsa\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(cases::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    assert!(wrong[3].is_empty(), "{:?}", wrong[3]);
    for (index, missed) in [
        (1, "expected safe: \"~/.ssh/id_rsa\""),
        (2, "expected finds [ReadSecret]: \"src/x\""),
        (4, "expected rules [NetworkShare, WriteOutside]"),
        (5, "expected first NetworkShare"),
        (6, "expected lacks NetworkShare"),
        (7, "expected reason \"reads a key\""),
        (8, "expected reason \"reads a key\""),
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

/// Every case of every case file, one to a line: where it is, the access,
/// the paths, the answer and the path as Rust writes a string, tab
/// separated.
#[test]
#[ignore = "prints every case: run it by name with --ignored --nocapture"]
fn dump() {
    for name in format::names() {
        for case in cases::load(&name) {
            println!("{}", cases::dumped(&case));
        }
    }
}
