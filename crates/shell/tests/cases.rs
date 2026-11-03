//! The runner of the case files in `tests/cases`: what a case says, every
//! case it refuses and every wrong answer it names by file and line, that
//! each case file is checked by the test file of its name, and that no case
//! repeats another across files. `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-shell --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self, format, parse, Case, Expect};
use milo_guards_shell::{Effect, Protected, Reach, Rule, Shell};

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
fn a_case_says_its_shell_paths_answer_and_line() {
    let cases = read(concat!(
        "# A comment.\n",
        "posix safe | ls -la\n",
        "powershell finds=delete,overwrite/read_secret | Remove-Item x\n",
        "cmd@posix rules=delete first=delete lacks=elevated effect=changes | del x\n",
        "posix finds=delete reason=\"deletes your home directory\" | rm -rf ~\n",
        "posix effect=reads_workspace | cat\\sa\\tb\\n\n",
        "posix@macos effect=reads_beyond |\n",
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
    let shells: Vec<Shell> = cases.iter().map(|case| case.shell).collect();
    assert_eq!(
        shells,
        [
            Shell::Posix,
            Shell::PowerShell,
            Shell::Cmd,
            Shell::Posix,
            Shell::Posix,
            Shell::Posix
        ]
    );
    // A POSIX line is judged on `posix`, the others on `windows`, unless
    // the case names its paths.
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
            "/home/me",
            "/Users/me"
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
        [vec![Rule::Delete], vec![Rule::Overwrite, Rule::ReadSecret]]
    );
    assert_eq!(
        cases[2].expect,
        Expect {
            rules: Some(vec![Rule::Delete]),
            first: Some(Rule::Delete),
            lacks: vec![Rule::Elevated],
            effect: Some(Effect::Changes),
            ..Expect::default()
        }
    );
    assert_eq!(
        cases[3].expect.reason.as_deref(),
        Some("deletes your home directory")
    );
    assert_eq!(cases[4].line, "cat a\tb\n");
    assert_eq!(
        cases[4].expect.effect,
        Some(Effect::ReadsOnly(Reach::Workspace))
    );
    assert_eq!(cases[5].line, "");
}

#[test]
fn a_paths_declaration_names_the_paths_a_case_is_judged_on() {
    let cases = read(concat!(
        "paths home cwd=/home/me home=/home/me workspace=/home/me\n",
        "paths two cwd=C:\\\\Users\\\\me\\\\repo home=C:\\\\Users\\\\me workspace=C:\\\\Users\\\\me\\\\repo workspace=D:\\\\ws\n",
        "paths agent base=posix folder=/home/me/.agent words=\"the agent's settings\" file=/home/me/work/repo/x.yaml words=\"the agent's rules\"\n",
        "posix@home safe | ls\n",
        "cmd@two safe | dir\n",
        "posix@agent safe | ls\n",
    ));
    let home = &cases[0].paths;
    assert_eq!(
        (home.cwd.to_str(), home.home.to_str()),
        (Some("/home/me"), Some("/home/me"))
    );
    assert_eq!(home.workspaces, [std::path::PathBuf::from("/home/me")]);
    let two = &cases[1].paths;
    assert_eq!(two.cwd.to_str(), Some(r"C:\Users\me\repo"));
    assert_eq!(
        two.workspaces,
        [r"C:\Users\me\repo", r"D:\ws"].map(std::path::PathBuf::from)
    );
    let agent = &cases[2].paths;
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
        ("posix safe ls\n", "t.cases:1: a case with no `| LINE`"),
        ("posix | ls\n", "t.cases:1: a case with no answer"),
        ("| ls\n", "t.cases:1: a case starts with its shell"),
        ("safe=1 | ls\n", "t.cases:1: a case starts with its shell"),
        (
            "posix safe finds=delete | rm x\n",
            "`safe` takes no other rule field",
        ),
        (
            "posix safe lacks=delete | rm x\n",
            "`safe` takes no other rule field",
        ),
        ("posix safe safe | ls\n", "`safe` twice"),
        (
            "posix finds=delete finds=overwrite | rm x\n",
            "`finds` twice",
        ),
        ("posix finds | rm x\n", "`finds` takes a value"),
        ("posix safe=yes | ls\n", "`safe` takes no value"),
        ("posix finds=delete, | rm x\n", "an empty item"),
        (
            "posix finds=delete,overwrite reason=x | rm x\n",
            "`reason` takes `first`, or `finds` of one rule",
        ),
        ("posix reason=x | rm x\n", "`reason` takes `first`"),
        ("posix safe | ls\\q\n", "t.cases:1: an unknown escape `\\q`"),
        ("posix safe | ls \n", "t.cases:1: a space at the end"),
        ("posix safe | a\tb\n", "t.cases:1: a raw \\t"),
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
        ("paths x base=posix | ls\n", "an unknown shell `paths`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_field_word_rule_shell_effect_or_paths_is_refused() {
    for (source, why) in [
        (
            "posix safe colour=red | ls\n",
            "t.cases:1: an unknown field `colour`",
        ),
        ("posix sure | ls\n", "t.cases:1: an unknown word `sure`"),
        ("posix finds=deletes | rm x\n", "an unknown rule `deletes`"),
        (
            "posix finds=delete/Delete | rm x\n",
            "an unknown rule `Delete`",
        ),
        ("posix rules=delete,wipe | rm x\n", "an unknown rule `wipe`"),
        ("posix effect=reads | cat x\n", "an unknown effect `reads`"),
        ("fish safe | ls\n", "an unknown shell `fish`"),
        ("posix@mars safe | ls\n", "no paths named `mars`"),
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
    let got = refused("posix safe | ls\nposix finds=delete | rm x\nposix safe | ls\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    // The same paths, named or by default, and the same answer in another
    // order are the same case.
    let got = refused("posix@posix safe | ls\nposix safe | ls\n");
    assert!(
        got.contains("t.cases:2: repeats the case at t.cases:1"),
        "{got}"
    );
    let got = refused(
        "posix effect=changes finds=delete | rm x\nposix finds=delete effect=changes | rm x\n",
    );
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    let got = refused("paths same base=posix\nposix@same safe | ls\nposix safe | ls\n");
    assert!(got.contains("t.cases:3: repeats"), "{got}");
    // Another shell, other paths, another answer or another line is not.
    read(concat!(
        "posix safe | ls\n",
        "posix@macos safe | ls\n",
        "powershell safe | ls\n",
        "posix effect=reads_workspace | ls\n",
        "posix safe | ls\\s\n",
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
        "posix safe | ls\n",
        "posix safe | rm -rf ~\n",
        "posix finds=delete | ls\n",
        "posix finds=overwrite/delete | rm -rf ~\n",
        "posix rules=delete,overwrite | rm -rf ~\n",
        "posix first=overwrite | rm -rf ~\n",
        "posix lacks=delete | rm -rf ~\n",
        "posix finds=delete reason=\"deletes a file\" | rm -rf ~\n",
        "posix first=delete reason=\"deletes a file\" | rm -rf ~\n",
        "posix effect=reads_workspace | rm -rf ~\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(cases::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    assert!(wrong[3].is_empty(), "{:?}", wrong[3]);
    for (index, missed) in [
        (1, "expected safe: \"rm -rf ~\""),
        (2, "expected finds [Delete]: \"ls\""),
        (4, "expected rules [Delete, Overwrite]"),
        (5, "expected first Overwrite"),
        (6, "expected lacks Delete"),
        (7, "expected reason \"deletes a file\""),
        (8, "expected reason \"deletes a file\""),
        (9, "expected effect ReadsOnly(Workspace), got Changes"),
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

/// The build a case file's test runs in: the `#![cfg(...)]` its test file
/// starts with (`inline_off.rs` runs without the `inline` feature), or none.
fn build(name: &str) -> String {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    std::fs::read_to_string(tests.join(format!("{name}.rs")))
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("#![cfg("))
        .unwrap_or_default()
        .to_string()
}

/// No case repeats one in another file checked in the same build; a line of
/// a file checked in another build may get the same answer there.
#[test]
fn no_case_repeats_another_across_files() {
    let all: Vec<(String, Case)> = format::names()
        .iter()
        .flat_map(|name| {
            let build = build(name);
            cases::load(name)
                .into_iter()
                .map(move |case| (build.clone(), case))
        })
        .collect();
    let repeats = format::repeated(
        all.iter()
            .map(|(build, case)| (case.at.clone(), (build.clone(), cases::key(case)))),
    );
    assert!(repeats.is_empty(), "{}", repeats.join("\n"));
}

/// Every case of every case file, one to a line: where it is, the shell, the
/// paths, the answer and the line as Rust writes a string, tab separated.
#[test]
#[ignore = "prints every case: run it by name with --ignored --nocapture"]
fn dump() {
    for name in format::names() {
        for case in cases::load(&name) {
            println!("{}", cases::dumped(&case));
        }
    }
}
