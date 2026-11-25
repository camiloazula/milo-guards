//! The runner of the case files in `tests/cases`: what a case says, every
//! case it refuses and every wrong answer it names by file and line, that
//! each case file is checked by the test file of its name, and that no case
//! repeats another across files. `dump` prints every case, one to a line:
//!
//! ```text
//! cargo test -p milo-guards-script --all-features --test cases -- --ignored --nocapture dump
//! ```

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test reads the test files, and `dump` prints the cases"
)]

mod common;

use common::cases::{self, format, parse, Case, Expect};
use milo_guards_script::{Language, Protected, Rule, Secret};

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
fn a_case_says_its_language_paths_answer_and_code() {
    let cases = read(concat!(
        "# A comment.\n",
        "python safe | print(1)\n",
        "javascript@windows finds=delete,unknown/unreadable | x\n",
        "python rules=delete first=delete lacks=overwrite | y\n",
        "python finds=read_secret reason=\"reads your SSH keys\" target=\"~\" | z\n",
        "javascript@macos first=unknown | \\sa\\nb\n",
        "python finds=unknown |\n",
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
    let languages: Vec<Language> = cases.iter().map(|case| case.language).collect();
    assert_eq!(
        languages,
        [
            Language::Python,
            Language::JavaScript,
            Language::Python,
            Language::Python,
            Language::JavaScript,
            Language::Python
        ]
    );
    // Code is judged on `posix` unless the case names its paths.
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
        [vec![Rule::Delete], vec![Rule::Unknown, Rule::Unreadable]]
    );
    assert_eq!(
        cases[2].expect,
        Expect {
            rules: Some(vec![Rule::Delete]),
            first: Some(Rule::Delete),
            lacks: vec![Rule::Overwrite],
            ..Expect::default()
        }
    );
    assert_eq!(
        cases[3].expect.reason.as_deref(),
        Some("reads your SSH keys")
    );
    assert_eq!(cases[3].expect.target.as_deref(), Some("~"));
    assert_eq!(cases[4].expect.target, None);
    assert_eq!(cases[4].code, " a\nb");
    assert_eq!(cases[5].code, "");
}

#[test]
fn a_paths_declaration_names_the_paths_a_case_is_judged_on() {
    let cases = read(concat!(
        "paths outside cwd=/tmp/x home=/home/me workspace=/home/me/work/repo\n",
        "paths agent base=posix folder=/home/me/.agent words=\"the agent's settings\" secret_file=/home/me/work/repo/.env words=\"the project's environment file\"\n",
        "python@outside safe | x\n",
        "python@agent safe | x\n",
    ));
    let outside = &cases[0].paths;
    assert_eq!(outside.cwd.to_str(), Some("/tmp/x"));
    assert_eq!(
        outside.workspaces,
        [std::path::PathBuf::from("/home/me/work/repo")]
    );
    let agent = &cases[1].paths;
    assert_eq!(agent.cwd, common::posix().cwd);
    assert_eq!(
        agent.protected,
        [Protected::folder("/home/me/.agent", "the agent's settings")]
    );
    assert_eq!(
        agent.secrets,
        [Secret::file(
            "/home/me/work/repo/.env",
            "the project's environment file"
        )]
    );
}

#[test]
fn a_malformed_line_is_refused() {
    for (source, why) in [
        ("python safe x\n", "t.cases:1: a case with no `| CODE`"),
        ("python | x\n", "t.cases:1: a case with no answer"),
        ("| x\n", "t.cases:1: a case starts with its language"),
        ("safe=1 | x\n", "t.cases:1: a case starts with its language"),
        (
            "@posix safe | x\n",
            "t.cases:1: a case starts with its language",
        ),
        (
            "python safe finds=delete | x\n",
            "`safe` takes no other rule field",
        ),
        ("python safe safe | x\n", "`safe` twice"),
        ("python finds | x\n", "`finds` takes a value"),
        ("python safe=yes | x\n", "`safe` takes no value"),
        ("python finds=delete, | x\n", "an empty item"),
        (
            "python finds=delete,unknown reason=x | x\n",
            "`reason`, `target` and `instead` take `first`, or `finds` of one rule",
        ),
        (
            "python rules=delete target=x | x\n",
            "`reason`, `target` and `instead` take `first`",
        ),
        ("python safe | x\\q\n", "t.cases:1: an unknown escape `\\q`"),
        ("python safe | x \n", "t.cases:1: a space at the end"),
        ("paths x cwd=/a\n", "takes `base`, or `cwd` and `home`"),
        (
            "paths posix base=posix\n",
            "the paths `posix` are already named",
        ),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn an_unknown_field_word_rule_language_or_paths_is_refused() {
    for (source, why) in [
        (
            "python safe colour=red | x\n",
            "t.cases:1: an unknown field `colour`",
        ),
        ("python sure | x\n", "t.cases:1: an unknown word `sure`"),
        ("python finds=deletes | x\n", "an unknown rule `deletes`"),
        (
            "python finds=write_outside | x\n",
            "an unknown rule `write_outside`",
        ),
        ("python effect=changes | x\n", "an unknown field `effect`"),
        ("ruby safe | x\n", "an unknown language `ruby`"),
        ("posix safe | x\n", "an unknown language `posix`"),
        ("python@mars safe | x\n", "no paths named `mars`"),
    ] {
        let got = refused(source);
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
}

#[test]
fn a_repeated_case_is_refused() {
    let got = refused("python safe | x\njavascript safe | x\npython safe | x\n");
    assert!(
        got.contains("t.cases:3: repeats the case at t.cases:1"),
        "{got}"
    );
    let got = refused("python@posix safe | x\npython safe | x\n");
    assert!(got.contains("t.cases:2: repeats"), "{got}");
    // Another language, other paths, another answer or other code is not.
    read(concat!(
        "python safe | x\n",
        "javascript safe | x\n",
        "python@macos safe | x\n",
        "python lacks=delete | x\n",
        "python safe | x\\s\n",
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
        "python safe | print(1)\n",
        "python safe | import shutil; shutil.rmtree('/home/me')\n",
        "python finds=read_secret | print(1)\n",
        "python rules=unknown | import shutil; shutil.rmtree('/home/me')\n",
        "python first=unknown | import shutil; shutil.rmtree('/home/me')\n",
        "python lacks=delete | import shutil; shutil.rmtree('/home/me')\n",
        "python finds=delete reason=\"deletes a key\" | import shutil; shutil.rmtree('/home/me')\n",
        "python finds=delete target=\"/home\" | import shutil; shutil.rmtree('/home/me')\n",
        "python finds=delete instead=none | import shutil; shutil.rmtree('/home/me')\n",
    ));
    let wrong: Vec<Vec<String>> = cases.iter().map(cases::wrong).collect();
    assert!(wrong[0].is_empty(), "{:?}", wrong[0]);
    for (index, missed) in [
        (1, "expected safe"),
        (2, "expected finds [ReadSecret]"),
        (3, "expected rules [Unknown]"),
        (4, "expected first Unknown"),
        (5, "expected lacks Delete"),
        (6, "expected reason \"deletes a key\""),
        (7, "expected target \"/home\""),
        (8, "expected instead Nothing"),
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

/// Every rule is found by some case, in each language, so no rule goes
/// untested: but `run_downloaded` in Python, whose reader finds no code
/// downloaded (a module is a file, and a download it runs is code it does
/// not read).
#[test]
fn every_rule_has_cases_in_each_language() {
    let all: Vec<Case> = format::names()
        .iter()
        .flat_map(|name| cases::load(name))
        .collect();
    let mut missing = Vec::new();
    for rule in Rule::ALL {
        for language in [Language::Python, Language::JavaScript] {
            if (rule, language) == (Rule::RunDownloaded, Language::Python) {
                continue;
            }
            let found = all.iter().any(|case| {
                case.language == language
                    && (case.expect.finds.iter().any(|group| group == &[rule])
                        || case.expect.first == Some(rule)
                        || case.expect.rules.as_deref() == Some(&[rule]))
            });
            if !found {
                missing.push(format!(
                    "{} in {}",
                    rule.name(),
                    cases::language_name(language)
                ));
            }
        }
    }
    assert!(missing.is_empty(), "no case finds {}", missing.join(", "));
}

/// Every case of every case file, one to a line: where it is, the language,
/// the paths, the answer and the code as Rust writes a string, tab
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
