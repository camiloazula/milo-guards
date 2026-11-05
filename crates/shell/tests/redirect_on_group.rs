//! A redirect on a group, a branch, a loop or a function call is opened before
//! its body runs, so from the folder the line is in then, not from the one a
//! `cd` in the body leaves it in. `{ cd sub; cat; } < ../../.ssh/id_rsa` opens
//! the same key `cat ../../.ssh/id_rsa` does, and `{ cd ../..; ls; } > x`
//! writes `x` where the line is, not two folders up.
//!
//! A `cd` in the body that may not have run (in a branch, after `&&` or
//! `||`, in a loop body) leaves the line in a folder that is not certain, so
//! a later run of the file the redirect wrote may be from the folder the file
//! is in. `{ cd sub; echo x; } > x.sh; bash x.sh` runs `sub/x.sh`, which is
//! not written; `if false; then cd sub; else echo x; fi > x.sh; bash x.sh`
//! may run the `x.sh` it wrote.
//!
//! The lines and their answers are in `tests/cases/redirect_on_group.cases`;
//! here are the paths a group lists and the lines made of many definitions
//! and calls. The time those take is in `tests/timing.rs`.

mod common;

use common::lines::{
    many_definitions_that_may_not_run, many_functions_that_move_the_line,
    one_function_defined_and_called_many_times, repeated,
};
use common::{exact, lists, posix};
use milo_guards_shell::{classify, Rule, Shell};

/// How many `unknown` findings of `line` say it defines more functions that
/// move the line than the guard keeps.
fn past_the_cap(line: &str) -> usize {
    classify(line, Shell::Posix, &posix())
        .findings()
        .iter()
        .filter(|finding| {
            finding.rule == Rule::Unknown
                && finding
                    .reason
                    .contains("defines more functions that move the line")
        })
        .count()
}

#[test]
fn every_case_holds() {
    common::cases::check("redirect_on_group");
}

#[test]
fn the_paths_of_a_group_are_placed_from_where_it_starts() {
    let repo = "/home/me/work/repo";
    lists(
        Shell::Posix,
        &posix(),
        &[
            (
                "{ cd sub; cat; } < ../../.ssh/id_rsa",
                vec![
                    exact(&format!("{repo}/../../.ssh/id_rsa")),
                    exact(&format!("{repo}/sub")),
                ],
            ),
            (
                "{ cd ../..; cat; } < .ssh/id_rsa",
                vec![exact("/home/me"), exact(&format!("{repo}/.ssh/id_rsa"))],
            ),
            (
                "{ cd sub; } < ../x",
                vec![
                    exact(&format!("{repo}/../x")),
                    exact(&format!("{repo}/sub")),
                ],
            ),
            (
                "cd ~ && { cat; } < .ssh/id_rsa",
                vec![exact("/home/me"), exact("/home/me/.ssh/id_rsa")],
            ),
        ],
    );
}

#[test]
fn a_line_that_defines_many_functions_that_move_the_line_is_unknown_once() {
    // Past the most functions that move the line a line may define (a name
    // defined again counts again), the redirects on its calls are unknown,
    // once, and not placed from where each function was defined.
    let distinct = repeated(300, |i| format!("f{i}() {{ cd /; }}; "));
    let same = repeated(300, |_| "f() { cd /; }; ".to_string());
    let cases = repeated(150, |_| "f() { cd /; }; F() { cd /; }; ".to_string());
    for definitions in [distinct, same, cases] {
        let one = format!("{definitions}f0 < x; f < y; f < z; F < w");
        assert_eq!(past_the_cap(&one), 1, "{one}");
        let group = format!("{definitions}{{ f; f; }} > x");
        assert_eq!(past_the_cap(&group), 1, "{group}");
    }
    // Under it, the same names are worked out.
    let few = repeated(20, |_| "f() { cd /; }; ".to_string());
    assert_eq!(past_the_cap(&format!("{few}f < x; {{ f; }} > y")), 0);
}

#[test]
fn a_name_that_is_defined_and_called_many_times_is_reported_once() {
    // Each call of a function whose definition is redirected, and whose
    // folder is only known when it runs, says so for the name once.
    let reported = |line: &str, name: &str| {
        classify(line, Shell::Posix, &posix())
            .findings()
            .iter()
            .filter(|finding| {
                finding.rule == Rule::Unknown && finding.target.as_deref() == Some(name)
            })
            .count()
    };
    let definitions = repeated(5, |_| "f() { cd sub | cat; }; ".to_string());
    let calls = repeated(5, |_| "f; ".to_string());
    let line = format!("{definitions}{calls}f > log.txt; f > log.txt");
    assert_eq!(reported(&line, "f"), 1, "{line}");
    let line = format!("{definitions}{{ {calls}}} > log.txt");
    assert_eq!(reported(&line, "f"), 1, "{line}");
}

#[test]
fn a_redirect_on_calls_to_many_functions_from_other_folders_is_unknown() {
    // Each function was defined in another folder, and the redirect is
    // placed from each of them: past a few dozen, the line is unknown and
    // not judged from every one.
    let definitions = repeated(100, |i| format!("f{i}() {{ cd a; }}; "));
    let calls = repeated(100, |i| format!("f{i}; "));
    let line = format!("{definitions}{{ {calls}}} < x");
    let assessment = classify(&line, Shell::Posix, &posix());
    assert!(
        assessment
            .findings()
            .iter()
            .any(|finding| finding.rule == Rule::Unknown
                && finding.reason.contains("more functions that move the line")),
        "{:?}",
        assessment.findings()
    );
}

#[test]
fn many_functions_that_move_the_line_and_many_calls_are_not_read_as_safe() {
    // Neither line reads every function, or every earlier unit, again for
    // each call (the time is in `timing.rs`).
    for line in many_functions_that_move_the_line() {
        assert!(line.len() < 64 * 1024, "{}", line.len());
        let rules = common::rules(&line, Shell::Posix, &posix());
        assert!(!rules.is_empty(), "a long line of calls is read as safe");
    }
}

#[test]
fn one_function_defined_many_times_and_called_many_times_has_a_finding_for_each_reason() {
    // A later definition replaces the earlier, so a call does not read every
    // definition of the name, and the name is not reported once for each.
    for line in one_function_defined_and_called_many_times() {
        assert!(line.len() < 64 * 1024, "{}", line.len());
        let assessment = classify(&line, Shell::Posix, &posix());
        assert!(
            !assessment.findings().is_empty(),
            "a long line of calls is read as safe"
        );
        // One finding for each reason and name, not one for each call.
        assert!(
            assessment.findings().len() < 16,
            "{} findings",
            assessment.findings().len()
        );
    }
}

#[test]
fn many_definitions_that_may_not_run_are_unknown_once() {
    // Each of them is kept beside the others, so what is kept is counted:
    // past the most a line may define, it is unknown, once.
    for line in many_definitions_that_may_not_run() {
        assert!(line.len() < 64 * 1024, "{}", line.len());
        let assessment = classify(&line, Shell::Posix, &posix());
        assert!(
            !assessment.findings().is_empty(),
            "a long line of definitions is read as safe"
        );
        assert_eq!(past_the_cap(&line), 1, "{} bytes", line.len());
    }
    // Under it, a few of them are worked out, and are not past the cap.
    let few = repeated(20, |_| "true || f(){ :;}>x;".to_string());
    assert_eq!(past_the_cap(&format!("{few}f")), 0);
}
