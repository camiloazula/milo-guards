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
//! here are the paths a group lists, the lines made of many definitions and
//! calls, and the time they take.

mod common;

use common::{exact, lists, posix, took};
use milo_guards_shell::{classify, Rule, Shell};

/// The text `piece` makes for each number below `count`, one after the other.
fn repeated(count: usize, piece: impl Fn(usize) -> String) -> String {
    let mut text = String::new();
    for index in 0..count {
        text.push_str(&piece(index));
    }
    text
}

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
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_functions_that_move_the_line_and_many_calls_are_read_in_linear_time() {
    // A group that calls many functions with several redirects on it, and
    // one redirected call for each of as many definitions: neither reads
    // every function, or every earlier unit, again for each call. (Each
    // definition moves to an absolute folder: a relative one makes the line
    // a little deeper each time, and a path that deep costs time of its own.)
    let count = 1_600;
    let definitions = repeated(count, |i| format!("f{i}() {{ cd /a; }}; "));
    let calls = repeated(count, |i| format!("f{i}; "));
    let group = format!("{definitions}{{ {calls}}} < x > y 2> z < w");
    let each = repeated(count, |i| format!("f{i}() {{ cd /a; }}; f{i} < x; "));
    for line in [group, each] {
        assert!(line.len() < 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &posix());
        assert!(
            took < std::time::Duration::from_secs(4),
            "{} bytes took {took:?}",
            line.len()
        );
        let rules = common::rules(&line, Shell::Posix, &posix());
        assert!(!rules.is_empty(), "a long line of calls is read as safe");
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn one_function_defined_many_times_and_called_many_times_is_read_in_linear_time() {
    // The same name defined again and again, then called under a redirect:
    // a later definition replaces the earlier, so a call does not read every
    // definition of the name, and the name is not reported once for each.
    let same = repeated(2_700, |_| "f(){ cd /;};".to_string());
    let cases = repeated(1_350, |_| "f(){ cd /;};F(){ cd /;};".to_string());
    let group = repeated(15_000, |_| "f;".to_string());
    let calls = repeated(7_000, |_| "f<x;".to_string());
    let lines = [
        format!("{same}{{ {group}}} > y"),
        format!("{cases}{{ {group}}} > y"),
        format!("{same}{calls}"),
        format!("{cases}{calls}"),
    ];
    for line in lines {
        assert!(line.len() < 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &posix());
        assert!(
            took < std::time::Duration::from_secs(4),
            "{} bytes took {took:?}",
            line.len()
        );
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
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_definitions_that_may_not_run_are_unknown_once_and_read_in_linear_time() {
    // Each of them is kept beside the others, so what is kept is counted:
    // past the most a line may define, it is unknown, once, and a call does
    // not look through every one.
    let redirected = repeated(2_000, |_| "true || f(){ :;}>x;".to_string());
    let moving = repeated(2_000, |_| "true || f(){ cd /;};".to_string());
    let calls = repeated(5_000, |_| "f;".to_string());
    let lines = [
        format!("{redirected}{calls}"),
        format!("{moving}{{ {calls}}} > y"),
        format!("{redirected}{calls}f > z"),
    ];
    for line in lines {
        assert!(line.len() < 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &posix());
        assert!(
            took < std::time::Duration::from_secs(4),
            "{} bytes took {took:?}",
            line.len()
        );
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
