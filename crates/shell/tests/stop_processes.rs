//! Stopping processes in a POSIX shell. A process stopped by a plain name
//! that is not the system's is safe; a name, a pattern, an option or a service
//! the system needs, every process of a user, a group or the caller's own
//! group (`kill 0`, a negative id), and a fork bomb are `stop_system`. An id,
//! a name, a listing or a substitution the guard cannot read for sure may be
//! any process and is `stop_unknown`; signal 0 sends nothing, but only in its
//! one plain shape.
//!
//! The lines and their answers are in `tests/cases/stop_processes.cases`;
//! here are the place of `stop_unknown` among the rules and the timed tests.

mod common;

use common::{assert_linear, at, posix, took, Maker};
use milo_guards_shell::{Rule, Shell};
use std::fmt::Write as _;
use std::time::Duration;

#[test]
fn every_case_holds() {
    common::cases::check("stop_processes");
}

#[test]
fn stop_unknown_is_named_beside_stop_system() {
    assert_eq!(Rule::StopUnknown.name(), "stop_unknown");
    let at = |rule: Rule| Rule::ALL.iter().position(|&listed| listed == rule);
    assert_eq!(
        at(Rule::StopUnknown),
        at(Rule::StopSystem).map(|position| position + 1)
    );
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_process_rules_read_long_patterns_in_linear_time() {
    // Each pattern, the head, the part repeated, the tail and the count a
    // line of 64 KB holds (`at`): at 16 KB a quarter of them, which must
    // take about a quarter of the time, not a sixteenth.
    for (head, part, tail, count) in [
        ("", "x{", "}", 31_000),
        ("x", "{1", "", 31_000),
        ("", "(", "", 60_000),
        ("", "a|", "", 30_000),
        ("", "^(.*", "", 15_000),
        ("", "[a-z]x?(a|b)+", "", 4_000),
        ("", "(a|b|c)", "", 8_000),
        ("", "[a]*", "x", 15_000),
    ] {
        let line = |size| format!("pkill '{head}{}{tail}'", part.repeat(at(count, size)));
        assert!(line(64 * 1024).len() <= 64 * 1024, "{part}");
        assert_linear(
            &format!("pkill '{head}{part}…{tail}'"),
            Shell::Posix,
            &posix(),
            line,
        );
    }
}

/// `f(){ OPEN×depth f; ×calls CLOSE×depth }`: a body nested `depth` deep.
fn nested(open: &str, close: &str, depth: usize, calls: usize) -> String {
    format!(
        "f(){{ {}{}{} }}",
        open.repeat(depth),
        "f; ".repeat(calls),
        close.repeat(depth)
    )
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_fork_bomb_scan_reads_many_words_and_functions_in_linear_time() {
    // A loop over thousands of words in a function body, and thousands of
    // functions that call each other in one long cycle: at 64 KB each holds
    // the count written here (`at`), at 16 KB a quarter of it.
    let cycle = |size| {
        let count = at(2_400, size);
        (0..count).fold(String::new(), |mut line, at| {
            let _ = write!(
                line,
                "f{at}(){{ f{} & f{}; }}; ",
                (at + 1) % count,
                at * 7 % count
            );
            line
        })
    };
    let lines: [(&str, Maker); 2] = [
        ("f() { for x in a …; do f & done; }", &|size| {
            format!(
                "f() {{ for x in {}; do f & done; }}",
                "a ".repeat(at(30_000, size))
            )
        }),
        ("f0(){ f1 & f0; }; …", &cycle),
    ];
    for (what, line) in lines {
        assert!(line(64 * 1024).len() <= 64 * 1024, "{what}");
        assert_linear(what, Shell::Posix, &posix(), line);
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_fork_bomb_scan_reads_nested_functions_quickly() {
    // Each line is as deep as the guard reads, or deeper: its time is set by
    // the depth, not by the length, so it is held to a fixed bound, which
    // an optimized build here takes a twentieth of or less.
    let linux = posix();
    let slow = Duration::from_millis(500);
    let lines = [
        format!("{}f & {}", "f(){ ".repeat(390), "; }".repeat(390)),
        format!("{}{}", "f(){ f & ".repeat(390), "}; ".repeat(390)),
        format!("{}f; {}", "f(){ ".repeat(1_000), "; }".repeat(1_000)),
        format!(
            "f() {{ {}f & {}; }}",
            "{ ".repeat(1_500),
            "echo x; ".repeat(2_500)
        ),
        format!("f() {{ {}{}f & }}", "{ ".repeat(1_500), "f; ".repeat(5_000)),
    ];
    // A body of balanced `if`, `while` and `( )` nested near the depth limit,
    // with thousands of calls to the function inside it. A read that climbs
    // from each call takes minutes; the limit is loose so that a slow or
    // busy machine does not trip it.
    let deep = [
        nested("if true; then ", "fi; ", 390, 15_000),
        nested("while true; do ", "done; ", 390, 15_000),
        nested("( ", ") ", 390, 15_000),
        // Loops over a word known when it runs, each call checked against
        // the variable of each.
        format!(
            "f(){{ {}{}{} }}",
            "for d in $x; do ".repeat(390),
            "f \"$d\" & ".repeat(15_000),
            "done; ".repeat(390)
        ),
    ];
    let limits = lines
        .iter()
        .map(|line| (line, slow))
        .chain(deep.iter().map(|line| (line, slow * 8)));
    for (line, limit) in limits {
        let took = took(line, Shell::Posix, &linux);
        assert!(took < limit, "{} bytes took {took:?}", line.len());
    }
}
