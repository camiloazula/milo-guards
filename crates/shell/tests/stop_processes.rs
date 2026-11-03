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

use common::{posix, took};
use milo_guards_shell::{Rule, Shell};
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
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_process_rules_read_long_patterns_quickly() {
    let linux = posix();
    for line in [
        format!("pkill '{}}}'", "x{".repeat(31_000)),
        format!("pkill 'x{}'", "{1".repeat(31_000)),
        format!("pkill '{}'", "(".repeat(60_000)),
        format!("pkill '{}'", "a|".repeat(30_000)),
        format!("pkill '{}'", "^(.*".repeat(15_000)),
        format!("pkill '{}'", "[a-z]x?(a|b)+".repeat(4_000)),
        format!("pkill '{}'", "(a|b|c)".repeat(8_000)),
        format!("pkill '{}x'", "[a]*".repeat(15_000)),
    ] {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &linux);
        assert!(
            took < Duration::from_millis(500),
            "{} bytes took {took:?}",
            line.len()
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
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_fork_bomb_scan_reads_nested_functions_quickly() {
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
