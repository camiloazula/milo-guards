//! Stopping processes in a POSIX shell. A process stopped by a plain name
//! that is not the system's is safe; a name, a pattern, an option or a service
//! the system needs, every process of a user, a group or the caller's own
//! group (`kill 0`, a negative id), and a fork bomb are `stop_system`. An id,
//! a name, a listing or a substitution the guard cannot read for sure may be
//! any process and is `stop_unknown`; signal 0 sends nothing, but only in its
//! one plain shape.
//!
//! The lines and their answers are in `tests/cases/stop_processes.cases`;
//! here is the place of `stop_unknown` among the rules. The time long
//! patterns and the fork bomb scan take is in `tests/timing.rs`.

mod common;

use milo_guards_shell::Rule;

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
