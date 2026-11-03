//! What the guard does not see, kept as cases so a change to any of them is
//! a decision and not an accident. A case here is a limit named in
//! `docs/design/file.md`, not a goal: a symlink is judged by its own name,
//! and core's table lists places known to hold a secret, not every one. The
//! cases are in `tests/cases/limits.cases`.

mod common;

#[test]
fn what_the_guard_does_not_see_stays_as_it_is() {
    common::cases::check("limits");
}
