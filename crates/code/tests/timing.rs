//! The raw scan of Ruby, and the reason `refusal` gives, read a text of
//! 256 KB in time linear in its length: a run of embedded documents that
//! never end (`=begin` on every line) once took seconds, each `=begin`
//! looking for its `=end` again. `just timing` runs this binary alone in an
//! optimized build. Every test of the reader that reads the clock is here.
//!
//! The time is measured here: the crate keeps no clock.

#![allow(
    clippy::disallowed_methods,
    reason = "the reader keeps no clock; only this test times it, to catch a quadratic read"
)]

use std::time::{Duration, Instant};

/// Far above what a linear read of this size takes, far below a quadratic one.
const LIMIT: Duration = Duration::from_secs(2);

/// Whether `took` is under `LIMIT`, saying on standard output how near it
/// came, as `timing: 41.0% <the row>` (CONTRIBUTING.md).
#[allow(
    clippy::disallowed_macros,
    reason = "a timing test prints each row's time, for the timing job's log"
)]
fn under(what: &str, took: Duration) -> bool {
    let share = took.as_secs_f64() / LIMIT.as_secs_f64();
    println!(
        "timing: {:5.1}% {took:.1?} of {LIMIT:?}: {what}",
        share * 100.0
    );
    took < LIMIT
}

#[cfg(feature = "ruby")]
#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn documents_that_never_end_are_scanned_in_a_bound() {
    use milo_guards_code::testing;
    use milo_guards_code::{refusal, Language};
    for (name, unit) in [
        ("a document opened on every line", "=begin\n"),
        (
            "documents ended where the grammar ends them",
            "=begin\n=end\n",
        ),
        ("documents with text", "=begin\nx = 1\n"),
    ] {
        let text = unit.repeat((256 << 10) / unit.len());
        let started = Instant::now();
        let _ = testing::ruby_raw(&text);
        let took = started.elapsed();
        assert!(under(&format!("{name}, raw"), took), "{name}: {took:?}");
        let started = Instant::now();
        let _ = refusal(Language::Ruby, &text);
        let took = started.elapsed();
        assert!(under(&format!("{name}, refusal"), took), "{name}: {took:?}");
    }
}
