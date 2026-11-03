//! `effect`: whether a line only reads, changes something, or cannot be
//! told. The answer is independent of `classify`'s, except that a line
//! `classify` flags is never reads-only (every case of every case file is
//! held to that). Where a line that only reads reads (its `Reach`) is in
//! `reach.rs` and `reach_windows.rs`.
//!
//! The lines and their answers, one section per shell, are in
//! `tests/cases/effect.cases`; what stays here are the lines made long or
//! nested deep.

mod common;

use common::posix;
use milo_guards_shell::{effect, Effect, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("effect");
}

#[test]
fn a_line_past_the_length_limit_is_unknown() {
    let long = "echo x; ".repeat(10_000);
    assert_eq!(effect(&long, Shell::Posix, &posix()), Effect::Unknown);
    let nested = "(".repeat(30_000) + "ls" + &")".repeat(30_000);
    assert_eq!(effect(&nested, Shell::Posix, &posix()), Effect::Unknown);
    // A script too deeply nested to read is not read.
    let mut deep = "ls".to_string();
    for _ in 0..12 {
        deep = format!("bash -c '{deep}'");
    }
    assert_eq!(effect(&deep, Shell::Posix, &posix()), Effect::Unknown);
}
