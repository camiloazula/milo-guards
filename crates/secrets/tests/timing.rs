//! A hostile text of a megabyte is read inside a bound and in time linear
//! in its length, because the table is built of regular expressions that
//! never backtrack and the hand loops do not rescan. Every test of the guard
//! that reads the clock is here, and `just timing` runs this binary alone in
//! an optimized build; what the guard answers for these texts is checked in
//! `robust.rs`, in every build.
//!
//! The time is measured here: the crate keeps no clock.

#![allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]

mod common;

use std::time::{Duration, Instant};

use common::hostile::{hostile, HOSTILE};
use milo_guards_secrets::{find, find_high_entropy, find_spans};

/// The best of `runs` reads of `text`: noise only ever adds.
fn timed(text: &str, runs: usize) -> Duration {
    (0..runs)
        .map(|_| {
            let started = Instant::now();
            let _ = find_spans(text);
            let _ = find_high_entropy(text, 4.5);
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_megabyte_of_one_character_and_of_nested_quotes_is_read_in_a_bound() {
    for name in [
        "one character",
        "nested quotes",
        "base64",
        "partial prefixes",
    ] {
        let text = hostile(name, 1 << 20);
        let took = timed(&text, 1);
        assert!(took < LIMIT, "{name} took {took:?}");
    }
}

/// Far above what a read of this size takes (under a second in a build with
/// no optimisation), far below what a quadratic one would take.
const LIMIT: Duration = Duration::from_secs(10);

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn every_hostile_text_is_read_in_a_bound() {
    for name in HOSTILE {
        let text = hostile(name, 128 << 10);
        let took = timed(&text, 1);
        assert!(took < LIMIT, "{name} took {took:?}");
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn reading_takes_time_in_proportion_to_the_text() {
    // Four times the text takes about four times as long to read; a read
    // that rescans takes sixteen. The bound is ten, with a floor under the
    // short time so a fast machine's noise is not a ratio.
    let floor = Duration::from_millis(25);
    for name in HOSTILE {
        let small = timed(&hostile(name, 32 << 10), 2);
        let large = timed(&hostile(name, 128 << 10), 2);
        assert!(
            large < small.max(floor) * 10,
            "{name}: {small:?} for 32 KiB, {large:?} for 128 KiB"
        );
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_long_line_of_hits_costs_the_same_per_hit_as_a_short_one() {
    // Every hit on one line asks where the line begins, and where an escape
    // ends: a read that looks back over the line for each (it was once
    // `rfind('\n')`) takes four times the text sixteen times as long.
    // The sizes are large enough that the difference is not noise.
    for name in [
        "spans of escaped names",
        "spans of escaped values",
        "spans of escaped keys",
    ] {
        let small = hostile(name, 256 << 10);
        let large = hostile(name, 1 << 20);
        for (read, label) in [
            (
                (|text: &str| {
                    let _ = find(text);
                }) as fn(&str),
                "find",
            ),
            (
                |text: &str| {
                    let _ = find_spans(text);
                },
                "find_spans",
            ),
            (
                |text: &str| {
                    let _ = find_high_entropy(text, 4.5);
                },
                "find_high_entropy",
            ),
        ] {
            let time = |text: &str| {
                let started = Instant::now();
                read(text);
                started.elapsed()
            };
            let (a, b) = (time(&small), time(&large));
            assert!(
                b < a.max(Duration::from_millis(25)) * 10,
                "{name} by {label}: {a:?} for 256 KiB, {b:?} for 1 MiB"
            );
        }
    }
}
