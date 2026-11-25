//! The readings of a POSIX pattern whose parts can match `..`, held to a
//! count: each such part is read as its names, `.` and `..`, three readings
//! each, for at most so many parts, so a pattern of many such parts has a
//! bounded number of readings. It reads the counts through core's
//! `testing` feature.
//!
//! The bound is held to the number written here, so a bound that is
//! removed, or made larger, fails.

use milo_guards_core::testing::{link_work, posix, MOST_CLIMBING};
use milo_guards_core::Flavour;

/// The most parts read as `.` and `..` too, as written here.
const CLIMBING: usize = 4;

#[test]
fn the_bound_is_the_one_written_here() {
    assert_eq!(MOST_CLIMBING, CLIMBING);
}

#[test]
fn a_pattern_is_read_three_ways_for_each_part_up_to_the_bound() {
    for parts in 1..=CLIMBING + 3 {
        let path = format!("{}x", ".*/".repeat(parts));
        let work = link_work(&posix(), &path, Flavour::Posix);
        let read = 3_usize.pow(u32::try_from(parts.min(CLIMBING)).unwrap_or(0));
        assert_eq!(work.readings, read, "{parts} parts");
    }
}
