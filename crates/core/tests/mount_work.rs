//! The work of placing a path through the drive mounts the caller names,
//! held to a count, not to the clock: one resolver has one budget of
//! counted work for every walk it makes through a mount, and past it a path
//! is only known when it runs, never a place. Each part of a path costs one
//! lookup in the tree of the mounts' folders, whatever the number of
//! mounts. A count is the same on every machine, so this runs in every
//! build. It reads the counts through core's `testing` feature.
//!
//! The bound is held to the number written here, so a bound that is
//! removed, or made ten times larger, fails.

use milo_guards_core::testing::{mount_work, posix, MOST_WORK};
use milo_guards_core::{Flavour, Paths, Place, Sensitivity};

/// The most work one resolver spends on mounts, as written here.
const WORK: usize = 1_048_576;

const KEY: Place = Place::Sensitive("your SSH keys", Sensitivity::Secret);

/// WSL's mount, and `count` more, none of them on the paths below but the
/// first.
fn many_mounts(count: usize) -> Paths {
    posix()
        .with_drive_mounts(["/mnt"])
        .with_drive_mounts((0..count).map(|at| format!("/media/m{at}")))
}

#[test]
fn the_bound_is_the_one_written_here() {
    assert_eq!(MOST_WORK, WORK);
}

#[test]
fn a_path_costs_the_same_whatever_the_number_of_mounts() {
    for parts in [1, 10, 100, 1_000] {
        let path = vec!["d"; parts].join("/");
        let (alone, place) = mount_work(&many_mounts(0), &path, Flavour::Posix);
        assert_eq!(place, Place::Inside);
        for count in [10, 100, 1_000, 10_000] {
            let (work, place) = mount_work(&many_mounts(count), &path, Flavour::Posix);
            assert_eq!(work, alone, "{count} mounts, {parts} parts");
            assert_eq!(place, Place::Inside);
        }
        // The walk reads each part once, from the working directory's four.
        assert!(alone <= 4 + parts, "{parts} parts: {alone}");
    }
}

#[test]
fn a_path_through_a_mount_costs_one_lookup_for_each_part() {
    for parts in [1, 10, 100, 1_000] {
        let path = format!("/mnt/c/{}Users/me/.ssh/id_rsa", "d/../".repeat(parts));
        let (work, place) = mount_work(&many_mounts(1_000), &path, Flavour::Posix);
        assert_eq!(place, KEY, "{parts} parts");
        assert!(work <= 2 * parts + 8, "{parts} parts: {work}");
    }
}

#[test]
fn a_pattern_through_the_mounts_costs_each_name_once_for_each_part() {
    // Every mount's folder is matched against the pattern's `*`, and each
    // letter against its next part: no more.
    for count in [10, 100, 1_000] {
        let (work, place) = mount_work(
            &many_mounts(count),
            "/*/*/Users/me/.ssh/id_rsa",
            Flavour::Posix,
        );
        assert_eq!(place, KEY, "{count} mounts");
        assert!(work <= 4 * (count + 10), "{count} mounts: {work}");
    }
}

#[test]
fn past_the_budget_a_pattern_stops_and_is_never_placed_inside() {
    // Two thousand mounts in one folder of the workspace, and a pattern of
    // six hundred `**`: each part is matched against each of them, more than
    // the budget. What it picks in a drive is the root of a disk, and what
    // it would pick past the budget is only known when it runs.
    let paths =
        posix().with_drive_mounts((0..2_000).map(|at| format!("/home/me/work/repo/m/{at}")));
    let pattern = format!("m/{}x", "**/".repeat(600));
    let (work, place) = mount_work(&paths, &pattern, Flavour::Posix);
    assert_eq!(place, Place::Top("the root of the disk"));
    assert!(work <= WORK && work > WORK - 1_000, "{work}");
    // With a tenth of the stars, the budget is not reached.
    let pattern = format!("m/{}x", "**/".repeat(60));
    let (work, place) = mount_work(&paths, &pattern, Flavour::Posix);
    assert_eq!(place, Place::Top("the root of the disk"));
    assert!(work < WORK / 2, "{work}");
    // Without the mounts, the pattern is the workspace's.
    let (_, place) = mount_work(&posix(), &pattern, Flavour::Posix);
    assert_eq!(place, Place::Inside);
}
