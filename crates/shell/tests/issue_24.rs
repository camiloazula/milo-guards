//! A part after `fd/<digits>` makes the descriptor a folder, so a `..`
//! after it is no longer the descriptor's own place.

mod common;

use common::{check, macos};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_dot_dot_after_a_descriptor_is_not_a_device() {
    check(
        Shell::Posix,
        &macos(),
        &[
            "echo x > /dev/fd/1",
            "cat /dev/fd/0",
            "echo x > /dev/fd/../fd/1",
            "echo x > /dev/fd/../null",
        ],
        &[
            ("rm -rf /dev/fd/3/../1", Rule::Delete),
            ("echo x > /dev/fd/0/./../1", Rule::Overwrite),
            ("rm -rf /dev/fd/3/../null", Rule::Delete),
            ("echo x > /dev/fd/3/../stdout", Rule::Overwrite),
        ],
    );
}

#[test]
fn an_empty_or_dot_part_does_not_hide_the_descriptor_folder() {
    check(
        Shell::Posix,
        &macos(),
        &["echo x > /dev/fd//1", "echo x > /dev/fd/./1"],
        &[
            ("rm -rf /dev/fd//3/../1", Rule::Delete),
            ("echo x > /dev/fd/./3/../1", Rule::Overwrite),
            ("rm -rf /dev//fd//3//..//1", Rule::Delete),
            ("tee /dev/fd/./3/../1", Rule::Overwrite),
            ("truncate -s0 /dev/fd//3/../1", Rule::Overwrite),
            ("dd if=/dev/zero of=/dev/fd//3/../1", Rule::Overwrite),
            ("rm -rf '/dev/fd//3/../1'", Rule::Delete),
            ("cd /dev/fd && rm -rf ./3/../1", Rule::Delete),
        ],
    );
}
