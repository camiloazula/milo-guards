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
