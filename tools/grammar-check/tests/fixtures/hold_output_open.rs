//! A program for `tests/room.rs` only: it starts a copy of itself that keeps
//! its standard output open for a few seconds, and ends at once, as a shell
//! that left a program running would. The room must say so and stop.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "a test's program: it starts a copy of itself, and nothing else"
)]

use std::process::Command;
use std::time::Duration;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("child") {
        std::thread::sleep(Duration::from_secs(8));
        return;
    }
    if let Ok(me) = std::env::current_exe() {
        // The child inherits this program's standard output and error.
        let _ = Command::new(me).arg("child").spawn();
    }
}
