//! Archives. Unpacking writes into a folder: the one an option names, or
//! the working directory with none, judged like any write, in every shell
//! and by every prefix of tar's long options; a mode only known when it runs
//! may unpack, and `tar -xP` unpacks to absolute paths. Archiving that
//! deletes what it archives (`tar --remove-files`, `zip -m`, `7z a -sdel`,
//! `rar m`, `rsync --remove-source-files`) deletes its members, judged as
//! `rm` judges its operands and with the reasons of `rm`; without such an
//! option it deletes nothing. The commands `tar` and `zip` run through a
//! shell are judged as lines of their own.
//!
//! The lines and their answers are in `tests/cases/archives.cases`; here is
//! the timing of a long chain of `-C`.

mod common;

use common::{posix, took};
use milo_guards_shell::{classify, Shell};
use std::time::Duration;

#[test]
fn every_case_holds() {
    common::cases::check("archives");
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_long_chain_of_dash_c_is_read_quickly() {
    // Each `-C` is joined to the one before it; the chain must stay bounded,
    // not be copied onto every later member.
    let mut line = "tar -cf x.tar --remove-files".to_string();
    line.push_str(&" -Ca".repeat(8_000));
    line.push_str(&" *".repeat(3_000));
    assert!(line.len() <= 64 * 1024, "{}", line.len());
    let took = took(&line, Shell::Posix, &posix());
    assert!(took < Duration::from_millis(200), "took {took:?}");
    assert!(!classify(&line, Shell::Posix, &posix())
        .findings()
        .is_empty());
}
