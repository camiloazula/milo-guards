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
//! a long chain of `-C`, whose time, and that of many options and folders of
//! an unpacker, is in `tests/timing.rs`.

mod common;

use common::lines::dash_c_chain;
use common::posix;
use milo_guards_shell::{classify, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("archives");
}

#[test]
fn a_long_chain_of_dash_c_is_not_safe() {
    assert!(
        !classify(&dash_c_chain(8_000, 3_000), Shell::Posix, &posix())
            .findings()
            .is_empty()
    );
}
