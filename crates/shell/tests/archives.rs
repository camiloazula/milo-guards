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
//! the timing of a long chain of `-C`, and of many options and folders of an
//! unpacker.

mod common;

use common::{posix, took, windows};
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

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_options_and_folders_of_an_unpacker_are_read_quickly() {
    // Each folder is judged once, and a run of `-H` looks one word ahead.
    let lines = [
        (
            format!("tar -xf x.tar{}", " -H".repeat(6_000)),
            Shell::Posix,
        ),
        (
            format!("cpio -i{}", " -D build".repeat(3_000)),
            Shell::Posix,
        ),
        (
            format!("unrar x a.rar{}", " b/".repeat(7_000)),
            Shell::Posix,
        ),
        (
            format!(
                "unrar x a.rar{}",
                (0..1_500)
                    .map(|n| format!(" b{n}/"))
                    .collect::<Vec<_>>()
                    .concat()
            ),
            Shell::Posix,
        ),
        (
            format!("jar xf a.jar{}", " -C b".repeat(5_000)),
            Shell::Posix,
        ),
        (format!("pax -r{}", " -s ,a,b,".repeat(3_000)), Shell::Posix),
        (
            "[IO.Compression.ZipFile]::ExtractToDirectory('x.zip', 'b'); ".repeat(300),
            Shell::PowerShell,
        ),
    ];
    for (line, shell) in lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let took = took(&line, shell, &paths);
        assert!(
            took < Duration::from_millis(200),
            "took {took:?} for {}",
            &line[..40]
        );
    }
}
