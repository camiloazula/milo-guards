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

use common::{at, posix, windows, Maker};
use milo_guards_shell::{classify, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("archives");
}

/// `tar --remove-files` given `-C a` `count` times, then `*` `files` times.
fn dash_c_chain(count: usize, files: usize) -> String {
    format!(
        "tar -cf x.tar --remove-files{}{}",
        " -Ca".repeat(count),
        " *".repeat(files)
    )
}

#[test]
fn a_long_chain_of_dash_c_is_not_safe() {
    assert!(
        !classify(&dash_c_chain(8_000, 3_000), Shell::Posix, &posix())
            .findings()
            .is_empty()
    );
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_long_chain_of_dash_c_is_read_in_linear_time() {
    // Each `-C` is joined to the one before it; the chain must stay bounded,
    // not be copied onto every later member. At 64 KB the line holds the
    // counts written here (`at`), at 16 KB a quarter of them.
    assert!(dash_c_chain(8_000, 3_000).len() <= 64 * 1024);
    common::assert_linear(
        "tar -cf x.tar --remove-files -Ca … * …",
        Shell::Posix,
        &posix(),
        |size| dash_c_chain(at(8_000, size), at(3_000, size)),
    );
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_options_and_folders_of_an_unpacker_are_read_in_linear_time() {
    // Each folder is judged once, and a run of `-H` looks one word ahead. At
    // 64 KB or less each line holds the counts written here (`at`), at a
    // quarter of the size a quarter of them.
    let lines: [(&str, Shell, Maker); 7] = [
        ("tar -xf x.tar -H …", Shell::Posix, &|size| {
            format!("tar -xf x.tar{}", " -H".repeat(at(6_000, size)))
        }),
        ("cpio -i -D build …", Shell::Posix, &|size| {
            format!("cpio -i{}", " -D build".repeat(at(3_000, size)))
        }),
        ("unrar x a.rar b/ …", Shell::Posix, &|size| {
            format!("unrar x a.rar{}", " b/".repeat(at(7_000, size)))
        }),
        ("unrar x a.rar b0/ b1/ …", Shell::Posix, &|size| {
            let folders = (0..at(1_500, size)).fold(String::new(), |mut folders, n| {
                folders.push_str(" b");
                folders.push_str(&n.to_string());
                folders.push('/');
                folders
            });
            format!("unrar x a.rar{folders}")
        }),
        ("jar xf a.jar -C b …", Shell::Posix, &|size| {
            format!("jar xf a.jar{}", " -C b".repeat(at(5_000, size)))
        }),
        ("pax -r -s ,a,b, …", Shell::Posix, &|size| {
            format!("pax -r{}", " -s ,a,b,".repeat(at(3_000, size)))
        }),
        (
            "[IO.Compression.ZipFile]::ExtractToDirectory(…); …",
            Shell::PowerShell,
            &|size| {
                "[IO.Compression.ZipFile]::ExtractToDirectory('x.zip', 'b'); ".repeat(at(300, size))
            },
        ),
    ];
    for (what, shell, line) in lines {
        assert!(line(64 * 1024).len() <= 64 * 1024, "{what}");
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        common::assert_linear(what, shell, &paths, line);
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_archives_written_are_read_in_linear_time() {
    for (what, start, part) in [
        ("tar -c -f ~/a -f ~/b …", "tar -c", " -f ~/a"),
        ("cpio -o -F ~/a …", "cpio -o", " -F ~/a -O ~/b"),
        ("pax -w -f ~/a …", "pax -w", " -f ~/a"),
        ("jar cf … @a …", "jar c", " -f ~/a @x"),
        ("aunpack -X ~ \"$O\" …", "aunpack", " -X ~ \"$O\" a.zip"),
        ("zip x.zip -O ~/a …", "zip x.zip", " -O ~/a"),
    ] {
        common::assert_linear(what, Shell::Posix, &posix(), |size| {
            format!("{start}{}", common::filled(part, size, start.len()))
        });
    }
}
