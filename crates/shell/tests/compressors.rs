//! Compressors: `gzip x` writes `x.gz` and deletes `x`, so a compressor run
//! on a file deletes it, judged as `rm` judges its operands, and writes the
//! file it makes, judged as any write; `-c` and `-k` keep the file, and
//! `zstd`, `lz4`, `lzop` and `brotli` keep it unless told not to. The same
//! lines inside the workspace stay safe.
//!
//! The lines and their answers are in `tests/cases/compressors.cases`.

mod common;

use common::{assert_linear, filled, posix};
use milo_guards_shell::{classify, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("compressors");
}

/// The file written into a folder only known when it runs keeps the folder
/// in what a prompt shows, not only its own name.
#[test]
fn a_folder_only_known_when_it_runs_stays_in_the_target() {
    let assessment = classify(
        "zstd --output-dir-flat \"$D\" src/a",
        Shell::Posix,
        &posix(),
    );
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("\"$D\"/a.zst")
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_files_and_options_are_read_in_linear_time() {
    for (what, start, part) in [
        ("gzip ~/a ~/b …", "gzip", " ~/a"),
        ("gzip -d ~/x.gz ~/y.gz …", "gzip -d", " ~/x.gz ~/y.tgz"),
        ("zstd -S -o …", "zstd --rm", " -S x -o ~/o -D d ~/x"),
        ("lz4 \"-$L\" …", "lz4", " \"-$L\" ~/a"),
        ("xz --files=l …", "xz", " --files=l -k -T 4"),
    ] {
        assert_linear(what, Shell::Posix, &posix(), |size| {
            format!("{start}{}", filled(part, size, start.len()))
        });
    }
}
