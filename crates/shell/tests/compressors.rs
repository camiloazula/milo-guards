//! Compressors: `gzip x` writes `x.gz` and deletes `x`, so a compressor run
//! on a file deletes it, judged as `rm` judges its operands, and writes the
//! file it makes, judged as any write; `-c` and `-k` keep the file, and
//! `zstd`, `lz4`, `lzop` and `brotli` keep it unless told not to. The same
//! lines inside the workspace stay safe.
//!
//! The lines and their answers are in `tests/cases/compressors.cases`; the
//! time of many files and options is in `tests/timing.rs`.

mod common;

use common::posix;
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
