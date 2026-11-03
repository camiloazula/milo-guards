//! What the file calls of inline code do to their paths: the target of
//! `rename` and `replace`, file calls that were not listed (`io.FileIO`,
//! `Bun.file().unlink()`), a read with a flag that writes, the `fs` stream
//! classes, `fileinput` in place, pathlib's move and copy methods, an `open`
//! whose argument can be a mode, copying permission bits, and
//! `argparse.FileType`.
//!
//! The lines and their answers are in `tests/cases/inline_files.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_files");
}
