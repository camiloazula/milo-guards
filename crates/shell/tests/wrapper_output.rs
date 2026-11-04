//! A tracer, a recorder or a timer that writes its own output to a file,
//! named by an option or an operand beside the command it runs (`strace -o`,
//! `ltrace -o`, `script FILE`, `time -o`), writes that file as a redirect
//! does: it is judged by where it lands, and a file only known when it runs
//! is not known. `strace -o '|cmd'` pipes its output to a command, which is
//! read as a shell line.
//!
//! The lines and their answers are in `tests/cases/wrapper_output.cases`;
//! the time many files a wrapper names take is in `tests/timing.rs`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("wrapper_output");
}
