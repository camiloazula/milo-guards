//! A tracer, a recorder or a timer that writes its own output to a file,
//! named by an option or an operand beside the command it runs (`strace -o`,
//! `ltrace -o`, `script FILE`, `time -o`), writes that file as a redirect
//! does: it is judged by where it lands, and a file only known when it runs
//! is not known. `strace -o '|cmd'` pipes its output to a command, which is
//! read as a shell line.
//!
//! The lines and their answers are in `tests/cases/wrapper_output.cases`.

mod common;

use common::{assert_linear, posix};
use milo_guards_shell::Shell;

#[test]
fn every_case_holds() {
    common::cases::check("wrapper_output");
}

/// Distinct options `option`, each naming a file of its own, in
/// about `size` bytes.
fn distinct(option: &str, size: usize) -> String {
    let mut words = String::new();
    for at in 0.. {
        let word = format!("{option} a{at} ");
        if words.len() + word.len() > size - 40 {
            break;
        }
        words.push_str(&word);
    }
    words
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_files_a_wrapper_names_are_told_apart_in_linear_time() {
    let (shell, paths) = (Shell::Posix, posix());
    // `script` reads its options both ways `-F` reads, and keeps each file
    // once, by a set of those it has, not a pass over them all.
    assert_linear("script -c ls -O a0 -O a1 …", shell, &paths, |size| {
        format!("script -c ls {}", distinct("-O", size))
    });
    assert_linear("strace -o a0 -o a1 … ls", shell, &paths, |size| {
        format!("strace {}ls", distinct("-o", size))
    });
}
