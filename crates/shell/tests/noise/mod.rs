//! What the random-line tests of `robust.rs`, `limits.rs` and `timing.rs`
//! share: a seeded generator, the pieces of syntax they join, and the shells.

#![allow(dead_code, unreachable_pub)]

use milo_guards_core::testing::{posix, windows};
use milo_guards_shell::Shell;

/// A small deterministic generator, so a failure names its seed.
pub struct Lcg(pub u64);

impl Lcg {
    pub fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as usize
    }
}

/// More syntax than `PIECES`: quotes and substitutions left open, here-
/// documents with no end, here-strings, control and Unicode edge characters,
/// PowerShell and cmd metacharacters, the keywords that open a block, and
/// a few plain words.
pub const WIDE_PIECES: [&str; 76] = [
    // Left open.
    "'",
    "\"",
    "`",
    "$(",
    "$((",
    "${",
    "$'",
    "@(",
    "@{",
    "<(",
    ">(",
    "(",
    "((",
    "{",
    "[",
    "[[",
    // Closing with nothing to close.
    ")",
    "))",
    "}",
    "]",
    "]]",
    ";;",
    "esac",
    "fi",
    "done",
    "'@",
    "\"@",
    // Here-documents and here-strings, with no end.
    "<<EOF",
    "<<-EOF",
    "<<'EOF'",
    "<<<",
    "@'",
    "@\"",
    "<#",
    // Blocks that open.
    "if",
    "then",
    "case x in",
    "for x in",
    "while",
    "function f {",
    "f() {",
    "ForEach-Object {",
    "|%",
    // Operators, alone or doubled.
    "|",
    "||",
    "&",
    "&&",
    ";",
    ">",
    ">>",
    "<",
    "2>&1",
    "\n",
    "\r\n",
    // The edges of text.
    "\0",
    "\\",
    "\u{feff}",
    "\u{fffd}",
    "\u{2028}",
    "é",
    // Variables and escapes of the other shells.
    "%X%",
    "%~dp0",
    "!X!",
    "^",
    "^&",
    "$_",
    "$env:X",
    // What they run.
    "rm -rf /",
    "Remove-Item -Recurse",
    "cmd /c",
    "powershell -c",
    "sh -c",
    "Invoke-Expression",
    "echo",
    "ls",
    "pwd",
];

pub const SHELLS: [Shell; 3] = [Shell::Posix, Shell::PowerShell, Shell::Cmd];

pub fn paths_for(shell: Shell) -> milo_guards_shell::Paths {
    if shell == Shell::Posix {
        posix()
    } else {
        windows()
    }
}

/// A line cut where it may split a character, with bytes no text holds
/// joined on, read back the way `String::from_utf8_lossy` does.
pub fn lossy(line: &str, random: &mut Lcg) -> String {
    let mut bytes = line.as_bytes().to_vec();
    if !bytes.is_empty() && random.next().is_multiple_of(2) {
        bytes.truncate(random.next() % bytes.len());
    }
    for _ in 0..random.next() % 3 {
        bytes.push([0xff, 0xfe, 0xc3, 0xe2, 0x80, 0xf0, 0x00][random.next() % 7]);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The wide noise `robust.rs` judges and `timing.rs` times: 4,500 lines of
/// up to 32 of [`WIDE_PIECES`], joined with or without spaces, a third of
/// them cut or with stray bytes joined on ([`lossy`]).
pub fn wide_lines() -> Vec<String> {
    let mut random = Lcg(0x5eed);
    (0..4_500)
        .map(|number| {
            let length = random.next() % 32;
            let pieces: Vec<&str> = (0..length)
                .map(|_| WIDE_PIECES[random.next() % WIDE_PIECES.len()])
                .collect();
            let line = pieces.join(if random.next().is_multiple_of(3) {
                ""
            } else {
                " "
            });
            if number % 3 == 0 {
                lossy(&line, &mut random)
            } else {
                line
            }
        })
        .collect()
}
