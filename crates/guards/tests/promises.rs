//! The promises each entry point keeps for any input, held in the gate: the
//! fuzz targets' own checks (`tests/common/promises.rs`, which `tools/fuzz`
//! includes), run on the text of every guard's case files changed at random
//! by a seeded generator, a few hundred inputs for each target, so every
//! change is held to them without a nightly Rust or a fuzzer. The fuzz
//! targets follow coverage into the rarer branches (`just fuzz`, and the
//! scheduled fuzz workflow); this follows none, and its count is small, so
//! the gate stays quick. What it finds is a failing test, which names the
//! target, the round and the input.

#![cfg(all(
    feature = "shell",
    feature = "file",
    feature = "url",
    feature = "secrets",
    feature = "code",
    feature = "script"
))]

mod common;

use std::path::Path;

use common::promises::{
    access_choice, check, decode, encode, language_choice, machine, Target, MACHINES,
};
use common::seeds::{self, Seed};
use milo_guards::code::Language;

/// How many inputs each target is held to: the case lines changed at
/// random. A count, not a time, so the test does the same work on every
/// machine; see the module's documentation for why it is small.
const ROUNDS: usize = 300;

/// A small deterministic generator, so a failure names its round.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).unwrap_or_default()
    }
}

/// Pieces of the syntax the guards read, put into a case's text at random:
/// quotes, brackets and operators of the shells and of Python and
/// JavaScript, escapes, the parts of a URL and of a path, a line break, a
/// control character and characters outside ASCII.
const PIECES: [&str; 48] = [
    "\"",
    "'",
    "`",
    "$(",
    ")",
    "${",
    "}",
    "(",
    "[",
    "]",
    "{",
    "|",
    "&&",
    ";",
    "&",
    ">",
    "<<EOF\n",
    "\n",
    "\\",
    "\\\\",
    "%",
    "%2f",
    "@",
    ":",
    "//",
    "/",
    "..",
    "~",
    "*",
    "?",
    "#",
    "=",
    "-",
    "--",
    "0x",
    "::",
    "\u{0}",
    "\t",
    "\r",
    "é",
    "\u{202e}",
    "\u{feff}",
    "C:\\",
    "\\\\?\\",
    "\"\"\"",
    "\\u{",
    "import os\n",
    "require('fs')",
];

/// `text` changed in one to six places at random: a piece put in, a
/// character taken out or replaced, a few characters repeated, two swapped,
/// or the text of another seed spliced in.
fn mutated(random: &mut Lcg, text: &str, other: &str) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    for _ in 0..=random.next() % 6 {
        let len = chars.len();
        let piece = PIECES[random.next() % PIECES.len()];
        let at = random.next() % (len + 1);
        match random.next() % 6 {
            0 => {
                chars.splice(at..at, piece.chars());
            }
            1 if at < len => {
                chars.remove(at);
            }
            2 if at < len => {
                chars.splice(at..=at, piece.chars());
            }
            3 if at < len => {
                let end = (at + 1 + random.next() % 8).min(len);
                let again: Vec<char> = chars[at..end].to_vec();
                chars.splice(at..at, again);
            }
            4 if len > 1 => chars.swap(at % len, random.next() % len),
            5 => {
                let spliced: Vec<char> = other.chars().collect();
                let from = random.next() % (spliced.len() + 1);
                chars.splice(at.., spliced[from..].iter().copied());
            }
            _ => {}
        }
    }
    chars.into_iter().collect()
}

/// The repository's root, two folders above this crate.
fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn every_target_keeps_its_promises_on_case_lines_changed_at_random() -> Result<(), String> {
    let seeds = seeds::read(root())?;
    for (number, target) in Target::ALL.into_iter().enumerate() {
        let mine: Vec<&Seed> = seeds.iter().filter(|seed| seed.target == target).collect();
        assert!(
            mine.len() > 10,
            "{}: only {} seeds in the case files",
            target.name(),
            mine.len()
        );
        let mut random = Lcg(7 + number as u64);
        for round in 0..ROUNDS {
            let seed = mine[random.next() % mine.len()];
            let other = mine[random.next() % mine.len()];
            // One in four as written, and now and then on another machine.
            let text = if random.next().is_multiple_of(4) {
                seed.text.clone()
            } else {
                mutated(&mut random, &seed.text, &other.text)
            };
            let choice = if random.next().is_multiple_of(5) {
                u8::try_from(random.next() % 256).unwrap_or_default()
            } else {
                seed.choice
            };
            let data = encode(choice, &text);
            let held = std::panic::catch_unwind(|| check(target, &data));
            assert!(
                held.is_ok(),
                "{} round {round} breaks a promise: choice {choice}, {text:?}",
                target.name()
            );
        }
    }
    Ok(())
}

#[test]
fn every_case_file_gives_each_target_its_seeds() -> Result<(), String> {
    let seeds = seeds::read(root())?;
    for target in Target::ALL {
        let count = seeds.iter().filter(|seed| seed.target == target).count();
        assert!(count > 10, "{}: {count} seeds", target.name());
    }
    // A case on a test machine is a seed on that machine (the Mac is the
    // second), and a write is a write.
    let has = |target: Target, choice: u8| {
        seeds
            .iter()
            .any(|seed| seed.target == target && seed.choice == choice)
    };
    assert!(has(Target::ShellPosix, 1), "a POSIX line on the Mac");
    assert!(has(Target::File, access_choice(true, 0)), "a write");
    assert!(
        has(Target::File, access_choice(false, 1)),
        "a read on the Mac"
    );
    assert!(
        has(Target::Code, language_choice(Language::JavaScript, 0)),
        "JavaScript"
    );
    assert!(
        has(Target::Code, language_choice(Language::Ruby, 0)),
        "Ruby"
    );
    assert!(
        has(Target::Script, language_choice(Language::Ruby, 0)),
        "Ruby in a script"
    );
    Ok(())
}

/// Code that names a path of the Windows drives, on the machine that mounts
/// them: the script guard judges it again on the paths as spelled (see
/// `Paths::also_judged_on`), where the key is no key and the code is not
/// read whole, so its answer holds every finding of its own work and more.
#[test]
fn script_code_on_a_machine_that_mounts_drives_keeps_its_promises() {
    let mounts = 5;
    for (language, code) in [
        (
            Language::Python,
            "import os\nos.remove('/mnt/c/Users/me/.ssh/id_rsa')",
        ),
        (
            Language::Python,
            "print(open('/mnt/c/Users/me/.ssh/id_rsa').read())",
        ),
        (
            Language::Ruby,
            "print(open('/mnt/c/Users/me/.ssh/id_rsa').read())",
        ),
        (Language::Ruby, "File.delete('/mnt/c/Users/me/.ssh/id_rsa')"),
        (
            Language::JavaScript,
            "require('fs').readFileSync('/mnt/c/Users/me/.ssh/id_rsa')",
        ),
    ] {
        let data = encode(language_choice(language, mounts), code);
        assert!(
            std::panic::catch_unwind(|| check(Target::Script, &data)).is_ok(),
            "{language:?} {code:?}"
        );
    }
}

#[test]
fn an_input_is_read_as_it_was_written() {
    for choice in [0, 1, 7, 255] {
        for text in ["", "rm -rf ~", "é\u{0}\n", "C:\\Users"] {
            let data = encode(choice, text);
            let (read, back) = decode(&data);
            assert_eq!((read, back.as_ref()), (choice, text));
        }
    }
    // No byte is refused: what is not UTF-8 is replaced, and an empty
    // input is the empty text.
    assert_eq!(decode(&[3, 0xff, b'a']), (3, "\u{fffd}a".into()));
    assert_eq!(decode(&[]), (0, "".into()));
    // Every choice names a machine, and each target a name of its own.
    for index in 0..=u8::MAX {
        let _ = machine(index);
    }
    assert_eq!(
        format!("{:?}", machine(MACHINES)),
        format!("{:?}", machine(0))
    );
    for target in Target::ALL {
        assert_eq!(Target::named(target.name()), Some(target));
    }
    assert_eq!(Target::named("nothing"), None);
}
