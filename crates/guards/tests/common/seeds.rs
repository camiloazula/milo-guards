//! The text of every case of the repository, each as an input of the target
//! of its guard: what the fuzz targets start from (their seed corpus, which
//! `tools/fuzz` writes from this), and what the gate's `tests/promises.rs`
//! changes at random. A case file is read with the format every guard shares
//! (`crates/core/tests/common/cases.rs`); its first word says the target and
//! how the text is judged, the machine a case names after its `@` is the
//! nearest of [`super::promises::machine`]'s, and a case that names none is
//! judged on the machine its runner judges it on.
//!
//! The fuzz package includes this file by its path, beside
//! [`super::promises`].

#![allow(
    dead_code,
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the case files are read from the repository, which no guard may do"
)]

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::duplicate_mod,
    reason = "the reader of the case files, written for the tests, which the shell \
              guard's helpers (`super::promises`) include too"
)]
#[path = "../../../core/tests/common/cases.rs"]
mod format;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::promises::{access_choice, encode, language_choice, Target};
use format::Word;
use milo_guards::code::Language;

/// The test machine `posix` of [`super::promises::machine`].
const POSIX: u8 = 0;
/// The test machine `macos`.
const MACOS: u8 = 1;
/// The test machine `windows`.
const WINDOWS: u8 = 2;

/// The crates whose case files are read, by folder under `crates/`.
pub const CRATES: [&str; 8] = [
    "core", "code", "shell", "file", "url", "secrets", "script", "guards",
];

/// One case's text, as an input of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    /// The target it is an input of.
    pub target: Target,
    /// The first byte of the input: how the text is judged.
    pub choice: u8,
    /// The text.
    pub text: String,
}

impl Seed {
    /// The input, as [`super::promises::decode`] reads it.
    pub fn bytes(&self) -> Vec<u8> {
        encode(self.choice, &self.text)
    }
}

/// The machine of [`super::promises::machine`] nearest the one `name`
/// names: a test machine by its name, or a machine a `paths` line declared,
/// by the one it starts from or by its home; `default` for none.
fn machine_named(name: Option<&str>, declared: &HashMap<String, u8>, default: u8) -> u8 {
    match name {
        None => default,
        Some("posix") => POSIX,
        Some("macos") => MACOS,
        Some("windows") => WINDOWS,
        Some(other) => declared.get(other).copied().unwrap_or(default),
    }
}

/// The machine a `paths` line declares, as the nearest test machine.
fn declared_machine(words: &[Word], declared: &HashMap<String, u8>) -> Option<(String, u8)> {
    let declaration = format::declaration(words).ok()?;
    let index = match (&declaration.base, &declaration.home) {
        (Some(base), _) => machine_named(Some(base), declared, POSIX),
        (None, Some(home)) => {
            let home = home.to_string_lossy();
            if home.as_bytes().get(1) == Some(&b':') || home.starts_with('\\') {
                WINDOWS
            } else if home.starts_with("/Users/") {
                MACOS
            } else {
                POSIX
            }
        }
        (None, None) => POSIX,
    };
    Some((declaration.name, index))
}

/// The seed of a case of the crate `folder`, with the words `words` and the
/// text `text`, if its target is one of the fuzz targets'.
fn seed(folder: &str, words: &[Word], text: &str, declared: &HashMap<String, u8>) -> Option<Seed> {
    let Some(Word::Bare(first)) = words.first() else {
        // A case of the URL guard or the secrets guard that names no paths
        // starts with its answer.
        return match folder {
            "url" => Some((Target::Url, POSIX)),
            "secrets" => Some((Target::Secrets, 0)),
            _ => None,
        }
        .map(|(target, choice)| Seed {
            target,
            choice,
            text: text.to_string(),
        });
    };
    let (kind, at) = match first.split_once('@') {
        Some((kind, at)) => (kind, Some(at)),
        None => (first.as_str(), None),
    };
    let (target, choice) = match (folder, kind) {
        ("shell" | "guards", "posix") => (Target::ShellPosix, machine_named(at, declared, POSIX)),
        ("shell" | "guards", "powershell") => (
            Target::ShellPowerShell,
            machine_named(at, declared, WINDOWS),
        ),
        ("shell" | "guards", "cmd") => (Target::ShellCmd, machine_named(at, declared, WINDOWS)),
        ("file", "read" | "write") => (
            Target::File,
            access_choice(kind == "write", machine_named(at, declared, POSIX)),
        ),
        // A path of the path model, read through the file API on a machine
        // of its flavour.
        ("core", "posix") => (
            Target::File,
            access_choice(false, machine_named(at, declared, POSIX)),
        ),
        ("core", "windows") => (
            Target::File,
            access_choice(false, machine_named(at, declared, WINDOWS)),
        ),
        ("url", "address") => (Target::UrlAddress, 0),
        ("url", "") => (Target::Url, machine_named(at, declared, POSIX)),
        // `safe`, the one answer that is a bare word.
        ("url", _) => (Target::Url, POSIX),
        ("secrets", _) => (Target::Secrets, 0),
        ("code", "python" | "python2") => (Target::Code, language_choice(Language::Python, 0)),
        ("code", "javascript") => (Target::Code, language_choice(Language::JavaScript, 0)),
        ("code", "ruby") => (Target::Code, language_choice(Language::Ruby, 0)),
        ("script", "python") => (
            Target::Script,
            language_choice(Language::Python, machine_named(at, declared, POSIX)),
        ),
        ("script", "javascript") => (
            Target::Script,
            language_choice(Language::JavaScript, machine_named(at, declared, POSIX)),
        ),
        ("script", "ruby") => (
            Target::Script,
            language_choice(Language::Ruby, machine_named(at, declared, POSIX)),
        ),
        _ => return None,
    };
    Some(Seed {
        target,
        choice,
        text: text.to_string(),
    })
}

/// Every case of the repository at `root` as a seed, in the order the case
/// files are named and read, or why a file could not be read.
pub fn read(root: &Path) -> Result<Vec<Seed>, String> {
    let mut found = Vec::new();
    for folder in CRATES {
        let cases = root.join("crates").join(folder).join("tests/cases");
        let entries =
            fs::read_dir(&cases).map_err(|e| format!("cannot list {}: {e}", cases.display()))?;
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "cases"))
            .collect();
        files.sort();
        for file in files {
            let shown = file.display().to_string();
            let source =
                fs::read_to_string(&file).map_err(|e| format!("cannot read {shown}: {e}"))?;
            let records = format::parse(&shown, &source).map_err(|refused| refused.join("\n"))?;
            let mut declared = HashMap::new();
            for record in records {
                match &record.text {
                    Some(text) => found.extend(seed(folder, &record.words, text, &declared)),
                    None => {
                        if let [Word::Bare(paths), rest @ ..] = record.words.as_slice() {
                            if let Some((name, index)) = (paths == "paths")
                                .then(|| declared_machine(rest, &declared))
                                .flatten()
                            {
                                declared.insert(name, index);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(found)
}
