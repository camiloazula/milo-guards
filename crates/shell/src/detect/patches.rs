//! The rules about patches. `patch` changes the files its patch names, which
//! the line does not show, in the folder `-d` moves it to or the one the
//! line is in: a write into that folder, which may change a protected path
//! the folder holds. Given an original file (`patch x.c fix.diff`) or `-o`,
//! it writes that one file. A dry run writes nothing.

use super::Checker;
use crate::path::within;
use crate::unit::{may_be_option, Arg, Unit};

impl Checker<'_> {
    /// `patch`, in any shell.
    pub(super) fn patch(&mut self, unit: &Unit) {
        let shell = unit.shell;
        let read = Patch::read(&unit.args);
        if read.dry {
            return;
        }
        let scope = unit.scope();
        // `-d` moves it before it reads anything, its files and `-o` too.
        let directory = read.directory.as_ref();
        if let Some(output) = &read.output {
            if output.known() != Some("-") {
                self.write(shell, scope, &within(directory, output, shell), "writes to");
            }
            return;
        }
        if let Some(original) = read.original {
            self.write(
                shell,
                scope,
                &within(directory, &original, shell),
                "patches",
            );
            return;
        }
        // An argument only known when it runs may be `-d` and any folder.
        let folder = if may_be_option(&unit.args, shell, |_| true) {
            Arg::Unknown("the folder patch moves to".to_string())
        } else {
            directory
                .cloned()
                .unwrap_or_else(|| Arg::Known(".".to_string()))
        };
        self.write_folder(shell, scope, &folder, "patches files in");
    }
}

/// What `patch`'s arguments say, as GNU and BSD patch read them.
#[derive(Debug, Default)]
struct Patch {
    /// `--dry-run`, or BSD's `--check`: nothing is written.
    dry: bool,
    /// `-d DIR`, `--directory=DIR`: the folder it works in.
    directory: Option<Arg>,
    /// `-o FILE`, `--output=FILE`: the one file it writes.
    output: Option<Arg>,
    /// The first operand, the file it patches; a second is the patch.
    original: Option<Arg>,
}

/// Short options that take a value, joined (`-p1`, `-dsrc`) or as the next
/// argument.
const SHORT_VALUED: &str = "BDFVYdgiopruxz";

/// Long options, and whether each takes a value; GNU patch takes any
/// prefix that names one alone.
const LONG: [(&str, bool); 35] = [
    ("basename-prefix", true),
    ("batch", false),
    ("binary", false),
    ("backup", false),
    ("backup-if-mismatch", false),
    ("check", false),
    ("context", false),
    ("debug", true),
    ("directory", true),
    ("dry-run", false),
    ("ed", false),
    ("follow-symlinks", false),
    ("force", false),
    ("forward", false),
    ("fuzz", true),
    ("get", true),
    ("help", false),
    ("ifdef", true),
    ("ignore-whitespace", false),
    ("input", true),
    ("merge", false),
    ("no-backup-if-mismatch", false),
    ("normal", false),
    ("output", true),
    ("posix", false),
    ("prefix", true),
    ("quiet", false),
    ("quoting-style", true),
    ("read-only", true),
    ("reject-file", true),
    ("reject-format", true),
    ("remove-empty-files", false),
    ("reverse", false),
    ("strip", true),
    ("suffix", true),
];

impl Patch {
    fn read(args: &[Arg]) -> Self {
        let mut patch = Self::default();
        let mut operands = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some(text) = arg.known() else {
                operands.push(arg.clone());
                continue;
            };
            if text == "--" {
                operands.extend(iter.by_ref().cloned());
                break;
            }
            if let Some(long) = text.strip_prefix("--") {
                let (name, joined) = match long.split_once('=') {
                    Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
                    None => (long, None),
                };
                let Some((name, valued)) = long_option(name) else {
                    continue;
                };
                let value = if valued {
                    joined.or_else(|| iter.next().cloned())
                } else {
                    None
                };
                patch.set(name, value);
            } else if let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty())
            {
                for (at, short) in bundle.char_indices() {
                    if short == 'C' {
                        patch.set_short(short, None);
                    }
                    if SHORT_VALUED.contains(short) {
                        let rest = &bundle[at + short.len_utf8()..];
                        let value = if rest.is_empty() {
                            iter.next().cloned()
                        } else {
                            Some(Arg::Known(rest.to_string()))
                        };
                        patch.set_short(short, value);
                        break;
                    }
                }
            } else {
                operands.push(arg.clone());
            }
        }
        patch.original = operands.into_iter().next();
        patch
    }

    fn set(&mut self, name: &str, value: Option<Arg>) {
        match name {
            "dry-run" | "check" => self.dry = true,
            "directory" => self.directory = value,
            "output" => self.output = value,
            _ => {}
        }
    }

    fn set_short(&mut self, short: char, value: Option<Arg>) {
        match short {
            // BSD's `--check`; GNU patch refuses it, and runs nothing.
            'C' => self.dry = true,
            'd' => self.directory = value,
            'o' => self.output = value,
            _ => {}
        }
    }
}

/// The long option `name` names, written out or as a prefix of one alone,
/// and whether it takes a value.
fn long_option(name: &str) -> Option<(&'static str, bool)> {
    if let Some(&(full, valued)) = LONG.iter().find(|(full, _)| *full == name) {
        return Some((full, valued));
    }
    let mut prefixed = LONG.iter().filter(|(full, _)| full.starts_with(name));
    match (prefixed.next(), prefixed.next()) {
        (Some(&(full, valued)), None) if !name.is_empty() => Some((full, valued)),
        _ => None,
    }
}
