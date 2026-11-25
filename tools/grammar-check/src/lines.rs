//! The lines compared: every POSIX and PowerShell line of the case files,
//! and a set generated from their words.
//!
//! The case files are read with [`crate::cases`], so a line is the line its
//! case holds, escapes decoded. cmd's lines are left out: `cmd.exe` has no
//! way to parse a line without running it.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the tool reads the case files from the repository"
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::cases::{self, Record};

/// Which grammar a line is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// `sh`, `bash`, `zsh`: the guard's POSIX grammar, held to bash.
    Posix,
    /// PowerShell: the guard's PowerShell grammar.
    PowerShell,
}

/// A line to compare, once, with every place it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Its grammar.
    pub family: Family,
    /// The line, as the shell is given it.
    pub text: String,
    /// Where it is: `crates/shell/tests/cases/posix.cases:12`, or
    /// `generated`.
    pub from: Vec<String>,
}

impl Line {
    /// Whether it is a line of the generated set, and of no case file.
    pub fn generated(&self) -> bool {
        self.from == ["generated"]
    }
}

/// Every POSIX and PowerShell line of the case files in `folders` (their
/// `*.cases`, by name), each once, in order of family and text; the case
/// files that are refused, each line named, when any is.
pub fn from_cases(root: &Path, folders: &[&Path]) -> Result<Vec<Line>, Vec<String>> {
    let mut found: BTreeMap<(Family, String), Vec<String>> = BTreeMap::new();
    let mut refused = Vec::new();
    for folder in folders {
        let mut names: Vec<_> = fs::read_dir(folder)
            .map_err(|e| vec![format!("cannot list {}: {e}", folder.display())])?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "cases"))
            .collect();
        names.sort();
        for path in names {
            let shown = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let source =
                fs::read_to_string(&path).map_err(|e| vec![format!("cannot read {shown}: {e}")])?;
            match cases::parse(&shown, &source) {
                Ok(records) => {
                    for (family, text, at) in records.into_iter().filter_map(of_record) {
                        found.entry((family, text)).or_default().push(at);
                    }
                }
                Err(why) => refused.extend(why),
            }
        }
    }
    if !refused.is_empty() {
        return Err(refused);
    }
    Ok(found
        .into_iter()
        .map(|((family, text), from)| Line { family, text, from })
        .collect())
}

/// The family, line and place of a record that is a POSIX or PowerShell
/// case.
fn of_record(record: Record) -> Option<(Family, String, String)> {
    let (kind, _) = cases::head(&record.words)?;
    let family = match kind {
        "posix" => Family::Posix,
        "powershell" => Family::PowerShell,
        _ => return None,
    };
    Some((family, record.text?, record.at))
}

/// The seed of the generated set: fixed, so every run makes the same lines.
const SEED: u64 = 0x5EED_5EED_5EED_5EED;

/// The most words a generated line takes from the case files.
const MOST_WORDS: usize = 6;

/// A word longer than this is not taken: the set is of short lines.
const LONGEST_WORD: usize = 32;

/// `count` lines of each family, made from the words of `lines` (split at
/// white space, each word once) joined by spaces and by the operators that
/// end or join a command, from a fixed seed: the same lines on every run and
/// every machine for the same case files. None is one of `lines`, and each
/// is made once.
///
/// Each generated line takes the words that rank first for it, by a hash of
/// the line's number and the word, not by the word's place in a list: a word
/// added to the case files or taken out changes only the few lines it ranks
/// first for, not the whole set, so the known list does not churn with every
/// new case.
pub fn generated(lines: &[Line], count: usize) -> Vec<Line> {
    let mut out = Vec::new();
    for (family, joints) in [
        (
            Family::Posix,
            &[" ", " ", " ", " ", "; ", " && ", " || ", " | ", " & ", "\n"][..],
        ),
        (
            Family::PowerShell,
            &[" ", " ", " ", " ", "; ", " && ", " || ", " | ", "\n"][..],
        ),
    ] {
        let mut words: Vec<&str> = lines
            .iter()
            .filter(|line| line.family == family)
            .flat_map(|line| line.text.split_whitespace())
            .filter(|word| word.len() <= LONGEST_WORD)
            .collect();
        words.sort_unstable();
        words.dedup();
        if words.is_empty() {
            continue;
        }
        let hashed: Vec<(u64, &str)> = words.iter().map(|word| (fnv(word), *word)).collect();
        let known: std::collections::HashSet<&str> = lines
            .iter()
            .filter(|line| line.family == family)
            .map(|line| line.text.as_str())
            .collect();
        let mut made = std::collections::BTreeSet::new();
        // Bounded: a set of few words may not make `count` different lines.
        for number in 0..count.saturating_mul(4) as u64 {
            if made.len() == count {
                break;
            }
            let seed = mix(SEED ^ mix(number));
            let many = 1 + below(mix(seed), MOST_WORDS);
            // The `many` words of the smallest rank for this line, in it.
            let mut first: Vec<(u64, &str)> = Vec::with_capacity(many + 1);
            for &(hash, word) in &hashed {
                let rank = mix(seed ^ hash);
                if first.len() < many || first.last().is_some_and(|last| rank < last.0) {
                    let at = first.partition_point(|taken| taken.0 < rank);
                    first.insert(at, (rank, word));
                    first.truncate(many);
                }
            }
            let mut text = String::new();
            for (index, (_, word)) in first.iter().enumerate() {
                if index > 0 {
                    let joint = mix(seed.wrapping_add(index as u64));
                    text.push_str(joints[below(joint, joints.len())]);
                }
                text.push_str(word);
            }
            if !known.contains(text.as_str()) {
                made.insert(text);
            }
        }
        out.extend(made.into_iter().map(|text| Line {
            family,
            text,
            from: vec!["generated".to_string()],
        }));
    }
    out
}

/// The `SplitMix64` finaliser: the same number for the same input on every
/// machine.
fn mix(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// FNV-1a of `text`'s bytes.
fn fnv(text: &str) -> u64 {
    text.bytes().fold(0xCBF2_9CE4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01B3)
    })
}

/// `value` brought below `bound`, which is not zero.
fn below(value: u64, bound: usize) -> usize {
    let bound = u64::try_from(bound).unwrap_or(u64::MAX).max(1);
    usize::try_from(value % bound).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(family: Family, text: &str) -> Line {
        Line {
            family,
            text: text.to_string(),
            from: vec!["here".to_string()],
        }
    }

    #[test]
    fn the_generated_set_is_the_same_every_time_and_bounded() {
        let lines = [
            line(Family::Posix, "echo a b"),
            line(Family::Posix, "ls -la"),
            line(Family::PowerShell, "Get-Item x"),
        ];
        let first = generated(&lines, 50);
        assert_eq!(first, generated(&lines, 50));
        let posix = first.iter().filter(|l| l.family == Family::Posix).count();
        let powershell = first.len() - posix;
        assert_eq!(posix, 50);
        assert!(powershell <= 50 && powershell > 0);
        assert!(first.iter().all(|l| l.from == ["generated"]));
        assert!(first
            .iter()
            .all(|l| !["echo a b", "ls -la", "Get-Item x"].contains(&l.text.as_str())));
        for made in &first {
            let words = made.text.split_whitespace().count();
            assert!((1..=MOST_WORDS * 2).contains(&words), "{:?}", made.text);
        }
        assert!(generated(&lines, 0).is_empty());
        assert!(generated(&[], 10).is_empty());
    }

    #[test]
    fn a_new_word_changes_few_generated_lines() {
        let words: Vec<String> = (0..400).map(|n| format!("w{n}")).collect();
        let before = [line(Family::Posix, &words.join(" "))];
        let after = [line(Family::Posix, &format!("{} added", words.join(" ")))];
        let old: std::collections::BTreeSet<String> = generated(&before, 200)
            .into_iter()
            .map(|l| l.text)
            .collect();
        let new: std::collections::BTreeSet<String> =
            generated(&after, 200).into_iter().map(|l| l.text).collect();
        let changed = new.difference(&old).count();
        assert!(changed < 20, "{changed} of 200 lines changed for one word");
    }

    #[test]
    fn the_hashes_are_the_same_on_every_machine() {
        assert_eq!(mix(0), 0xE220_A839_7B1D_CDAF);
        assert_eq!(fnv(""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv("a"), 0xAF63_DC4C_8601_EC8C);
        assert!(below(7, 3) < 3);
        assert_eq!(below(7, 0), 0);
    }
}
