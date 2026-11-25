//! The known differences: `tools/grammar-check/known.cases`, read with the
//! tool's reader of the case-file format.
//!
//! An entry is `SHELL KIND [versions=LIST] reason="..." | LINE`: the shell
//! (`bash` or `pwsh`), the kind of difference (`grammar_rejects` or
//! `shell_rejects`), the versions of that shell it holds for, why it is
//! known and left, and the line. The versions are a comma-separated list,
//! each a version (`3.2`, every 3.2) or a range (`4.0-5.1`, either end left
//! open: `-3.2`, `5.0-`), so an entry seen on bash 3.2 and on 5.2 says
//! `versions=3.2,5.2` and claims nothing of 4.x; without it, every version. A
//! version is matched by as many of its numbers as the item gives: `5.3`
//! holds 5.3.9.
//! A split (both accept, the guard reads it otherwise) is never an entry: it
//! is reported privately, as SECURITY.md says. An entry no difference
//! matches, for a shell and version that ran, is stale and fails the run.

use crate::cases::{self, Word};
use crate::compare::Kind as Difference;
use crate::shells::Kind;

/// Versions, by their numbers: a list of ranges, each end, when it has one,
/// compared with as many numbers of a version as it holds; an empty list is
/// every version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versions {
    ranges: Vec<(Vec<u32>, Vec<u32>)>,
}

impl Versions {
    /// Every version.
    pub const ALL: Self = Self { ranges: Vec::new() };

    /// A comma-separated list of `VERSION`, `FROM-TO`, `FROM-` or `-TO`.
    pub fn parse(text: &str) -> Option<Self> {
        let ranges = text
            .split(',')
            .map(|item| {
                let (from, to) = item.split_once('-').unwrap_or((item, item));
                let range = (numbers(from)?, numbers(to)?);
                (!(range.0.is_empty() && range.1.is_empty())).then_some(range)
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { ranges })
    }

    /// Whether `version` (`3.2.57`) is in one of the ranges.
    pub fn holds(&self, version: &str) -> bool {
        let Some(version) = numbers(version) else {
            return false;
        };
        let cut = |bound: &[u32]| {
            version
                .iter()
                .take(bound.len())
                .copied()
                .collect::<Vec<_>>()
        };
        self.ranges.is_empty()
            || self.ranges.iter().any(|(from, to)| {
                (from.is_empty() || cut(from) >= *from) && (to.is_empty() || cut(to) <= *to)
            })
    }
}

/// The numbers of `1.2.3`; none for an empty text.
fn numbers(text: &str) -> Option<Vec<u32>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split('.').map(|part| part.parse().ok()).collect()
}

/// One known difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Where it is: `tools/grammar-check/known.cases:12`.
    pub at: String,
    /// Its shell.
    pub shell: Kind,
    /// Its kind of difference.
    pub kind: Difference,
    /// The versions it holds for.
    pub versions: Versions,
    /// Why it is known and left as it is.
    pub reason: String,
    /// The line.
    pub line: String,
}

impl Entry {
    /// Whether it is the difference `kind` of `line` under `shell` at
    /// `version`.
    pub fn matches(&self, shell: Kind, version: &str, kind: Difference, line: &str) -> bool {
        self.shell == shell
            && self.kind == kind
            && self.line == line
            && self.versions.holds(version)
    }
}

/// The entries of `source`, the text of the known list `file`, or every
/// line that is refused.
pub fn parse(file: &str, source: &str) -> Result<Vec<Entry>, Vec<String>> {
    let records = cases::parse(file, source)?;
    let mut entries = Vec::new();
    let mut refused = Vec::new();
    for record in records {
        match entry(&record.words, record.text) {
            Ok(entry) => entries.push(Entry {
                at: record.at,
                ..entry
            }),
            Err(why) => refused.push(format!("{}: {why}", record.at)),
        }
    }
    let keys = entries.iter().map(|entry| {
        (
            entry.at.clone(),
            (
                entry.shell,
                entry.kind,
                entry.line.clone(),
                format!("{:?}", entry.versions),
            ),
        )
    });
    refused.extend(cases::repeated(keys));
    if refused.is_empty() {
        Ok(entries)
    } else {
        Err(refused)
    }
}

fn entry(words: &[Word], text: Option<String>) -> Result<Entry, String> {
    let line = text.ok_or("an entry without its `| LINE`")?;
    let mut shell = None;
    let mut kind = None;
    let mut versions = None;
    let mut reason = None;
    for word in words {
        match word {
            Word::Bare(name) if shell.is_none() => {
                shell = Some(Kind::named(name).ok_or(format!("no shell `{name}`"))?);
            }
            Word::Bare(name) if kind.is_none() => {
                kind = Some(match name.as_str() {
                    "grammar_rejects" => Difference::GrammarRejects,
                    "shell_rejects" => Difference::ShellRejects,
                    _ => {
                        return Err(format!(
                            "no kind `{name}`: an entry is `grammar_rejects` or `shell_rejects`, \
                             and a split is never kept here"
                        ))
                    }
                });
            }
            Word::Field(name, value) if name == "versions" && versions.is_none() => {
                versions = Some(Versions::parse(value).ok_or(format!("no versions `{value}`"))?);
            }
            Word::Field(name, value) if name == "reason" && reason.is_none() => {
                if value.trim().is_empty() {
                    return Err("an empty reason".to_string());
                }
                reason = Some(value.clone());
            }
            other => return Err(format!("an unknown or repeated word {other:?}")),
        }
    }
    Ok(Entry {
        at: String::new(),
        shell: shell.ok_or("an entry without its shell")?,
        kind: kind.ok_or("an entry without its kind")?,
        versions: versions.unwrap_or(Versions::ALL),
        reason: reason.ok_or("an entry without its reason")?,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_holds_the_versions_between_its_ends() {
        let old = Versions::parse("-3.2").unwrap();
        assert!(
            old.holds("3.2.57") && old.holds("3.1") && !old.holds("4.0") && !old.holds("5.2.21")
        );
        let new = Versions::parse("4.0-").unwrap();
        assert!(new.holds("5.2.21") && new.holds("4.0") && !new.holds("3.2.57"));
        let one = Versions::parse("5.9-5.9").unwrap();
        assert!(one.holds("5.9") && !one.holds("5.8.1"));
        assert!(Versions::ALL.holds("1") && !Versions::ALL.holds("x"));
        // A version is matched by as many numbers as an item gives: `5.3`
        // holds every 5.3 (5.3.9 is CI's bash), and no 5.4.
        let ci = Versions::parse("3.2,5.3").unwrap();
        assert!(ci.holds("5.3.9") && ci.holds("3.2.57") && ci.holds("5.3"));
        assert!(!ci.holds("5.4.0") && !ci.holds("5.2.21") && !ci.holds("4.4.20"));
        let two = Versions::parse("3.2,5.2").unwrap();
        assert!(two.holds("3.2.57") && two.holds("5.2.21"));
        assert!(!two.holds("4.4.20") && !two.holds("5.1.16") && !two.holds("5.3"));
        assert_eq!(Versions::parse("-"), None);
        assert_eq!(Versions::parse("3.2,"), None);
        assert_eq!(Versions::parse("a-b"), None);
    }

    #[test]
    fn an_entry_is_read_whole_or_refused() {
        let source = "# known\nbash shell_rejects versions=-3.2 reason=\"bash 3.2 has no ;& in a case\" | case x in a) ;& esac\npwsh grammar_rejects reason=r | echo a\\nb\n";
        let entries = parse("known.cases", source).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].at, "known.cases:2");
        assert!(entries[0].matches(
            Kind::Bash,
            "3.2.57",
            Difference::ShellRejects,
            "case x in a) ;& esac"
        ));
        assert!(!entries[0].matches(
            Kind::Bash,
            "5.2.21",
            Difference::ShellRejects,
            "case x in a) ;& esac"
        ));
        assert!(!entries[0].matches(
            Kind::Pwsh,
            "3.2.57",
            Difference::ShellRejects,
            "case x in a) ;& esac"
        ));
        assert!(entries[1].matches(Kind::Pwsh, "7.4", Difference::GrammarRejects, "echo a\nb"));
        for bad in [
            "bash shell_rejects | x",
            "bash split reason=r | x",
            "fish shell_rejects reason=r | x",
            "zsh shell_rejects reason=r | x",
            "bash shell_rejects reason=r",
            "bash shell_rejects reason=\"\\s\" | x",
            "bash shell_rejects versions=x reason=r | x",
            "bash shell_rejects reason=r other=1 | x",
            "bash shell_rejects reason=r reason=s | x",
            "shell_rejects reason=r | x",
            "bash reason=r | x",
            "bash shell_rejects reason=r | x\nbash shell_rejects reason=s | x",
        ] {
            assert!(parse("k", bad).is_err(), "{bad}");
        }
    }
}
