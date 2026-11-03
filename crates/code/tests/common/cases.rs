//! The code reader's case files: what the words of a case mean here, and the
//! runner that checks every case of a file. The format is in CONTRIBUTING.md;
//! the reading of it is shared with the guards (see [`format`]).
//!
//! A case is `WHAT ANSWER... | CODE`:
//!
//! - `WHAT` is `python` or `javascript` (code in that language), `python2`
//!   (Python code a Python 2 interpreter runs) or `module` (a module
//!   specifier, as `import` and `require` are given);
//! - the answer is one or more fields: `acts="..."` (the acts `read` finds,
//!   as `common::shown` spells them; `acts=""` is none) and
//!   `understand=yes|importing|no` (what `understand` says: understood, and
//!   understood though it imports when it runs, or not understood) for
//!   `python` and `javascript`; `understand=` alone for `python2`
//!   (`understand_python2`); `other_encoding=yes|no`
//!   (`declares_other_encoding`) for `python`; `data_url=yes|no`
//!   (`is_data_url`) and `foreign=yes|no` (`is_foreign_module`) for
//!   `module`.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test reads its case files from the crate's `tests/cases`"
)]

#[path = "../../../core/tests/common/cases.rs"]
pub mod format;

use std::collections::{BTreeMap, HashSet};

use format::{Record, Word};
use milo_guards_code::Language::{JavaScript, Python};
use milo_guards_code::{
    declares_other_encoding, is_data_url, is_foreign_module, read, understand, understand_python2,
    Understanding,
};

use super::shown;

/// What a case reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum What {
    Python,
    JavaScript,
    Python2,
    Module,
}

impl What {
    /// The fields a case of this kind can hold.
    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Python => &["acts", "understand", "other_encoding"],
            Self::JavaScript => &["acts", "understand"],
            Self::Python2 => &["understand"],
            Self::Module => &["data_url", "foreign"],
        }
    }

    /// The word a case file writes it with.
    pub fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::Python2 => "python2",
            Self::Module => "module",
        }
    }
}

/// One case of a case file.
#[derive(Debug, Clone)]
pub struct Case {
    /// Where it is: `tests/cases/NAME.cases:LINE`.
    pub at: String,
    pub what: What,
    /// Each question asked, and the answer it must give, as a case writes it.
    pub expect: BTreeMap<&'static str, String>,
    /// The code or the specifier, decoded.
    pub code: String,
}

impl Case {
    /// The answer as a case file writes it, its fields in a fixed order.
    pub fn spelled(&self) -> String {
        self.expect
            .iter()
            .map(|(field, value)| format!("{field}={value:?}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// An understanding as a case file writes it.
pub fn understanding(understanding: Understanding) -> &'static str {
    match understanding {
        Understanding::Understood { imports: false } => "yes",
        Understanding::Understood { imports: true } => "importing",
        Understanding::NotUnderstood => "no",
    }
}

/// What `field` answers for `case`, as a case file writes it.
pub fn answer(case: &Case, field: &str) -> String {
    let yes = |yes: bool| if yes { "yes" } else { "no" }.to_string();
    let code = case.code.as_str();
    let language = match case.what {
        What::JavaScript => JavaScript,
        _ => Python,
    };
    match (case.what, field) {
        (What::Python | What::JavaScript, "acts") => shown(&read(language, code).acts),
        (What::Python | What::JavaScript, "understand") => {
            understanding(understand(language, code)).to_string()
        }
        (What::Python2, "understand") => understanding(understand_python2(code)).to_string(),
        (What::Python, "other_encoding") => yes(declares_other_encoding(code)),
        (What::Module, "data_url") => yes(is_data_url(code)),
        (What::Module, "foreign") => yes(is_foreign_module(code)),
        (what, other) => format!("no question `{other}` of `{}`", what.name()),
    }
}

/// Every case of the file named `name`, checked: a file that is not there,
/// a line that is refused and a case that is wrong fail the test, each named
/// by its file and line.
pub fn check(name: &str) {
    let cases = load(name);
    let wrong: Vec<String> = cases.iter().flat_map(wrong).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} cases wrong:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}

/// The cases of the file named `name`; every refusal fails the test.
pub fn load(name: &str) -> Vec<Case> {
    let read = format::read(name).and_then(|records| cases(&records));
    let refused = read.as_ref().err().cloned().unwrap_or_default();
    assert!(
        refused.is_empty(),
        "{} lines refused:\n{}",
        refused.len(),
        refused.join("\n")
    );
    read.unwrap_or_default()
}

/// The cases of `source`, the text of the file `file`, or every refusal.
pub fn parse(file: &str, source: &str) -> Result<Vec<Case>, Vec<String>> {
    format::parse(file, source).and_then(|records| cases(&records))
}

/// The key a repeated case shares with the first: what it reads, the code
/// and the answer.
pub fn key(case: &Case) -> (What, String, BTreeMap<&'static str, String>) {
    (case.what, case.code.clone(), case.expect.clone())
}

/// One line for a case: where it is, what it reads, the answer and the code
/// as Rust writes a string, tab separated.
pub fn dumped(case: &Case) -> String {
    format!(
        "{}\t{}\t{}\t{:?}",
        case.at,
        case.what.name(),
        case.spelled(),
        case.code
    )
}

/// What is wrong with `case`: one message for each answer it misses.
pub fn wrong(case: &Case) -> Vec<String> {
    case.expect
        .iter()
        .filter_map(|(field, want)| {
            let got = answer(case, field);
            (got != *want).then(|| {
                format!(
                    "{}: expected {field}={want:?}: {:?}\n    got {got:?}",
                    case.at, case.code
                )
            })
        })
        .collect()
}

/// The cases of `records`, or every refusal: an unknown word or field, a
/// malformed answer, a repeated case.
fn cases(records: &[Record]) -> Result<Vec<Case>, Vec<String>> {
    let mut cases = Vec::new();
    let mut refused = Vec::new();
    for record in records {
        let result = match &record.text {
            None => Err(vec!["a case with no `| CODE`".to_string()]),
            Some(code) => case(&record.words).map(|(what, expect)| {
                cases.push(Case {
                    at: record.at.clone(),
                    what,
                    expect,
                    code: code.clone(),
                });
            }),
        };
        if let Err(whys) = result {
            refused.extend(whys.into_iter().map(|why| format!("{}: {why}", record.at)));
        }
    }
    refused.extend(format::repeated(
        cases.iter().map(|case| (case.at.clone(), key(case))),
    ));
    if refused.is_empty() {
        Ok(cases)
    } else {
        Err(refused)
    }
}

type Answer = (What, BTreeMap<&'static str, String>);

/// What a case reads and the answer of its words.
fn case(words: &[Word]) -> Result<Answer, Vec<String>> {
    let what = match words.first() {
        Some(Word::Bare(word)) => match word.as_str() {
            "python" => What::Python,
            "javascript" => What::JavaScript,
            "python2" => What::Python2,
            "module" => What::Module,
            other => return Err(vec![format!("an unknown kind of code `{other}`")]),
        },
        _ => return Err(vec!["a case starts with what it reads".to_string()]),
    };
    let mut expect = BTreeMap::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut refused = Vec::new();
    for word in &words[1..] {
        let (name, value) = match word {
            Word::Bare(name) => {
                refused.push(format!("an unknown word `{name}`"));
                continue;
            }
            Word::Field(name, value) => (name.as_str(), value.as_str()),
        };
        if !seen.insert(name) {
            refused.push(format!("`{name}` twice"));
            continue;
        }
        let Some(field) = what.fields().iter().find(|field| **field == name) else {
            refused.push(format!("an unknown field `{name}` for `{}`", what.name()));
            continue;
        };
        let fits = match *field {
            "acts" => true,
            "understand" => ["yes", "importing", "no"].contains(&value),
            _ => value == "yes" || value == "no",
        };
        if fits {
            expect.insert(*field, value.to_string());
        } else {
            refused.push(format!("`{value}` is no answer `{field}` gives"));
        }
    }
    if refused.is_empty() && expect.is_empty() {
        refused.push(format!(
            "a case with no answer: one of `{}`",
            what.fields().join("`, `")
        ));
    }
    if refused.is_empty() {
        Ok((what, expect))
    } else {
        Err(refused)
    }
}
