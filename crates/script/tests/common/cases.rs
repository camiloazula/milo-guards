//! The script guard's case files: what the words of a case mean here, and
//! the runner that checks every case of a file. The format is in
//! CONTRIBUTING.md; the reading of it is shared with the other guards (see
//! [`format`]).
//!
//! A case is `LANGUAGE[@PATHS] ANSWER... | CODE`:
//!
//! - `LANGUAGE` is `python` or `javascript` (read by [`format::head`]);
//! - `PATHS` names the machine the code is judged on: `posix`, `macos`,
//!   `windows`, or a `paths` declaration earlier in the file. Without it, the
//!   code is judged on `posix`;
//! - the answer is `safe`, or fields: `finds=RULES` (every rule is found;
//!   `a/b` is either), `rules=RULES` (exactly these, in order), `first=RULE`
//!   (the first finding), `lacks=RULES` (none of them), and `reason="..."`
//!   and `target="..."` (the reason and the target of the first finding of
//!   `first`, or of the one rule of `finds`), and `instead="..."` (what that
//!   same finding says to do instead, or `instead=none` for no advice).
//!   Rules are their wire names, comma separated.
//!
//! Every case is also held to what every answer keeps: a reason is one plain
//! sentence with no trailing period, and the same code gets the same answer
//! twice.
//!
//! A declaration is `paths NAME FIELDS`: `base=MACHINE`, or `cwd=` and
//! `home=`; `workspace=` (one for each folder, after the base's);
//! `folder=` or `file=` (a protected path) and `secret_folder=` or
//! `secret_file=` (a secret the caller names), each followed by its `words=`
//! (read by [`format::declaration`]).

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test reads its case files from the crate's `tests/cases`"
)]

#[path = "../../../core/tests/common/cases.rs"]
pub mod format;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use format::{Record, Word};
use milo_guards_core::RuleName;
use milo_guards_script::{judge, Language, Paths, Protected, Rule, Secret};

use super::{macos, posix, windows};

/// One case of a case file.
#[derive(Debug, Clone)]
pub struct Case {
    /// Where it is: `tests/cases/NAME.cases:LINE`.
    pub at: String,
    pub language: Language,
    pub paths: Paths,
    pub expect: Expect,
    /// The code judged, decoded.
    pub code: String,
}

/// What a case expects of its code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Expect {
    pub safe: bool,
    /// Each group must be found: one of its rules is.
    pub finds: Vec<Vec<Rule>>,
    /// The rules found, exactly and in order.
    pub rules: Option<Vec<Rule>>,
    pub first: Option<Rule>,
    pub lacks: Vec<Rule>,
    pub reason: Option<String>,
    /// The target of the same finding.
    pub target: Option<String>,
    /// What the same finding says to do instead.
    pub instead: Option<Instead>,
}

/// What a case expects a finding to say to do instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Instead {
    /// No advice: `instead=none`.
    Nothing,
    /// This advice.
    Says(String),
}

impl Instead {
    /// What `instead` on a finding says this is.
    fn of(instead: Option<&String>) -> Self {
        instead.map_or(Self::Nothing, |text| Self::Says(text.clone()))
    }
}

/// The word a case file writes a language with.
pub fn language_name(language: Language) -> &'static str {
    match language {
        Language::Python => "python",
        Language::JavaScript => "javascript",
    }
}

impl Expect {
    /// The answer as a case file writes it, its fields in a fixed order.
    pub fn spelled(&self) -> String {
        let names = |rules: &[Rule]| {
            rules
                .iter()
                .map(|rule| rule.name())
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut words = Vec::new();
        if self.safe {
            words.push("safe".to_string());
        }
        if !self.finds.is_empty() {
            let groups: Vec<String> = self
                .finds
                .iter()
                .map(|group| {
                    group
                        .iter()
                        .map(|rule| rule.name())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .collect();
            words.push(format!("finds={}", groups.join(",")));
        }
        if let Some(rules) = &self.rules {
            words.push(format!("rules={}", names(rules)));
        }
        if let Some(rule) = self.first {
            words.push(format!("first={}", rule.name()));
        }
        if !self.lacks.is_empty() {
            words.push(format!("lacks={}", names(&self.lacks)));
        }
        if let Some(reason) = &self.reason {
            words.push(format!("reason={reason:?}"));
        }
        if let Some(target) = &self.target {
            words.push(format!("target={target:?}"));
        }
        match &self.instead {
            Some(Instead::Says(instead)) => words.push(format!("instead={instead:?}")),
            Some(Instead::Nothing) => words.push("instead=none".to_string()),
            None => {}
        }
        words.join(" ")
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

/// The key a repeated case shares with the first: the language, the paths,
/// the code judged and the answer.
pub fn key(case: &Case) -> (&'static str, String, String, Expect) {
    (
        language_name(case.language),
        format!("{:?}", case.paths),
        case.code.clone(),
        case.expect.clone(),
    )
}

/// One line for a case: where it is, the language, the paths, the answer
/// and the code as Rust writes a string, tab separated.
pub fn dumped(case: &Case) -> String {
    format!(
        "{}\t{}\t{:?}\t{}\t{:?}",
        case.at,
        language_name(case.language),
        case.paths,
        case.expect.spelled(),
        case.code
    )
}

/// What is wrong with `case`: one message for each expectation it misses,
/// one for a reason that is not one plain sentence, and one when the same
/// code gets another answer the second time.
pub fn wrong(case: &Case) -> Vec<String> {
    let Case {
        at,
        language,
        paths,
        expect,
        code,
    } = case;
    let assessment = judge(*language, code, paths);
    let findings = assessment.findings();
    let mut wrong = Vec::new();
    if judge(*language, code, paths) != assessment {
        wrong.push(format!("{at}: another answer the second time: {code:?}"));
    }
    for finding in findings {
        let plain = |text: &str| {
            !text.is_empty() && !text.ends_with('.') && !text.contains(". ") && !text.contains('\n')
        };
        if !plain(&finding.reason) || finding.instead.as_deref().is_some_and(|text| !plain(text)) {
            wrong.push(format!(
                "{at}: a reason is not one plain sentence with no trailing period: {finding:?}"
            ));
        }
    }
    let found: Vec<Rule> = findings.iter().map(|finding| finding.rule).collect();
    let mut missed = Vec::new();
    if expect.safe && !assessment.is_safe() {
        missed.push("safe".to_string());
    }
    for group in &expect.finds {
        if !group.iter().any(|rule| found.contains(rule)) {
            missed.push(format!("finds {group:?}"));
        }
    }
    if let Some(rules) = &expect.rules {
        if &found != rules {
            missed.push(format!("rules {rules:?}"));
        }
    }
    let first = findings.first();
    if let Some(rule) = expect.first {
        if first.map(|finding| finding.rule) != Some(rule) {
            missed.push(format!("first {rule:?}"));
        }
    }
    for rule in &expect.lacks {
        if found.contains(rule) {
            missed.push(format!("lacks {rule:?}"));
        }
    }
    let of = match expect.first {
        Some(_) => first,
        None => expect
            .finds
            .first()
            .and_then(|group| group.first())
            .and_then(|rule| findings.iter().find(|finding| finding.rule == *rule)),
    };
    if let Some(reason) = &expect.reason {
        if of.map(|finding| finding.reason.as_str()) != Some(reason.as_str()) {
            missed.push(format!("reason {reason:?}"));
        }
    }
    if let Some(target) = &expect.target {
        if of.and_then(|finding| finding.target.as_deref()) != Some(target.as_str()) {
            missed.push(format!("target {target:?}"));
        }
    }
    if let Some(instead) = &expect.instead {
        if of
            .map(|finding| Instead::of(finding.instead.as_ref()))
            .as_ref()
            != Some(instead)
        {
            missed.push(format!("instead {instead:?}"));
        }
    }
    if !missed.is_empty() {
        wrong.push(format!(
            "{at}: expected {}: {code:?}\n    got {findings:?}",
            missed.join(", ")
        ));
    }
    wrong
}

/// The cases of `records`, or every refusal: an unknown word or field, a
/// malformed answer, an unknown language or machine, a repeated case.
fn cases(records: &[Record]) -> Result<Vec<Case>, Vec<String>> {
    let mut machines: HashMap<String, Paths> = [
        ("posix".to_string(), posix()),
        ("macos".to_string(), macos()),
        ("windows".to_string(), windows()),
    ]
    .into_iter()
    .collect();
    let mut cases = Vec::new();
    let mut refused = Vec::new();
    for record in records {
        let result = match (&record.text, record.words.first()) {
            (None, Some(Word::Bare(word))) if word == "paths" => {
                declaration(&record.words[1..], &machines)
                    .map(|(name, paths)| {
                        machines.insert(name, paths);
                    })
                    .map_err(|why| vec![why])
            }
            (None, _) => Err(vec!["a case with no `| CODE`".to_string()]),
            (Some(code), _) => case(&record.words, &machines).map(|(language, paths, expect)| {
                cases.push(Case {
                    at: record.at.clone(),
                    language,
                    paths,
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

/// A `paths` declaration: its name and the paths it makes.
fn declaration(
    words: &[Word],
    machines: &HashMap<String, Paths>,
) -> Result<(String, Paths), String> {
    let declared = format::declaration(words)?;
    if machines.contains_key(&declared.name) {
        return Err(format!("the paths `{}` are already named", declared.name));
    }
    let mut paths = match (&declared.base, declared.cwd, declared.home) {
        (Some(base), ..) => machines
            .get(base)
            .cloned()
            .ok_or_else(|| format!("no paths named `{base}`"))?,
        (None, Some(cwd), Some(home)) => Paths::new(cwd, home, Vec::<PathBuf>::new()),
        _ => return Err("a `paths` declaration takes `base`, or `cwd` and `home`".to_string()),
    };
    paths.workspaces.extend(declared.workspaces);
    for named in declared.named {
        paths = match (named.secret, named.folder) {
            (false, true) => paths.with_protected([Protected::folder(named.path, named.words)]),
            (false, false) => paths.with_protected([Protected::file(named.path, named.words)]),
            (true, true) => paths.with_secrets([Secret::folder(named.path, named.words)]),
            (true, false) => paths.with_secrets([Secret::file(named.path, named.words)]),
        };
    }
    Ok((declared.name, paths))
}

/// The language, paths and answer of a case's words.
fn case(
    words: &[Word],
    machines: &HashMap<String, Paths>,
) -> Result<(Language, Paths, Expect), Vec<String>> {
    let Some((language, machine)) = format::head(words) else {
        return Err(vec!["a case starts with its language".to_string()]);
    };
    let language = match language {
        "python" => Language::Python,
        "javascript" => Language::JavaScript,
        other => return Err(vec![format!("an unknown language `{other}`")]),
    };
    let machine = machine.unwrap_or("posix");
    let paths = machines
        .get(machine)
        .ok_or_else(|| vec![format!("no paths named `{machine}`")])?
        .clone();
    let mut expect = Expect::default();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut refused = Vec::new();
    for word in &words[1..] {
        let (name, value) = match word {
            Word::Bare(name) => (name.as_str(), None),
            Word::Field(name, value) => (name.as_str(), Some(value.as_str())),
        };
        if !seen.insert(name) {
            refused.push(format!("`{name}` twice"));
            continue;
        }
        if let Err(why) = answer(&mut expect, name, value) {
            refused.push(why);
        }
    }
    if refused.is_empty() {
        if let Err(why) = whole(&expect) {
            refused.push(why);
        }
    }
    if refused.is_empty() {
        Ok((language, paths, expect))
    } else {
        Err(refused)
    }
}

/// `expect` with the word `name` (and its `value`) added.
fn answer(expect: &mut Expect, name: &str, value: Option<&str>) -> Result<(), String> {
    match (name, value) {
        ("safe", None) => expect.safe = true,
        ("finds", Some(value)) => {
            expect.finds = list(value)?
                .iter()
                .map(|group| group.split('/').map(rule).collect())
                .collect::<Result<_, _>>()?;
        }
        ("rules", Some(value)) => {
            expect.rules = Some(
                list(value)?
                    .into_iter()
                    .map(rule)
                    .collect::<Result<_, _>>()?,
            );
        }
        ("first", Some(value)) => expect.first = Some(rule(value)?),
        ("lacks", Some(value)) => {
            expect.lacks = list(value)?
                .into_iter()
                .map(rule)
                .collect::<Result<_, _>>()?;
        }
        ("reason", Some(value)) => expect.reason = Some(value.to_string()),
        ("target", Some(value)) => expect.target = Some(value.to_string()),
        ("instead", Some("none")) => expect.instead = Some(Instead::Nothing),
        ("instead", Some(value)) => expect.instead = Some(Instead::Says(value.to_string())),
        ("safe", Some(_)) => return Err("`safe` takes no value".to_string()),
        ("finds" | "rules" | "first" | "lacks" | "reason" | "target" | "instead", None) => {
            return Err(format!("`{name}` takes a value: `{name}=...`"))
        }
        (other, None) => return Err(format!("an unknown word `{other}`")),
        (other, Some(_)) => return Err(format!("an unknown field `{other}`")),
    }
    Ok(())
}

/// The comma-separated items of `value`, none of them empty.
fn list(value: &str) -> Result<Vec<&str>, String> {
    let items: Vec<&str> = value.split(',').collect();
    if items.iter().any(|item| item.is_empty()) {
        return Err(format!("an empty item in `{value}`"));
    }
    Ok(items)
}

/// The rule of a wire name.
fn rule(name: &str) -> Result<Rule, String> {
    Rule::ALL
        .into_iter()
        .find(|rule| rule.name() == name)
        .ok_or_else(|| format!("an unknown rule `{name}`"))
}

/// Whether the answer's fields make one answer.
fn whole(expect: &Expect) -> Result<(), String> {
    let risky = !expect.finds.is_empty()
        || expect.rules.is_some()
        || expect.first.is_some()
        || expect.reason.is_some()
        || expect.target.is_some()
        || expect.instead.is_some();
    if expect.safe && (risky || !expect.lacks.is_empty()) {
        return Err("`safe` takes no other rule field".to_string());
    }
    if !expect.safe && !risky && expect.lacks.is_empty() {
        return Err(
            "a case with no answer: `safe`, `finds`, `rules`, `first` or `lacks`".to_string(),
        );
    }
    if (expect.reason.is_some() || expect.target.is_some() || expect.instead.is_some())
        && expect.first.is_none()
        && !(expect.finds.len() == 1 && expect.finds[0].len() == 1)
    {
        return Err(
            "`reason`, `target` and `instead` take `first`, or `finds` of one rule".to_string(),
        );
    }
    Ok(())
}
