//! The secrets guard's case files: what the words of a case mean here, and
//! the runner that checks every case of a file. The format is in
//! CONTRIBUTING.md; the reading of it is shared with the other guards (see
//! [`format`]).
//!
//! A case is `ANSWER... | TEXT`. The answer is `safe`, or fields:
//! `finds=RULES` (every rule is found; `a/b` is either), `rules=RULES`
//! (exactly these, in order), `first=RULE` (the first finding),
//! `lacks=RULES` (none of them), `reason="..."` and `target="..."` (the
//! reason and the masked target of the first finding of `first`, or of the
//! one rule of `finds`), `span="..."` (the text has one span, and it covers
//! exactly this) and `covers="..."` (every byte of the first place this is
//! in the text is in a span). Rules are their wire names, comma separated.
//!
//! Only a text that holds no credential-shaped value is written in a case
//! file; the tests build those in Rust (`tests/common`), so that none sits
//! in the repository.
//!
//! Every case is also held to what every answer keeps: the spans of
//! `find_spans` are one for one with the findings of `find`, by rule, on
//! character boundaries, in order and apart.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test reads its case files from the crate's `tests/cases`"
)]

#[path = "../../../core/tests/common/cases.rs"]
pub mod format;

use std::collections::HashSet;

use format::Record;
use format::Word;
use milo_guards_secrets::{find, find_spans, Finding, Rule};

/// One case of a case file.
#[derive(Debug, Clone)]
pub struct Case {
    /// Where it is: `tests/cases/NAME.cases:LINE`.
    pub at: String,
    pub expect: Expect,
    /// The text read, decoded.
    pub text: String,
}

/// What a case expects of its text.
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
    pub target: Option<String>,
    /// The text of the one span.
    pub span: Option<String>,
    /// A part of the text every byte of which is in a span.
    pub covers: Option<String>,
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
        for (name, value) in [
            ("reason", &self.reason),
            ("target", &self.target),
            ("span", &self.span),
            ("covers", &self.covers),
        ] {
            if let Some(value) = value {
                words.push(format!("{name}={value:?}"));
            }
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

/// The key a repeated case shares with the first: the text read and the
/// answer.
pub fn key(case: &Case) -> (String, Expect) {
    (case.text.clone(), case.expect.clone())
}

/// One line for a case: where it is, the answer and the text as Rust writes
/// a string, tab separated.
pub fn dumped(case: &Case) -> String {
    format!("{}\t{}\t{:?}", case.at, case.expect.spelled(), case.text)
}

/// What is wrong with `case`: one message for each expectation it misses,
/// and one when the spans and the findings do not agree.
pub fn wrong(case: &Case) -> Vec<String> {
    let Case { at, expect, text } = case;
    let assessment = find(text);
    let findings = assessment.findings();
    let spans = find_spans(text);
    let shown: Vec<(Rule, &str)> = spans
        .iter()
        .map(|span| (span.rule, text.get(span.start..span.end).unwrap_or("?")))
        .collect();
    let mut wrong = Vec::new();
    let found: Vec<Rule> = findings.iter().map(|finding| finding.rule).collect();
    let spanned: Vec<Rule> = spans.iter().map(|span| span.rule).collect();
    let apart = spans.windows(2).all(|pair| pair[0].end <= pair[1].start);
    let bounded = spans.iter().all(|span| {
        span.start < span.end
            && text.is_char_boundary(span.start)
            && text.is_char_boundary(span.end)
    });
    if found != spanned || !apart || !bounded {
        wrong.push(format!(
            "{at}: the spans do not agree with the findings: {text:?}\n    spans {spans:?}\n    findings {findings:?}"
        ));
    }
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
    let of: Option<&Finding> = match expect.first {
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
    if let Some(span) = &expect.span {
        if shown.len() != 1 || shown[0].1 != span {
            missed.push(format!("span {span:?}"));
        }
    }
    if let Some(part) = &expect.covers {
        let covered = text.find(part.as_str()).is_some_and(|at| {
            (at..at + part.len()).all(|byte| {
                spans
                    .iter()
                    .any(|span| span.start <= byte && byte < span.end)
            })
        });
        if !covered {
            missed.push(format!("covers {part:?}"));
        }
    }
    if !missed.is_empty() {
        wrong.push(format!(
            "{at}: expected {}: {text:?}\n    got {findings:?}\n    spans {shown:?}",
            missed.join(", ")
        ));
    }
    wrong
}

/// The cases of `records`, or every refusal: an unknown word or field, a
/// malformed answer, a repeated case.
fn cases(records: &[Record]) -> Result<Vec<Case>, Vec<String>> {
    let mut cases = Vec::new();
    let mut refused = Vec::new();
    for record in records {
        let result = match &record.text {
            None => Err(vec!["a case with no `| TEXT`".to_string()]),
            Some(text) => case(&record.words).map(|expect| {
                cases.push(Case {
                    at: record.at.clone(),
                    expect,
                    text: text.clone(),
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

/// The answer of a case's words.
fn case(words: &[Word]) -> Result<Expect, Vec<String>> {
    let mut expect = Expect::default();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut refused = Vec::new();
    for word in words {
        let (name, value) = match word {
            Word::Bare(name) => (name.as_str(), None),
            Word::Field(name, value) => (name.as_str(), Some(value.as_str())),
        };
        if !seen.insert(name) {
            refused.push(format!("`{name}` twice"));
            continue;
        }
        if let Err(why) = add(&mut expect, name, value) {
            refused.push(why);
        }
    }
    if refused.is_empty() {
        if let Err(why) = whole(&expect) {
            refused.push(why);
        }
    }
    if refused.is_empty() {
        Ok(expect)
    } else {
        Err(refused)
    }
}

/// `expect` with the word `name` (and its `value`) added.
fn add(expect: &mut Expect, name: &str, value: Option<&str>) -> Result<(), String> {
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
        ("span", Some(value)) => expect.span = Some(value.to_string()),
        ("covers", Some("")) => return Err("`covers` takes a part of the text".to_string()),
        ("covers", Some(value)) => expect.covers = Some(value.to_string()),
        ("safe", Some(_)) => return Err("`safe` takes no value".to_string()),
        ("finds" | "rules" | "first" | "lacks" | "reason" | "target" | "span" | "covers", None) => {
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
        || expect.span.is_some()
        || expect.covers.is_some();
    if expect.safe && (risky || !expect.lacks.is_empty()) {
        return Err("`safe` takes no other field".to_string());
    }
    if !expect.safe && !risky && expect.lacks.is_empty() {
        return Err(
            "a case with no answer: `safe`, `finds`, `rules`, `first`, `lacks`, `span` or `covers`"
                .to_string(),
        );
    }
    let one = expect.first.is_some() || (expect.finds.len() == 1 && expect.finds[0].len() == 1);
    if expect.reason.is_some() && !one {
        return Err("`reason` takes `first`, or `finds` of one rule".to_string());
    }
    if expect.target.is_some() && !one {
        return Err("`target` takes `first`, or `finds` of one rule".to_string());
    }
    Ok(())
}
