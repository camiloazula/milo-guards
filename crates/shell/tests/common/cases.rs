//! The shell guard's case files: what the words of a case mean here, and the
//! runner that checks every case of a file. The format is in
//! CONTRIBUTING.md; the reading of it is shared with the other guards (see
//! [`format`]).
//!
//! A case is `SHELL[@PATHS] ANSWER... | LINE`:
//!
//! - `SHELL` is `posix`, `powershell` or `cmd`;
//! - `PATHS` names the machine the line is judged on: `posix`, `macos`,
//!   `windows`, or a `paths` declaration earlier in the file. Without it, a
//!   POSIX line is judged on `posix` and the others on `windows`;
//! - the answer is `safe`, or fields: `finds=RULES` (every rule is found;
//!   `a/b` is either), `rules=RULES` (exactly these, in order), `first=RULE`
//!   (the first finding), `lacks=RULES` (none of them), `reason="..."` (the
//!   reason of the first finding of `first`, or of the one rule of
//!   `finds`), `instead="..."` (what that finding says to do instead, or
//!   `instead=none` for no advice), and
//!   `effect=reads_workspace|reads_beyond|changes|unknown`. Rules are their
//!   wire names, comma separated.
//!
//! Every case also goes through [`super::disagreements`]: its `effect`,
//! `explain` and `effect_paths` agree with `classify`. And every finding's
//! reason and `instead` are each one plain sentence (see [`unsaid`]).
//!
//! A declaration is `paths NAME FIELDS`: `base=MACHINE`, or `cwd=` and
//! `home=`; `workspace=` (one for each folder, after the base's), and
//! `folder=` or `file=` (a protected path), each followed by its `words=`.

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
use milo_guards_shell::{classify, effect, Effect, Paths, Protected, Reach, Rule, Shell};

use super::{disagreements, macos, posix, windows};

/// One case of a case file.
#[derive(Debug, Clone)]
pub struct Case {
    /// Where it is: `tests/cases/NAME.cases:LINE`.
    pub at: String,
    pub shell: Shell,
    pub paths: Paths,
    pub expect: Expect,
    /// The command line, decoded.
    pub line: String,
}

/// What a case expects of its line.
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
    /// What the finding of `reason` says to do instead.
    pub instead: Option<Instead>,
    pub effect: Option<Effect>,
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
        match &self.instead {
            Some(Instead::Says(instead)) => words.push(format!("instead={instead:?}")),
            Some(Instead::Nothing) => words.push("instead=none".to_string()),
            None => {}
        }
        if let Some(effect) = self.effect {
            words.push(format!("effect={}", effect_name(effect)));
        }
        words.join(" ")
    }
}

/// An effect as a case file writes it.
pub fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::ReadsOnly(Reach::Workspace) => "reads_workspace",
        Effect::ReadsOnly(Reach::Beyond) => "reads_beyond",
        Effect::Changes => "changes",
        Effect::Unknown => "unknown",
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

/// The key a repeated case shares with the first: the shell, the paths, the
/// line and the answer.
pub fn key(case: &Case) -> (Shell, String, String, Expect) {
    (
        case.shell,
        format!("{:?}", case.paths),
        case.line.clone(),
        case.expect.clone(),
    )
}

/// One line for a case: where it is, the shell, the paths, the answer and
/// the line as Rust writes a string, tab separated.
pub fn dumped(case: &Case) -> String {
    format!(
        "{}\t{:?}\t{:?}\t{}\t{:?}",
        case.at,
        case.shell,
        case.paths,
        case.expect.spelled(),
        case.line
    )
}

/// What is wrong with `case`: one message for each expectation it misses,
/// and for each answer that disagrees with `classify`.
pub fn wrong(case: &Case) -> Vec<String> {
    let Case {
        at,
        shell,
        paths,
        expect,
        line,
    } = case;
    let mut wrong: Vec<String> = disagreements(*shell, paths, [line.as_str()])
        .into_iter()
        .map(|why| format!("{at}: {why}"))
        .collect();
    let assessment = classify(line, *shell, paths);
    let findings = assessment.findings();
    wrong.extend(
        findings
            .iter()
            .flat_map(unsaid)
            .map(|why| format!("{at}: {why}: {line:?}")),
    );
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
    // The finding `reason` and `instead` are about: the first, or the one
    // of the one rule of `finds`.
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
    if let Some(instead) = &expect.instead {
        if of
            .map(|finding| Instead::of(finding.instead.as_ref()))
            .as_ref()
            != Some(instead)
        {
            missed.push(format!("instead {instead:?}"));
        }
    }
    if let Some(want) = expect.effect {
        let got = effect(line, *shell, paths);
        if got != want {
            missed.push(format!("effect {want:?}, got {got:?}"));
        }
    }
    if !missed.is_empty() {
        wrong.push(format!(
            "{at}: expected {}: {line:?}\n    got {findings:?}",
            missed.join(", ")
        ));
    }
    wrong
}

/// What is wrong with what `finding` says: its reason and its `instead`
/// are each one plain sentence, as a permission prompt shows it: not empty,
/// on one line, with no space at either end, no trailing period and no
/// second sentence.
pub fn unsaid(finding: &milo_guards_shell::Finding) -> Vec<String> {
    [
        ("reason", Some(&finding.reason)),
        ("instead", finding.instead.as_ref()),
    ]
    .into_iter()
    .filter_map(|(field, text)| Some((field, text?)))
    .filter(|(_, text)| {
        text.is_empty()
            || text.trim() != text.as_str()
            || text.ends_with('.')
            || text.contains(['\n', '\r'])
            || text.contains(". ")
    })
    .map(|(field, text)| format!("the {field} {text:?} is not one plain sentence"))
    .collect()
}

/// The cases of `records`, or every refusal: an unknown word or field, a
/// malformed answer, an unknown machine, a repeated case.
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
            (None, _) => Err(vec!["a case with no `| LINE`".to_string()]),
            (Some(line), _) => case(&record.words, &machines).map(|(shell, paths, expect)| {
                cases.push(Case {
                    at: record.at.clone(),
                    shell,
                    paths,
                    expect,
                    line: line.clone(),
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
    let Some(Word::Bare(name)) = words.first() else {
        return Err("`paths` takes a name first".to_string());
    };
    if machines.contains_key(name) {
        return Err(format!("the paths `{name}` are already named"));
    }
    let mut base: Option<Paths> = None;
    let (mut cwd, mut home) = (None, None);
    let mut workspaces: Vec<PathBuf> = Vec::new();
    let mut protected: Vec<(bool, PathBuf, Option<String>)> = Vec::new();
    for word in &words[1..] {
        let (field, value) = match word {
            Word::Field(field, value) => (field, value),
            Word::Bare(bare) => {
                return Err(format!("an unknown word `{bare}` in a `paths` declaration"))
            }
        };
        match field.as_str() {
            "base" => {
                let paths = machines
                    .get(value)
                    .ok_or_else(|| format!("no paths named `{value}`"))?;
                base = Some(paths.clone());
            }
            "cwd" => cwd = Some(PathBuf::from(value)),
            "home" => home = Some(PathBuf::from(value)),
            "workspace" => workspaces.push(PathBuf::from(value)),
            "folder" | "file" => protected.push((field == "folder", PathBuf::from(value), None)),
            "words" => match protected.last_mut() {
                Some((_, _, words @ None)) => *words = Some(value.clone()),
                _ => return Err("`words` must follow its `folder` or `file`".to_string()),
            },
            other => {
                return Err(format!(
                    "an unknown field `{other}` in a `paths` declaration"
                ))
            }
        }
    }
    let mut paths = match (base, cwd, home) {
        (Some(base), None, None) => base,
        (None, Some(cwd), Some(home)) => Paths::new(cwd, home, Vec::<PathBuf>::new()),
        _ => return Err("a `paths` declaration takes `base`, or `cwd` and `home`".to_string()),
    };
    paths.workspaces.extend(workspaces);
    for (folder, path, words) in protected {
        let words: &'static str = Box::leak(
            words
                .ok_or("each `folder` and `file` takes its `words`")?
                .into_boxed_str(),
        );
        paths = paths.with_protected([if folder {
            Protected::folder(path, words)
        } else {
            Protected::file(path, words)
        }]);
    }
    Ok((name.clone(), paths))
}

/// The shell, paths and answer of a case's words.
fn case(
    words: &[Word],
    machines: &HashMap<String, Paths>,
) -> Result<(Shell, Paths, Expect), Vec<String>> {
    let Some(Word::Bare(head)) = words.first() else {
        return Err(vec!["a case starts with its shell".to_string()]);
    };
    let (shell, machine) = match head.split_once('@') {
        Some((shell, machine)) => (shell, Some(machine)),
        None => (head.as_str(), None),
    };
    let shell = match shell {
        "posix" => Shell::Posix,
        "powershell" => Shell::PowerShell,
        "cmd" => Shell::Cmd,
        other => return Err(vec![format!("an unknown shell `{other}`")]),
    };
    let machine = machine.unwrap_or(if shell == Shell::Posix {
        "posix"
    } else {
        "windows"
    });
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
        Ok((shell, paths, expect))
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
        ("instead", Some("none")) => expect.instead = Some(Instead::Nothing),
        ("instead", Some(value)) => expect.instead = Some(Instead::Says(value.to_string())),
        ("effect", Some(value)) => {
            expect.effect = Some(match value {
                "reads_workspace" => Effect::ReadsOnly(Reach::Workspace),
                "reads_beyond" => Effect::ReadsOnly(Reach::Beyond),
                "changes" => Effect::Changes,
                "unknown" => Effect::Unknown,
                other => return Err(format!("an unknown effect `{other}`")),
            });
        }
        ("safe", Some(_)) => return Err("`safe` takes no value".to_string()),
        ("finds" | "rules" | "first" | "lacks" | "reason" | "instead" | "effect", None) => {
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
        || expect.instead.is_some();
    if expect.safe && (risky || !expect.lacks.is_empty()) {
        return Err("`safe` takes no other rule field".to_string());
    }
    if !expect.safe && !risky && expect.lacks.is_empty() && expect.effect.is_none() {
        return Err(
            "a case with no answer: `safe`, `finds`, `rules`, `first`, `lacks` or `effect`"
                .to_string(),
        );
    }
    for (field, given) in [
        ("reason", expect.reason.is_some()),
        ("instead", expect.instead.is_some()),
    ] {
        if given
            && expect.first.is_none()
            && !(expect.finds.len() == 1 && expect.finds[0].len() == 1)
        {
            return Err(format!("`{field}` takes `first`, or `finds` of one rule"));
        }
    }
    Ok(())
}
