//! The answers the shell guard gives a few thousand everyday commands, held
//! to their record. `tests/cases/everyday.cases` holds the lines that must
//! stay safe; this holds what the guard answers today for the much larger
//! set of `tests/cases/everyday_answers.templates`, safe or not, so a change
//! to the guard that moves an everyday answer shows in a diff of
//! `tests/cases/everyday_answers.cases`, the record, and fails here until
//! that record is rewritten on purpose (CONTRIBUTING.md).
//!
//! The templates are what agents run all day in a POSIX shell, in
//! PowerShell and in cmd, by task. Each expands, with fixed lists of
//! fillers and no randomness, into the lines of the set; the record is
//! every one of them with the answer it gets, in the shell guard's case
//! format, written by [`record`] and never by hand.
//!
//! [`everyday_answers_are_as_recorded`] judges the set, prints the report
//! (the lines of each shell, the share that is safe, the lines each rule is
//! found on, each group, and every line whose answer is not the recorded
//! one, with both answers) and fails when the record is not what [`record`]
//! would write. `just everyday` runs it and shows the report; `just
//! everyday-record` rewrites the record. The record is a case file, and
//! [`everyday_answers_agree_with_effect_and_explain`] checks it as the
//! shell guard's runner checks every case file. `just verify` runs both (in
//! `coverage`), and the cost of the set to it is held by a count of lines,
//! [`MOST_LINES`], not by the clock.

#![cfg(feature = "shell")]

#[path = "../../shell/tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use common::cases::{self, format, Expect};
use format::Word;
use milo_guards::shell::{self, Paths, Rule, Shell};

/// The templates, in `tests/cases`.
const TEMPLATES: &str = "everyday_answers.templates";

/// The record's name: `tests/cases/everyday_answers.cases`.
const RECORD: &str = "everyday_answers";

/// The most lines the templates may make. The test judges every one of them
/// in every build of the gate, so its cost is held by this count, not by the
/// clock: raise it with a reason, as a set that grows past it costs the gate
/// more.
const MOST_LINES: usize = 4_000;

/// The most lines one template may make, so that no one template weighs on
/// the shares more than a few of its neighbours do.
const MOST_PER_TEMPLATE: usize = 32;

/// The shells, in the order the report lists them.
const SHELLS: [Shell; 3] = [Shell::Posix, Shell::PowerShell, Shell::Cmd];

/// A shell as a case file names it. (`Shell` is not exhaustive: a shell
/// the templates cannot name has no line here.)
fn shell_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Posix => "posix",
        Shell::PowerShell => "powershell",
        Shell::Cmd => "cmd",
        _ => "another shell",
    }
}

/// The machine a line of `shell` is judged on: the one a case with no
/// `@PATHS` is judged on, so the record names none.
fn machine(shell: Shell) -> Paths {
    if shell == Shell::Posix {
        common::posix()
    } else {
        common::windows()
    }
}

// ---- the templates ----

/// A piece of a template: text as it is, or a slot that takes each of its
/// fillers in turn.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Slot(Vec<String>),
}

/// One template, read.
#[derive(Debug, Clone)]
struct Template {
    /// Where it is: `tests/cases/everyday_answers.templates:LINE`.
    at: String,
    shell: Shell,
    group: String,
    pieces: Vec<Piece>,
}

/// One line the templates make.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Made {
    /// The template that made it.
    at: String,
    shell: Shell,
    group: String,
    line: String,
}

/// The lines the templates of `source` (the text of the file `file`) make,
/// in order, or every reason they are refused, each named by where it is.
///
/// A template file has three kinds of line, besides blank lines and
/// comments, read with the case files' reading (and so their escapes):
///
/// - `group NAME`: the templates after it, up to the next `group`, are in
///   the group `NAME`;
/// - `fill NAME | A | B | ...`: the list of fillers `NAME`; a second `fill`
///   of the same name adds to it;
/// - `SHELL | TEMPLATE`: a template, `SHELL` one of `posix`, `powershell`
///   and `cmd`. In it `«NAME»` is a slot that takes each filler of the list
///   `NAME`, and `«A|B|C»` one that takes each of the alternatives written
///   in it, which may be empty. A template makes a line for each way of
///   filling its slots, the first slot changing slowest.
fn expand(file: &str, source: &str) -> Result<Vec<Made>, Vec<String>> {
    let records = format::parse(file, source)?;
    let mut refused = Vec::new();
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut listed_at: HashMap<String, String> = HashMap::new();
    for record in &records {
        if let (Some(text), [Word::Bare(fill), Word::Bare(name)]) =
            (&record.text, record.words.as_slice())
        {
            if fill == "fill" {
                let fillers: Vec<String> = text.split(" | ").map(str::to_string).collect();
                if fillers.iter().any(String::is_empty) || !is_name(name) {
                    refused.push(format!(
                        "{}: a `fill` takes a name of lowercase letters, digits and `_`, \
                         and fillers that are not empty",
                        record.at
                    ));
                }
                lists.entry(name.clone()).or_default().extend(fillers);
                listed_at
                    .entry(name.clone())
                    .or_insert_with(|| record.at.clone());
            }
        }
    }
    let mut used: HashSet<String> = HashSet::new();
    let mut templates = Vec::new();
    let mut group: Option<String> = None;
    for record in &records {
        match (record.words.as_slice(), &record.text) {
            ([Word::Bare(word), Word::Bare(_)], Some(_)) if word == "fill" => {}
            ([Word::Bare(word), Word::Bare(name)], None) if word == "group" => {
                group = Some(name.clone());
            }
            ([Word::Bare(shell)], Some(text)) => {
                let shell = match shell.as_str() {
                    "posix" => Shell::Posix,
                    "powershell" => Shell::PowerShell,
                    "cmd" => Shell::Cmd,
                    other => {
                        refused.push(format!("{}: an unknown shell `{other}`", record.at));
                        continue;
                    }
                };
                let Some(group) = group.clone() else {
                    refused.push(format!("{}: a template before any `group`", record.at));
                    continue;
                };
                match pieces(text, &lists, &mut used) {
                    Ok(pieces) => templates.push(Template {
                        at: record.at.clone(),
                        shell,
                        group,
                        pieces,
                    }),
                    Err(why) => refused.push(format!("{}: {why}", record.at)),
                }
            }
            _ => refused.push(format!(
                "{}: not a `group NAME`, a `fill NAME | ...` or a `SHELL | TEMPLATE`",
                record.at
            )),
        }
    }
    for name in lists.keys().filter(|name| !used.contains(*name)) {
        refused.push(format!(
            "{}: the list `{name}` fills no template",
            listed_at[name]
        ));
    }
    let mut made: Vec<Made> = Vec::new();
    let mut first: HashMap<(Shell, String), String> = HashMap::new();
    for template in &templates {
        let lines = lines_of(&template.pieces);
        if lines.len() > MOST_PER_TEMPLATE {
            refused.push(format!(
                "{}: makes {} lines, more than {MOST_PER_TEMPLATE}: split it, or shorten a list",
                template.at,
                lines.len()
            ));
        }
        for line in lines {
            if line.starts_with(' ') || line.ends_with(' ') {
                refused.push(format!(
                    "{}: makes a line with a space at an end: {line:?}",
                    template.at
                ));
            }
            if let Some(at) = first.get(&(template.shell, line.clone())) {
                refused.push(format!(
                    "{}: makes {line:?}, which the template at {at} makes too",
                    template.at
                ));
                continue;
            }
            first.insert((template.shell, line.clone()), template.at.clone());
            made.push(Made {
                at: template.at.clone(),
                shell: template.shell,
                group: template.group.clone(),
                line,
            });
        }
    }
    if made.len() > MOST_LINES {
        refused.push(format!(
            "{file}: makes {} lines, more than {MOST_LINES}",
            made.len()
        ));
    }
    if refused.is_empty() {
        Ok(made)
    } else {
        Err(refused)
    }
}

/// Whether `name` is a list's name: lowercase letters, digits and `_`.
fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The pieces of a template's `text`, its slots filled from `lists`, each
/// list it names added to `used`.
fn pieces(
    text: &str,
    lists: &BTreeMap<String, Vec<String>>,
    used: &mut HashSet<String>,
) -> Result<Vec<Piece>, String> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('«') {
        let (before, after) = rest.split_at(open);
        let after = &after['«'.len_utf8()..];
        let close = after
            .find('»')
            .ok_or("a `«` with no `»` after it".to_string())?;
        let inside = &after[..close];
        if before.contains('»') {
            return Err("a `»` with no `«` before it".to_string());
        }
        if inside.contains('«') {
            return Err("a slot inside a slot".to_string());
        }
        if !before.is_empty() {
            pieces.push(Piece::Text(before.to_string()));
        }
        let fillers = if inside.contains('|') {
            inside.split('|').map(str::to_string).collect()
        } else {
            let fillers = lists
                .get(inside)
                .ok_or_else(|| format!("no list named `{inside}`"))?;
            used.insert(inside.to_string());
            fillers.clone()
        };
        pieces.push(Piece::Slot(fillers));
        rest = &after[close + '»'.len_utf8()..];
    }
    if rest.contains('»') {
        return Err("a `»` with no `«` before it".to_string());
    }
    if !rest.is_empty() {
        pieces.push(Piece::Text(rest.to_string()));
    }
    Ok(pieces)
}

/// Every line `pieces` make, the first slot changing slowest.
fn lines_of(pieces: &[Piece]) -> Vec<String> {
    let mut lines = vec![String::new()];
    for piece in pieces {
        lines = match piece {
            Piece::Text(text) => lines.into_iter().map(|line| line + text).collect(),
            Piece::Slot(fillers) => lines
                .iter()
                .flat_map(|line| fillers.iter().map(move |filler| format!("{line}{filler}")))
                .collect(),
        };
    }
    lines
}

/// The lines the repository's templates make; a refusal fails the test.
#[allow(clippy::disallowed_methods, reason = "it reads the templates")]
fn made() -> Vec<Made> {
    let file = format!("tests/cases/{TEMPLATES}");
    let source = std::fs::read_to_string(format::folder().join(TEMPLATES));
    assert!(source.is_ok(), "{file}: cannot read it: {source:?}");
    let made = expand(&file, &source.unwrap_or_default());
    let refused = made.as_ref().err().cloned().unwrap_or_default();
    assert!(
        refused.is_empty(),
        "{} lines refused:\n{}",
        refused.len(),
        refused.join("\n")
    );
    made.unwrap_or_default()
}

// ---- the answers ----

/// What the shell guard answers for `line`, as a case writes it: `safe`, or
/// every rule it finds in order, with the first finding's reason.
fn answer(shell: Shell, line: &str) -> Expect {
    let assessment = shell::classify(line, shell, &machine(shell));
    let findings = assessment.findings();
    match findings.first() {
        None => Expect {
            safe: true,
            ..Expect::default()
        },
        Some(first) => Expect {
            rules: Some(findings.iter().map(|finding| finding.rule).collect()),
            first: Some(first.rule),
            reason: Some(first.reason.clone()),
            ..Expect::default()
        },
    }
}

/// One line of the set, judged.
struct Judged {
    made: Made,
    answer: Expect,
}

/// Every line the templates make, with what the guard answers for it today.
fn judged(made: Vec<Made>) -> Vec<Judged> {
    made.into_iter()
        .map(|made| Judged {
            answer: answer(made.shell, &made.line),
            made,
        })
        .collect()
}

/// The record of `judged`, as [`record`] writes it: a header, then each line
/// as a case, in the order the templates make them, under a comment that
/// names its group whenever the group changes.
fn written(judged: &[Judged]) -> String {
    let mut out = String::from(concat!(
        "# The answers the shell guard gives the everyday commands that\n",
        "# `everyday_answers.templates` makes, one case to a line, in the order the\n",
        "# templates make them. Written by `just everyday-record`, never by hand:\n",
        "# `tests/everyday_answers.rs` fails when this is not what it writes\n",
        "# (CONTRIBUTING.md, \"The everyday answers\").\n",
    ));
    let mut group: Option<(Shell, &str)> = None;
    for line in judged {
        let here = (line.made.shell, line.made.group.as_str());
        if group != Some(here) {
            let _ = write!(
                out,
                "\n# {}: {}\n",
                shell_name(line.made.shell),
                line.made.group
            );
            group = Some(here);
        }
        let _ = writeln!(
            out,
            "{} {} | {}",
            shell_name(line.made.shell),
            line.answer.spelled(),
            format::encode(&line.made.line)
        );
    }
    out
}

/// The record in the repository: every case, by its shell and line, with
/// the answer it holds; empty when there is no record yet. A record that is
/// refused fails the test.
#[allow(clippy::disallowed_methods, reason = "it reads the record")]
fn recorded() -> (Option<String>, HashMap<(Shell, String), Expect>) {
    let path = format::file(RECORD);
    let Ok(source) = std::fs::read_to_string(&path) else {
        return (None, HashMap::new());
    };
    let cases = cases::parse(&format!("tests/cases/{RECORD}.cases"), &source);
    let refused = cases.as_ref().err().cloned().unwrap_or_default();
    assert!(
        refused.is_empty(),
        "the record is refused:\n{}",
        refused.join("\n")
    );
    let answers = cases
        .unwrap_or_default()
        .into_iter()
        .map(|case| ((case.shell, case.line), case.expect))
        .collect();
    (Some(source), answers)
}

// ---- the report ----

/// `part` of `whole` as a percentage with one decimal, rounded half up, in
/// integers so it prints the same everywhere.
fn share(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "-".to_string();
    }
    let tenths = (part * 1000 + whole / 2) / whole;
    format!("{}.{}%", tenths / 10, tenths % 10)
}

/// The rules an answer finds, each once.
fn rules_of(answer: &Expect) -> Vec<Rule> {
    let mut rules: Vec<Rule> = Vec::new();
    for rule in answer.rules.iter().flatten() {
        if !rules.contains(rule) {
            rules.push(*rule);
        }
    }
    rules
}

/// The report: the lines of each shell, the share that is safe, the lines
/// each rule is found on, each group, and every line whose answer is not the
/// recorded one (`recorded`), with both answers.
fn report(judged: &[Judged], recorded: &HashMap<(Shell, String), Expect>) -> (String, usize) {
    let mut out = String::new();
    let total = judged.len();
    let safe = judged.iter().filter(|line| line.answer.safe).count();
    let _ = writeln!(
        out,
        "The everyday answers: {total} lines, {safe} safe ({}), {} risky: \
         a false-alarm share of {}",
        share(safe, total),
        total - safe,
        share(total - safe, total),
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:<12} {:>6} {:>6} {:>7} {:>6} {:>12}",
        "shell", "lines", "safe", "% safe", "risky", "false alarms"
    );
    let of = |shell: Option<Shell>| {
        judged
            .iter()
            .filter(move |line| shell.is_none_or(|shell| line.made.shell == shell))
    };
    for shell in SHELLS.map(Some).into_iter().chain([None]) {
        let lines = of(shell).count();
        let safe = of(shell).filter(|line| line.answer.safe).count();
        let _ = writeln!(
            out,
            "{:<12} {lines:>6} {safe:>6} {:>7} {:>6} {:>12}",
            shell.map_or("all", shell_name),
            share(safe, lines),
            lines - safe,
            share(lines - safe, lines),
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:<18} {:>6} {:>10} {:>6} {:>6} {:>12}",
        "rule (lines)", "posix", "powershell", "cmd", "all", "of all lines"
    );
    for rule in Rule::ALL {
        let on = |shell: Option<Shell>| {
            of(shell)
                .filter(|line| rules_of(&line.answer).contains(&rule))
                .count()
        };
        let all = on(None);
        if all == 0 {
            continue;
        }
        let _ = writeln!(
            out,
            "{:<18} {:>6} {:>10} {:>6} {all:>6} {:>12}",
            rule.name(),
            on(Some(Shell::Posix)),
            on(Some(Shell::PowerShell)),
            on(Some(Shell::Cmd)),
            share(all, total),
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:<30} {:>6} {:>6} {:>6} {:>12}",
        "group", "lines", "safe", "risky", "false alarms"
    );
    let mut groups: Vec<(Shell, &str)> = Vec::new();
    for line in judged {
        let key = (line.made.shell, line.made.group.as_str());
        if !groups.contains(&key) {
            groups.push(key);
        }
    }
    for (shell, group) in groups {
        let lines = judged
            .iter()
            .filter(|line| line.made.shell == shell && line.made.group == group)
            .count();
        let safe = judged
            .iter()
            .filter(|line| line.made.shell == shell && line.made.group == group)
            .filter(|line| line.answer.safe)
            .count();
        let _ = writeln!(
            out,
            "{:<30} {lines:>6} {safe:>6} {:>6} {:>12}",
            format!("{}: {group}", shell_name(shell)),
            lines - safe,
            share(lines - safe, lines),
        );
    }
    let mut differ = Vec::new();
    let mut made: HashSet<(Shell, &str)> = HashSet::new();
    for line in judged {
        made.insert((line.made.shell, line.made.line.as_str()));
        let was = recorded
            .get(&(line.made.shell, line.made.line.clone()))
            .map_or("not recorded".to_string(), Expect::spelled);
        let now = line.answer.spelled();
        if was != now {
            differ.push(format!(
                "{} | {}\n    was: {was}\n    now: {now}\n    made by: {}",
                shell_name(line.made.shell),
                format::encode(&line.made.line),
                line.made.at
            ));
        }
    }
    let mut gone: Vec<String> = recorded
        .iter()
        .filter(|((shell, line), _)| !made.contains(&(*shell, line.as_str())))
        .map(|((shell, line), was)| {
            format!(
                "{} | {}\n    was: {}\n    now: not made by the templates",
                shell_name(*shell),
                format::encode(line),
                was.spelled()
            )
        })
        .collect();
    gone.sort();
    differ.extend(gone);
    let _ = writeln!(out);
    if differ.is_empty() {
        let _ = writeln!(out, "Every answer is the recorded one.");
    } else {
        let (answers, differ_word) = if differ.len() == 1 {
            ("answer", "differs")
        } else {
            ("answers", "differ")
        };
        let _ = writeln!(
            out,
            "{} {answers} {differ_word} from the record (`just everyday-record` records them):",
            differ.len()
        );
        for line in &differ {
            let _ = writeln!(out, "{line}");
        }
    }
    (out, differ.len())
}

// ---- the tests ----

/// Every line the templates make gets the answer the record holds for it,
/// and the record is exactly what [`record`] writes: no line more, none
/// less, none edited by hand. The report is printed whatever the outcome,
/// and shown by `just everyday` (and by the test harness when it fails).
#[test]
#[allow(clippy::disallowed_macros, reason = "the test prints the report")]
fn everyday_answers_are_as_recorded() {
    let judged = judged(made());
    let (source, answers) = recorded();
    let (shown, differ) = report(&judged, &answers);
    println!("{shown}");
    assert_eq!(
        differ, 0,
        "everyday answers differ from the record, each named in the report above: \
         if the change means them, `just everyday-record` records them"
    );
    assert!(
        source.as_deref() == Some(written(&judged).as_str()),
        "tests/cases/{RECORD}.cases holds every answer, but is not what \
         `just everyday-record` writes (edited by hand, or the templates moved): rewrite it"
    );
}

/// The variable `just everyday-record` sets, without which [`record`]
/// writes nothing: `cargo test -- --ignored` (or `--include-ignored`), which
/// runs the `dump` tests, runs it too, and must not rewrite the record.
const RECORD_ON_PURPOSE: &str = "MILO_EVERYDAY_RECORD";

/// Prints the report of what moved and, run on purpose by `just
/// everyday-record` (which sets [`RECORD_ON_PURPOSE`] to `1`), rewrites the
/// record with today's answers. Without the variable it writes nothing and
/// says so. Only this test reads the environment, and the gate never runs
/// it.
#[test]
#[ignore = "rewrites the record: `just everyday-record` runs it on purpose"]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "it prints the report, reads the variable that says it runs on purpose, \
              and writes the record"
)]
fn record() {
    let judged = judged(made());
    let (_, answers) = recorded();
    let (shown, _) = report(&judged, &answers);
    println!("{shown}");
    if std::env::var(RECORD_ON_PURPOSE).as_deref() != Ok("1") {
        println!(
            "The record is not written: `just everyday-record` writes it \
             (it sets {RECORD_ON_PURPOSE}=1)."
        );
        return;
    }
    let wrote = std::fs::write(format::file(RECORD), written(&judged));
    assert!(wrote.is_ok(), "cannot write the record: {wrote:?}");
}

/// The record is a case file, and is checked as every case file is, by the
/// shell guard's runner: each case gets the answer it holds, and goes
/// through the agreement checks (its `effect`, `explain` and `effect_paths`
/// agree with `classify`, and what each finding says is one plain
/// sentence).
#[test]
fn everyday_answers_agree_with_effect_and_explain() {
    cases::check(RECORD);
}

/// The templates' own reading: each way of filling the slots, in order, from
/// a list or from the alternatives written in the slot.
#[test]
fn a_template_makes_a_line_for_each_way_of_filling_it() {
    let made = expand(
        "t.templates",
        concat!(
            "# A comment.\n",
            "fill file | src/a.rs | src/b.rs\n",
            "fill file | src/c.rs\n",
            "group build\n",
            "posix | cargo «build|test»«| --release»\n",
            "group read\n",
            "powershell | Get-Content «file» | Select-Object -First 5\n",
        ),
    );
    assert!(made.is_ok(), "{made:?}");
    let made = made.unwrap_or_default();
    let lines: Vec<(&str, &str, &str)> = made
        .iter()
        .map(|made| {
            (
                shell_name(made.shell),
                made.group.as_str(),
                made.line.as_str(),
            )
        })
        .collect();
    assert_eq!(
        lines,
        [
            ("posix", "build", "cargo build"),
            ("posix", "build", "cargo build --release"),
            ("posix", "build", "cargo test"),
            ("posix", "build", "cargo test --release"),
            (
                "powershell",
                "read",
                "Get-Content src/a.rs | Select-Object -First 5"
            ),
            (
                "powershell",
                "read",
                "Get-Content src/b.rs | Select-Object -First 5"
            ),
            (
                "powershell",
                "read",
                "Get-Content src/c.rs | Select-Object -First 5"
            ),
        ]
    );
    assert_eq!(made[0].at, "t.templates:5");
}

#[test]
fn a_malformed_template_file_is_refused() {
    for (source, why) in [
        (
            "posix | ls\n",
            "t.templates:1: a template before any `group`",
        ),
        (
            "group g\nfish | ls\n",
            "t.templates:2: an unknown shell `fish`",
        ),
        ("group g\nposix | ls «x»\n", "no list named `x`"),
        ("group g\nposix | ls «a|b\n", "a `«` with no `»` after it"),
        ("group g\nposix | ls a» b\n", "a `»` with no `«` before it"),
        ("group g\nposix | ls «a|«b|c»»\n", "a slot inside a slot"),
        (
            "fill x | a\ngroup g\nposix | ls\n",
            "t.templates:1: the list `x` fills no template",
        ),
        (
            "fill X | a\ngroup g\nposix | ls «X»\n",
            "a `fill` takes a name",
        ),
        (
            "group g\nposix | ls «a|a»\n",
            "t.templates:2: makes \"ls a\", which the template at t.templates:2 makes too",
        ),
        (
            "group g\nposix | ls\nposix | ls\n",
            "t.templates:3: makes \"ls\", which the template at t.templates:2 makes too",
        ),
        ("group g\nposix | ls«| »\n", "a space at an end"),
        ("group g\nposix safe | ls\n", "not a `group NAME`"),
        ("group\n", "not a `group NAME`"),
        ("group g\nposix | ls \\q\n", "an unknown escape"),
    ] {
        let got = expand("t.templates", source)
            .err()
            .unwrap_or_default()
            .join("\n");
        assert!(got.contains(why), "{source:?}: wanted {why:?}, got {got:?}");
    }
    let wide = format!(
        "fill n | {}\ngroup g\nposix | ls «n»\n",
        (0..=MOST_PER_TEMPLATE)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(" | ")
    );
    let got = expand("t.templates", &wide)
        .err()
        .unwrap_or_default()
        .join("\n");
    assert!(got.contains("more than 32: split it"), "{got}");
    // Templates that each make no more than one may, but together more
    // than the set may.
    let fillers: Vec<String> = (0..MOST_PER_TEMPLATE).map(|n| n.to_string()).collect();
    let templates = MOST_LINES / MOST_PER_TEMPLATE + 1;
    let many = format!(
        "fill n | {}\ngroup g\n{}",
        fillers.join(" | "),
        (0..templates)
            .map(|t| format!("posix | ls{t} «n»"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let got = expand("t.templates", &many)
        .err()
        .unwrap_or_default()
        .join("\n");
    let lines = templates * MOST_PER_TEMPLATE;
    assert_eq!(
        got,
        format!("t.templates: makes {lines} lines, more than {MOST_LINES}")
    );
    // The same line in another shell is another line.
    assert!(expand("t.templates", "group g\nposix | ls\ncmd | ls\n").is_ok());
}

/// The report counts each shell, each rule and each group, and names a line
/// whose answer moved, one that is new and one the templates no longer make.
#[test]
fn the_report_names_every_answer_that_moved() {
    let made = expand(
        "t.templates",
        "group g\nposix | ls\nposix | rm -rf ~\ncmd | dir\n",
    );
    let judged = judged(made.unwrap_or_default());
    let safe = Expect {
        safe: true,
        ..Expect::default()
    };
    let recorded: HashMap<(Shell, String), Expect> = [
        ((Shell::Posix, "ls".to_string()), safe.clone()),
        ((Shell::Posix, "rm -rf ~".to_string()), safe.clone()),
        ((Shell::Cmd, "gone".to_string()), safe),
    ]
    .into_iter()
    .collect();
    let (shown, differ) = report(&judged, &recorded);
    assert_eq!(differ, 3, "{shown}");
    for part in [
        "The everyday answers: 3 lines, 2 safe (66.7%), 1 risky: a false-alarm share of 33.3%",
        "posix             2      1   50.0%      1        50.0%",
        "cmd               1      1  100.0%      0         0.0%",
        "delete                  1          0      0      1        33.3%",
        "posix: g                            2      1      1        50.0%",
        "posix | rm -rf ~\n    was: safe\n    now: rules=delete first=delete reason=",
        "cmd | dir\n    was: not recorded\n    now: safe\n    made by: t.templates:4",
        "cmd | gone\n    was: safe\n    now: not made by the templates",
    ] {
        assert!(shown.contains(part), "wanted {part:?} in:\n{shown}");
    }
    let (shown, differ) = report(&judged[..1], &HashMap::new());
    assert_eq!(differ, 1, "{shown}");
    let recorded = [((Shell::Posix, "ls".to_string()), judged[0].answer.clone())];
    let (shown, differ) = report(&judged[..1], &recorded.into_iter().collect());
    assert_eq!(differ, 0, "{shown}");
    assert!(
        shown.contains("Every answer is the recorded one."),
        "{shown}"
    );
    assert_eq!(share(1, 3), "33.3%");
    assert_eq!(share(2, 3), "66.7%");
    assert_eq!(share(0, 0), "-");
}

/// The record writes each line as a case the shell guard's runner reads
/// back with the same answer.
#[test]
fn the_record_reads_back_as_written() {
    let made = expand(
        "t.templates",
        "group g\nposix | ls «a b|x\\\\y»\nposix | rm -rf ~\ngroup h\ncmd | echo \"a\"\n",
    );
    let judged = judged(made.unwrap_or_default());
    let text = written(&judged);
    assert!(text.contains("\n# posix: g\nposix safe | ls a b\nposix safe | ls x\\\\y\n"));
    assert!(text.contains("\n# cmd: h\ncmd safe | echo \"a\"\n"));
    let cases = cases::parse("t.cases", &text);
    assert!(cases.is_ok(), "{cases:?}");
    let cases = cases.unwrap_or_default();
    assert_eq!(cases.len(), judged.len());
    for (case, line) in cases.iter().zip(&judged) {
        assert_eq!(
            (case.shell, &case.line, &case.expect),
            (line.made.shell, &line.made.line, &line.answer)
        );
    }
}
