//! What the tables share: the directories commands run with, and a check
//! that names every row that came out wrong at once.

#![allow(dead_code, unreachable_pub, unused_imports)]

use milo_guards_core::testing;
pub use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_shell::{classify as judge, effect, explain, Effect, Paths, Rule, Shell};

/// `classify`, and the line's `effect` and `explain` held to agree with it
/// (see [`disagreements`]): the tests of `posix.rs` and `windows.rs` judge
/// every line through this, so each line they name goes through both too.
pub fn classify(command: &str, shell: Shell, paths: &Paths) -> milo_guards_shell::Assessment {
    let wrong = disagreements(shell, paths, [command]);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    judge(command, shell, paths)
}

/// The rules a line breaks, in order.
pub fn rules(command: &str, shell: Shell, paths: &Paths) -> Vec<Rule> {
    testing::rules(command, |line| classify(line, shell, paths))
}

/// Every `safe` line is safe and every `risky` line breaks its rule; the
/// rows that do not are named together. Every row also goes through
/// [`effect`], whose answer must agree with `classify`'s: see
/// [`disagreements`].
pub fn check(shell: Shell, paths: &Paths, safe: &[&str], risky: &[(&str, Rule)]) {
    let rows = safe
        .iter()
        .copied()
        .chain(risky.iter().map(|(line, _)| *line));
    let wrong = disagreements(shell, paths, rows);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    testing::check(safe, risky, |line| classify(line, shell, paths));
}

/// The lines of `rows` that `classify` finds risky for anything but running
/// as root (a delete, an overwrite, a disk wipe, a discard of git work, a
/// script it does not read, ...) and that `effect` nevertheless calls
/// reads-only. There must be none: a line the guard flags is not one that
/// only reads. (`sudo cat` is `Elevated` and reads only, so an elevation
/// alone does not count.) And the lines whose `explain` does not give
/// `classify`'s findings and assessment, or whose tree does not show every
/// finding.
pub fn disagreements<'a>(
    shell: Shell,
    paths: &Paths,
    rows: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    rows.into_iter()
        .flat_map(|line| {
            let assessment = judge(line, shell, paths);
            let flagged: Vec<Rule> = assessment
                .findings()
                .iter()
                .map(|finding| finding.rule)
                .filter(|rule| *rule != Rule::Elevated)
                .collect();
            let reads = (!flagged.is_empty() && effect(line, shell, paths) == Effect::ReadsOnly)
                .then(|| format!("reads only, but classify finds {flagged:?}: {line}"));
            let explanation = explain(line, shell, paths);
            let tree = explanation.to_string();
            let unshown = assessment
                .findings()
                .iter()
                .any(|finding| !tree.contains(&finding.reason));
            let explained = (explanation.assessment() != assessment
                || explanation.findings() != assessment.findings()
                || unshown)
                .then(|| format!("explain and classify disagree: {line}"));
            reads.into_iter().chain(explained)
        })
        .collect()
}

/// `effect` of each `lines` row is `expected`; the rows that are not are
/// named together.
pub fn check_effect(shell: Shell, paths: &Paths, expected: Effect, lines: &[&str]) {
    let wrong: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let got = effect(line, shell, paths);
            (got != expected).then(|| format!("expected {expected:?}: {line}\n    got {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
