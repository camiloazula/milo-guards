//! What the tables share: the directories commands run with, a check that
//! names every row that came out wrong at once (and one that a row breaks one
//! rule and not another), the makers of the paths a
//! reads-only line lists, a clock and a linear-time check for the timed
//! tests, (in [`cases`]) the runner of the case files in `tests/cases`, and
//! (in [`inline`]) the builder of nested inline code.

#![allow(dead_code, unreachable_pub, unused_imports)]

pub mod cases;
pub mod inline;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use milo_guards_core::testing;
pub use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_shell::{
    classify as judge, effect, effect_paths, explain, Effect, How, Paths, Reach, ReadPath, Rule,
    Shell,
};

/// The format characters of Unicode (category `Cf`), which the tree writes
/// as escapes.
const FORMAT: [(char, char); 21] = [
    ('\u{00ad}', '\u{00ad}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061c}', '\u{061c}'),
    ('\u{06dd}', '\u{06dd}'),
    ('\u{070f}', '\u{070f}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08e2}', '\u{08e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// A text as the tree prints it: a control character, a line or paragraph
/// separator and a format character written as an escape.
pub fn as_printed(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control()
                || matches!(c, '\u{2028}' | '\u{2029}')
                || FORMAT.iter().any(|&(from, to)| (from..=to).contains(&c))
            {
                c.escape_debug().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// `classify`, and the line's `effect` and `explain` held to agree with it
/// (see [`disagreements`]): the tests of a finding's target and of what a
/// line nested too deep gives judge their lines through this, so each line
/// they name goes through both too, as every case of a case file does.
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
/// as root or reading a key (a delete, an overwrite, a disk wipe, a discard of git work, a
/// script it does not read, ...) and that `effect` nevertheless calls
/// reads-only. There must be none: a line the guard flags is not one that
/// only reads. (`sudo cat` is `Elevated` and reads only, and `cat ~/.ssh/id_rsa` is
/// `ReadSecret` and reads only, so neither alone counts.) And the lines whose
/// `explain` does not give `classify`'s findings and assessment, or whose tree
/// does not show every finding.
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
                .filter(|rule| !matches!(rule, Rule::Elevated | Rule::ReadSecret))
                .collect();
            let reads = (!flagged.is_empty()
                && matches!(effect(line, shell, paths), Effect::ReadsOnly(_)))
            .then(|| format!("reads only, but classify finds {flagged:?}: {line}"));
            let explanation = explain(line, shell, paths);
            let tree = explanation.to_string();
            let unshown = assessment
                .findings()
                .iter()
                .any(|finding| !tree.contains(&as_printed(&finding.reason)));
            let explained = (explanation.assessment() != assessment
                || explanation.findings() != assessment.findings()
                || unshown)
                .then(|| format!("explain and classify disagree: {line}"));
            reads
                .into_iter()
                .chain(explained)
                .chain(path_disagreement(shell, paths, line))
        })
        .collect()
}

/// Whether `effect_paths` of `line` disagrees with `effect`: the paths are
/// `Some` exactly when the line is reads-only, and when its reach is the
/// workspace every path is inside a workspace folder or a temporary folder by
/// its spelling. Every row of every table goes through this too.
pub fn path_disagreement(shell: Shell, paths: &Paths, line: &str) -> Option<String> {
    let effect = effect(line, shell, paths);
    let listed = effect_paths(line, shell, paths);
    let reads = matches!(effect, Effect::ReadsOnly(_));
    if listed.is_some() != reads {
        return Some(format!(
            "paths are {listed:?} but effect is {effect:?}: {line}"
        ));
    }
    if effect != Effect::ReadsOnly(Reach::Workspace) {
        return None;
    }
    let windows = shell != Shell::Posix;
    listed?
        .iter()
        .map(|read| read.path.to_string_lossy().into_owned())
        .find(|path| !stays(path, paths, windows))
        .map(|path| format!("reads only in the workspace, but lists {path}: {line}"))
}

/// Whether `path` is inside a workspace folder or a temporary folder, as
/// spelled (the macOS names for the root volume dropped).
fn stays(path: &str, paths: &Paths, windows: bool) -> bool {
    let key = |text: &str| {
        let text = if windows {
            text.replace('\\', "/").to_ascii_lowercase()
        } else {
            text.to_string()
        };
        let mut text = text.as_str();
        for link in [
            "/system/volumes/data",
            "/volumes/macintosh hd - data",
            "/volumes/macintosh hd",
        ] {
            if !windows && text.to_ascii_lowercase().starts_with(link) {
                text = &text[link.len()..];
            }
        }
        // `effect` judges by spelling, so the `..` the list keeps are applied
        // here, as the guard's own verdict applies them.
        let mut parts: Vec<&str> = Vec::new();
        for part in text.split('/').filter(|part| !part.is_empty()) {
            if part == ".." {
                parts.pop();
            } else {
                parts.push(part);
            }
        }
        format!("/{}", parts.join("/"))
            .trim_end_matches('/')
            .to_string()
    };
    let inside = |path: &str, folder: &str| {
        let (path, folder) = (key(path), key(folder));
        path == folder || path.starts_with(&format!("{folder}/"))
    };
    let home = paths.home.to_string_lossy().into_owned();
    let temporary: Vec<String> = if windows {
        vec![
            format!("{home}\\AppData\\Local\\Temp"),
            "C:\\Windows\\Temp".to_string(),
        ]
    } else {
        [
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "/private/var/tmp",
            "/var/folders",
            "/private/var/folders",
        ]
        .map(String::from)
        .to_vec()
    };
    paths
        .workspaces
        .iter()
        .map(|folder| folder.to_string_lossy().into_owned())
        .chain(temporary)
        .any(|folder| inside(path, &folder))
}

/// Every `lines` row breaks `has` and does not break `lacks`; the rows that
/// do not are named together.
pub fn only(shell: Shell, paths: &Paths, has: Rule, lacks: Rule, lines: &[&str]) {
    let wrong: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let found = rules(line, shell, paths);
            (!found.contains(&has) || found.contains(&lacks))
                .then(|| format!("expected {has:?} without {lacks:?}: {line}\n    got {found:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// `effect` of each `lines` row is `expected`; the rows that are not are
/// named together.
pub fn check_effect(shell: Shell, paths: &Paths, expected: Effect, lines: &[&str]) {
    let wrong: Vec<String> = lines
        .iter()
        .flat_map(|line| {
            let got = effect(line, shell, paths);
            let wrong = (got != expected)
                .then(|| format!("expected {expected:?}: {line}\n    got {got:?}"));
            wrong
                .into_iter()
                .chain(path_disagreement(shell, paths, line))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// `effect_paths` of each row's line is the row's list, and agrees with
/// `effect` (see [`path_disagreement`]); the rows that do not are named
/// together.
pub fn lists(shell: Shell, paths: &Paths, rows: &[(&str, Vec<ReadPath>)]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let got = effect_paths(line, shell, paths);
            let disagree = path_disagreement(shell, paths, line);
            (got.as_ref() != Some(want) || disagree.is_some())
                .then(|| format!("{line}\n    want {want:?}\n    got  {got:?}\n    {disagree:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A path read as it is.
pub fn exact(path: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Exact,
    }
}

/// A pattern: the folder it expands in, and the rest.
pub fn glob(path: &str, rest: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Glob(rest.to_string()),
    }
}

/// A walk of the folder at `path`, and whether it opens what it finds
/// through links.
pub fn walk(path: &str, follows_links: bool) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Tree { follows_links },
    }
}

/// The reason of the first finding of `rule` that `classify` gives `line`.
pub fn reason(line: &str, shell: Shell, paths: &Paths, rule: Rule) -> Option<String> {
    judge(line, shell, paths)
        .findings()
        .iter()
        .find(|finding| finding.rule == rule)
        .map(|finding| finding.reason.clone())
}

/// How long `classify` takes to judge `line`: the best of three runs, so a
/// busy machine slows it less.
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only a test times it, to catch a quadratic read"
)]
pub fn took(line: &str, shell: Shell, paths: &Paths) -> Duration {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            let _ = judge(line, shell, paths);
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

/// A line of a quarter of the size takes about a quarter of the time; one
/// that is read in quadratic time takes sixteen times as long. `line` makes
/// the line of a size; the two are compared with each other, so a slow or
/// busy machine, which slows both, does not fail it.
pub fn assert_linear(what: &str, shell: Shell, paths: &Paths, line: impl Fn(usize) -> String) {
    let floor = Duration::from_millis(5);
    let mut last = (Duration::ZERO, Duration::ZERO);
    let linear = (0..3).any(|_| {
        let small = took(&line(16 * 1024), shell, paths);
        let big = took(&line(64 * 1024), shell, paths);
        last = (small, big);
        big <= 10 * small.max(floor)
    });
    assert!(
        linear,
        "{what}: 16 KB took {:?}, 64 KB took {:?}",
        last.0, last.1
    );
}

/// `part` repeated to fill `size` bytes, less `slack` for what is around it.
pub fn filled(part: &str, size: usize, slack: usize) -> String {
    part.repeat((size - slack) / part.len())
}
