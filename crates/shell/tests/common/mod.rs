//! What the tables share: the directories commands run with, and a check
//! that names every row that came out wrong at once.

#![allow(dead_code, unreachable_pub, unused_imports)]

use milo_guards_core::testing;
pub use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_shell::{
    classify as judge, effect, effect_paths, Effect, Paths, Reach, Rule, Shell,
};

/// `classify`, and the line's `effect` held to agree with it (see
/// [`disagreements`]): the tests of `posix.rs` and `windows.rs` judge every
/// line through this, so each line they name goes through `effect` too.
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
/// alone does not count.)
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
            let wrong = (!flagged.is_empty()
                && matches!(effect(line, shell, paths), Effect::ReadsOnly(_)))
            .then(|| format!("reads only, but classify finds {flagged:?}: {line}"));
            wrong
                .into_iter()
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
        .map(|path| path.to_string_lossy().into_owned())
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
        text.trim_end_matches('/').to_string()
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
