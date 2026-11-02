//! `pushd` takes its own options before the folder, as `cd` does: `-n` (the
//! stack changes and the shell stays), `-L` and `-P`. None of them is the
//! folder, so the line that follows is judged where `pushd` goes, and an
//! option the guard does not know makes the folder only known when it runs.

mod common;

use std::path::PathBuf;

use common::{check, check_effect, path_disagreement, posix};
use milo_guards_shell::{effect, effect_paths, Effect, How, Reach, ReadPath, Rule, Shell};

fn exact(path: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Exact,
    }
}

/// The list a line has, or the rows that differ, named together; no row's
/// list may hold an option as a path.
fn lists(rows: &[(&str, Vec<ReadPath>)]) {
    let paths = posix();
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let got = effect_paths(line, Shell::Posix, &paths);
            let disagree = path_disagreement(Shell::Posix, &paths, line);
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

#[test]
fn an_option_of_pushd_is_not_the_folder_it_moves_to() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("pushd -P ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -L ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -PL ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -P -L ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -P ~/.ssh; cat id_rsa", Rule::ReadSecret),
            ("pushd -P -- ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -- ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -P ~/.ssh >/dev/null; cat id_rsa", Rule::ReadSecret),
            ("pushd -P ~/.aws && cat credentials", Rule::ReadSecret),
            ("pushd ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("cd -P ~/.ssh && cat id_rsa", Rule::ReadSecret),
            ("pushd -L /etc && cat shadow", Rule::ReadSecret),
            ("pushd -P /etc && cat shadow", Rule::ReadSecret),
        ],
    );
}

#[test]
fn pushd_n_does_not_move_the_line() {
    // `-n` only changes the stack: what follows runs where the line began.
    check(
        Shell::Posix,
        &posix(),
        &[
            "pushd -n ~/.ssh && cat id_rsa",
            "pushd -n /etc && cat shadow",
            "pushd -n ~",
            "pushd -n",
            "pushd -nP ~/.ssh && cat README.md",
            "pushd -n -P ~/.ssh && cat README.md",
            "pushd -n -- ~/.ssh && cat README.md",
            "pushd -n +1 && cat README.md",
            "pushd -n $dir && cat README.md",
        ],
        &[],
    );
    lists(&[
        (
            "pushd -n ~/.ssh && cat id_rsa",
            vec![exact("/home/me/work/repo/id_rsa")],
        ),
        (
            "pushd -n -P /etc && cat shadow",
            vec![exact("/home/me/work/repo/shadow")],
        ),
        (
            "pushd -nP ~/.ssh && cat src/a.rs",
            vec![exact("/home/me/work/repo/src/a.rs")],
        ),
        ("pushd -n ~/.ssh", vec![]),
    ]);
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Workspace),
        &["pushd -n ~/.ssh && cat id_rsa", "pushd -n ~"],
    );
}

#[test]
fn the_line_after_pushd_p_is_read_from_the_folder_written() {
    let src = "/home/me/work/repo/src";
    lists(&[
        (
            "pushd -P ~/.ssh && cat id_rsa",
            vec![exact("/home/me/.ssh"), exact("/home/me/.ssh/id_rsa")],
        ),
        (
            "pushd -L /etc && cat shadow",
            vec![exact("/etc"), exact("/etc/shadow")],
        ),
        (
            "pushd -P src && cat a.rs",
            vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
        ),
        (
            "pushd -P src && cat ../../x",
            vec![exact(src), exact("/home/me/work/repo/src/../../x")],
        ),
        (
            "pushd -PL src && cat a.rs",
            vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
        ),
        (
            "pushd -- src && cat a.rs",
            vec![exact(src), exact("/home/me/work/repo/src/a.rs")],
        ),
        (
            "pushd -- -P && cat a",
            vec![
                exact("/home/me/work/repo/-P"),
                exact("/home/me/work/repo/-P/a"),
            ],
        ),
    ]);
    // `cat ../../x` from `src` reads outside the workspace.
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Beyond),
        &[
            "pushd -P src && cat ../../x",
            "pushd -L src && cat ../../x",
            "pushd -P ~/.ssh && cat id_rsa",
        ],
    );
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Workspace),
        &["pushd -P src && cat a.rs", "pushd -P src && cat ../x"],
    );
}

#[test]
fn an_option_the_guard_does_not_know_leaves_the_folder_unknown() {
    // Nothing says where these go, so what follows is judged from nowhere
    // known, never from a folder named for the option.
    let paths = posix();
    for line in [
        "pushd -q ~/.ssh && cat id_rsa",
        "pushd -s ~/.ssh && cat id_rsa",
        "pushd --help && cat id_rsa",
        "pushd --foo ~/.ssh && cat id_rsa",
        "pushd -P -q ~/.ssh && cat id_rsa",
        "pushd -Pq ~/.ssh && cat id_rsa",
        "pushd +1 && cat id_rsa",
        "pushd -1 && cat id_rsa",
        "pushd - && cat id_rsa",
        "pushd && cat id_rsa",
        "pushd -P && cat id_rsa",
        "pushd -P $dir && cat id_rsa",
        "pushd $opt ~/.ssh && cat id_rsa",
        "pushd -- && cat id_rsa",
    ] {
        assert_eq!(
            effect(line, Shell::Posix, &paths),
            Effect::Unknown,
            "{line}"
        );
        assert_eq!(effect_paths(line, Shell::Posix, &paths), None, "{line}");
        assert!(
            path_disagreement(Shell::Posix, &paths, line).is_none(),
            "{line}"
        );
    }
}

#[test]
fn no_option_of_pushd_is_listed_as_a_path() {
    let paths = posix();
    for line in [
        "pushd -P src && ls",
        "pushd -L src && ls",
        "pushd -n -P src && ls",
        "pushd -n src && ls",
        "pushd -n",
        "pushd -nL",
        "pushd -- src && ls",
    ] {
        let list = effect_paths(line, Shell::Posix, &paths).unwrap();
        for read in &list {
            let name = read.path.file_name().unwrap_or_default().to_string_lossy();
            assert!(!name.starts_with('-'), "{line}: {list:?}");
        }
    }
}
