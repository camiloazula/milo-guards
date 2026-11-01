//! `effect_paths` keeps every `..` where the line wrote it. The system
//! applies a `..` after it has followed the link before it, so
//! `cat link/../etc/hosts` with `link -> /etc` reads `/etc/hosts`, while the
//! same path with its `..` applied by spelling is `<cwd>/etc/hosts`. `effect`
//! keeps judging by spelling, as before.

mod common;

use std::path::PathBuf;

use common::{check_effect, path_disagreement, posix, windows};
use milo_guards_shell::{effect, effect_paths, Effect, How, Paths, Reach, ReadPath, Shell};

const ROOT: &str = "/home/me/work/repo";
const WIN_ROOT: &str = r"C:\Users\me\dev\repo";

fn exact(path: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Exact,
    }
}

fn glob(path: &str, rest: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Glob(rest.to_string()),
    }
}

fn tree(path: &str, follows_links: bool) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Tree { follows_links },
    }
}

/// The list a line has, or the rows of a table that differ, named together.
fn check(shell: Shell, paths: &Paths, rows: &[(&str, Vec<ReadPath>)]) {
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

/// A disk with a few links, played by a table (the guard does no I/O, and
/// neither do its tests): where `path` really is, each link followed before
/// the next part, so a `..` climbs from where the parts before it led. This
/// is what a caller does on the real disk, and what the docs say.
fn resolve(path: &str) -> String {
    const LINKS: [(&str, &str); 3] = [
        ("/home/me/work/repo/link", "/etc"),
        (
            "/home/me/work/repo/src/deep",
            "/home/me/work/repo/src/a/b/c",
        ),
        ("/home/me/work/repo/out", "/var/data/out"),
    ];
    let mut at = String::new();
    for name in path.split('/').filter(|name| !name.is_empty()) {
        if name == ".." {
            at.truncate(at.rfind('/').unwrap_or(0));
            continue;
        }
        at = format!("{at}/{name}");
        if let Some((_, to)) = LINKS.iter().find(|(from, _)| *from == at) {
            at = (*to).to_string();
        }
    }
    if at.is_empty() {
        "/".to_string()
    } else {
        at
    }
}

/// Apply the `..` of an absolute POSIX path by spelling: what the list was
/// before, and what `effect` still judges.
fn fold(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    format!("/{}", parts.join("/"))
}

/// The one path a line lists, when it lists exactly one.
fn only(line: &str, paths: &Paths) -> Option<PathBuf> {
    let list = effect_paths(line, Shell::Posix, paths)?;
    (list.len() == 1).then(|| list[0].path.clone())
}

#[test]
fn a_dotdot_after_a_link_is_left_for_the_caller_to_apply_on_the_disk() {
    let paths = posix();
    // The line of the issue, with `link -> /etc`: the shell reads
    // `/etc/hosts`, and the list lets a caller resolve to it.
    let line = "cat link/../etc/hosts";
    check(
        Shell::Posix,
        &paths,
        &[(line, vec![exact("/home/me/work/repo/link/../etc/hosts")])],
    );
    let listed = only(line, &paths).unwrap();
    assert_eq!(resolve(&listed.to_string_lossy()), "/etc/hosts");
    // `effect` judges by spelling, so it still calls this inside.
    assert_eq!(
        effect(line, Shell::Posix, &paths),
        Effect::ReadsOnly(Reach::Workspace)
    );
    // A `..` after a plain folder still lets a caller confirm it stays inside.
    let line = "cat src/../README.md";
    check(
        Shell::Posix,
        &paths,
        &[(line, vec![exact("/home/me/work/repo/src/../README.md")])],
    );
    let listed = only(line, &paths).unwrap();
    assert_eq!(
        resolve(&listed.to_string_lossy()),
        "/home/me/work/repo/README.md"
    );
    assert_eq!(
        effect(line, Shell::Posix, &paths),
        Effect::ReadsOnly(Reach::Workspace)
    );
}

#[test]
fn resolving_the_list_on_the_disk_gives_where_the_shell_reads() {
    let paths = posix();
    for (line, want) in [
        ("cat link/../etc/hosts", "/etc/hosts"),
        ("cat link/../hosts", "/hosts"),
        ("cat link/..", "/"),
        ("cat src/../README.md", "/home/me/work/repo/README.md"),
        ("cat src/deep/../x", "/home/me/work/repo/src/a/b/x"),
        ("cat src/deep/../../x", "/home/me/work/repo/src/a/x"),
        ("cat out/../x", "/var/data/x"),
        ("cat ./out/./../x", "/var/data/x"),
        ("cat ../x", "/home/me/work/x"),
        ("cat ../../x", "/home/me/x"),
        ("cat /home/me/work/repo/link/../passwd", "/passwd"),
        ("cat ~/work/repo/link/../passwd", "/passwd"),
        ("cat < link/../etc/hosts", "/etc/hosts"),
        ("cat a b link/../c", "/c"),
    ] {
        let list = effect_paths(line, Shell::Posix, &paths).unwrap();
        let resolved: Vec<String> = list
            .iter()
            .map(|read| resolve(&read.path.to_string_lossy()))
            .collect();
        assert!(resolved.contains(&want.to_string()), "{line}: {resolved:?}");
    }
}

#[test]
fn the_dotdot_of_every_way_of_reading_is_kept() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // An exact path, in every place a line names one.
            (
                "cat < link/../etc/hosts",
                vec![exact("/home/me/work/repo/link/../etc/hosts")],
            ),
            (
                "head -n 3 link/../a",
                vec![exact("/home/me/work/repo/link/../a")],
            ),
            ("ls link/..", vec![exact("/home/me/work/repo/link/..")]),
            ("cat ~/link/../x", vec![exact("/home/me/link/../x")]),
            ("cat /var/link/../x", vec![exact("/var/link/../x")]),
            ("cat ../x", vec![exact("/home/me/work/repo/../x")]),
            (
                "cat a/b/../../c",
                vec![exact("/home/me/work/repo/a/b/../../c")],
            ),
            // The folder a pattern expands in is a path the shell opens: a
            // `..` in it is kept. A `..` in the rest of the pattern is the
            // pattern's, as written.
            (
                "cat link/../*.rs",
                vec![glob("/home/me/work/repo/link/..", "*.rs")],
            ),
            (
                "cat link/../src/*/x.rs",
                vec![glob("/home/me/work/repo/link/../src", "*/x.rs")],
            ),
            (
                "cat src/*/../x",
                vec![glob("/home/me/work/repo/src", "*/../x")],
            ),
            (
                "for f in link/../*.rs; do cat \"$f\"; done",
                vec![glob("/home/me/work/repo/link/..", "*.rs")],
            ),
            // A walk starts at a path the shell opens.
            (
                "rg TODO link/..",
                vec![tree("/home/me/work/repo/link/..", false)],
            ),
            (
                "find link/.. -name x",
                vec![tree("/home/me/work/repo/link/..", false)],
            ),
            (
                "grep -R x link/../src",
                vec![tree("/home/me/work/repo/link/../src", true)],
            ),
            (
                "ls link/.. | xargs cat",
                vec![tree("/home/me/work/repo/link/..", true)],
            ),
            (
                "find link/.. -exec cat {} +",
                vec![tree("/home/me/work/repo/link/..", true)],
            ),
            // `git` reads the repository where `-C` goes, each folder from
            // the one before it.
            (
                "git -C link/.. status",
                vec![tree("/home/me/work/repo/link/..", false)],
            ),
            (
                "git -C link -C .. log",
                vec![tree("/home/me/work/repo/link/..", false)],
            ),
            // A part that starts with a dot can pick `..`: the folder above
            // the one it is in, which the disk names.
            (
                "cat link/.*",
                vec![
                    glob("/home/me/work/repo/link", ".*"),
                    exact("/home/me/work/repo/link/.."),
                ],
            ),
        ],
    );
}

#[test]
fn applying_the_dotdot_of_each_listed_path_by_spelling_is_the_old_answer() {
    // What the list held before the `..` were kept, which is also the place
    // `effect` judges: the same rows as `tests/paths.rs`, folded.
    let paths = posix();
    for (line, old) in [
        ("cat ./src/../a.txt", "/home/me/work/repo/a.txt"),
        ("cat ../x", "/home/me/work/x"),
        ("cat ../../../../../..", "/"),
        ("cat /a/./b/../c", "/a/c"),
        ("find ../other -name x", "/home/me/work/other"),
        ("cat ~/../you", "/home/you"),
        ("cat link/../etc/hosts", "/home/me/work/repo/etc/hosts"),
    ] {
        let list = effect_paths(line, Shell::Posix, &paths).unwrap();
        assert_eq!(list.len(), 1, "{line}: {list:?}");
        assert_eq!(fold(&list[0].path.to_string_lossy()), old, "{line}");
    }
}

#[test]
fn effect_keeps_judging_by_spelling() {
    let paths = posix();
    // Inside by spelling, whatever the link before the `..` is.
    check_effect(
        Shell::Posix,
        &paths,
        Effect::ReadsOnly(Reach::Workspace),
        &[
            "cat link/../etc/hosts",
            "cat src/../README.md",
            "cat src/../../repo/a",
            "cat ./a/../b",
            "rg TODO src/..",
            "cat link/../*.rs",
            "ls link/..",
            "cd link/.. && cat x",
            "cd src && cd .. && cat x",
        ],
    );
    // Beyond by spelling.
    check_effect(
        Shell::Posix,
        &paths,
        Effect::ReadsOnly(Reach::Beyond),
        &[
            "cat ../x",
            "cat src/../../x",
            "cat link/../../x",
            "cd .. && cat x",
            "cat /etc/../etc/hosts",
            "cat ~/link/../x",
        ],
    );
}

#[test]
fn a_cd_applies_its_own_dotdot_but_not_the_one_a_program_opens() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The shell folds the `..` of what it is given to `cd` itself
            // (`cd link/..` is the folder `link` is in), so the folder it
            // moves to is a place, and a read from there starts at it.
            (
                "cd link/.. && cat x",
                vec![exact(ROOT), exact("/home/me/work/repo/x")],
            ),
            (
                "cd src/../.. && cat x",
                vec![exact("/home/me/work"), exact("/home/me/work/x")],
            ),
            (
                "cd src && cd .. && ls",
                vec![exact(ROOT), exact("/home/me/work/repo/src")],
            ),
            // A `..` the program opens is applied after the links on the way,
            // from where the shell is: the folder the `cd` found.
            (
                "cd src/.. && cat ../x",
                vec![exact(ROOT), exact("/home/me/work/repo/../x")],
            ),
            (
                "cd link && cat ../x",
                vec![
                    exact("/home/me/work/repo/link"),
                    exact("/home/me/work/repo/link/../x"),
                ],
            ),
            (
                "cd src && cat link/../x",
                vec![
                    exact("/home/me/work/repo/src"),
                    exact("/home/me/work/repo/src/link/../x"),
                ],
            ),
            (
                "cd src && git -C ../link status",
                vec![
                    exact("/home/me/work/repo/src"),
                    tree("/home/me/work/repo/src/../link", false),
                ],
            ),
            (
                "cd src && cat *.rs link/../x",
                vec![
                    exact("/home/me/work/repo/src"),
                    glob("/home/me/work/repo/src", "*.rs"),
                    exact("/home/me/work/repo/src/link/../x"),
                ],
            ),
        ],
    );
}

#[test]
fn a_cd_that_keeps_the_physical_path_follows_links_before_its_dotdot() {
    // (`set -P` and `set -o physical` change a shell option the guard does
    // not read as harmless: those lines are not reads-only, so have no list.)
    for line in [
        "set -P; cd link/..; cat x",
        "set -o physical; cd link/..; cat x",
    ] {
        assert_eq!(effect_paths(line, Shell::Posix, &posix()), None, "{line}");
    }
    for line in [
        "cd -P link/.. && cat x",
        "cd -P link/..; cat x",
        "(cd -P link/.. && cat x)",
    ] {
        // `cd -P` lists its own flag as a path (over-listing, as `cat 0< x`
        // lists a path `0`): it is not one of the places asked about.
        let list: Vec<ReadPath> = effect_paths(line, Shell::Posix, &posix())
            .unwrap()
            .into_iter()
            .filter(|read| !read.path.ends_with("-P"))
            .collect();
        assert_eq!(
            list,
            vec![
                exact("/home/me/work/repo/link/.."),
                exact("/home/me/work/repo/link/../x"),
            ],
            "{line}"
        );
        // Physical, `link/..` is the parent of what `link` points to.
        let places: Vec<String> = list
            .iter()
            .map(|read| resolve(&read.path.to_string_lossy()))
            .collect();
        assert_eq!(places, ["/", "/x"], "{line}");
    }
}

#[test]
fn the_list_holds_each_spelling_once_and_is_sorted() {
    let paths = posix();
    let line = "cat link/../x link/../x ./link/../x src/../x x";
    let list = effect_paths(line, Shell::Posix, &paths).unwrap();
    assert_eq!(
        list,
        vec![
            exact("/home/me/work/repo/link/../x"),
            exact("/home/me/work/repo/src/../x"),
            exact("/home/me/work/repo/x"),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    for _ in 0..8 {
        assert_eq!(effect_paths(line, Shell::Posix, &paths), Some(list.clone()));
    }
}

#[test]
fn a_walk_over_the_same_spelling_is_kept_over_an_exact_path() {
    check(
        Shell::Posix,
        &posix(),
        &[
            (
                "cat link/..; ls link/..",
                vec![exact("/home/me/work/repo/link/..")],
            ),
            (
                "rg x link/..; cat link/..",
                vec![tree("/home/me/work/repo/link/..", false)],
            ),
            (
                "rg x link/..; grep -R x link/..",
                vec![tree("/home/me/work/repo/link/..", true)],
            ),
        ],
    );
}

#[test]
fn a_line_that_does_not_only_read_has_no_list() {
    let paths = posix();
    for line in [
        "rm link/../x",
        "mkdir link/../x",
        "$CMD link/../x",
        "cat $X/../y",
    ] {
        assert_eq!(effect_paths(line, Shell::Posix, &paths), None, "{line}");
    }
}

#[test]
fn powershell_and_cmd_paths_keep_their_dotdot_too() {
    let win = windows();
    check(
        Shell::PowerShell,
        &win,
        &[
            (
                r"Get-Content link\..\x",
                vec![exact(r"C:\Users\me\dev\repo\link\..\x")],
            ),
            (
                r"Get-Content ..\x",
                vec![exact(r"C:\Users\me\dev\repo\..\x")],
            ),
            (
                r"Get-Content C:\a\link\..\x",
                vec![exact(r"C:\a\link\..\x")],
            ),
            (
                r"Get-Content ~\link\..\x",
                vec![exact(r"C:\Users\me\link\..\x")],
            ),
            (
                r"Get-Content link\..\*.rs",
                vec![glob(r"C:\Users\me\dev\repo\link\..", "*.rs")],
            ),
            (
                r"Get-ChildItem link\.. -Recurse",
                vec![tree(r"C:\Users\me\dev\repo\link\..", true)],
            ),
            (
                r"cd link\..; Get-Content x",
                vec![exact(WIN_ROOT), exact(r"C:\Users\me\dev\repo\x")],
            ),
            (
                r"cd src; Get-Content ..\x",
                vec![
                    exact(r"C:\Users\me\dev\repo\src"),
                    exact(r"C:\Users\me\dev\repo\src\..\x"),
                ],
            ),
        ],
    );
    check(
        Shell::Cmd,
        &win,
        &[
            (
                r"type link\..\x",
                vec![exact(r"C:\Users\me\dev\repo\link\..\x")],
            ),
            (r"type ..\x", vec![exact(r"C:\Users\me\dev\repo\..\x")]),
            (r"dir link\..", vec![exact(r"C:\Users\me\dev\repo\link\..")]),
            (
                r"type link\..\*.txt",
                vec![glob(r"C:\Users\me\dev\repo\link\..", "*.txt")],
            ),
        ],
    );
    // By spelling, still inside.
    for (shell, line) in [
        (Shell::PowerShell, r"Get-Content link\..\x"),
        (Shell::Cmd, r"type link\..\x"),
    ] {
        assert_eq!(
            effect(line, shell, &win),
            Effect::ReadsOnly(Reach::Workspace),
            "{line}"
        );
    }
}
