//! `effect_paths` keeps every `..` where the line wrote it. The system
//! applies a `..` after it has followed the link before it, so
//! `cat link/../etc/hosts` with `link -> /etc` reads `/etc/hosts`, while the
//! same path with its `..` applied by spelling is `<cwd>/etc/hosts`. `effect`
//! keeps judging by spelling, as before.

mod common;

use std::path::{Path, PathBuf};

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
        // Which `cd` of a line is physical is not told (see the next test),
        // so the folded way is listed beside the kept one.
        assert_eq!(
            list,
            vec![
                exact("/home/me/work/repo"),
                exact("/home/me/work/repo/link/.."),
                exact("/home/me/work/repo/link/../x"),
                exact("/home/me/work/repo/x"),
            ],
            "{line}"
        );
        // Physical, `link/..` is the parent of what `link` points to.
        let places: Vec<String> = list
            .iter()
            .map(|read| resolve(&read.path.to_string_lossy()))
            .collect();
        assert_eq!(
            places,
            ["/home/me/work/repo", "/", "/x", "/home/me/work/repo/x"],
            "{line}"
        );
    }
}

/// Where each path of the list is on the table disk (none when the line has
/// no list).
fn places(line: &str, paths: &Paths) -> Vec<String> {
    effect_paths(line, Shell::Posix, paths)
        .unwrap_or_default()
        .iter()
        .map(|read| resolve(&read.path.to_string_lossy()))
        .collect()
}

#[test]
fn an_absolute_operand_does_not_borrow_the_folder_a_cd_moved_to() {
    // The line of the issue, spelled absolute after a `cd` whose folder is
    // the first part of the operand's own text. The `cd` does not change what
    // the operand opens: `link/..` after `link -> /etc` is `/`, and `etc` in
    // it is `/etc`, never `<cwd>/etc`.
    let paths = posix();
    let e = "/home/me/work/repo/link/../etc";
    for root in ["/home/me/work/repo", "~/work/repo"] {
        let cd = format!("cd {root}/link/..");
        let target = format!("{root}/link/../etc");
        // The `cd` goes to the folder `link` is in, and the operand is
        // listed once, with its `..` kept.
        let read = |want: ReadPath| vec![exact(ROOT), want];
        let rows = [
            (
                format!("{cd} && cat {target}/hosts"),
                read(exact(&format!("{e}/hosts"))),
                "/etc/hosts",
            ),
            (
                format!("{cd} && cat < {target}/hosts"),
                read(exact(&format!("{e}/hosts"))),
                "/etc/hosts",
            ),
            (
                format!("{cd}\ncat {target}/hosts"),
                read(exact(&format!("{e}/hosts"))),
                "/etc/hosts",
            ),
            (format!("{cd} && ls {target}"), read(exact(e)), "/etc"),
            (
                format!("{cd} && grep -r x {target}"),
                read(tree(e, false)),
                "/etc",
            ),
            (
                format!("{cd} && cat {target}/*"),
                read(glob(e, "*")),
                "/etc",
            ),
            (
                format!("{cd} && git -C {target} status"),
                read(tree(e, false)),
                "/etc",
            ),
        ];
        for (line, want, place) in &rows {
            check(Shell::Posix, &paths, &[(line.as_str(), want.clone())]);
            assert!(places(line, &paths).contains(&place.to_string()), "{line}");
        }
        // A `cd` that itself goes through the `..` is listed both ways (see
        // below), and the operand after it still once, kept.
        let line = format!("cd {target} && cat {target}/hosts");
        check(
            Shell::Posix,
            &paths,
            &[(
                line.as_str(),
                vec![
                    exact("/home/me/work/repo/etc"),
                    exact(e),
                    exact(&format!("{e}/hosts")),
                ],
            )],
        );
    }
}

#[test]
fn a_cd_target_with_a_part_after_a_dotdot_is_listed_both_ways() {
    // bash and zsh go to the path as written when the folded folder does not
    // exist: with `link -> /etc` and no `etc` beside `link`, `cd link/../etc`
    // lands in `/etc`, and a read from there opens `/etc/hosts`. The folded
    // `<cwd>/etc` is where it goes when it exists, so both are listed.
    let paths = posix();
    let both = |folder: &str, kept: &str| {
        vec![
            exact(folder),
            exact(&format!("{folder}/hosts")),
            exact(kept),
            exact(&format!("{kept}/hosts")),
        ]
    };
    let four = both("/home/me/work/repo/etc", "/home/me/work/repo/link/../etc");
    for line in [
        "cd link/../etc && cat hosts",
        "cd link/../etc; cat ./hosts",
        "cd link/../etc\ncat hosts",
        "pushd link/../etc && cat hosts",
    ] {
        check(Shell::Posix, &paths, &[(line, four.clone())]);
        assert!(
            places(line, &paths).contains(&"/etc/hosts".to_string()),
            "{line}"
        );
    }
    check(
        Shell::Posix,
        &paths,
        &[
            (
                "cd link/../etc && ls",
                vec![
                    exact("/home/me/work/repo/etc"),
                    exact("/home/me/work/repo/link/../etc"),
                ],
            ),
            // A link that leads deeper inside the workspace: the folded
            // folder is outside it, the physical one inside.
            (
                "cd src/deep/../../x && cat y",
                vec![
                    exact("/home/me/work/repo/src/deep/../../x"),
                    exact("/home/me/work/repo/src/deep/../../x/y"),
                    exact("/home/me/work/repo/x"),
                    exact("/home/me/work/repo/x/y"),
                ],
            ),
        ],
    );
    let places = places("cd src/deep/../../x && cat y", &paths);
    assert!(places.contains(&"/home/me/work/repo/src/a/x/y".to_string()));
    // A relative operand after it is joined to the folder, so it has both
    // ways too, and a `..` in it is the program's own, kept.
    let line = "cd link/../etc && cat ../x";
    let listed = effect_paths(line, Shell::Posix, &paths).unwrap();
    for want in [
        "/home/me/work/repo/etc/../x",
        "/home/me/work/repo/link/../etc/../x",
    ] {
        assert!(listed.contains(&exact(want)), "{line}: {listed:?}");
    }
    // The physical path (`cd -P`) is both ways too: which `cd` is physical is
    // not told, so the folded way is kept beside the kept one.
    let line = "cd -P link/../etc && cat hosts";
    let list: Vec<ReadPath> = effect_paths(line, Shell::Posix, &paths)
        .unwrap()
        .into_iter()
        .filter(|read| !read.path.ends_with("-P"))
        .collect();
    assert_eq!(list, four);
}

#[test]
fn a_cd_with_a_part_after_a_later_dotdot_is_listed_both_ways() {
    // bash, zsh and dash check the folder before every `..` that follows a
    // part (`cd a/../nonexist/..` fails although the folded folder exists),
    // and bash and zsh then go to the path as written: with `link -> /etc`
    // and no `etc` beside `link`, `cd link/../etc/..` goes to `/`.
    let paths = posix();
    let folded_and_kept = |kept: &str| {
        vec![
            exact(ROOT),
            exact(kept),
            exact(&format!("{kept}/x")),
            exact(&format!("{ROOT}/x")),
        ]
    };
    let kept = "/home/me/work/repo/link/../etc/..";
    for line in [
        "cd link/../etc/.. && cat x",
        "cd link/../etc && cd .. && cat x",
        "pushd link/../etc/.. && cat x",
    ] {
        let listed = effect_paths(line, Shell::Posix, &paths).unwrap();
        for want in folded_and_kept(kept) {
            assert!(listed.contains(&want), "{line}: {listed:?}");
        }
    }
    check(
        Shell::Posix,
        &paths,
        &[
            (
                "cd link/../a/b/../.. && cat x",
                folded_and_kept("/home/me/work/repo/link/../a/b/../.."),
            ),
            (
                "cd src/../x/.. && cat y",
                vec![
                    exact(ROOT),
                    exact("/home/me/work/repo/src/../x/.."),
                    exact("/home/me/work/repo/src/../x/../y"),
                    exact("/home/me/work/repo/y"),
                ],
            ),
        ],
    );
}

#[test]
fn a_cd_of_the_line_that_keeps_the_physical_path_does_not_hide_the_folded_way_of_another() {
    // The physical flag is the line's, but each `cd` has its own: the last of
    // `-L` and `-P` decides it, and a `cd` before the `-P` is logical. With
    // `link -> sub/deep` and `x -> ~/.ssh/id_rsa`, `cat x` after
    // `cd link/..` opens the key, and the folded `<cwd>/x` is that read.
    let paths = posix();
    for line in [
        "cd link/.. && cat x; cd -P .",
        "cd -P -L link/.. && cat x",
        "cd -PL link/.. && cat x",
        "cd -P sub && cd ../link/.. && cat x",
        "(cd -P sub); cd link/.. && cat x",
        "cd link/.. && cat x; pushd -P sub",
    ] {
        let listed = effect_paths(line, Shell::Posix, &paths).unwrap();
        assert!(
            listed.contains(&exact("/home/me/work/repo/x")),
            "{line}: {listed:?}"
        );
    }
    // The kept way is listed beside it.
    let listed = effect_paths("cd link/.. && cat x; cd -P .", Shell::Posix, &paths).unwrap();
    assert!(
        listed.contains(&exact("/home/me/work/repo/link/../x")),
        "{listed:?}"
    );
}

#[test]
fn a_cd_with_no_part_after_its_dotdot_is_one_way() {
    // A `..` with no part before it climbs from the folder the line is in,
    // which the guard knows. A folder that ends at its `..` is a leading part
    // of the text: it exists when the text does, so the shell goes there.
    check(
        Shell::Posix,
        &posix(),
        &[
            (
                "cd .. && cat x",
                vec![exact("/home/me/work"), exact("/home/me/work/x")],
            ),
            (
                "cd ../../etc && cat hosts",
                vec![exact("/home/me/etc"), exact("/home/me/etc/hosts")],
            ),
            (
                "cd ../.. && cat x",
                vec![exact("/home/me"), exact("/home/me/x")],
            ),
            (
                "cd link/.. && cd .. && ls",
                vec![exact("/home/me/work"), exact(ROOT)],
            ),
        ],
    );
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

#[test]
fn a_pattern_in_the_folder_a_cd_moved_to_is_listed_in_the_folded_folder() {
    // The shell goes to the folded folder and expands the pattern there. A
    // caller that resolves `<R>/link/..` on the disk follows the link and
    // expands a different folder, so the folded glob must be listed.
    let paths = posix();
    check(
        Shell::Posix,
        &paths,
        &[
            ("cd link/.. && cat *", vec![exact(ROOT), glob(ROOT, "*")]),
            (
                "cd link/../etc && cat *.conf",
                vec![
                    exact("/home/me/work/repo/etc"),
                    glob("/home/me/work/repo/etc", "*.conf"),
                    exact("/home/me/work/repo/link/../etc"),
                    glob("/home/me/work/repo/link/../etc", "*.conf"),
                ],
            ),
        ],
    );
    // `cd -P` keeps the physical path: the kept glob is listed beside the
    // folded one (`cd -P` lists its own flag as a path, left out here).
    let list: Vec<ReadPath> = effect_paths("cd -P link/.. && cat *", Shell::Posix, &paths)
        .unwrap()
        .into_iter()
        .filter(|read| !read.path.ends_with("-P"))
        .collect();
    assert_eq!(
        list,
        vec![
            exact(ROOT),
            glob(ROOT, "*"),
            exact("/home/me/work/repo/link/.."),
            glob("/home/me/work/repo/link/..", "*"),
        ]
    );
    // Every pattern after a cd that folds a `..`, whatever the pattern and
    // however the cd is written, has the folded folder.
    for line in [
        "cd link/.. && cat *.rs",
        "cd link/.. && grep x *",
        "cd link/.. && echo *",
        "cd link/.. && wc -l *",
        "cd link/.. && head *",
        "cd link/.. && cat ?",
        "cd link/.. && cat [ab]",
        "cd link/.. && cat .*",
        "cd link/.. && for f in *; do cat \"$f\"; done",
        "cd src/.. && cat *",
        "cd a/b/../.. && cat *",
        "cd src/../.. && cat *",
        "cd link && cd .. && cat *",
        "pushd link/.. && cat *",
        "cd link/..; cat *",
        "cd link/..\ncat *",
    ] {
        let listed = effect_paths(line, Shell::Posix, &paths).unwrap();
        let folder = if line.contains("src/../..") {
            "/home/me/work"
        } else {
            ROOT
        };
        assert!(
            listed
                .iter()
                .any(|read| matches!(read.how, How::Glob(_))
                    && read.path.as_path() == Path::new(folder)),
            "{line}: {listed:?}"
        );
    }
}
