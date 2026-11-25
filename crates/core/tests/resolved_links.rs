//! The links the caller has resolved (`Paths::links`): a path through one is
//! placed where it lands, `..` after it climbing from there, a link to a
//! link followed again up to the system's own limit, and a pattern that can
//! pick one read through it too. The cases are in `tests/cases/resolved_links.cases`;
//! what the API itself does is tested here.

mod common;

use std::path::PathBuf;

use milo_guards_core::{Flavour, Link, Paths, Place, Resolver, Spelling};

#[test]
fn a_path_through_a_link_is_placed_where_it_lands() {
    common::cases::check("resolved_links");
}

/// Every question a case file asks, so that each case is asked them all.
const QUESTIONS: [&str; 14] = [
    "place",
    "into",
    "place_hidden",
    "startup",
    "below",
    "picks",
    "holds",
    "named",
    "kernel",
    "git",
    "absolute",
    "opened",
    "reaches",
    "network",
];

/// A link no path of the cases goes through, and on Windows a drive mount
/// none is spelled through, turn the walk through links on: every question
/// of every case of the other files gets the answer it gets without them,
/// so the walk lands where the spelling did.
#[test]
fn a_link_no_path_goes_through_changes_no_answer() {
    let mut wrong = Vec::new();
    let mut asked = 0_usize;
    for name in [
        "absolute",
        "drives",
        "holds_protected",
        "named_secrets",
        "opened",
        "picks",
        "reaches_secret",
        "sensitive",
        "startup",
    ] {
        for case in common::cases::load(name) {
            let mut linked = case.clone();
            let windows = linked.paths.home.to_string_lossy().contains(':');
            // A mount is named beside the link on Windows, but not for the
            // drive mounts' own cases, which name the mounts they mean.
            linked.paths = if windows && name != "drives" {
                linked
                    .paths
                    .with_links([Link::new(r"Q:\nowhere\link", r"Q:\elsewhere")])
                    .with_drive_mounts(["/nowhere-mounted"])
            } else {
                linked
                    .paths
                    .with_links([Link::new("/nowhere/link", "/elsewhere")])
            };
            for question in QUESTIONS {
                asked += 1;
                let (plain, through) = (
                    common::cases::answer(&case, question),
                    common::cases::answer(&linked, question),
                );
                if plain != through {
                    wrong.push(format!(
                        "{}: {question} is {plain} without the link, {through} with it",
                        case.at
                    ));
                }
            }
        }
    }
    assert!(asked > 10_000, "only {asked} questions were asked");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn links_mounts_and_a_windows_home_are_added_by_each_call() {
    let paths = common::cases::posix();
    assert!(paths.links.is_empty() && paths.drive_mounts.is_empty());
    assert!(paths.windows_home.is_none());
    let paths = paths
        .with_links([Link::new("/home/me/work/repo/a", "/data")])
        .with_links([Link::new("/home/me/work/repo/b", "y")])
        .with_drive_mounts(["/mnt"])
        .with_drive_mounts(["/"])
        .with_windows_home(r"C:\Users\one")
        .with_windows_home(r"C:\Users\me");
    assert_eq!(
        paths.links.as_slice(),
        [
            Link::new("/home/me/work/repo/a", "/data"),
            Link::new("/home/me/work/repo/b", "y"),
        ]
    );
    assert_eq!(
        paths.drive_mounts,
        [PathBuf::from("/mnt"), PathBuf::from("/")]
    );
    assert_eq!(paths.windows_home, Some(PathBuf::from(r"C:\Users\me")));
    let resolver = Resolver::new(&paths);
    let place = |path| resolver.place(Spelling::Plain(path), Flavour::Posix);
    assert_eq!(place("a/b"), Place::Outside);
    assert_eq!(place("/mnt/c/Users/me"), Place::Home { exact: true });
    assert_eq!(place("/c/Users/me"), Place::Home { exact: true });
    assert_eq!(place("/mnt/c/Users/one"), Place::Outside);
}

/// A link sends what a guard is handed back by its spelling: the workspace a
/// path is in is the folder the caller named, as the caller spelled it.
#[test]
fn the_workspace_a_path_is_in_is_spelled_as_the_caller_spelled_it() {
    let paths = Paths::new("/mnt/c/Users/me/repo", "/home/me", ["/mnt/c/Users/me/repo"])
        .with_drive_mounts(["/mnt"])
        .with_links([Link::new("/mnt/c/Users/me/repo/lib", "vendor/lib")]);
    let resolver = Resolver::new(&paths);
    assert_eq!(
        resolver.workspace_of(Spelling::Plain("lib/x"), Flavour::Posix),
        Some(PathBuf::from("/mnt/c/Users/me/repo"))
    );
    // The key of a file is the same through a link, a mount and as Windows
    // spells it.
    let key = |path, flavour| resolver.key(Spelling::Plain(path), flavour);
    let through = key("lib/x", Flavour::Posix);
    assert!(through.is_some());
    assert_eq!(through, key("vendor/lib/x", Flavour::Posix));
    assert_eq!(
        through,
        key(r"C:\Users\me\repo\vendor\lib\x", Flavour::Windows)
    );
    // A workspace with a link in it is not clear: a plain name there may go
    // anywhere.
    assert!(!resolver.cwd_is_clear() && !resolver.cwd_is_clear_but_for_named());
    let unlinked = Resolver::new(&Paths::new(
        "/mnt/c/Users/me/repo",
        "/home/me",
        ["/mnt/c/Users/me/repo"],
    ));
    assert!(unlinked.cwd_is_clear());
    // The flavour is the machine's, whatever its home lands on.
    assert_eq!(resolver.flavour(), Flavour::Posix);
}
