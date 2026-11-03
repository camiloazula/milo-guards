//! What the path model says about keys, credentials and the paths that reach
//! them by another spelling: the kind of a sensitive place, names without
//! case, Windows short names, other users' homes, long paths and drive-
//! relative paths. The cases, each a spelling a review could try, are in
//! `tests/cases/sensitive.cases`; what is left here is made in a loop or asks
//! the API itself.

mod common;

use common::cases::{macos, posix, windows};
use milo_guards_core::{Flavour, Paths, Place, Resolver, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;

fn at(paths: &Paths, path: &str, flavour: Flavour) -> Place {
    Resolver::new(paths).place(Spelling::Plain(path), flavour)
}

#[test]
fn every_spelling_lands_where_the_cases_say() {
    common::cases::check("sensitive");
}

#[test]
fn the_flavour_follows_the_home_directory() {
    assert_eq!(Resolver::new(&posix()).flavour(), POSIX);
    assert_eq!(Resolver::new(&macos()).flavour(), POSIX);
    assert_eq!(Resolver::new(&windows()).flavour(), WINDOWS);
    let share = Paths::new(r"\\srv\home\me", r"\\srv\home\me", [r"\\srv\home\me"]);
    assert_eq!(Resolver::new(&share).flavour(), WINDOWS);
    assert_eq!(
        Resolver::new(&Paths::new("", "", Vec::<&str>::new())).flavour(),
        POSIX
    );
    // The folders the caller names may be spelled as a long path.
    let verbatim = Paths::new(
        r"\\?\C:\Users\me\dev\repo",
        r"\\?\C:\Users\me",
        [r"\\?\C:\Users\me\dev\repo"],
    );
    assert_eq!(Resolver::new(&verbatim).flavour(), WINDOWS);
}

#[test]
fn a_drive_relative_path_is_one_file_with_its_absolute_spelling() {
    let paths = windows();
    let resolver = Resolver::new(&paths);
    let key = |path| resolver.key(Spelling::Plain(path), WINDOWS);
    assert_eq!(key("C:x.ps1"), key(r"c:\users\me\dev\repo\x.ps1"));
    assert_eq!(key("D:x.ps1"), None);
}

#[test]
fn only_the_names_ntfs_folds_make_the_workspace_the_workspace() {
    // The Kelvin sign, the Ångström sign, the Ohm sign and the capital sharp
    // s fold to `k`, `å`, `ω` and `ß` in the widest reading (APFS), not on
    // NTFS: a folder by those names is another folder, so it is not the
    // workspace's own. Matching too much here would open a hole. Where
    // matching too much fails closed, the wide fold stays (the `kim` cases).
    for (workspace, other) in [
        ("work", "wor\u{212a}"),
        ("WORK", "wor\u{212a}"),
        ("wor\u{e5}", "wor\u{212b}"),
        ("wor\u{c5}", "wor\u{212b}"),
        ("wor\u{3c9}", "wor\u{2126}"),
        ("wor\u{3a9}", "wor\u{2126}"),
        ("stra\u{df}e", "stra\u{1e9e}e"),
        ("work", "wor\u{17f}"),
    ] {
        let dir = format!(r"C:\Users\me\{workspace}");
        let paths = Paths::new(dir.as_str(), r"C:\Users\me", [dir.as_str()]);
        let same = format!(r"{dir}\x");
        let folded = format!(r"C:\Users\me\{other}\x");
        assert_eq!(at(&paths, &same, WINDOWS), Place::Inside, "{same}");
        assert_eq!(at(&paths, &folded, WINDOWS), Place::Outside, "{folded}");
        let folded = format!(r"C:\Users\me\{other}");
        assert_eq!(at(&paths, &folded, WINDOWS), Place::Outside, "{folded}");
        let folded = format!(r"C:\USERS\ME\{}\x", other.to_uppercase());
        assert_ne!(at(&paths, &folded, WINDOWS), Place::Inside, "{folded}");
    }
}
