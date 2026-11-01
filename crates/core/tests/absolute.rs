//! The absolute path a spelling names, as spelled: nothing read from the
//! disk, so a link is not followed and no case is folded. Each row is a
//! spelling a review could try.

use std::path::PathBuf;

use milo_guards_core::{Flavour, Paths, Resolver, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;

fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

fn of(paths: &Paths, flavour: Flavour, text: &str) -> Option<String> {
    let spelling = match text.strip_prefix('~') {
        Some(rest) => Spelling::Home(rest),
        None => Spelling::Plain(text),
    };
    Resolver::new(paths)
        .absolute(spelling, flavour)
        .map(|path: PathBuf| path.to_string_lossy().into_owned())
}

#[test]
fn a_posix_path_is_made_absolute_with_its_dots_applied() {
    let paths = posix();
    for (text, want) in [
        ("src/main.rs", "/home/me/work/repo/src/main.rs"),
        (".", "/home/me/work/repo"),
        ("./src/../a", "/home/me/work/repo/a"),
        ("src//a/", "/home/me/work/repo/src/a"),
        ("..", "/home/me/work"),
        ("../../../../..", "/"),
        ("/etc/hosts", "/etc/hosts"),
        ("/a/./b/../c", "/a/c"),
        ("/", "/"),
        ("~", "/home/me"),
        ("~/.ssh/config", "/home/me/.ssh/config"),
        ("~/../you", "/home/you"),
    ] {
        assert_eq!(of(&paths, POSIX, text).as_deref(), Some(want), "{text}");
    }
}

#[test]
fn a_posix_name_keeps_its_case_and_a_backslash_is_part_of_it() {
    let paths = posix();
    assert_eq!(
        of(&paths, POSIX, "Src\\A/B").as_deref(),
        Some("/home/me/work/repo/Src\\A/B")
    );
}

#[test]
fn the_names_of_the_root_volume_are_kept_as_spelled() {
    let mac = Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"]);
    assert_eq!(
        of(&mac, POSIX, "/System/Volumes/Data/Users/me/x").as_deref(),
        Some("/System/Volumes/Data/Users/me/x")
    );
    assert_eq!(
        of(&mac, POSIX, "/Volumes/Macintosh HD/x").as_deref(),
        Some("/Volumes/Macintosh HD/x")
    );
}

#[test]
fn a_windows_path_is_written_with_backslashes_and_its_drive() {
    let paths = windows();
    for (text, want) in [
        ("src/main.rs", r"C:\Users\me\dev\repo\src\main.rs"),
        (r"src\.\a\..\b", r"C:\Users\me\dev\repo\src\b"),
        ("..", r"C:\Users\me\dev"),
        (r"C:\", r"C:\"),
        ("c:/Users/me", r"C:\Users\me"),
        (r"D:\x\y", r"D:\x\y"),
        (r"\Windows", r"C:\Windows"),
        ("~", r"C:\Users\me"),
        (r"~\AppData", r"C:\Users\me\AppData"),
        ("C:x", r"C:\Users\me\dev\repo\x"),
        ("C:", r"C:\Users\me\dev\repo"),
        // A long path is the plain path it names.
        (r"\\?\C:\Users\me\x", r"C:\Users\me\x"),
        (r"\\?\UNC\Server\Share\dir", r"\\server\share\dir"),
        (r"\\server\share", r"\\server\share"),
        (r"\\server\share\a\..\b", r"\\server\share\b"),
    ] {
        assert_eq!(of(&paths, WINDOWS, text).as_deref(), Some(want), "{text}");
    }
}

#[test]
fn a_windows_name_loses_what_windows_drops_from_its_end() {
    let paths = windows();
    assert_eq!(
        of(&paths, WINDOWS, "src.\\a. ").as_deref(),
        Some(r"C:\Users\me\dev\repo\src\a")
    );
}

#[test]
fn what_is_not_one_place_on_a_disk_has_no_path() {
    let posix = posix();
    for text in ["/dev/null", "/dev/zero", "/dev/urandom"] {
        assert_eq!(of(&posix, POSIX, text), None, "{text}");
    }
    let windows = windows();
    for text in ["NUL", r"\\.\PhysicalDrive0", "D:x", "E:", "d:y/z"] {
        assert_eq!(of(&windows, WINDOWS, text), None, "{text}");
    }
}

#[test]
fn a_drive_relative_path_on_the_drive_of_the_working_directory_is_from_it() {
    let paths = windows();
    assert_eq!(
        of(&paths, WINDOWS, "c:x/../y").as_deref(),
        Some(r"C:\Users\me\dev\repo\y")
    );
}
