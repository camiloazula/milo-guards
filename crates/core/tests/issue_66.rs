//! `Resolver::opened`: the absolute path the system opens, with every `..`
//! kept where it was written. The system applies a `..` after it has followed
//! the link before it, so a caller that checks the disk needs the `..` that
//! `Resolver::absolute` applies by spelling.

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

fn spelling(text: &str) -> Spelling<'_> {
    match text.strip_prefix('~') {
        Some(rest) => Spelling::Home(rest),
        None => Spelling::Plain(text),
    }
}

fn opened(paths: &Paths, flavour: Flavour, text: &str) -> Option<String> {
    Resolver::new(paths)
        .opened(spelling(text), flavour)
        .map(|path| path.to_string_lossy().into_owned())
}

fn applied(paths: &Paths, flavour: Flavour, text: &str) -> Option<String> {
    Resolver::new(paths)
        .absolute(spelling(text), flavour)
        .map(|path| path.to_string_lossy().into_owned())
}

/// Apply the `..` of an absolute path by spelling, as `absolute` does.
fn fold(path: &str, separator: char) -> String {
    let (root, rest) = if let Some(rest) = path.strip_prefix(separator) {
        (separator.to_string(), rest)
    } else {
        let (drive, rest) = path.split_at(3);
        (drive.to_string(), rest)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split(separator).filter(|part| !part.is_empty()) {
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    format!("{root}{}", parts.join(&separator.to_string()))
}

#[test]
fn a_posix_path_keeps_every_dotdot_where_it_was_written() {
    let paths = posix();
    for (text, want) in [
        // The issue's line: after a link, `..` is the parent of its target.
        ("link/../etc/hosts", "/home/me/work/repo/link/../etc/hosts"),
        ("src/../README.md", "/home/me/work/repo/src/../README.md"),
        ("./src/../a", "/home/me/work/repo/src/../a"),
        ("..", "/home/me/work/repo/.."),
        ("../x", "/home/me/work/repo/../x"),
        ("../../x", "/home/me/work/repo/../../x"),
        ("a/../../b", "/home/me/work/repo/a/../../b"),
        ("a/b/..", "/home/me/work/repo/a/b/.."),
        ("/a/link/../x", "/a/link/../x"),
        ("/a/./b/../c", "/a/b/../c"),
        ("~/link/../x", "/home/me/link/../x"),
        ("~/../you", "/home/me/../you"),
        // `.` is dropped, and so are an empty part and a closing separator.
        ("./a/./b", "/home/me/work/repo/a/b"),
        ("src//a/", "/home/me/work/repo/src/a"),
        (".", "/home/me/work/repo"),
        ("~", "/home/me"),
        ("/", "/"),
        // Nothing is above the root: `/..` is `/`, whatever is before it.
        ("/..", "/"),
        ("/../etc", "/etc"),
        ("/../../etc/../x", "/etc/../x"),
    ] {
        assert_eq!(opened(&paths, POSIX, text).as_deref(), Some(want), "{text}");
    }
}

#[test]
fn applying_the_dotdot_of_what_is_opened_gives_the_absolute_path() {
    let posix = posix();
    for text in [
        "link/../etc/hosts",
        "src/../README.md",
        "../../../../../..",
        "a/../../../../../../b",
        "~/../../../x",
        "/a/b/../../../..",
        "/a/../b/./c/..",
        "x/./y/../z/",
    ] {
        let kept = opened(&posix, POSIX, text).unwrap();
        assert_eq!(
            Some(fold(&kept, '/')),
            applied(&posix, POSIX, text),
            "{text}: {kept}"
        );
    }
    let windows = windows();
    for text in [
        r"link\..\x",
        r"..\..\x",
        r"C:\a\b\..\..\x",
        r"~\..\x",
        r"\..\x",
        r"src\.\a\..\b",
    ] {
        let kept = opened(&windows, WINDOWS, text).unwrap();
        assert_eq!(
            Some(fold(&kept, '\\')),
            applied(&windows, WINDOWS, text),
            "{text}: {kept}"
        );
    }
}

#[test]
fn a_windows_path_keeps_its_dotdot_with_backslashes_and_its_drive() {
    let paths = windows();
    for (text, want) in [
        (r"link\..\x", r"C:\Users\me\dev\repo\link\..\x"),
        (r"..\x", r"C:\Users\me\dev\repo\..\x"),
        ("../x", r"C:\Users\me\dev\repo\..\x"),
        (r"C:\a\link\..\b", r"C:\a\link\..\b"),
        (r"D:\x\..\y", r"D:\x\..\y"),
        (r"\Windows\..\x", r"C:\Windows\..\x"),
        (r"~\..\you", r"C:\Users\me\..\you"),
        (r"\\server\share\a\..\b", r"\\server\share\a\..\b"),
        (r"c:x\..\y", r"C:\Users\me\dev\repo\x\..\y"),
        // A long path is the plain path it names, its `..` kept.
        (r"\\?\C:\Users\me\x\..\y", r"C:\Users\me\x\..\y"),
        // Above a drive's root there is nothing to climb to.
        (r"C:\..\x", r"C:\x"),
        (r"\\server\share\..\x", r"\\server\share\x"),
    ] {
        assert_eq!(
            opened(&paths, WINDOWS, text).as_deref(),
            Some(want),
            "{text}"
        );
    }
}

#[test]
fn what_is_not_one_place_on_a_disk_has_no_path_either_way() {
    let posix = posix();
    for text in ["/dev/null", "/dev/zero"] {
        assert_eq!(opened(&posix, POSIX, text), None, "{text}");
    }
    let windows = windows();
    for text in ["NUL", r"\\.\PhysicalDrive0", "D:x", "d:y/z/../w"] {
        assert_eq!(opened(&windows, WINDOWS, text), None, "{text}");
    }
}

#[test]
fn a_path_with_no_dotdot_is_the_same_both_ways() {
    let posix = posix();
    for text in [
        "a.txt",
        "src/main.rs",
        "/etc/hosts",
        "~/.ssh/config",
        "~",
        ".",
    ] {
        assert_eq!(
            opened(&posix, POSIX, text),
            applied(&posix, POSIX, text),
            "{text}"
        );
    }
}
