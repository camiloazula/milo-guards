//! `Resolver::opened`: the absolute path the system opens, with every `..`
//! kept where it was written. The system applies a `..` after it has followed
//! the link before it, so a caller that checks the disk needs the `..` that
//! `Resolver::absolute` applies by spelling. The cases are in
//! `tests/cases/opened.cases`; what is left here holds the two answers to
//! each other.

mod common;

use common::cases::{posix, windows};
use milo_guards_core::{Flavour, Paths, Resolver, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;

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
fn every_spelling_keeps_its_dotdot_where_it_was_written() {
    common::cases::check("opened");
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
