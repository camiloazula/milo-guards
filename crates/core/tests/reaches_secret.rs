//! What reading a folder or a pattern can reach below it: a secret that
//! `place` does not say, since it names only the path itself. A folder read
//! whole (`deep`) holds whatever is below it; a pattern picks what its parts
//! match, by the shell's own rules for hidden names.

use milo_guards_core::{Flavour, Paths, Resolver, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;

fn plain(paths: &Paths, flavour: Flavour, text: &str, hidden: bool, deep: bool) -> bool {
    let spelling = match text.strip_prefix('~') {
        Some(rest) => Spelling::Home(rest),
        None => Spelling::Plain(text),
    };
    Resolver::new(paths).reaches_secret(spelling, flavour, hidden, deep)
}

fn project() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn config() -> Paths {
    Paths::new("/home/me/.config", "/home/me", ["/home/me/.config"])
}

#[test]
fn a_project_folder_holds_no_secret() {
    let paths = project();
    for text in [
        ".",
        "src",
        "./src/..",
        "/home/me/work/repo",
        "src/*",
        "*",
        "**/*.rs",
        ".*",
    ] {
        for deep in [false, true] {
            assert!(!plain(&paths, POSIX, text, false, deep), "{text} {deep}");
        }
    }
}

#[test]
fn a_folder_holding_a_login_reaches_it_only_when_read_whole() {
    let paths = config();
    for text in [".", "/home/me/.config", "../.config"] {
        assert!(plain(&paths, POSIX, text, false, true), "{text}");
        assert!(!plain(&paths, POSIX, text, false, false), "{text}");
    }
    // Neither holds one below.
    assert!(!plain(&paths, POSIX, "sub", false, true));
    assert!(!plain(&paths, POSIX, "gh/..", false, false));
}

#[test]
fn the_home_folder_and_what_holds_it_hold_every_secret() {
    let paths = project();
    for text in ["~", "/home/me", "/home", "/", "~/", "/home/me/."] {
        assert!(plain(&paths, POSIX, text, false, true), "{text}");
    }
    // Another user's home, and the root user's.
    for text in ["/home/other", "/root", "/Users/other"] {
        assert!(plain(&paths, POSIX, text, false, true), "{text}");
    }
    assert!(!plain(&paths, POSIX, "/home/me/work", false, true));
    assert!(!plain(&paths, POSIX, "/tmp", false, true));
    assert!(!plain(&paths, POSIX, "/etc/hosts", false, true));
}

#[test]
fn a_secret_itself_or_below_one_is_reached() {
    let paths = project();
    for text in [
        "~/.ssh",
        "~/.ssh/id_rsa",
        "~/.aws/credentials",
        "/home/me/.config/gh/hosts.yml",
    ] {
        assert!(plain(&paths, POSIX, text, false, false), "{text}");
    }
}

#[test]
fn a_pattern_reaches_what_it_can_pick() {
    let paths = config();
    // `gh` is a login in this folder.
    for text in [
        "g*",
        "g?",
        "[g]h",
        "*",
        "gh/*",
        "g*/hosts.yml",
        "*/hosts.yml",
        "*/x",
    ] {
        assert!(plain(&paths, POSIX, text, false, false), "{text}");
    }
    for text in ["z*", "sub/*", "*.md", "?x", "x*/hosts.yml"] {
        assert!(!plain(&paths, POSIX, text, false, false), "{text}");
    }
    // Deep, a pattern that picks a folder holding one reaches it.
    assert!(plain(&paths, POSIX, "g*", false, true));
    assert!(!plain(&paths, POSIX, "z*", false, true));
}

#[test]
fn a_hidden_name_is_picked_by_the_shells_own_rules() {
    let paths = Paths::new("/home/me", "/home/me", ["/home/me"]);
    // A leading dot is not matched by `*` in a POSIX shell, unless dotglob.
    assert!(!plain(&paths, POSIX, "src/*", false, false));
    // Beneath the home folder the folder itself is the home.
    assert!(plain(&paths, POSIX, ".s*/id_rsa", false, false));
    assert!(plain(&paths, POSIX, ".*/id_rsa", false, false));
    let nested = Paths::new("/home/me/.config", "/home/me", ["/home/me/.config"]);
    // `*` names `gh` here, which is not hidden; a hidden login is picked by
    // `*` only with dotglob.
    assert!(plain(&nested, POSIX, "*", false, false));
    // With dotglob on, `*` matches `.ssh` too; without it a pattern with no
    // dot of its own never does.
    let home = Paths::new("/home/me", "/home/me", ["/home/me"]);
    assert!(plain(&home, POSIX, "*/id_rsa", true, false));
    assert!(!plain(&home, POSIX, "*/id_rsa", false, false));
    assert!(!plain(&home, POSIX, "src/*", true, false));
}

#[test]
fn a_windows_wildcard_matches_a_hidden_folder() {
    let paths = Paths::new(r"C:\Users\me", r"C:\Users\me", [r"C:\Users\me"]);
    for text in [r"*\*", r"*\id_rsa", r".\*\*", r".s*\id_rsa", r"*"] {
        assert!(plain(&paths, WINDOWS, text, false, true), "{text}");
    }
    assert!(plain(&paths, WINDOWS, r"*\id_rsa", false, false));
    assert!(!plain(&paths, WINDOWS, r"src\*", false, true));
    let roaming = Paths::new(
        r"C:\Users\me\AppData\Roaming",
        r"C:\Users\me",
        [r"C:\Users\me\AppData\Roaming"],
    );
    assert!(plain(&roaming, WINDOWS, r"*\*", false, true));
    assert!(plain(&roaming, WINDOWS, ".", false, true));
    assert!(!plain(&roaming, WINDOWS, ".", false, false));
    assert!(!plain(&roaming, WINDOWS, r"Code\*", false, true));
}

#[test]
fn what_cannot_be_spelled_out_reaches_one() {
    let paths = project();
    assert!(plain(&paths, WINDOWS, "D:x", false, false));
}
