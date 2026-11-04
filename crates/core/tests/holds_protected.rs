//! `Resolver::holds_protected`: the protected path a program can reach when
//! it changes files below a folder that the line does not name (a search, a
//! patch, an archive, a recursive copy): one the folder is, is under or
//! holds, whatever else the folder is. The cases are in
//! `tests/cases/holds_protected.cases`; `holds_protected_picked`, which takes
//! the names a search may act on, is tested here.

mod common;

#[test]
fn a_folder_holds_the_protected_paths_below_it() {
    common::cases::check("holds_protected");
}

/// What a search picks by name below a folder: a protected file whose name
/// it never acts on is not reached, while the folder it is in, the file
/// itself, a protected folder of any name and a file on Windows still are.
#[test]
fn a_search_reaches_a_protected_file_only_by_a_name_it_can_act_on() {
    use milo_guards_core::{Flavour, Protected, Resolver, Spelling};

    let posix = common::cases::posix().with_protected([
        Protected::file("/home/me/work/repo/.agent/rules.md", "the agent's rules"),
        Protected::folder("/home/me/work/repo/cfg", "the agent's settings"),
    ]);
    let resolver = Resolver::new(&posix);
    let logs = |name: &str| name == "debug.log";
    let rules = |name: &str| name == "rules.md";
    let held = |path: &str, acts_on: &dyn Fn(&str) -> bool| {
        resolver.holds_protected_picked(Spelling::Plain(path), Flavour::Posix, false, acts_on)
    };
    assert_eq!(held(".agent", &logs), None);
    assert_eq!(held("/home/me/work/repo/.agent", &logs), None);
    assert_eq!(held(".agent", &rules), Some("the agent's rules"));
    assert_eq!(held(".agent/rules.md", &logs), Some("the agent's rules"));
    assert_eq!(held("cfg", &logs), Some("the agent's settings"));
    assert_eq!(held(".", &logs), Some("the agent's settings"));
    assert_eq!(held("src", &rules), None);
    assert_eq!(
        resolver.holds_protected(Spelling::Plain(".agent"), Flavour::Posix, false),
        Some("the agent's rules")
    );

    let windows = common::cases::windows().with_protected([Protected::file(
        r"C:\Users\me\dev\repo\.agent\rules.md",
        "the agent's rules",
    )]);
    let resolver = Resolver::new(&windows);
    assert_eq!(
        resolver.holds_protected_picked(Spelling::Plain(".agent"), Flavour::Windows, false, &logs),
        Some("the agent's rules")
    );
}
