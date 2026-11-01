//! Files a tool runs on its own, as the path model says it: a write into one
//! is `Sensitive` with the kind `Startup`, found at any depth in a workspace
//! folder; `place`, which a read or a delete asks, still says the workspace's
//! own. Each row is a spelling a review could try.

use milo_guards_core::{Flavour, Paths, Place, Resolver, Sensitivity, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;
const WORDS: &str = "a file a tool runs on its own";

fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn mac() -> Paths {
    Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"])
}

fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

fn startup(paths: &Paths, flavour: Flavour, path: &str) -> Option<&'static str> {
    Resolver::new(paths).startup(Spelling::Plain(path), flavour, false)
}

fn below(paths: &Paths, flavour: Flavour, path: &str) -> Option<&'static str> {
    Resolver::new(paths).startup_below(Spelling::Plain(path), flavour, false)
}

fn into(paths: &Paths, flavour: Flavour, path: &str) -> Place {
    Resolver::new(paths).place_into(Spelling::Plain(path), flavour, false)
}

fn wrong(rows: &[(&str, bool)], got: impl Fn(&str) -> Option<&'static str>) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(path, found)| {
            let got = got(path);
            let expected = found.then_some(WORDS);
            (got != expected).then(|| format!("{path}: expected {expected:?}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_write_into_one_is_sensitive_and_everything_else_is_unchanged() {
    let paths = posix();
    let resolver = Resolver::new(&paths);
    let write = |path| resolver.place_into(Spelling::Plain(path), POSIX, false);
    let read = |path| resolver.place(Spelling::Plain(path), POSIX);
    let hidden = |path| resolver.place_hidden(Spelling::Plain(path), POSIX, false);
    for path in [
        ".envrc",
        ".vscode/tasks.json",
        ".github/workflows/ci.yml",
        ".husky/pre-commit",
        "src/deep/.envrc",
    ] {
        assert_eq!(
            write(path),
            Place::Sensitive(WORDS, Sensitivity::Startup),
            "{path}"
        );
        // A read, a delete and a move ask `place`, and `place_hidden`.
        assert_eq!(read(path), Place::Inside, "{path}");
        assert_eq!(hidden(path), Place::Inside, "{path}");
    }
    for path in ["Makefile", "justfile", "package.json", "src/main.rs"] {
        assert_eq!(write(path), Place::Inside, "{path}");
    }
}

#[test]
fn only_a_workspaces_own_paths_are_one() {
    let paths = posix();
    let history = Place::Sensitive("the repository's history", Sensitivity::History);
    let resolver = Resolver::new(&paths);
    for (path, place) in [
        (".git/.envrc", history),
        (".git/hooks/pre-commit", history),
        ("/home/me/other/.envrc", Place::Outside),
        ("/home/me/.envrc", Place::Home { exact: false }),
        ("/tmp/x/.envrc", Place::Temp { exact: false }),
        ("/etc/.envrc", Place::Top("a system folder")),
        (
            "/home/me/.ssh/.envrc",
            Place::Sensitive("your SSH keys", Sensitivity::Secret),
        ),
        (
            "/home/me/.bashrc",
            Place::Sensitive("a shell startup file", Sensitivity::Startup),
        ),
    ] {
        let spelled = Spelling::Plain(path);
        // What a write into it is, is what it was.
        assert_eq!(
            resolver.place_into(spelled, POSIX, false),
            resolver.place(spelled, POSIX),
            "{path}"
        );
        assert_eq!(startup(&paths, POSIX, path), None, "{path}");
        assert_eq!(below(&paths, POSIX, path), None, "{path}");
        let _ = place;
    }
}

#[test]
fn a_posix_machine_finds_every_spelling() {
    let paths = posix();
    wrong(
        &[
            (".envrc", true),
            ("./.envrc", true),
            ("src/../.envrc", true),
            (".//.envrc", true),
            ("/home/me/work/repo/.envrc", true),
            ("/home/me/work/./repo/.envrc", true),
            ("../repo/.envrc", true),
            (".vscode//tasks.json", true),
            (".vscode/./tasks.json", true),
            (".vscode/x/../tasks.json", true),
            (".github/workflows/", true),
            (".github/workflows/a/b/c/d.yml", true),
            ("a/b/c/.vscode/launch.json", true),
            ("a/.cursor/mcp.json", true),
            ("a/.mcp.json", true),
            (".ENVRC", true),
            (".VSCODE/TASKS.JSON", true),
            ("jenkinsfile", true),
            ("LeftHook-Local.YAML", true),
            ("lefthoo\u{212A}.yml", true),
            // A backslash is part of a name on POSIX.
            (r".vscode\tasks.json", false),
            (r".github\workflows\ci.yml", false),
            // Near misses are plain names.
            (".envrcx", false),
            ("x.envrc", false),
            (".env", false),
            (".vscode", false),
            (".vscode/settings.json", false),
            (".vscodex/tasks.json", false),
            (".github", false),
            (".github/workflows-old/x", false),
            (".githubx/workflows/x", false),
            (".husky-x/x", false),
            ("workflows/ci.yml", false),
            ("Makefile", false),
            ("justfile", false),
            ("package.json", false),
            (".cargo/config.toml", false),
            // A Windows short name is a plain name on POSIX.
            ("VSCODE~1/TASKS~1.JSO", false),
            ("ENVRC~1", false),
        ],
        |path| startup(&paths, POSIX, path),
    );
}

#[test]
fn a_mac_reads_its_links_and_its_fold() {
    let paths = mac();
    wrong(
        &[
            (".envrc", true),
            (".ENVRC", true),
            ("/Users/me/dev/repo/.envrc", true),
            ("/System/Volumes/Data/Users/me/dev/repo/.envrc", true),
            (
                "/Volumes/Macintosh HD/Users/me/dev/repo/.vscode/tasks.json",
                true,
            ),
            (
                "/Volumes/Macintosh HD - Data/Users/me/dev/repo/.github/workflows/x",
                true,
            ),
            (
                "../../../../System/Volumes/Data/Users/me/dev/repo/.envrc",
                true,
            ),
            (".vſcode/tasks.json", true),
            ("/users/ME/dev/repo/.envrc", false),
            ("/Users/me/other/.envrc", false),
            ("Makefile", false),
        ],
        |path| startup(&paths, POSIX, path),
    );
}

#[test]
fn windows_reads_every_spelling_as_one_name() {
    let paths = windows();
    wrong(
        &[
            (".envrc", true),
            (r".vscode\tasks.json", true),
            (".vscode/tasks.json", true),
            (r".vscode\/tasks.json", true),
            (r".vscode\\tasks.json", true),
            (r"C:\Users\me\dev\repo\.envrc", true),
            (r"c:\users\ME\dev\REPO\.ENVRC", true),
            (r"\\?\C:\Users\me\dev\repo\.envrc", true),
            (r"\Users\me\dev\repo\.envrc", true),
            ("C:.envrc", true),
            (".envrc.", true),
            (".envrc ", true),
            (r".vscode.\tasks.json", true),
            (r".github.\workflows.\x.yml", true),
            (".ENVRC", true),
            (r".GITHUB\WORKFLOWS\X.YML", true),
            ("ENVRC~1", true),
            (r"VSCODE~1\TASKS~1.JSO", true),
            (r"VSCODE~1\tasks.json", true),
            (r"GITHUB~1\WORKFL~1\x.yml", true),
            (r"GITHUB~1\ACTION~1\x\a.yml", true),
            (r"HUSKY~1\pre-commit", true),
            ("GITLAB~1.YML", true),
            ("LEFTHO~1.YML", true),
            ("JENKIN~1", true),
            ("VS1A2B~1\\tasks.json", true),
            (r"src\ENVRC~1", true),
            // What Windows cannot read to a name is `Unknown`, not one.
            (r".vscode\tasks.json::$DATA", false),
            (r".envrc:s", false),
            (r"D:.envrc", false),
            (r".github\workflows\x \y.yml", false),
            // Plain names.
            ("PROGRA~1", false),
            ("ENVRCX~1", false),
            (r"VSCODE~1\SETTIN~1.JSO", false),
            (r".vscode\settings.json", false),
            ("Makefile", false),
            (r"C:\Users\me\other\.envrc", false),
        ],
        |path| startup(&paths, WINDOWS, path),
    );
}

#[test]
fn a_folder_that_holds_one_counts_for_a_write_that_can_replace_what_is_below() {
    let paths = posix();
    wrong(
        &[
            // The place itself.
            (".github/workflows", true),
            (".vscode/tasks.json", true),
            // A folder that ends in the first names of one.
            (".github", true),
            (".vscode", true),
            (".idea", true),
            (".cursor", true),
            ("sub/.github", true),
            ("sub/.vscode/", true),
            ("./.GitHub", true),
            ("src/../.idea", true),
            // Not one: the workspace and any folder can hold one, which a
            // name cannot tell.
            (".", false),
            ("/home/me/work/repo", false),
            ("src", false),
            ("dist", false),
            (".config", false),
            (".vscodex", false),
            (".github-x", false),
            ("workflows", false),
            ("/tmp/x/.github", false),
            ("/home/me/other/.github", false),
        ],
        |path| below(&paths, POSIX, path),
    );
    let paths = windows();
    wrong(
        &[
            (".github", true),
            (r"GITHUB~1", true),
            (r"VSCODE~1", true),
            (r".GITHUB.", true),
            (r"sub\.vscode", true),
            ("src", false),
            ("PROGRA~1", false),
        ],
        |path| below(&paths, WINDOWS, path),
    );
}

#[test]
fn a_pattern_that_can_pick_one_is_one() {
    let paths = posix();
    wrong(
        &[
            // Below a folder on the list.
            (".github/workflows/*", true),
            (".github/workflows/*.yml", true),
            (".github/workflows/c?.yml", true),
            (".github/workflows/[c]i.yml", true),
            (".husky/*", true),
            ("sub/.husky/pre-*", true),
            (".devcontainer/*", true),
            (".circleci/*", true),
            // A pattern that picks the last names of one.
            (".vscode/*.json", true),
            (".vscode/*", true),
            (".vscode/t*", true),
            (".vscode/[t]asks.json", true),
            (".vscode/?asks.json", true),
            (".cursor/mcp.*", true),
            (".github/*/ci.yml", true),
            (".github/*", true),
            ("src/.vscode/*.json", true),
            // A pattern that names one by a part that is more than stars.
            ("*.yml", true),
            ("src/*.yml", true),
            ("lefthook.*", true),
            ("Jenkins*", true),
            ("*/Jenkinsfile", true),
            ("**/Jenkinsfile", true),
            ("src/**/Jenkinsfile", true),
            // Wildcards alone take what the folder holds, which is its own.
            ("*", false),
            ("src/*", false),
            ("src/*/*", false),
            ("src/**", false),
            ("**/*", false),
            ("src/?*", false),
            // Patterns that cannot pick one.
            ("*.rs", false),
            ("src/*.js", false),
            ("*.md", false),
            ("*.json", false),
            ("*.toml", false),
            (".vscode/s*", false),
            (".vscode/*.txt", false),
            (".github/*.md", false),
            (".github/ISSUE_*/*", false),
            ("lefthook.y", false),
            ("Makefile*", false),
            ("justfil?", false),
            ("package.*", false),
        ],
        |path| startup(&paths, POSIX, path),
    );
}

/// A pattern whose first part starts with a dot can pick `.git`, so it is
/// already the repository's history at the workspace root and below it: what
/// it is says so, and nothing is added.
#[test]
fn a_pattern_that_can_pick_a_dot_name_is_already_the_histories_own() {
    let paths = posix();
    let history = Place::Sensitive(
        "a hidden file such as the repository's history",
        Sensitivity::History,
    );
    for path in [
        ".env*",
        ".?nvrc",
        ".e*",
        "*/.envrc",
        ".*/mcp.json",
        ".*/tasks.json",
        "src/.env*",
    ] {
        assert_eq!(into(&paths, POSIX, path), history, "{path}");
        assert_eq!(startup(&paths, POSIX, path), None, "{path}");
    }
}

#[test]
fn a_wildcard_picks_a_leading_dot_where_the_shell_says_so() {
    let paths = posix();
    let resolver = Resolver::new(&paths);
    for (path, plain, dotted) in [
        ("*/tasks.json", false, true),
        ("*/*.json", false, true),
        ("*.json", false, true),
        ("[.]envrc", false, true),
        (".vscode/[t]asks.json", true, true),
        ("*/mcp.json", false, true),
        ("*", false, false),
    ] {
        for (hidden, expected) in [(false, plain), (true, dotted)] {
            let got = resolver
                .startup(Spelling::Plain(path), POSIX, hidden)
                .is_some();
            assert_eq!(got, expected, "{path} hidden={hidden}");
        }
    }
    // On Windows a wildcard always matches a leading dot.
    let windows = windows();
    wrong(
        &[
            ("*.json", true),
            ("*.yml", true),
            (r"*\tasks.json", true),
            (r"*\*.json", true),
            (r".vscode\*.json", true),
            (r"GITHUB~1\workflows\*", true),
            (r"VSCODE~*\tasks.json", true),
            (r"VSCODE~1\*", true),
            ("*.rs", false),
            ("*", false),
            (r"src\*", false),
        ],
        |path| startup(&windows, WINDOWS, path),
    );
}

#[test]
fn a_pattern_that_goes_below_a_folder_by_a_dot_dot_is_read_where_it_lands() {
    let paths = posix();
    wrong(
        &[
            ("src/*/../../.envrc", true),
            ("src/*/../../.vscode/tasks.json", true),
            ("src/*/../x", false),
            ("src/*/../../.vscode/settings.json", false),
        ],
        |path| startup(&paths, POSIX, path),
    );
}

#[test]
fn a_home_spelling_reads_from_the_home_directory() {
    // The home directory as the workspace.
    let paths = Paths::new("/home/me", "/home/me", ["/home/me"]);
    let resolver = Resolver::new(&paths);
    let from_home = |rest| resolver.startup(Spelling::Home(rest), POSIX, false);
    assert_eq!(from_home("proj/.envrc"), Some(WORDS));
    assert_eq!(from_home(".vscode/tasks.json"), Some(WORDS));
    assert_eq!(from_home("proj/Makefile"), None);
    // The home directory's own startup files and keys are what they were.
    assert_eq!(from_home(".bashrc"), None);
    assert_eq!(from_home(".ssh/id_rsa"), None);
    // Beside the workspace, not in it.
    let paths = posix();
    let resolver = Resolver::new(&paths);
    assert_eq!(
        resolver.startup(Spelling::Home(".envrc"), POSIX, false),
        None
    );
    assert_eq!(
        resolver.startup(Spelling::Home("work/repo/.envrc"), POSIX, false),
        Some(WORDS)
    );
}

#[test]
fn every_workspace_folder_counts() {
    let paths = Paths::new(
        "/home/me/work/repo",
        "/home/me",
        ["/home/me/work/repo", "/home/me/work/other"],
    );
    assert_eq!(
        startup(&paths, POSIX, "/home/me/work/other/.envrc"),
        Some(WORDS)
    );
    assert_eq!(startup(&paths, POSIX, "/home/me/work/third/.envrc"), None);
}

#[test]
fn a_protected_path_wins() {
    let paths = posix().with_protected([milo_guards_core::Protected::folder(
        "/home/me/work/repo/.github",
        "the agent's rules",
    )]);
    let resolver = Resolver::new(&paths);
    assert_eq!(
        resolver.place_into(Spelling::Plain(".github/workflows/ci.yml"), POSIX, false),
        Place::Protected("the agent's rules")
    );
    assert_eq!(startup(&paths, POSIX, ".github/workflows/ci.yml"), None);
    assert_eq!(startup(&paths, POSIX, ".vscode/tasks.json"), Some(WORDS));
}
