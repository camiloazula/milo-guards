//! What the caller gates with: a write to it breaks `write_protected` with
//! the caller's words, wherever it sits and however it is spelled, and a read
//! of it is safe.

mod common;

use common::{exactly, macos, posix, risky, safe, windows};
use milo_guards_file::{judge, Access, Paths, Protected, Rule};

const W: &str = "the agent's settings";

/// A folder in the home directory, a folder in the workspace and a file in
/// the workspace.
fn posix_paths() -> Paths {
    posix().with_protected([
        Protected::folder("/home/me/.agent", W),
        Protected::folder("/home/me/work/repo/.agent", W),
        Protected::file("/home/me/work/repo/conf/app/x.yaml", W),
    ])
}

fn windows_paths() -> Paths {
    windows().with_protected([
        Protected::folder(r"C:\Users\me\.agent", W),
        Protected::folder(r"C:\Users\me\dev\repo\.agent", W),
        Protected::file(r"C:\Users\me\dev\repo\conf\app\x.yaml", W),
    ])
}

#[test]
fn a_write_to_a_protected_path_is_a_finding_with_the_callers_words() {
    let paths = posix_paths();
    risky(
        Access::Write,
        &paths,
        &[
            ("~/.agent/config.yaml", Rule::WriteProtected),
            ("/home/me/.agent/config.yaml", Rule::WriteProtected),
            ("~/.agent", Rule::WriteProtected),
            ("~/.agent/", Rule::WriteProtected),
            ("~/.agent/a/b/c", Rule::WriteProtected),
            (".agent/rules", Rule::WriteProtected),
            (".agent", Rule::WriteProtected),
            ("./.agent/x", Rule::WriteProtected),
            ("conf/app/x.yaml", Rule::WriteProtected),
            ("/home/me/work/repo/conf/app/x.yaml", Rule::WriteProtected),
            // Spelled another way.
            ("src/../.agent/x", Rule::WriteProtected),
            ("~/./.agent/x", Rule::WriteProtected),
            ("~/work/../.agent/x", Rule::WriteProtected),
            ("~//.agent//x", Rule::WriteProtected),
            ("conf/./app/../app/x.yaml", Rule::WriteProtected),
            // Names compare without case on every host.
            ("~/.AGENT/x", Rule::WriteProtected),
            (".Agent/x", Rule::WriteProtected),
            ("conf/APP/X.YAML", Rule::WriteProtected),
            ("/HOME/ME/.agent/x", Rule::WriteProtected),
            // A folder that holds it is judged as it is: a file API names
            // the file itself, and nothing here holds a folder's contents.
            ("conf", Rule::WriteProtected),
            ("conf/app", Rule::WriteProtected),
            ("conf/", Rule::WriteProtected),
        ],
    );
    for (path, reason) in [
        ("~/.agent/config.yaml", "writes to the agent's settings"),
        (".agent/x", "writes to the agent's settings"),
        ("conf/app/x.yaml", "writes to the agent's settings"),
    ] {
        let assessment = judge(Access::Write, path, &paths);
        assert_eq!(assessment.findings().len(), 1, "{path}");
        assert_eq!(assessment.findings()[0].rule, Rule::WriteProtected);
        assert_eq!(assessment.findings()[0].reason, reason);
        assert_eq!(assessment.findings()[0].target.as_deref(), Some(path));
    }
}

#[test]
fn a_protected_path_wins_over_the_workspace_and_a_temporary_folder() {
    // Inside the workspace it is `write_protected`, not safe.
    exactly(
        Access::Write,
        &posix_paths(),
        &[
            (".agent/x", &[Rule::WriteProtected][..]),
            ("src/x", &[][..]),
        ],
    );
    let temp = posix().with_protected([Protected::folder("/tmp/state", W)]);
    exactly(
        Access::Write,
        &temp,
        &[
            ("/tmp/state/x", &[Rule::WriteProtected][..]),
            ("/tmp/other/x", &[][..]),
        ],
    );
    // And in the home directory it is the caller's file, not a path outside.
    exactly(
        Access::Write,
        &posix_paths(),
        &[("~/.agent/x", &[Rule::WriteProtected][..])],
    );
}

#[test]
fn a_write_beside_a_protected_path_is_not_a_finding() {
    safe(
        Access::Write,
        &posix_paths(),
        &[
            "conf/app/y.yaml",
            "conf/new.txt",
            "conf/app/x.yaml.bak",
            "conf/app/x",
            ".agentx/x",
            ".agent.d/x",
            "x.agent",
            "src/.agent.rs",
            "src/.agent/x",
            "agent/x",
        ],
    );
    exactly(
        Access::Write,
        &posix_paths(),
        &[
            ("~/.agentx/x", &[Rule::WriteOutside][..]),
            ("~/agent/x", &[Rule::WriteOutside][..]),
        ],
    );
}

#[test]
fn a_read_of_a_protected_path_is_safe() {
    safe(
        Access::Read,
        &posix_paths(),
        &[
            "~/.agent/config.yaml",
            "/home/me/.agent",
            ".agent/rules",
            ".AGENT/rules",
            "conf/app/x.yaml",
            "conf",
        ],
    );
}

#[test]
fn a_pattern_is_not_one_path_even_if_it_picks_a_protected_one() {
    risky(
        Access::Write,
        &posix_paths(),
        &[
            ("*", Rule::Unreadable),
            (".a*/x", Rule::Unreadable),
            ("**/x.yaml", Rule::Unreadable),
            ("[.]agent/x", Rule::Unreadable),
            ("conf/app/[x].yaml", Rule::Unreadable),
            ("~/.ag[e]nt/x", Rule::Unreadable),
        ],
    );
    safe(Access::Write, &posix_paths(), &["app/[id]/page.tsx"]);
}

#[test]
fn a_protected_path_on_windows_is_judged_by_every_name_windows_gives_it() {
    let paths = windows_paths();
    risky(
        Access::Write,
        &paths,
        &[
            (r"C:\Users\me\.agent\config.yaml", Rule::WriteProtected),
            (r"~\.agent\config.yaml", Rule::WriteProtected),
            ("~/.agent/config.yaml", Rule::WriteProtected),
            (r".agent\rules", Rule::WriteProtected),
            (r"conf\app\x.yaml", Rule::WriteProtected),
            // Case.
            (r"C:\USERS\ME\.AGENT\x", Rule::WriteProtected),
            (r".AGENT\x", Rule::WriteProtected),
            // What Windows drops from a name.
            (r".agent.\x", Rule::WriteProtected),
            (r".agent\x.", Rule::WriteProtected),
            (r".agent\x ", Rule::WriteProtected),
            // Short names, the folder's and the file's.
            (r"AGENT~1\x", Rule::WriteProtected),
            (r"agent~1\x", Rule::WriteProtected),
            (r"~\AGENT~1\x", Rule::WriteProtected),
            (r"C:\Users\me\AGENT~2\x", Rule::WriteProtected),
            (r"conf\app\X~1.YAM", Rule::WriteProtected),
            (r"CONF\APP\X.YAML", Rule::WriteProtected),
            // Long paths and a drive-relative path.
            (r"\\?\C:\Users\me\.agent\x", Rule::WriteProtected),
            (r"\\?\C:\Users\me\dev\repo\.agent\x", Rule::WriteProtected),
            (r"C:.agent\x", Rule::WriteProtected),
            (r"C:..\..\.agent\x", Rule::WriteProtected),
            (r"C:\Users\me\dev\repo\..\..\.agent\x", Rule::WriteProtected),
            (r"\Users\me\.agent\x", Rule::WriteProtected),
            // A folder that holds it.
            (r"conf", Rule::WriteProtected),
        ],
    );
    // A stream or a trailing space on a folder is known only when it runs.
    risky(
        Access::Write,
        &paths,
        &[
            (r".agent::$INDEX_ALLOCATION\x", Rule::Unreadable),
            (r".agent \x", Rule::Unreadable),
            (r"C:\Users\me\.agent:s\x", Rule::Unreadable),
        ],
    );
    safe(
        Access::Write,
        &paths,
        &[
            r"conf\app\y.yaml",
            r".agentx\x",
            r"src\AGENT~1.rs",
            r"src\.agent\x",
        ],
    );
    safe(
        Access::Read,
        &paths,
        &[r"~\.agent\config.yaml", r"AGENT~1\x", r".agent\x"],
    );
}

#[test]
fn a_protected_path_on_a_mac_compares_without_case() {
    let paths = macos().with_protected([
        Protected::folder("/Users/me/.agent", W),
        Protected::folder("/Users/me/dev/repo/.agent", W),
    ]);
    risky(
        Access::Write,
        &paths,
        &[
            ("~/.agent/x", Rule::WriteProtected),
            ("~/.Agent/x", Rule::WriteProtected),
            ("/users/me/.AGENT/x", Rule::WriteProtected),
            (".AGENT/x", Rule::WriteProtected),
            (
                "/System/Volumes/Data/Users/me/.agent/x",
                Rule::WriteProtected,
            ),
        ],
    );
}

#[test]
fn with_no_protected_paths_the_same_path_is_judged_by_its_place() {
    exactly(
        Access::Write,
        &posix(),
        &[
            (".agent/rules", &[][..]),
            ("~/.agent/x", &[Rule::WriteOutside][..]),
        ],
    );
}

#[test]
fn what_the_caller_gates_with_may_also_hold_a_secret() {
    // Protected wins: the caller named it on purpose, and a write to it is
    // the caller's to refuse, even where it lies under a key's folder.
    let paths = posix().with_protected([Protected::file("/home/me/.ssh/agent.conf", W)]);
    exactly(
        Access::Write,
        &paths,
        &[
            ("~/.ssh/agent.conf", &[Rule::WriteProtected][..]),
            ("~/.ssh/config", &[Rule::WriteSensitive][..]),
        ],
    );
    // A read is safe: reading the caller's own file is not what it gates.
    exactly(
        Access::Read,
        &paths,
        &[
            ("~/.ssh/agent.conf", &[][..]),
            ("~/.ssh/id_rsa", &[Rule::ReadSecret][..]),
        ],
    );
}

#[test]
fn a_protected_path_by_the_data_volume_or_a_wide_fold_is_still_protected() {
    let paths = macos().with_protected([Protected::folder("/Users/me/.agent", W)]);
    risky(
        Access::Write,
        &paths,
        &[
            // Relative, from `~`, and by the links to the root: all the same
            // folder once the path is absolute.
            (
                "../../../../System/Volumes/Data/Users/me/.agent/x",
                Rule::WriteProtected,
            ),
            (
                "../../../../Volumes/Macintosh HD/Users/me/.agent/x",
                Rule::WriteProtected,
            ),
            (
                "/System/Volumes/Data/Users/me/.agent/x",
                Rule::WriteProtected,
            ),
        ],
    );
    let kelvin = posix().with_protected([Protected::folder("/home/me/.k", W)]);
    risky(
        Access::Write,
        &kelvin,
        &[("/home/me/.\u{212a}/x", Rule::WriteProtected)],
    );
    let win = windows().with_protected([Protected::folder(r"C:\Users\me\.agent\k", W)]);
    risky(
        Access::Write,
        &win,
        &[("C:\\Users\\me\\.agent\\\u{212a}\\x", Rule::WriteProtected)],
    );
}
