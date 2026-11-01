//! Whatever the text, judging it ends, never panics, and never calls a path
//! it could not read safe.

mod common;

use common::{posix, windows};
use milo_guards_file::{judge, Access, Paths, Protected, Rule, MAX_PATH_LEN};

/// Pieces of paths, joined at random into texts no file API expects.
const PIECES: [&str; 44] = [
    "~",
    "~root",
    "/",
    "//",
    "\\",
    "\\\\",
    "..",
    ".",
    "...",
    "*",
    "?",
    "[",
    "]",
    "[!",
    "$",
    "${",
    "%",
    "%X%",
    "`",
    "\0",
    "\n",
    " ",
    ":",
    "::$DATA",
    "C:",
    "D:",
    "\\\\?\\",
    "\\\\.\\",
    "//?/",
    "UNC",
    "GLOBALROOT",
    ".ssh",
    ".git",
    ".agent",
    "AGENT~1",
    "GIT~1",
    "SSH~1",
    "id_rsa",
    "etc",
    "shadow",
    "System/Volumes/Data",
    "\u{17f}",
    "\u{212a}",
    "é",
];

/// A small deterministic generator, so a failure names its seed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as usize
    }
}

fn machines() -> [Paths; 4] {
    [
        posix(),
        windows(),
        posix().with_protected([Protected::folder("/home/me/.agent", "the agent's settings")]),
        windows().with_protected([Protected::file(
            r"C:\Users\me\.agent",
            "the agent's settings",
        )]),
    ]
}

#[test]
fn random_paths_never_panic_and_a_path_it_cannot_read_is_never_safe() {
    let machines = machines();
    let mut random = Lcg(7);
    for _ in 0..4_000 {
        let length = random.next() % 14;
        let path: Vec<&str> = (0..length)
            .map(|_| PIECES[random.next() % PIECES.len()])
            .collect();
        let path = path.join(if random.next().is_multiple_of(2) {
            ""
        } else {
            "/"
        });
        for paths in &machines {
            for access in [Access::Read, Access::Write] {
                let assessment = judge(access, &path, paths);
                // The same text, the same answer.
                assert_eq!(assessment, judge(access, &path, paths), "{path:?}");
                // A risky answer names a finding for each reason.
                assert_eq!(assessment.is_safe(), assessment.findings().is_empty());
                // What is no one literal path is never safe.
                let unreadable = path.is_empty()
                    || path.contains(['\0', '\n', '*', '`'])
                    || path.starts_with(' ');
                if unreadable {
                    assert!(
                        assessment
                            .findings()
                            .iter()
                            .any(|finding| finding.rule == Rule::Unreadable),
                        "{access:?} {path:?}: {assessment:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_path_too_long_is_not_read() {
    for machine in machines() {
        for access in [Access::Read, Access::Write] {
            for long in [
                "a".repeat(MAX_PATH_LEN + 1),
                "/".repeat(MAX_PATH_LEN + 1),
                "../".repeat(MAX_PATH_LEN),
                "a/../".repeat(MAX_PATH_LEN) + "x",
                ".ssh/".repeat(10_000),
                "é".repeat(MAX_PATH_LEN),
                "\\\\?\\C:\\".to_string() + &"a\\".repeat(MAX_PATH_LEN),
            ] {
                let assessment = judge(access, &long, &machine);
                assert!(
                    assessment
                        .findings()
                        .iter()
                        .any(|finding| finding.rule == Rule::Unreadable),
                    "{access:?} {} bytes",
                    long.len()
                );
            }
        }
    }
}

#[test]
fn a_thousand_dot_dot_segments_end_at_the_top() {
    let up = "../".repeat(1_000);
    assert!(up.len() < MAX_PATH_LEN);
    let at_the_top = |rest: &str| format!("{up}{rest}");
    let rules = |access, path: &str| -> Vec<Rule> {
        judge(access, path, &posix())
            .findings()
            .iter()
            .map(|finding| finding.rule)
            .collect()
    };
    // Climbing past the root stays at the root, and the root's folders are
    // what they are from there.
    assert_eq!(
        rules(Access::Read, &at_the_top("etc/shadow")),
        [Rule::ReadSecret]
    );
    assert_eq!(
        rules(Access::Write, &at_the_top("etc/shadow")),
        [Rule::WriteSensitive]
    );
    assert_eq!(rules(Access::Write, &at_the_top("x")), [Rule::WriteOutside]);
    assert_eq!(rules(Access::Read, &at_the_top("etc/hosts")), []);
    assert_eq!(
        rules(Access::Read, &at_the_top("root/.ssh/id_rsa")),
        [Rule::ReadSecret]
    );
    // And back down into the workspace.
    let back = at_the_top("home/me/work/repo/src/x.rs");
    assert_eq!(rules(Access::Write, &back), []);
    // A thousand climbs and as many descents cancel out.
    let there_and_back = "a/../".repeat(800) + "src/x.rs";
    assert_eq!(rules(Access::Write, &there_and_back), []);
    // The same on Windows, where a drive's root holds too.
    let up = "..\\".repeat(1_000);
    let on_windows = judge(
        Access::Read,
        &format!("{up}Windows\\System32\\config\\SAM"),
        &windows(),
    );
    assert_eq!(on_windows.findings()[0].rule, Rule::ReadSecret);
    let on_windows = judge(Access::Write, &format!("{up}x"), &windows());
    assert_eq!(on_windows.findings()[0].rule, Rule::WriteOutside);
}

#[test]
fn a_path_at_the_limit_is_judged() {
    let name = "a".repeat(MAX_PATH_LEN);
    for machine in machines() {
        assert!(judge(Access::Read, &name, &machine).is_safe());
        assert!(judge(Access::Write, &name, &machine).is_safe());
    }
}

#[test]
fn a_path_of_odd_unicode_is_judged_and_returns() {
    for path in [
        "\u{0}",
        "\u{feff}~/.ssh/id_rsa",
        "~/.ssh/id_rsa\u{200b}",
        "~/.ssh/\u{202e}id_rsa",
        "\u{1f4c1}/x",
        "é/é/é",
        "e\u{301}/x",
        "/home/me/.ssh/id_rsa\u{0}",
        "ß/ẞ/ǅ/ǆ",
        "İ/ı/i̇",
    ] {
        for machine in machines() {
            for access in [Access::Read, Access::Write] {
                let _ = judge(access, path, &machine);
            }
        }
    }
}
