//! A `file:` URL is always a finding; where its path lands only sharpens the
//! words, and the path is placed through core's resolver like any other.

use milo_guards_core::testing::{macos, posix, windows};
use milo_guards_core::{Paths, Protected};
use milo_guards_url::{judge, Rule};

/// The one finding of a `file:` URL: its rule must be `local_file`.
fn read(url: &str, paths: &Paths) -> (String, Option<String>) {
    let assessment = judge(url, paths);
    let findings = assessment.findings();
    assert_eq!(findings.len(), 1, "{url}: {findings:?}");
    assert_eq!(findings[0].rule, Rule::LocalFile, "{url}");
    (findings[0].reason.clone(), findings[0].target.clone())
}

#[test]
fn a_file_url_says_where_its_path_lands() {
    for (url, reason) in [
        ("file:///home/me/.ssh/id_rsa", "reads your SSH keys"),
        (
            "file:///home/me/.aws/credentials",
            "reads your AWS credentials",
        ),
        (
            "file:///home/me/work/repo/src/main.rs",
            "reads a path inside the workspace",
        ),
        (
            "file:///home/me/work/repo/.git/config",
            "reads the repository's history",
        ),
        (
            "file:///home/me/notes.txt",
            "reads a path outside the workspace",
        ),
        ("file:///home/me", "reads your home directory"),
        ("file:///tmp/x.txt", "reads a temporary file"),
        ("file:///etc/passwd", "reads a system folder"),
        ("file:///", "reads the root of the disk"),
    ] {
        assert_eq!(read(url, &posix()).0, reason, "{url}");
    }
}

#[test]
fn a_file_url_is_a_finding_even_inside_the_workspace() {
    assert!(!judge("file:///home/me/work/repo/README.md", &posix()).is_safe());
    assert!(!judge("file:///tmp/x", &posix()).is_safe());
    assert!(!judge("file:///dev/null", &posix()).is_safe());
}

#[test]
fn the_path_is_judged_after_escapes_and_dot_segments() {
    for url in [
        "FILE:///home/me/.ssh/id_rsa",
        "File:///home/me/.ssh/id_rsa",
        "file:/home/me/.ssh/id_rsa",
        "file:home/me/.ssh/id_rsa",
        "file://localhost/home/me/.ssh/id_rsa",
        "file:///home/me/.ssh//id_rsa",
        "file:///home/me/./.ssh/id_rsa",
        "file:///home/me/.ssh/../.ssh/id_rsa",
        "file:///home/me/work/repo/../../.ssh/id_rsa",
        "file:///home/me/%2essh/id_rsa",
        "file:///home/me/.ssh/%69d_rsa",
        "file:///home/me/%2e%2e/me/.ssh/id_rsa",
        "file:///home/me/%2E%2E/me/.ssh/id_rsa",
        "file:///home/me/.ssh%2fid_rsa",
        "file:///home/me/.ssh%2Fid_rsa",
        "file:///home/me/.ssh\\id_rsa",
        " file:///home/me/.ssh/id_rsa ",
    ] {
        assert_eq!(read(url, &posix()).0, "reads your SSH keys", "{url}");
    }
}

#[test]
fn the_words_are_cores_and_a_file_url_is_a_finding_whatever_they_are() {
    // Core compares the SSH folder's name without case on every host, and
    // the URL guard says what core says.
    let (reason, _) = read("file:///home/me/.SSH/id_rsa", &posix());
    assert_eq!(reason, "reads your SSH keys");
    let (reason, _) = read("file:///home/me/.sshx/id_rsa", &posix());
    assert_eq!(reason, "reads a path outside the workspace");
}

#[test]
fn the_target_is_the_path() {
    assert_eq!(
        read("file:///home/me/.ssh/../.ssh/id_rsa", &posix())
            .1
            .as_deref(),
        Some("/home/me/.ssh/id_rsa")
    );
    assert_eq!(
        read("file:///home/me/a%20b.txt", &posix()).1.as_deref(),
        Some("/home/me/a b.txt")
    );
}

#[test]
fn a_path_that_is_not_what_it_reads_as_is_known_only_when_it_runs() {
    let (reason, target) = read("file:///home/me/.ssh%00/id_rsa", &posix());
    assert_eq!(reason, "reads a path only known when it runs");
    assert_eq!(target.as_deref(), Some("/home/me/.ssh\u{fffd}/id_rsa"));
}

#[test]
fn a_macos_home_is_the_same() {
    assert_eq!(
        read("file:///Users/me/.ssh/id_rsa", &macos()).0,
        "reads your SSH keys"
    );
    assert_eq!(
        read("file:///Users/me/dev/repo/x.rs", &macos()).0,
        "reads a path inside the workspace"
    );
}

#[test]
fn a_windows_path_is_read_as_one() {
    for (url, reason) in [
        ("file:///C:/Users/me/.ssh/id_rsa", "reads your SSH keys"),
        ("file:///c:/users/me/.ssh/id_rsa", "reads your SSH keys"),
        ("file:///C|/Users/me/.ssh/id_rsa", "reads your SSH keys"),
        ("file:///C:\\Users\\me\\.ssh\\id_rsa", "reads your SSH keys"),
        (
            "file:///C:/Users/me/dev/repo/src/x.rs",
            "reads a path inside the workspace",
        ),
        (
            "file:///C:/Windows/System32/config/SAM",
            "reads the Windows account database",
        ),
        (
            "file:///C:/Windows/System32/notepad.exe",
            "reads a system folder",
        ),
    ] {
        assert_eq!(read(url, &windows()).0, reason, "{url}");
    }
    // `repo/..` is `dev`: a sibling of the SSH folder, not the folder.
    assert_eq!(
        read("file:///C:/Users/me/dev/repo/../.ssh/id_rsa", &windows()).0,
        "reads a path outside the workspace"
    );
}

#[test]
fn what_the_caller_gates_with_is_read_in_its_words() {
    let paths =
        posix().with_protected([Protected::folder("/home/me/.agent", "the agent's settings")]);
    assert_eq!(
        read("file:///home/me/.agent/config.yaml", &paths).0,
        "reads the agent's settings"
    );
    assert_eq!(
        read("file:///home/me/work/repo/src/x.rs", &paths).0,
        "reads a path inside the workspace"
    );
}

#[test]
fn a_file_on_another_machine_is_named_so_and_its_host_is_judged() {
    let assessment = judge("file://127.0.0.1/etc/passwd", &posix());
    let found: Vec<_> = assessment
        .findings()
        .iter()
        .map(|f| (f.rule, f.reason.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            (Rule::LocalFile, "reads a file from another machine"),
            (Rule::LocalAddress, "fetches your own machine"),
        ]
    );
    for url in ["file://server/share/x", "file://evil.example.com/share/x"] {
        assert_eq!(
            judge(url, &windows()).findings()[0].rule,
            Rule::LocalFile,
            "{url}"
        );
        assert_eq!(
            judge(url, &windows()).findings()[0].reason,
            "reads a file from another machine",
            "{url}"
        );
    }
    // `file://user@host/` is not a URL.
    assert_eq!(
        judge("file://user@host/x", &posix()).findings()[0].rule,
        Rule::Unreadable
    );
}
