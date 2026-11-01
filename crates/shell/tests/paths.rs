//! `effect_paths`: the absolute paths a reads-only line reads, from the same
//! reading as `effect`. Each row names the list for a line; a line that does
//! not only read has none. Every row of every other table is also held to
//! agree with `effect` (see `common::path_disagreement`).

mod common;

use std::path::PathBuf;

use common::{path_disagreement, posix, windows};
use milo_guards_shell::{effect, effect_paths, Effect, Paths, Protected, Reach, Shell};

/// The paths of each row, or none, written as the row says; the rows that
/// differ are named together.
fn check(shell: Shell, paths: &Paths, rows: &[(&str, Option<&[&str]>)]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let want = want.map(|paths| paths.iter().map(PathBuf::from).collect::<Vec<_>>());
            let got = effect_paths(line, shell, paths);
            (got != want).then(|| format!("{line}\n    want {want:?}\n    got  {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

const ROOT: &str = "/home/me/work/repo";

#[test]
fn the_ticket_rows() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat link/id_rsa", Some(&["/home/me/work/repo/link/id_rsa"])),
            ("rg TODO src", Some(&["/home/me/work/repo/src"])),
            ("ls", Some(&[ROOT])),
            ("cat *.rs", Some(&[ROOT])),
            ("git status", Some(&[ROOT])),
            ("mkdir x", None),
        ],
    );
}

#[test]
fn operands_and_redirect_sources_are_listed_as_absolute_paths() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat a.txt", Some(&["/home/me/work/repo/a.txt"])),
            ("cat ./src/../a.txt", Some(&["/home/me/work/repo/a.txt"])),
            ("cat /etc/hosts", Some(&["/etc/hosts"])),
            ("cat ~/.ssh/config", Some(&["/home/me/.ssh/config"])),
            ("cat ../x", Some(&["/home/me/work/x"])),
            ("cat < in.txt", Some(&["/home/me/work/repo/in.txt"])),
            (
                "head -n 3 a.txt b.txt",
                Some(&["/home/me/work/repo/a.txt", "/home/me/work/repo/b.txt"]),
            ),
            (
                "sort -u names.txt | head",
                Some(&["/home/me/work/repo/names.txt"]),
            ),
            (
                "diff a.txt b.txt",
                Some(&["/home/me/work/repo/a.txt", "/home/me/work/repo/b.txt"]),
            ),
            ("wc -l src/lib.rs", Some(&["/home/me/work/repo/src/lib.rs"])),
            ("cat -- -x", Some(&["/home/me/work/repo/-x"])),
            (
                "cat 'my file.txt'",
                Some(&["/home/me/work/repo/my file.txt"]),
            ),
            ("cat ~", Some(&["/home/me"])),
            ("cat /", Some(&["/"])),
            ("cat ../../../../../..", Some(&["/"])),
        ],
    );
}

#[test]
fn what_reads_nothing_lists_nothing() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("", Some(&[])),
            ("echo hi", Some(&[])),
            ("pwd", Some(&[])),
            ("true", Some(&[])),
            ("printf '%s\\n' a b", Some(&[])),
            ("cat a.txt > /dev/null", Some(&["/home/me/work/repo/a.txt"])),
            ("cat /dev/null", Some(&[])),
            ("cat /dev/zero | head -c 4", Some(&[])),
            (
                "cat missing 2>/dev/null",
                Some(&["/home/me/work/repo/missing"]),
            ),
        ],
    );
}

#[test]
fn a_lister_lists_its_folder_and_a_bare_reader_the_working_directory() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("ls", Some(&[ROOT])),
            ("ls -la", Some(&[ROOT])),
            (
                "ls src docs",
                Some(&["/home/me/work/repo/docs", "/home/me/work/repo/src"]),
            ),
            ("ls ~/.config", Some(&["/home/me/.config"])),
            ("ls /", Some(&["/"])),
            ("ls -R", Some(&[ROOT])),
            ("du -sh target", Some(&["/home/me/work/repo/target"])),
            ("du -sh", Some(&[ROOT])),
            ("fd -e rs", Some(&[ROOT])),
            ("find . -name '*.rs'", Some(&[ROOT])),
            ("find src -type f", Some(&["/home/me/work/repo/src"])),
            ("find", Some(&[ROOT])),
            ("rg TODO", Some(&[ROOT])),
            ("grep -rn TODO docs/", Some(&["/home/me/work/repo/docs"])),
            ("grep -r TODO", Some(&[ROOT])),
            ("ls | head -n 5", Some(&[ROOT])),
            ("ls | xargs cat", Some(&[ROOT])),
        ],
    );
}

#[test]
fn a_deep_read_is_listed_as_its_root() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("rg TODO src", Some(&["/home/me/work/repo/src"])),
            (
                "grep -r x src docs",
                Some(&["/home/me/work/repo/docs", "/home/me/work/repo/src"]),
            ),
            (
                "diff -r a b",
                Some(&["/home/me/work/repo/a", "/home/me/work/repo/b"]),
            ),
            ("rg TODO ~/notes", Some(&["/home/me/notes"])),
            ("rg TODO /etc", Some(&["/etc"])),
            ("find ../other -name x", Some(&["/home/me/work/other"])),
        ],
    );
}

#[test]
fn a_pattern_is_the_folder_it_expands_in() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat *.rs", Some(&[ROOT])),
            ("cat src/*.rs", Some(&["/home/me/work/repo/src"])),
            ("cat src/*/mod.rs", Some(&["/home/me/work/repo/src"])),
            ("wc -l src/**/*.rs", Some(&["/home/me/work/repo/src"])),
            ("cat src/a?.rs", Some(&["/home/me/work/repo/src"])),
            ("cat src/[ab].rs", Some(&["/home/me/work/repo/src"])),
            ("cat ../*/x", Some(&["/home/me/work"])),
            ("cat /etc/*", Some(&["/etc"])),
            ("cat /*", Some(&["/"])),
            ("cat ~/.ssh/*", Some(&["/home/me/.ssh"])),
            ("cat ~/*", Some(&["/home/me"])),
            ("echo ~/.ssh/*", Some(&["/home/me/.ssh"])),
            (
                "cat src/*.rs docs/*.md",
                Some(&["/home/me/work/repo/docs", "/home/me/work/repo/src"]),
            ),
            ("cat src/*.rs src/*.toml", Some(&["/home/me/work/repo/src"])),
            // A part that starts with a dot can also pick `..`.
            ("cat .*/x", Some(&["/home/me/work", ROOT])),
            ("cat é*", Some(&[ROOT])),
        ],
    );
}

#[test]
fn git_reads_the_repository_at_the_working_directory_or_where_c_goes() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("git status", Some(&[ROOT])),
            ("git diff --stat", Some(&[ROOT])),
            ("git log --oneline -n 5", Some(&[ROOT])),
            ("git status && git diff", Some(&[ROOT])),
            ("git -C sub status", Some(&["/home/me/work/repo/sub"])),
            ("git -C a -C b status", Some(&["/home/me/work/repo/a/b"])),
            ("git -C a -C /other status", Some(&["/other"])),
            ("git -C .. status", Some(&["/home/me/work"])),
            ("git -C ~ status", Some(&["/home/me"])),
            (
                "git diff -- src/lib.rs",
                Some(&[ROOT, "/home/me/work/repo/src/lib.rs"]),
            ),
            // A revision may be a path, and `REV:path` is from the root of
            // the repository, which the line does not say: it is read from
            // the working directory and from every workspace folder.
            (
                "git show HEAD:a.rs",
                Some(&[ROOT, "/home/me/work/repo/a.rs"]),
            ),
        ],
    );
    let two = Paths::new(ROOT, "/home/me", [ROOT, "/home/me/other"]);
    check(
        Shell::Posix,
        &two,
        &[(
            "git show HEAD:a.rs",
            Some(&["/home/me/other/a.rs", ROOT, "/home/me/work/repo/a.rs"]),
        )],
    );
}

#[test]
fn a_cd_moves_the_line_and_is_itself_a_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cd src && ls", Some(&["/home/me/work/repo/src"])),
            (
                "cd src && cat a.txt",
                Some(&["/home/me/work/repo/src", "/home/me/work/repo/src/a.txt"]),
            ),
            (
                "cd crates/shell && git status",
                Some(&["/home/me/work/repo/crates/shell"]),
            ),
            ("(cd crates && ls)", Some(&["/home/me/work/repo/crates"])),
            ("cd .. && ls", Some(&["/home/me/work"])),
            ("cd ~ && cat x", Some(&["/home/me", "/home/me/x"])),
            ("cd /etc && cat hosts", Some(&["/etc", "/etc/hosts"])),
            (
                "cd src && cd .. && ls",
                Some(&["/home/me/work/repo", "/home/me/work/repo/src"]),
            ),
        ],
    );
}

#[test]
fn the_list_is_sorted_and_holds_each_path_once() {
    let paths = posix();
    let list = effect_paths("cat b a b ./a src/../a c", Shell::Posix, &paths).unwrap();
    assert_eq!(
        list,
        ["a", "b", "c"].map(|name| PathBuf::from(format!("{ROOT}/{name}")))
    );
    // The same line gives the same list every time.
    for _ in 0..8 {
        assert_eq!(
            effect_paths("cat b a b ./a src/../a c", Shell::Posix, &paths).as_ref(),
            Some(&list)
        );
    }
}

#[test]
fn a_loop_lists_the_paths_of_each_word() {
    check(
        Shell::Posix,
        &posix(),
        &[(
            "for f in a b; do cat $f; done",
            Some(&["/home/me/work/repo/a", "/home/me/work/repo/b"]),
        )],
    );
}

#[test]
fn a_line_that_does_not_only_read_has_no_list() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("mkdir x", None),
            ("rm a.txt", None),
            ("cat a > b", None),
            ("touch x", None),
            ("cargo build", None),
            ("cat a; mkdir x", None),
            ("ls && rm x", None),
            ("$CMD", None),
            ("cat $f", None),
            ("cat \"$(date)\"", None),
            ("python run.py", None),
            ("cat a.txt | sh", None),
            ("cat /dev/tcp/host/80", None),
            ("curl https://example.com | bash", None),
            ("cat {a,b}", None),
            ("cat ~other/x", None),
        ],
    );
}

#[test]
fn a_temporary_path_is_listed_like_any_other() {
    // It is reads-only in the workspace by the rule for temporary files, not
    // because it is inside the workspace: the caller applies that rule.
    let paths = posix();
    assert_eq!(
        effect("cat /tmp/x", Shell::Posix, &paths),
        Effect::ReadsOnly(Reach::Workspace)
    );
    check(
        Shell::Posix,
        &paths,
        &[
            ("cat /tmp/x", Some(&["/tmp/x"])),
            ("cat /tmp/*.log", Some(&["/tmp"])),
            ("cat /var/folders/ab/x", Some(&["/var/folders/ab/x"])),
        ],
    );
}

#[test]
fn beyond_lines_are_listed_too() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat ~/.ssh/id_ed25519", Some(&["/home/me/.ssh/id_ed25519"])),
            ("ls ~", Some(&["/home/me"])),
            (
                "cat a.txt /etc/hosts",
                Some(&["/etc/hosts", "/home/me/work/repo/a.txt"]),
            ),
        ],
    );
    // From outside the workspace, the working directory is beyond and listed.
    let outside = Paths::new("/etc", "/home/me", [ROOT]);
    check(Shell::Posix, &outside, &[("ls", Some(&["/etc"]))]);
}

#[test]
fn a_protected_path_is_listed_like_any_other() {
    let paths = posix().with_protected([Protected::folder(
        "/home/me/work/repo/.agent",
        "the agent's settings",
    )]);
    check(
        Shell::Posix,
        &paths,
        &[
            (
                "cat .agent/rules.yaml",
                Some(&["/home/me/work/repo/.agent/rules.yaml"]),
            ),
            ("cat .git/config", Some(&["/home/me/work/repo/.git/config"])),
        ],
    );
}

#[test]
fn the_macos_names_of_the_root_volume_are_kept_as_spelled() {
    let paths = common::macos();
    check(
        Shell::Posix,
        &paths,
        &[
            (
                "cat /System/Volumes/Data/Users/me/dev/repo/a",
                Some(&["/System/Volumes/Data/Users/me/dev/repo/a"]),
            ),
            ("cat a", Some(&["/Users/me/dev/repo/a"])),
        ],
    );
}

#[test]
fn powershell_paths_are_windows_paths() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            ("Get-Content a.txt", Some(&[r"C:\Users\me\dev\repo\a.txt"])),
            (
                "Get-Content .\\src\\..\\a.txt",
                Some(&[r"C:\Users\me\dev\repo\a.txt"]),
            ),
            ("Get-Content ~\\a.txt", Some(&[r"C:\Users\me\a.txt"])),
            (
                "Get-Content C:\\Windows\\win.ini",
                Some(&[r"C:\Windows\win.ini"]),
            ),
            (
                "Get-Content C:/Windows/win.ini",
                Some(&[r"C:\Windows\win.ini"]),
            ),
            (
                "Get-Content src\\*.rs",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("Get-Content *.rs", Some(&[r"C:\Users\me\dev\repo"])),
            ("Get-Content C:\\*", Some(&[r"C:\"])),
            ("Get-Content C:*", Some(&[r"C:\Users\me\dev\repo"])),
            ("Get-Content C:x\\*", Some(&[r"C:\Users\me\dev\repo\x"])),
            (
                "Get-Content FileSystem::C:\\Users\\me\\dev\\repo\\x",
                Some(&[r"C:\Users\me\dev\repo\x"]),
            ),
            ("Get-Content FileSystem::C:\\*", Some(&[r"C:\"])),
            (
                "Get-Content \\\\?\\C:\\Users\\me\\dev\\repo\\y",
                Some(&[r"C:\Users\me\dev\repo\y"]),
            ),
            ("Get-ChildItem", Some(&[r"C:\Users\me\dev\repo"])),
            ("Get-ChildItem src", Some(&[r"C:\Users\me\dev\repo\src"])),
            (
                "Get-ChildItem -Recurse src",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("gci -Rec", Some(&[r"C:\Users\me\dev\repo"])),
            (
                "Select-String -Path src\\*.rs -Pattern TODO",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("git status", Some(&[r"C:\Users\me\dev\repo"])),
            ("git -C sub status", Some(&[r"C:\Users\me\dev\repo\sub"])),
            (
                "Get-Content a.txt | Select-Object -First 3",
                Some(&[r"C:\Users\me\dev\repo\a.txt"]),
            ),
            // Not a place on a disk: no path.
            ("Get-Content $null", Some(&[])),
            ("Get-Content HKLM:\\Software", Some(&[])),
            ("Get-Content Env:Path", Some(&[])),
            ("Get-Content D:x", Some(&[])),
            ("Write-Output hi", Some(&[])),
            // Not only a read: no list.
            ("Remove-Item a.txt", None),
            ("Set-Content a.txt hi", None),
            ("Get-Content a.txt > b.txt", None),
            ("Get-Content \\\\server\\share\\x", None),
            ("Get-Content $p", None),
        ],
    );
}

#[test]
fn cmd_paths_are_windows_paths() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            ("type a.txt", Some(&[r"C:\Users\me\dev\repo\a.txt"])),
            ("type ..\\x", Some(&[r"C:\Users\me\dev\x"])),
            ("type C:\\Windows\\win.ini", Some(&[r"C:\Windows\win.ini"])),
            ("type ~\\a", Some(&[r"C:\Users\me\a"])),
            ("type \\Windows\\win.ini", Some(&[r"C:\Windows\win.ini"])),
            ("dir", Some(&[r"C:\Users\me\dev\repo"])),
            ("dir src", Some(&[r"C:\Users\me\dev\repo\src"])),
            ("dir /s src", Some(&[r"C:\Users\me\dev\repo\src"])),
            ("findstr foo *.rs", Some(&[r"C:\Users\me\dev\repo"])),
            (
                "findstr foo src\\*.rs",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("type *.txt", Some(&[r"C:\Users\me\dev\repo"])),
            ("type nul", Some(&[])),
            ("git status", Some(&[r"C:\Users\me\dev\repo"])),
            (
                "type \\\\?\\C:\\Users\\me\\dev\\repo\\y",
                Some(&[r"C:\Users\me\dev\repo\y"]),
            ),
            ("type D:x", Some(&[])),
            ("del a.txt", None),
            ("type \\\\server\\share\\x", None),
        ],
    );
}

#[test]
fn a_workspace_that_is_the_home_folder_lists_what_is_read_there() {
    let home = Paths::new("/home/me", "/home/me", ["/home/me"]);
    check(
        Shell::Posix,
        &home,
        &[
            ("ls", Some(&["/home/me"])),
            ("cat .ssh/config", Some(&["/home/me/.ssh/config"])),
        ],
    );
}

#[test]
fn every_extra_row_agrees_with_effect() {
    // The tables go through `common::path_disagreement` already; these are
    // the lines that mix shells' habits and the spellings of paths.
    let rows = [
        "cat a b *.rs src/*.rs",
        "cd src && rg TODO .. | head",
        "git -C a log -p -- b c",
        "sudo cat /etc/hosts",
        "env LANG=C ls",
        "find . -name '*.log' -exec cat {} +",
        "mkdir x && cat x",
        "cat /*",
        "cat \"\"",
        "echo \"/usr/*\"",
        "ls ~root",
        "cat a >&2",
    ];
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|line| path_disagreement(Shell::Posix, &posix(), line))
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
/// The caller's side of the contract, with the disk played by a table of
/// links (the guard itself does no I/O, and neither do its tests): a link in
/// the workspace that points out of it reads as `Workspace` by spelling, and
/// resolving each listed path as the docs say finds where it really goes.
#[test]
fn a_link_that_leaves_the_workspace_is_found_by_resolving_the_listed_paths() {
    /// Where `path` really is: each link on the way is followed, and the names
    /// below one that does not exist are put back (the nearest existing
    /// ancestor, resolved, and the rest).
    fn resolve(path: &str, links: &[(&str, &str)]) -> String {
        let mut at = String::new();
        for name in path.split('/').filter(|name| !name.is_empty()) {
            at = format!("{at}/{name}");
            if let Some((_, to)) = links.iter().find(|(from, _)| *from == at) {
                at = (*to).to_string();
            }
        }
        at
    }

    let links = [("/home/me/work/repo/link", "/home/me/.ssh")];
    let paths = posix();
    let leaves = |line: &str| {
        effect_paths(line, Shell::Posix, &paths)
            .unwrap()
            .iter()
            .any(|path| {
                let real = resolve(&path.to_string_lossy(), &links);
                real != ROOT && !real.starts_with(&format!("{ROOT}/"))
            })
    };
    // Judged by spelling, all of them stay in the workspace; on the disk,
    // each reads what the link points at.
    for line in [
        "cat link/id_rsa",
        "ls link",
        "rg TODO link",
        "cat link/*",
        "cd link && ls",
        "cat src/../link/id_rsa",
    ] {
        assert_eq!(
            effect(line, Shell::Posix, &paths),
            Effect::ReadsOnly(Reach::Workspace),
            "{line}"
        );
        assert!(leaves(line), "{line}");
    }
    assert_eq!(
        effect_paths("cat link/id_rsa", Shell::Posix, &paths).unwrap(),
        [PathBuf::from("/home/me/work/repo/link/id_rsa")]
    );
    assert_eq!(
        resolve("/home/me/work/repo/link/id_rsa", &links),
        "/home/me/.ssh/id_rsa"
    );
    // What is in the workspace stays in it.
    for line in [
        "cat src/a.rs",
        "ls",
        "rg TODO src",
        "cat *.rs",
        "git status",
    ] {
        assert!(!leaves(line), "{line}");
    }
}
